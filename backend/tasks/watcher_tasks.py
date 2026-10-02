"""
watcher_tasks.py — Deployment watcher polling tasks.

Polls all verified, watcher-enabled targets every WATCHER_INTERVAL_SECONDS.
Detects prompt/deployment updates using a stable fingerprinting protocol:
- temperature=0 + seed=42 best-effort.
- Graceful fallback on HTTP 400/422 schema rejections.
- Median majority vote of 3 probes.
- Semantic Cosine Similarity check using sentence-transformers to eliminate
  minor formatting or token changes false positives.
- Triggers automatic retests of open findings upon detecting a deployment change.
"""

from datetime import datetime
import hashlib
from collections import Counter
import httpx
from sqlalchemy.orm import Session

from contracts import ScanStatus, ScanTrigger, ScanType
from crypto import decrypt_token
from database import SessionLocal
from models import Scan, Target
from tasks.celery_app import celery_app

FIXED_PROBE = "Hello, what can you help me with today?"
NUM_PROBE_SAMPLES = 3
CHANGE_SIM_THRESHOLD = 0.85  # Below this semantic similarity = real change detected




def _single_probe(url: str, headers: dict) -> str | None:
    """
    Send a single probe with temperature=0/seed=42 for deterministic output.
    Gracefully falls back to a minimal payload if target rejects extra schema fields.
    """
    deterministic_body = {
        "messages": [{"role": "user", "content": FIXED_PROBE}],
        "max_tokens": 80,
        "temperature": 0.0,
        "seed": 42,
    }
    minimal_body = {
        "messages": [{"role": "user", "content": FIXED_PROBE}],
    }

    for body in [deterministic_body, minimal_body]:
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.post(url, headers=headers, json=body)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices")
                    if choices and isinstance(choices, list) and len(choices) > 0:
                        content = choices[0].get("message", {}).get("content")
                        if content:
                            return content.strip().lower()[:300]

                    for key in ["response", "message", "output", "text"]:
                        val = data.get(key)
                        if val:
                            return str(val).strip().lower()[:300]
                    return resp.text.strip().lower()[:300]
                elif resp.status_code in (400, 422):
                    # Schema validation error — try the minimal body fallback
                    continue
                else:
                    return None
        except Exception:
            return None
    return None


def get_content_fingerprint_with_text(url: str, auth_token: str = None) -> tuple[str | None, str | None]:
    """
    Send 3 probes, pick the most common response, and return its SHA-256 hash
    along with the raw response text.
    """
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    responses = []
    for _ in range(NUM_PROBE_SAMPLES):
        text = _single_probe(url, headers)
        if text:
            responses.append(text)

    if not responses:
        return None, None

    # Vote for the most common response to handle occasional model fluctuations
    most_common = Counter(responses).most_common(1)[0][0]
    sha = hashlib.sha256(most_common.encode("utf-8")).hexdigest()
    return sha, most_common


_embed_model = None


def get_embed_model():
    """Lazy-load the SentenceTransformer model for similarity check."""
    global _embed_model
    if _embed_model is None:
        from sentence_transformers import SentenceTransformer
        _embed_model = SentenceTransformer("all-MiniLM-L6-v2")
    return _embed_model


def has_significant_change(
    old_fp: str,
    new_fp: str,
    old_text: str,
    new_text: str,
) -> bool:
    """
    Compare old and new fingerprints.
    Uses SentenceTransformer cosine-similarity to prevent false alerts from
    API formatting/spacing variations.
    """
    if old_fp == new_fp:
        return False

    try:
        model = get_embed_model()
        embs = model.encode([old_text, new_text], convert_to_tensor=True)
        from sentence_transformers import util
        sim = float(util.cos_sim(embs[0], embs[1]))
        # Change detected only if semantic similarity drops below threshold
        return sim < CHANGE_SIM_THRESHOLD
    except Exception:
        # Fallback to pure hash check if embedding fails
        return True


@celery_app.task(name="tasks.watcher_tasks.check_all_targets", queue="default")
def check_all_targets():
    """Celery Beat periodic task: queries and dispatches all active targets."""
    db: Session = SessionLocal()
    try:
        targets = (
            db.query(Target)
            .filter(Target.watcher_enabled == True, Target.ownership_verified == True)
            .all()
        )
        for target in targets:
            check_single_target.delay(str(target.id))
    finally:
        db.close()


@celery_app.task(name="tasks.watcher_tasks.check_single_target", queue="default")
def check_single_target(target_id: str):
    """Probes a single target and triggers retests on deployment changes."""
    db: Session = SessionLocal()
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target or not target.watcher_enabled:
            return

        # Decrypt auth token
        auth_token = None
        if target.auth_token_encrypted:
            try:
                auth_token = decrypt_token(target.auth_token_encrypted)
            except Exception:
                return

        new_fp, new_text = get_content_fingerprint_with_text(target.url, auth_token)
        if not new_fp or not new_text:
            return

        now = datetime.utcnow()

        # Initial probe cycle
        if target.last_fingerprint is None:
            target.last_fingerprint = new_fp
            target.last_fingerprint_text = new_text
            target.last_probed_at = now
            db.commit()
            return

        # Check for changes
        changed = has_significant_change(
            target.last_fingerprint,
            new_fp,
            target.last_fingerprint_text or "",
            new_text,
        )

        target.last_probed_at = now

        if changed:
            # Save new fingerprint
            target.last_fingerprint = new_fp
            target.last_fingerprint_text = new_text
            db.commit()

            # Trigger auto-retest
            # Fetch the most recent completed full scan for this target
            last_full_scan = (
                db.query(Scan)
                .filter(
                    Scan.target_id == target.id,
                    Scan.scan_type == ScanType.full,
                    Scan.status.in_([ScanStatus.done, ScanStatus.partial]),
                )
                .order_by(Scan.created_at.desc())
                .first()
            )

            if last_full_scan:
                retest_scan = Scan(
                    target_id=target.id,
                    scan_type=ScanType.retest,
                    triggered_by=ScanTrigger.deployment_detected,
                    status=ScanStatus.pending,
                    parent_scan_id=last_full_scan.id,
                    deployment_fingerprint=new_fp[:128],
                    total_attacks=0,  # calculated during retest task start
                    completed_attacks=0,
                )
                db.add(retest_scan)
                db.commit()
                db.refresh(retest_scan)

                # Queue the retest task
                from tasks.scan_tasks import run_retest_scan
                run_retest_scan.delay(
                    str(retest_scan.id),
                    str(target.id),
                    str(last_full_scan.id),
                )

                # Publish deployment detected event
                from tasks.scan_tasks import publish_sse_event
                publish_sse_event(
                    str(last_full_scan.id),
                    "deployment_detected",
                    {
                        "target_id": str(target.id),
                        "retest_scan_id": str(retest_scan.id),
                    },
                )
            else:
                # No prior scan exists to retest — just update fingerprint
                db.commit()
        else:
            db.commit()

    finally:
        db.close()
