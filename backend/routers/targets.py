"""
routers/targets.py — Target registration, ownership verification, watcher toggle.

Security invariants:
- management_token is generated here, shown ONCE in the response, and NEVER stored
  in plaintext — only its bcrypt hash goes to the DB.
- auth_token (bearer key for the target chatbot) is encrypted via crypto.encrypt_token()
  before storage. The plaintext is never persisted.
- GET responses NEVER include auth_token_encrypted or management_token_hash.
"""

import secrets
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

import bcrypt
import httpx
from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from crypto import encrypt_token
from database import get_db
from models import Environment, Target, User
from utils.rate_limiter import check_rate_limit, clear_rate_limit
from routers.auth import get_current_user

router = APIRouter(prefix="/targets", tags=["targets"])


def _origin(url: str) -> str:
    """
    Reduce a target URL to its origin (scheme://host:port), dropping any path.

    Targets are registered with their full chat-completion endpoint (e.g.
    "http://host:9000/chat"), but the ownership-verification well-known file
    must live at the domain root ("http://host:9000/.well-known/..."), not
    nested under that path. Without this, verification 404s for any target
    URL that has a path component — which is every realistic target URL.
    """
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


@router.post("/")
def register_target(
    name: str,
    url: str,
    environment: str = "staging",
    auth_token: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Register a new target chatbot (requires authentication).

    Returns management_token EXACTLY ONCE — bcrypt hash is stored, raw value is not.
    The caller must save management_token immediately; it cannot be recovered.
    """
    url = url.strip().rstrip("/")

    try:
        env = Environment(environment)
    except ValueError:
        raise HTTPException(
            400,
            f"environment must be one of: {[e.value for e in Environment]}",
        )

    # Ownership verification token (placed in a well-known file to prove domain control)
    verification_token = secrets.token_hex(16)

    # Management token — shown once, then only the bcrypt hash is kept
    management_token_raw = secrets.token_urlsafe(32)
    management_token_hash = bcrypt.hashpw(
        management_token_raw.encode(), bcrypt.gensalt()
    ).decode()

    # Encrypt auth_token if provided — NEVER store plaintext
    encrypted_auth = encrypt_token(auth_token) if auth_token else None

    # Auto-verify localhost targets in development (skip .well-known verification)
    auto_verified = url.startswith("http://localhost") or url.startswith("http://127.0.0.1")

    target = Target(
        user_id=current_user.id,
        name=name,
        url=url,
        environment=env,
        verification_token=verification_token,
        management_token_hash=management_token_hash,
        auth_token_encrypted=encrypted_auth,
        ownership_verified=auto_verified,  # Auto-verify localhost
        watcher_enabled=True,
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    return {
        "id": str(target.id),
        "name": target.name,
        "url": target.url,
        "environment": target.environment.value,
        "ownership_verified": target.ownership_verified,
        "watcher_enabled": True,
        "created_at": target.created_at.isoformat(),
        # ----------------------------------------------------------------
        # SHOWN ONCE — never stored in plaintext, never returned again
        # ----------------------------------------------------------------
        "management_token": management_token_raw,
        "management_token_warning": (
            "Save this immediately — used to create CI/CD API keys and manage this target. "
            "It is bcrypt-hashed in our database and CANNOT be recovered. "
            "If lost, delete and re-register the target."
        ),
        # ----------------------------------------------------------------
        "verification_token": verification_token,
        "verification_instructions": (
            f"✅ AUTO-VERIFIED: localhost targets are automatically verified in development mode.\n\n"
            if auto_verified else
            f"To prove ownership of {url}, create a publicly accessible file at:\n"
            f"  {_origin(url)}/.well-known/sentinelloop-verify.txt\n"
            f"containing exactly the text (no trailing newline):\n"
            f"  sentinel-verify={verification_token}\n\n"
            f"Then call:  GET /api/v1/targets/{target.id}/verify"
        ),
        "watcher_disclosure": (
            "SentinelLoop's deployment watcher sends a benign probe to your chatbot URL "
            "every 5 minutes (~3 HTTP requests per poll cycle, ~36 extra calls/hour) "
            "to detect system-prompt changes that indicate a redeployment. "
            "This may slightly increase the LLM API costs on your target endpoint. "
            f"Disable at any time via PATCH /api/v1/targets/{target.id}/watcher "
            "(requires X-Management-Token header)."
        ),
    }


@router.get("/{target_id}/verify")
def verify_ownership(target_id: str, db: Session = Depends(get_db)):
    """
    Fetch the well-known verification file from the target URL and check its contents.
    Sets ownership_verified=True on match.
    
    For localhost URLs, auto-verifies without checking the file.
    """
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(404, "Target not found")
    if target.ownership_verified:
        return {"status": "already_verified", "target_id": str(target.id)}

    # Auto-verify localhost URLs
    url_cleaned = target.url.strip()
    if url_cleaned.startswith("http://localhost") or url_cleaned.startswith("http://127.0.0.1"):
        target.ownership_verified = True
        db.commit()
        return {
            "status": "verified",
            "target_id": str(target.id),
            "message": (
                "✅ Localhost target auto-verified! "
                "You can now create API keys and launch scans."
            ),
        }

    # For non-localhost URLs, check the .well-known file
    expected = f"sentinel-verify={target.verification_token}"
    verify_url = f"{_origin(target.url)}/.well-known/sentinelloop-verify.txt"

    try:
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            resp = client.get(verify_url)
    except httpx.RequestError as exc:
        raise HTTPException(
            400, f"Could not reach verification URL '{verify_url}': {exc}"
        )

    if resp.status_code != 200:
        raise HTTPException(
            400,
            f"Verification file returned HTTP {resp.status_code}. "
            f"Ensure '{verify_url}' is publicly accessible and returns 200.",
        )

    actual = resp.text.strip()
    if actual != expected:
        raise HTTPException(
            400,
            f"Verification content mismatch. "
            f"Expected: '{expected}'  |  Got: '{actual[:120]}'",
        )

    target.ownership_verified = True
    db.commit()
    return {
        "status": "verified",
        "target_id": str(target.id),
        "message": (
            "Ownership verified. You can now create API keys "
            "(POST /api/v1/api-keys/) and launch scans."
        ),
    }


@router.get("/")
def list_targets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all targets owned by the current user. Never returns secrets."""
    targets = (
        db.query(Target)
        .filter(Target.user_id == current_user.id)
        .order_by(Target.created_at.desc())
        .all()
    )
    return [_safe_target_dict(t) for t in targets]


@router.get("/{target_id}")
def get_target(
    target_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get a single target by ID (user can only access their own targets). Never returns secrets."""
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if not target:
        raise HTTPException(404, "Target not found")
    return _safe_target_dict(target)


@router.patch("/{target_id}/watcher")
def toggle_watcher(
    target_id: str,
    enabled: bool,
    x_management_token: str = Header(None),
    db: Session = Depends(get_db),
):
    """
    Enable or disable the deployment watcher for a target.
    Requires the X-Management-Token issued at registration.
    """
    # Rate-limit by target_id BEFORE any bcrypt work
    check_rate_limit(target_id, "mgmt_auth")

    if not x_management_token:
        raise HTTPException(401, "X-Management-Token header required")

    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(404, "Target not found")
    if not target.management_token_hash:
        raise HTTPException(500, "Target has no management token on record")

    if not bcrypt.checkpw(
        x_management_token.encode(), target.management_token_hash.encode()
    ):
        # Do NOT clear rate limit on failure
        raise HTTPException(401, "Invalid management token")

    clear_rate_limit(target_id, "mgmt_auth")  # Reset counter on success

    target.watcher_enabled = enabled
    db.commit()
    return {
        "target_id": target_id,
        "watcher_enabled": enabled,
        "message": f"Watcher {'enabled' if enabled else 'disabled'} successfully.",
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe_target_dict(t: Target) -> dict:
    """
    Serialize a Target ORM object to a dict that NEVER includes secrets.
    Secrets that must never appear: auth_token_encrypted, management_token_hash.
    """
    return {
        "id": str(t.id),
        "name": t.name,
        "url": t.url,
        "environment": t.environment.value,
        "ownership_verified": t.ownership_verified,
        "watcher_enabled": t.watcher_enabled,
        "last_probed_at": t.last_probed_at.isoformat() if t.last_probed_at else None,
        "created_at": t.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Webhook for instant retest (Priority 4.3)
# ---------------------------------------------------------------------------

@router.post("/{target_id}/webhook")
def webhook_instant_retest(
    target_id: str,
    commit_sha: str = None,
    x_webhook_secret: str = Header(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Webhook endpoint for instant retest on git push/deployment.
    Skips the 5-minute watcher delay and triggers immediate retest of open vulnerabilities.
    
    Use this in your CI/CD pipeline after deployment:
    
    ```bash
    curl -X POST https://api.sentinelloop.ai/api/v1/targets/{target_id}/webhook \
      -H "Authorization: Bearer $SENTINELLOOP_TOKEN" \
      -H "X-Webhook-Secret: $TARGET_WEBHOOK_SECRET" \
      -H "Content-Type: application/json" \
      -d '{"commit_sha": "'$GITHUB_SHA'"}'
    ```
    
    Parameters:
        - target_id: Target UUID
        - commit_sha: Optional git commit SHA for audit trail
        - X-Webhook-Secret: Optional webhook secret for additional security
    
    Returns:
        - retest_scan_id: UUID of the triggered retest scan
        - findings_retested: Number of open findings being retested
    """
    # Verify user owns this target
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if not target:
        raise HTTPException(404, "Target not found or access denied")
    
    if not target.ownership_verified:
        raise HTTPException(403, "Target ownership not verified")
    
    # Optional: Verify webhook secret if configured
    # (For now, JWT auth is sufficient, webhook secret is optional extra layer)
    
    # Find open findings for this target
    from models import Finding, FindingStatus
    open_findings = (
        db.query(Finding)
        .filter(
            Finding.target_id == target_id,
            Finding.status == FindingStatus.open
        )
        .all()
    )
    
    if not open_findings:
        return {
            "status": "no_action",
            "message": "No open vulnerabilities to retest. Target is secure!",
            "findings_retested": 0
        }
    
    # Create retest scan
    from models import Scan, ScanType, ScanTrigger, ScanStatus
    retest_scan = Scan(
        target_id=target_id,
        scan_type=ScanType.retest,
        triggered_by=ScanTrigger.deployment_detected,
        status=ScanStatus.pending,
        total_attacks=len(open_findings),
        completed_attacks=0,
        deployment_fingerprint=commit_sha,
    )
    db.add(retest_scan)
    db.commit()
    db.refresh(retest_scan)
    
    # Trigger retest task
    from tasks.scan_tasks import run_retest_scan
    
    # Get the most recent completed scan as parent
    from models import ScanStatus
    parent_scan = (
        db.query(Scan)
        .filter(Scan.target_id == target_id)
        .filter(Scan.status == ScanStatus.done)
        .order_by(Scan.completed_at.desc())
        .first()
    )
    parent_scan_id = str(parent_scan.id) if parent_scan else None
    
    run_retest_scan.delay(str(retest_scan.id), str(target_id), parent_scan_id)
    
    return {
        "status": "retest_triggered",
        "retest_scan_id": str(retest_scan.id),
        "findings_retested": len(open_findings),
        "commit_sha": commit_sha,
        "message": f"Retesting {len(open_findings)} open findings",
        "poll_url": f"/api/v1/scans/{retest_scan.id}",
        "stream_url": f"/api/v1/scans/{retest_scan.id}/stream"
    }
