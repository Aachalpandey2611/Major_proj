"""
routers/scans.py — Scan management: create, get, SSE stream, retest, CI endpoint.

Attack logic is wired in Component 2. Stubs for Celery dispatch are marked TODO.
The CI endpoint (/scans/ci) is fully functional for auth — it validates the API key
via validate_api_key() from api_keys.py and creates a scan record. The Celery task
dispatch will be added in Component 2.
"""

import asyncio
import json

import redis as redis_lib
from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from database import get_db
from models import Finding, Scan, ScanStatus, ScanTrigger, ScanType, Target, User
from routers.api_keys import validate_api_key
from routers.auth import get_current_user
from fix_engine.compliance_mapper import get_compliance_mapping
from config import settings
from usage_limits import check_scan_limit

router = APIRouter(prefix="/scans", tags=["scans"])

_redis = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


# ---------------------------------------------------------------------------
# Manual scan creation
# ---------------------------------------------------------------------------

@router.post("/")
def create_scan(
    target_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Manually trigger a full scan against a verified target.
    Full attack-engine dispatch wired in Component 2.
    """
    # Check usage limits before creating scan - TEMPORARILY DISABLED FOR TESTING
    # check_scan_limit(current_user, db)
    
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if not target:
        raise HTTPException(404, "Target not found or access denied")
    if not target.ownership_verified:
        raise HTTPException(
            403,
            "Target ownership not verified. "
            "Complete verification first via GET /api/v1/targets/{id}/verify",
        )

    scan = Scan(
        target_id=target_id,
        scan_type=ScanType.full,
        triggered_by=ScanTrigger.manual,
        status=ScanStatus.pending,
        total_attacks=15,
        completed_attacks=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from tasks.scan_tasks import run_full_scan
    run_full_scan.delay(str(scan.id), str(target_id))

    return {
        "scan_id": str(scan.id),
        "status": scan.status.value,
        "message": "Scan queued. (Attack engine will be wired in Component 2.)",
        "stream_url": f"/api/v1/scans/{scan.id}/stream",
    }


# ---------------------------------------------------------------------------
# CI/CD triggered scan
# ---------------------------------------------------------------------------

@router.post("/ci")
def ci_scan(
    target_id: str,
    commit_sha: str = None,
    x_api_key: str = Header(None),
    db: Session = Depends(get_db),
):
    """
    CI/CD-triggered scan. Requires X-API-Key header.

    Rate-limited by first 12 chars of the provided key (see api_keys.validate_api_key).
    On success: creates a scan record and dispatches it to Celery.
    """
    # Full auth: rate-check → bcrypt match → clear counter on success (all in validate_api_key)
    validate_api_key(x_api_key, target_id, db)

    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(404, "Target not found")

    scan = Scan(
        target_id=target_id,
        scan_type=ScanType.full,
        triggered_by=ScanTrigger.manual,
        status=ScanStatus.pending,
        total_attacks=15,
        completed_attacks=0,
        deployment_fingerprint=commit_sha,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from tasks.scan_tasks import run_full_scan
    run_full_scan.delay(str(scan.id), str(target_id))

    return {
        "scan_id": str(scan.id),
        "status": scan.status.value,
        "poll_url": f"/api/v1/scans/{scan.id}",
        "stream_url": f"/api/v1/scans/{scan.id}/stream",
    }


# ---------------------------------------------------------------------------
# Scan detail + findings
# ---------------------------------------------------------------------------

@router.get("/{scan_id}")
def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scan = (
        db.query(Scan)
        .join(Target)
        .filter(Scan.id == scan_id, Target.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(404, "Scan not found or access denied")

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.risk_score.desc())
        .all()
    )

    return {
        "id": str(scan.id),
        "target_id": str(scan.target_id),
        "scan_type": scan.scan_type.value,
        "triggered_by": scan.triggered_by.value,
        "status": scan.status.value,
        "total_attacks": scan.total_attacks,
        "completed_attacks": scan.completed_attacks,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "created_at": scan.created_at.isoformat(),
        "findings": [
            {
                "id": str(f.id),
                "attack_type": f.attack_type.value,
                "severity": f.severity.value,
                "status": f.status.value,
                "layer_failed": f.layer_failed,
                "risk_score": f.risk_score,
                "owasp_category": f.owasp_category,
                "detection_method": f.detection_method,
                "confidence": f.confidence,
                "fix_code_snippet": f.fix_code_snippet,
                "created_at": f.created_at.isoformat(),
                "compliance": get_compliance_mapping(f.owasp_category) if f.owasp_category else None,
            }
            for f in findings
        ],
    }


# ---------------------------------------------------------------------------
# SSE stream for live scan progress
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/stream")
async def stream_scan_events(
    scan_id: str,
    token: str = None,
    db: Session = Depends(get_db)
):
    """
    Server-Sent Events stream for live scan progress.
    
    Auth: Accepts JWT token as query parameter since EventSource doesn't support headers.
    Usage: /scans/{scan_id}/stream?token=<jwt_token>

    Subscribes to Redis pub/sub channel "sse:{scan_id}".
    Component 2 publishes events via: redis.publish(f"sse:{scan_id}", json.dumps(event))

    Event types (published by scan_tasks.py in Component 2):
        connected           — sent immediately on SSE connection
        scan_started        — scan has been picked up by Celery worker
        attack_complete     — one attack finished {attack_type, success, confidence}
        finding_discovered  — a vulnerability was found {attack_type, severity}
        scan_done           — all attacks finished
        scan_failed         — Celery task error
        deployment_detected — watcher found a new deployment
        finding_retested    — one finding retested {finding_id, new_status}
        fully_secure        — all open findings resolved after retest
    """
    # Authenticate via token query parameter (EventSource doesn't support headers)
    if not token:
        raise HTTPException(401, "Authentication token required as query parameter")
    
    # Verify JWT token manually
    from auth_utils import decode_access_token
    try:
        user_id = decode_access_token(token)
        if not user_id:
            raise HTTPException(401, "Invalid token")
        current_user = db.query(User).filter(User.id == user_id).first()
        if not current_user or not current_user.is_active:
            raise HTTPException(401, "User not found or inactive")
    except Exception:
        raise HTTPException(401, "Invalid or expired token")
    
    # Verify user owns this scan
    scan = (
        db.query(Scan)
        .join(Target)
        .filter(Scan.id == scan_id, Target.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(404, "Scan not found or access denied")
    
    async def event_generator():
        pubsub = _redis.pubsub()
        channel = f"sse:{scan_id}"
        pubsub.subscribe(channel)

        yield (
            f"data: {json.dumps({'event_type': 'connected', 'data': {'scan_id': scan_id}})}\n\n"
        )

        try:
            for message in pubsub.listen():
                if message["type"] == "message":
                    yield f"data: {message['data']}\n\n"
                    # Auto-close stream when scan finishes
                    try:
                        payload = json.loads(message["data"])
                        if payload.get("event_type") in (
                            "scan_done", "scan_failed", "fully_secure"
                        ):
                            break
                    except (json.JSONDecodeError, KeyError):
                        pass
                # Yield control so the event loop can handle heartbeats/disconnects
                await asyncio.sleep(0.05)
        finally:
            pubsub.unsubscribe(channel)
            pubsub.close()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # Disable Nginx buffering for SSE
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# Manual retest trigger
# ---------------------------------------------------------------------------

@router.post("/{scan_id}/retest")
def retest_scan(scan_id: str, db: Session = Depends(get_db)):
    """
    Manually trigger a retest of all open findings from a completed scan.
    Full retest logic wired in Component 2.
    """
    original = db.query(Scan).filter(Scan.id == scan_id).first()
    if not original:
        raise HTTPException(404, "Scan not found")
    if original.status not in (ScanStatus.done, ScanStatus.partial):
        raise HTTPException(
            400,
            f"Can only retest completed scans (status: done or partial). "
            f"Current status: {original.status.value}",
        )

    retest = Scan(
        target_id=original.target_id,
        scan_type=ScanType.retest,
        triggered_by=ScanTrigger.manual,
        status=ScanStatus.pending,
        parent_scan_id=original.id,
        total_attacks=15,
        completed_attacks=0,
    )
    db.add(retest)
    db.commit()
    db.refresh(retest)

    from tasks.scan_tasks import run_retest_scan
    run_retest_scan.delay(str(retest.id), str(original.target_id), scan_id)

    return {
        "retest_scan_id": str(retest.id),
        "original_scan_id": scan_id,
        "status": retest.status.value,
        "stream_url": f"/api/v1/scans/{retest.id}/stream",
    }
