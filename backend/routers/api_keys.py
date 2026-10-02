"""
routers/api_keys.py — CI/CD API key management.

Auth chain:
  1. Caller provides X-Management-Token (issued once at target registration).
  2. Rate-limit checked FIRST (5 attempts/60s, keyed on target_id).
  3. bcrypt.checkpw against stored management_token_hash.
  4. On success, a "sl_..." raw key is generated, bcrypt-hashed, stored.
     Raw key returned ONCE — never again.

validate_api_key() is imported by scans.py for the /ci endpoint.
Rate-limit identifier for API key validation = first 12 chars of the key being tested.
Reason: different guessed keys don't share a rate-limit bucket, so brute-force
on one prefix doesn't lock out legitimate keys with different prefixes.
See rate_limiter.py module docstring for full rationale.
"""

import secrets
from datetime import datetime

import bcrypt
from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import APIKey, Target
from utils.rate_limiter import check_rate_limit, clear_rate_limit

router = APIRouter(prefix="/api-keys", tags=["api_keys"])


# ---------------------------------------------------------------------------
# Shared validation function (imported by scans.py)
# ---------------------------------------------------------------------------

def validate_api_key(
    x_api_key: str,
    target_id: str,
    db: Session,
) -> APIKey:
    """
    Validate a CI API key against bcrypt hashes in the APIKey table.

    Rate-limit identifier: first 12 characters of x_api_key.
    - All valid SentinelLoop keys start with "sl_" followed by url-safe b64.
    - Keying lockouts to the key prefix means a brute-force attempt on
      one guessed prefix doesn't lock out legitimately different keys.
    - Shared CI runner pools often share IPs; prefix-based lockout avoids
      false lockouts that IP-based limiting would cause in those environments.

    Raises:
        HTTPException(401) — missing or invalid key
        HTTPException(429) — rate limit exceeded
    """
    if not x_api_key:
        raise HTTPException(401, "X-API-Key header required")

    # Use first 12 chars as rate-limit scope
    rate_id = x_api_key[:12] if len(x_api_key) >= 12 else x_api_key
    check_rate_limit(rate_id, "ci_auth")  # Raises 429 if over limit

    active_keys = (
        db.query(APIKey)
        .filter(APIKey.target_id == target_id, APIKey.is_active == True)
        .all()
    )

    for row in active_keys:
        if bcrypt.checkpw(x_api_key.encode(), row.key_hash.encode()):
            clear_rate_limit(rate_id, "ci_auth")  # Reset on success
            row.last_used_at = datetime.utcnow()
            db.commit()
            return row

    # No matching key found — do NOT clear rate limit (only clear on success)
    raise HTTPException(401, "Invalid API key")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/")
def create_api_key(
    target_id: str,
    label: str = "default",
    x_management_token: str = Header(None),
    db: Session = Depends(get_db),
):
    """
    Create a CI/CD API key for a verified target.

    Requires the management token issued at registration (X-Management-Token header).
    The raw API key is returned EXACTLY ONCE — store it immediately in your CI secrets.
    """
    # Rate-limit BEFORE any DB/bcrypt work
    check_rate_limit(target_id, "mgmt_auth")

    if not x_management_token:
        raise HTTPException(401, "X-Management-Token header required")

    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(404, "Target not found")
    if not target.ownership_verified:
        raise HTTPException(
            403,
            "Target ownership not verified. "
            "Complete verification first via GET /api/v1/targets/{id}/verify",
        )
    if not target.management_token_hash:
        raise HTTPException(500, "Target has no management token on record")

    if not bcrypt.checkpw(
        x_management_token.encode(), target.management_token_hash.encode()
    ):
        # Do NOT clear rate limit on failure — only on success
        raise HTTPException(401, "Invalid management token")

    # Auth success — reset the attempt counter
    clear_rate_limit(target_id, "mgmt_auth")

    # Generate the raw key and store only its bcrypt hash
    raw_key = f"sl_{secrets.token_urlsafe(32)}"
    key_hash = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt()).decode()

    api_key_row = APIKey(
        target_id=target_id,
        key_hash=key_hash,
        label=label,
        is_active=True,
    )
    db.add(api_key_row)
    db.commit()
    db.refresh(api_key_row)

    return {
        "api_key_id": str(api_key_row.id),
        "api_key": raw_key,  # ← returned ONCE, never stored in DB
        "label": api_key_row.label,
        "created_at": api_key_row.created_at.isoformat(),
        "warning": (
            "Store this key immediately in your CI/CD secrets "
            "(e.g. GitHub Actions → Settings → Secrets → SENTINELLOOP_API_KEY). "
            "It will not be shown again. If lost, create a new key."
        ),
    }


@router.get("/")
def list_api_keys(target_id: str, db: Session = Depends(get_db)):
    """List API key metadata for a target. Never returns key hashes or raw keys."""
    keys = (
        db.query(APIKey)
        .filter(APIKey.target_id == target_id, APIKey.is_active == True)
        .order_by(APIKey.created_at.desc())
        .all()
    )
    return [
        {
            "id": str(k.id),
            "label": k.label,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "created_at": k.created_at.isoformat(),
        }
        for k in keys
    ]


@router.delete("/{key_id}")
def revoke_api_key(
    key_id: str,
    target_id: str,
    x_management_token: str = Header(None),
    db: Session = Depends(get_db),
):
    """Revoke (soft-delete) a CI API key. Requires X-Management-Token."""
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
        raise HTTPException(401, "Invalid management token")

    clear_rate_limit(target_id, "mgmt_auth")

    key_row = (
        db.query(APIKey)
        .filter(APIKey.id == key_id, APIKey.target_id == target_id)
        .first()
    )
    if not key_row:
        raise HTTPException(404, "API key not found")

    key_row.is_active = False
    db.commit()
    return {"status": "revoked", "key_id": key_id}
