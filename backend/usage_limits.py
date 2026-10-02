"""
usage_limits.py — Usage tier enforcement

Defines scan limits per subscription tier and provides middleware to check limits
before creating new scans.
"""

from fastapi import HTTPException
from sqlalchemy.orm import Session
from models import User, Scan
from datetime import datetime, timedelta

# Scan limits per tier per month
MAX_SCANS_PER_TIER = {
    "free": 5,
    "startup": 100,
    "scale": 500,
    "enterprise": 99999,  # Effectively unlimited
}

def check_scan_limit(user: User, db: Session) -> None:
    """
    Check if user has exceeded their monthly scan limit.
    Raises HTTPException 429 if limit exceeded.
    """
    # Get user's current tier
    tier = user.subscription_tier or "free"
    max_scans = MAX_SCANS_PER_TIER.get(tier, MAX_SCANS_PER_TIER["free"])
    
    # Count scans in current month
    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)
    
    # Count scans for all user's targets this month
    from models import Target
    target_ids = [str(t.id) for t in db.query(Target).filter(Target.user_id == user.id).all()]
    
    if not target_ids:
        # No targets = no scans, allow creation
        return
    
    scan_count = (
        db.query(Scan)
        .filter(
            Scan.target_id.in_(target_ids),
            Scan.created_at >= month_start
        )
        .count()
    )
    
    if scan_count >= max_scans:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Scan limit exceeded",
                "tier": tier,
                "limit": max_scans,
                "used": scan_count,
                "message": f"You've reached your {tier} tier limit of {max_scans} scans per month. "
                          f"Upgrade to scan more targets.",
                "upgrade_url": "/pricing",
            }
        )

def get_usage_stats(user: User, db: Session) -> dict:
    """
    Get current usage statistics for the user.
    Used for dashboard display.
    """
    tier = user.subscription_tier or "free"
    max_scans = MAX_SCANS_PER_TIER.get(tier, MAX_SCANS_PER_TIER["free"])
    
    # Count scans in current month
    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)
    
    from models import Target
    target_ids = [str(t.id) for t in db.query(Target).filter(Target.user_id == user.id).all()]
    
    scan_count = 0
    if target_ids:
        scan_count = (
            db.query(Scan)
            .filter(
                Scan.target_id.in_(target_ids),
                Scan.created_at >= month_start
            )
            .count()
        )
    
    return {
        "tier": tier,
        "scans_used": scan_count,
        "scans_limit": max_scans,
        "scans_remaining": max(0, max_scans - scan_count),
        "percentage_used": round((scan_count / max_scans) * 100, 1) if max_scans > 0 else 0,
        "period_start": month_start.isoformat(),
        "period_end": (month_start.replace(month=month_start.month % 12 + 1) if month_start.month < 12 
                       else month_start.replace(year=month_start.year + 1, month=1)).isoformat(),
    }
