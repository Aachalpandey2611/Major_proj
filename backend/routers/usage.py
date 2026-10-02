"""
routers/usage.py — Usage statistics and tier management
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import User
from routers.auth import get_current_user
from usage_limits import get_usage_stats, MAX_SCANS_PER_TIER

router = APIRouter(prefix="/usage", tags=["usage"])


@router.get("/stats")
def get_current_usage(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get current usage statistics for the authenticated user.
    
    Returns:
        - Current tier
        - Scans used this month
        - Scans remaining
        - Percentage used
        - Billing period dates
    """
    return get_usage_stats(current_user, db)


@router.get("/tiers")
def list_tiers():
    """
    List all available subscription tiers and their limits.
    Public endpoint for pricing page.
    """
    return {
        "tiers": [
            {
                "name": "Free",
                "tier_id": "free",
                "price_monthly": 0,
                "scans_per_month": MAX_SCANS_PER_TIER["free"],
                "features": [
                    "5 scans per month",
                    "All 15 attack types",
                    "Basic reporting",
                    "Email support"
                ],
                "cta": "Get Started"
            },
            {
                "name": "Startup",
                "tier_id": "startup",
                "price_monthly": 99,
                "scans_per_month": MAX_SCANS_PER_TIER["startup"],
                "features": [
                    "100 scans per month",
                    "All 15 attack types",
                    "PDF reports",
                    "CI/CD integration",
                    "Auto-retest on deploy",
                    "Priority support"
                ],
                "cta": "Start Trial",
                "popular": True
            },
            {
                "name": "Scale",
                "tier_id": "scale",
                "price_monthly": 399,
                "scans_per_month": MAX_SCANS_PER_TIER["scale"],
                "features": [
                    "500 scans per month",
                    "All features from Startup",
                    "Team workspaces",
                    "Compliance exports",
                    "Dedicated support",
                    "SLA guarantee"
                ],
                "cta": "Contact Sales"
            },
            {
                "name": "Enterprise",
                "tier_id": "enterprise",
                "price_monthly": "Custom",
                "scans_per_month": "Unlimited",
                "features": [
                    "Unlimited scans",
                    "All features from Scale",
                    "Custom integrations",
                    "On-premise deployment",
                    "White-label options",
                    "24/7 support"
                ],
                "cta": "Contact Sales"
            }
        ]
    }
