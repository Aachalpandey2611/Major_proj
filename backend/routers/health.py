from fastapi import APIRouter
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

import redis as redis_lib
from config import settings
from database import SessionLocal

router = APIRouter(prefix="/health", tags=["health"])

_redis = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


@router.get("/")
def health_check():
    """
    Check database (SELECT 1) and Redis (PING) connectivity.
    Returns {"status": "ok"} when both are healthy.
    """
    # --- Database ---
    db_status = "ok"
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
    except OperationalError as exc:
        db_status = f"error: {exc}"

    # --- Redis ---
    redis_status = "ok"
    try:
        _redis.ping()
    except Exception as exc:
        redis_status = f"error: {exc}"

    overall = "ok" if db_status == "ok" and redis_status == "ok" else "degraded"
    return {
        "status": overall,
        "database": db_status,
        "redis": redis_status,
    }
