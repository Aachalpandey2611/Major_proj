"""
tasks/celery_app.py — Celery application instance.

Workers launch as: celery -A tasks.celery_app worker --queues=scans,default
Beat launches as:  celery -A tasks.celery_app beat

Full task definitions (run_full_scan, check_all_targets, etc.) come in Component 2.
This file only sets up the Celery app and a minimal Beat schedule so the worker
and beat services start cleanly in docker-compose.
"""

from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_process_init
from config import settings

celery_app = Celery(
    "sentinelloop",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "tasks.scan_tasks",
        "tasks.watcher_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,                    # Don't ack until task completes
    worker_prefetch_multiplier=1,           # One task at a time per worker slot
    task_routes={
        "tasks.scan_tasks.*": {"queue": "scans"},
        "tasks.watcher_tasks.*": {"queue": "default"},
    },
)

@worker_process_init.connect
def _dispose_db_pool_after_fork(**kwargs):
    """
    Celery's prefork pool forks worker child processes from a parent that has
    already opened SQLAlchemy connections (database.engine is created at
    import time). Forked children inherit those raw sockets/file descriptors,
    and sharing a connection across the parent and child corrupts the
    Postgres wire protocol — queries in the child can silently return empty
    results (no exception raised, so the task just "succeeds" instantly with
    nothing done) instead of a clean error.

    Disposing the pool here forces every forked child to open brand-new
    connections on first use instead of reusing the parent's.
    """
    from database import engine
    engine.dispose()


# Periodic tasks (Beat schedule) — wired in Component 2
celery_app.conf.beat_schedule = {
    # Watcher: check all monitored targets every WATCHER_INTERVAL_SECONDS
    # Full task impl in tasks/watcher_tasks.py (Component 2)
    "check-all-targets": {
        "task": "tasks.watcher_tasks.check_all_targets",
        "schedule": settings.WATCHER_INTERVAL_SECONDS,
    },
}
