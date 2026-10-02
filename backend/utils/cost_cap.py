"""
cost_cap.py — Redis-based LLM call counter and hard limit enforcement.

Ensures that OpenAI API usage (both for LLM judge and PAIR adaptive generator)
does not exceed MAX_LLM_CALLS_PER_SCAN per scan. Checked BEFORE each API call.
"""

import redis as redis_lib
from config import settings

_redis = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)


def check_and_increment_llm_calls(scan_id: str = None) -> bool:
    """
    Check if the number of OpenAI API calls made during this scan exceeds the cap.
    Increments the counter.

    Args:
        scan_id: UUID string of the current scan. If None, allows the call (e.g. benchmark/dev).

    Returns:
        True if the call is allowed, False if the limit is exceeded.
    """
    if not scan_id:
        return True

    key = f"llm_calls:{scan_id}"
    count = _redis.incr(key)

    if count == 1:
        # Set 24-hour expiration so the key doesn't leak in Redis permanently
        _redis.expire(key, 86400)

    # Allow call only if the incremented count is within the cap
    return count <= settings.MAX_LLM_CALLS_PER_SCAN
