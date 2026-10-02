"""
rate_limiter.py — Redis-based sliding-window rate limiter with lockout.

IDENTIFIER DESIGN (important — read before using):

    The `identifier` parameter is caller-supplied, NOT hardcoded to client IP.
    Rationale:
      - IP addresses are unreliable behind proxies, NAT, or shared CI runner pools.
        GitHub Actions, for example, has thousands of runners sharing IP ranges —
        locking by IP would cause legitimate users to lock each other out.
      - We key rate limits to the CREDENTIAL being tested, so a brute-force attempt
        on one credential doesn't affect others.

    Recommended identifiers by endpoint:
      - /api-keys POST (create key)  → target_id
            Only one management token exists per target; target_id scopes correctly.
      - /scans/ci  (use CI key)      → x_api_key[:12]
            First 12 chars of the key being tested. A brute-force attempt guessing
            keys starting with "sl_AAAAAA" won't lock out a legitimate "sl_BBBBBB".
      - /targets/{id}/watcher PATCH  → target_id  (same as create-key)

    Defense-in-depth: callers MAY pass f"{target_id}:{ip}" as the identifier to
    combine both signals. This is optional — IP alone must NEVER be the sole key.

Algorithm:
    Sliding window: count attempts in the last WINDOW_SECONDS using Redis INCR + EXPIRE.
    Lockout: after MAX_ATTEMPTS failures, set a separate lockout key for LOCKOUT_SECONDS.
    The lockout check happens BEFORE the INCR so locked callers get a fast 429.
"""

import redis as redis_lib
from fastapi import HTTPException

from config import settings

_redis = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)

MAX_ATTEMPTS: int = 5
WINDOW_SECONDS: int = 60
LOCKOUT_SECONDS: int = 300  # 5-minute lockout after exceeding limit


def check_rate_limit(identifier: str, key_prefix: str) -> None:
    """
    Check and increment the sliding-window attempt counter for `identifier`.

    Must be called BEFORE any bcrypt work in auth endpoints.
    Raises HTTPException(429) if the identifier is locked out or over-limit.

    Args:
        identifier: A stable, credential-derived string (see module docstring).
        key_prefix: Namespace for the Redis keys, e.g. "mgmt_auth", "ci_auth".
    """
    lockout_key = f"lockout:{key_prefix}:{identifier}"
    attempt_key = f"rate:{key_prefix}:{identifier}"

    # Fast path: already locked out?
    if _redis.exists(lockout_key):
        remaining = _redis.ttl(lockout_key)
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {remaining} seconds.",
        )

    # Increment attempt counter
    count = _redis.incr(attempt_key)
    if count == 1:
        # First attempt in this window — set the expiry
        _redis.expire(attempt_key, WINDOW_SECONDS)

    if count > MAX_ATTEMPTS:
        # Exceeded limit: activate lockout and discard the window counter
        _redis.set(lockout_key, "1", ex=LOCKOUT_SECONDS)
        _redis.delete(attempt_key)
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Locked out for {LOCKOUT_SECONDS} seconds.",
        )


def clear_rate_limit(identifier: str, key_prefix: str) -> None:
    """
    Clear the attempt counter and any lockout for `identifier`.

    Call this ONLY after a successful authentication (correct bcrypt match).
    Never call it before or on partial success — only on confirmed success.
    """
    _redis.delete(f"rate:{key_prefix}:{identifier}")
    _redis.delete(f"lockout:{key_prefix}:{identifier}")
