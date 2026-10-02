"""
crypto.py — Token encryption using PBKDF2HMAC-derived Fernet keys.

Security design:
- Master password comes from TOKEN_ENCRYPTION_KEY env var (must be >= 16 chars).
- Each encrypted token gets its own random 16-byte salt, so the same plaintext
  encrypts to a different ciphertext every call.
- Key derivation uses PBKDF2HMAC-SHA256 with 480,000 iterations (OWASP 2024 minimum).
- Stored format: "{url-safe-b64(salt)}:{fernet-ciphertext}"  — split on FIRST ":" only.

Performance:
- _derive_key_cached() is decorated with @lru_cache(maxsize=512).
- Cache is PER-PROCESS (one cache per Celery worker / uvicorn process).
- It clears on process restart — accepted MVP tradeoff:
    first decrypt after restart  ≈ 200–400 ms  (PBKDF2 computation)
    subsequent decrypts of same token  <1 ms  (cache hit)
- At >512 unique tokens the LRU evicts the oldest; occasional re-derivations
  are then needed but are still correct.
- Production upgrade path: move to AWS KMS / GCP KMS envelope encryption
  (fast AES-256 decrypt, KMS-managed key) once you hit hundreds of targets.

What this file NEVER does (prior bug patterns — do not reintroduce):
- Does NOT truncate/pad the raw password string to 32 bytes as a Fernet key.
  That is not key derivation and would make short/guessable passwords weak.
- Does NOT store a raw (unencrypted) token anywhere.
"""

import os
import base64
from functools import lru_cache
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# OWASP recommended PBKDF2-SHA256 iteration count for 2024.
KDF_ITERATIONS = 480_000


def _get_master_password() -> bytes:
    """
    Load and validate the master password from the environment.
    Called only when deriving a new key (cache miss), not on every operation.
    """
    from config import settings  # local import avoids circular at module load

    pwd = settings.TOKEN_ENCRYPTION_KEY
    if not pwd or len(pwd) < 16:
        raise ValueError(
            "TOKEN_ENCRYPTION_KEY must be at least 16 characters. "
            "Generate a cryptographically random key with:\n"
            '    python -c "import secrets; print(secrets.token_hex(32))"\n'
            "Then set it in your .env file or secrets manager."
        )
    return pwd.encode("utf-8")


@lru_cache(maxsize=512)
def _derive_key_cached(salt_b64: str) -> bytes:
    """
    Derive a 32-byte key from the master password + salt using PBKDF2HMAC-SHA256.
    Returns the key as URL-safe base64 (suitable for Fernet).

    This function is cached: same (password + salt) → same key, computed once
    per process lifetime. See module docstring for performance details.

    Args:
        salt_b64: URL-safe base64-encoded 16-byte salt (the cache key).

    Returns:
        URL-safe base64-encoded 32-byte derived key, ready for Fernet(key).
    """
    salt = base64.urlsafe_b64decode(salt_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    raw_key = kdf.derive(_get_master_password())
    return base64.urlsafe_b64encode(raw_key)


def encrypt_token(token: str) -> str:
    """
    Encrypt a plaintext token (e.g. a bearer key for a target chatbot).

    Each call generates a fresh random salt, so the same token encrypts
    differently every time — prevents ciphertext equality leaks.

    Returns:
        str in format "{salt_b64}:{fernet_ciphertext}"
        Store this string; never store the plaintext token.
    """
    salt = os.urandom(16)
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
    fernet_key = _derive_key_cached(salt_b64)
    ciphertext = Fernet(fernet_key).encrypt(token.encode("utf-8")).decode("ascii")
    return f"{salt_b64}:{ciphertext}"


def decrypt_token(stored: str) -> str:
    """
    Decrypt a token previously returned by encrypt_token().

    Args:
        stored: str in format "{salt_b64}:{fernet_ciphertext}"

    Returns:
        The original plaintext token.

    Raises:
        cryptography.fernet.InvalidToken  if the ciphertext is tampered with
            or the wrong TOKEN_ENCRYPTION_KEY is used.
        ValueError  if the stored string is malformed (no ":" separator).
    """
    # Split on the FIRST ":" only — the Fernet ciphertext may itself contain ":"
    salt_b64, ciphertext = stored.split(":", 1)
    fernet_key = _derive_key_cached(salt_b64)
    return Fernet(fernet_key).decrypt(ciphertext.encode("ascii")).decode("utf-8")
