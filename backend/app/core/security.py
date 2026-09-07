import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional, Dict
import jwt
from jwt.exceptions import PyJWTError, ExpiredSignatureError, InvalidTokenError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from app.config import settings

# Initialize Argon2 password hasher with secure defaults
_hasher = PasswordHasher()

# Pre-computed constant dummy Argon2id hash to mitigate login timing enumeration.
# Pre-computed once at module load; no hash generation occurs per-request.
DUMMY_PASSWORD_HASH: str = _hasher.hash("seedoc_dummy_constant_for_timing_mitigation_non_secret")


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against an Argon2 hash."""
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def create_access_token(
    user_id: uuid.UUID | str,
    org_id: uuid.UUID | str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Generate a signed JWT containing standard identity and tenant claims:
    - sub: user UUID
    - org_id: organization UUID
    - role: ADMIN or MEMBER
    - iat: issued at timestamp
    - exp: expiration timestamp
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "org_id": str(org_id),
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    # Explicitly use configured algorithm (HS256)
    encoded_jwt = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode and cryptographically verify a JWT.
    Enforces the configured algorithm and rejects 'none' or untrusted algorithms.
    Raises PyJWTError on signature, expiration, or format failures.
    """
    # Strict verification: explicit algorithm white-list, requires exp and sub
    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"require": ["exp", "sub", "org_id", "role"]},
    )
    return payload
