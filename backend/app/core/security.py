from datetime import datetime, timedelta
from typing import Optional

from jose import jwt, JWTError

from app.core.config import get_settings
from app.core.time import utcnow

pwd_context = None
try:  # passlib is the documented hashing library for this project
    from passlib.context import CryptContext

    pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
except Exception:  # pragma: no cover - passlib is a hard requirement
    raise

ALGORITHM = "HS256"

# Roles recognised by the platform.
VALID_ROLES = ("admin", "analyst")


class PasswordPolicyError(ValueError):
    """Raised when a password does not satisfy the minimum policy."""


def validate_password_strength(password: str) -> None:
    """Enforce a minimal password policy for new accounts."""
    if not password or len(password) < 8:
        raise PasswordPolicyError("Password must be at least 8 characters long")
    if password.lower() in {"password", "admin123", "12345678"}:
        # The seeded development credential is allowed to exist, but new
        # accounts must not reuse well-known defaults.
        raise PasswordPolicyError("Password is too common")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None, extra: Optional[dict] = None) -> str:
    settings = get_settings()
    now = utcnow()
    expire = now + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode = {"sub": subject, "exp": expire, "iat": now}
    if extra:
        to_encode.update(extra)
    return jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except JWTError:
        return None
