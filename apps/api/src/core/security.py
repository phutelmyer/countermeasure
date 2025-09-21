"""
Security utilities for authentication and authorization.
Handles JWT tokens, password hashing, and security validations.
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import ValidationError

from .config import settings
from .exceptions import AuthenticationError, AuthorizationError
from .logging import get_logger

logger = get_logger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_access_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None
) -> str:
    """Create a JWT access token."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.access_token_expire_minutes
        )

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "access_token",
        "iat": datetime.now(timezone.utc),
    }

    if additional_claims:
        to_encode.update(additional_claims)

    encoded_jwt = jwt.encode(
        to_encode,
        settings.secret_key,
        algorithm=settings.algorithm
    )

    logger.info(
        "access_token_created",
        subject=str(subject),
        expires_at=expire,
        additional_claims=list(additional_claims.keys()) if additional_claims else None
    )

    return encoded_jwt


def create_refresh_token(subject: Union[str, Any]) -> str:
    """Create a JWT refresh token."""
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.refresh_token_expire_days
    )

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "refresh_token",
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_urlsafe(32),  # Unique token ID for revocation
    }

    encoded_jwt = jwt.encode(
        to_encode,
        settings.secret_key,
        algorithm=settings.algorithm
    )

    logger.info(
        "refresh_token_created",
        subject=str(subject),
        expires_at=expire,
        jti=to_encode["jti"]
    )

    return encoded_jwt


def verify_token(token: str, token_type: str = "access_token") -> Dict[str, Any]:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )

        # Verify token type
        if payload.get("type") != token_type:
            raise AuthenticationError("Invalid token type")

        # Verify expiration
        exp = payload.get("exp")
        if exp is None:
            raise AuthenticationError("Token missing expiration")

        if datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise AuthenticationError("Token has expired")

        # Verify subject
        sub = payload.get("sub")
        if sub is None:
            raise AuthenticationError("Token missing subject")

        logger.debug(
            "token_verified",
            subject=sub,
            token_type=token_type,
            expires_at=datetime.fromtimestamp(exp, tz=timezone.utc)
        )

        return payload

    except JWTError as e:
        logger.warning("jwt_verification_failed", error=str(e))
        raise AuthenticationError("Invalid token") from e
    except ValidationError as e:
        logger.warning("token_validation_failed", error=str(e))
        raise AuthenticationError("Token validation failed") from e


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        result = pwd_context.verify(plain_password, hashed_password)
        logger.debug("password_verification", success=result)
        return result
    except Exception as e:
        logger.warning("password_verification_error", error=str(e))
        return False


def get_password_hash(password: str) -> str:
    """Hash a password."""
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long")

    hashed = pwd_context.hash(password)
    logger.debug("password_hashed")
    return hashed


def generate_secure_random_string(length: int = 32) -> str:
    """Generate a cryptographically secure random string."""
    return secrets.token_urlsafe(length)


def validate_password_strength(password: str) -> bool:
    """Validate password meets security requirements."""
    if len(password) < 8:
        return False

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    # Require at least 3 of 4 character types for flexibility
    requirements_met = sum([has_upper, has_lower, has_digit, has_special])

    return requirements_met >= 3


def extract_token_from_header(authorization: str) -> str:
    """Extract JWT token from Authorization header."""
    if not authorization:
        raise AuthenticationError("Authorization header missing")

    try:
        scheme, token = authorization.split(" ", 1)
        if scheme.lower() != "bearer":
            raise AuthenticationError("Invalid authorization scheme")
        return token
    except ValueError:
        raise AuthenticationError("Invalid authorization header format") from None


class RoleChecker:
    """Check if user has required roles or permissions."""

    ROLE_HIERARCHY = {
        "admin": ["admin", "analyst", "viewer", "collector"],
        "analyst": ["analyst", "viewer"],
        "viewer": ["viewer"],
        "collector": ["collector"]
    }

    @classmethod
    def has_role(cls, user_role: str, required_role: str) -> bool:
        """Check if user role has access to required role."""
        user_permissions = cls.ROLE_HIERARCHY.get(user_role, [])
        return required_role in user_permissions

    @classmethod
    def check_role(cls, user_role: str, required_role: str) -> None:
        """Check role access and raise exception if unauthorized."""
        if not cls.has_role(user_role, required_role):
            logger.warning(
                "authorization_failed",
                user_role=user_role,
                required_role=required_role
            )
            raise AuthorizationError(
                f"Role '{user_role}' does not have access to '{required_role}' resources"
            )


# Security constants
MIN_PASSWORD_LENGTH = 8
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15