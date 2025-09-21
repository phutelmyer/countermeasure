"""
Authentication service for user management and authentication.
"""

import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.exceptions import (
    AuthenticationError,
    ResourceConflictError,
    ResourceNotFoundError,
    ValidationError
)
from src.core.logging import audit_log, get_logger
from src.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
    verify_token
)
from src.db.models import Tenant
from src.db.models import User
from src.core.config import settings
from src.schemas.auth import (
    LoginRequest,
    SignupRequest,
    TokenResponse,
    UserCreate,
    UserResponse
)

logger = get_logger(__name__)


class AuthService:
    """Service class for authentication operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def authenticate_user(self, email: str, password: str) -> User:
        """
        Authenticate user with email and password.

        Args:
            email: User email
            password: Plain text password

        Returns:
            User object if authentication successful

        Raises:
            AuthenticationError: If authentication fails
        """
        # Get user by email
        result = await self.db.execute(
            select(User)
            .options(selectinload(User.tenant))
            .where(User.email == email.lower())
        )
        user = result.scalar_one_or_none()

        if not user:
            logger.warning("authentication_failed", reason="user_not_found", email=email)
            # Don't reveal that user doesn't exist
            raise AuthenticationError("Invalid email or password")

        # Check if user is active
        if not user.is_active:
            logger.warning("authentication_failed", reason="user_inactive", user_id=str(user.id))
            audit_log(
                action="login_failed",
                resource="user",
                user_id=str(user.id),
                tenant_id=str(user.tenant_id),
                success=False,
                details={"reason": "user_inactive"}
            )
            raise AuthenticationError("User account is inactive")

        # Check if user is locked
        if user.is_locked:
            logger.warning("authentication_failed", reason="user_locked", user_id=str(user.id))
            audit_log(
                action="login_failed",
                resource="user",
                user_id=str(user.id),
                tenant_id=str(user.tenant_id),
                success=False,
                details={"reason": "user_locked"}
            )
            raise AuthenticationError("User account is locked due to too many failed login attempts")

        # Check if tenant is active
        if not user.tenant.is_active:
            logger.warning("authentication_failed", reason="tenant_inactive", user_id=str(user.id))
            audit_log(
                action="login_failed",
                resource="user",
                user_id=str(user.id),
                tenant_id=str(user.tenant_id),
                success=False,
                details={"reason": "tenant_inactive"}
            )
            raise AuthenticationError("Organization account is inactive")

        # Verify password
        if not user.password_hash or not verify_password(password, user.password_hash):
            # Record failed login attempt
            user.record_failed_login()
            await self.db.commit()

            logger.warning("authentication_failed", reason="invalid_password", user_id=str(user.id))
            audit_log(
                action="login_failed",
                resource="user",
                user_id=str(user.id),
                tenant_id=str(user.tenant_id),
                success=False,
                details={"reason": "invalid_password"}
            )
            raise AuthenticationError("Invalid email or password")

        # Record successful login
        user.record_login()
        await self.db.commit()

        logger.info("user_authenticated", user_id=str(user.id), tenant_id=str(user.tenant_id))
        audit_log(
            action="login_success",
            resource="user",
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            success=True
        )

        return user

    async def create_user_tokens(self, user: User) -> TokenResponse:
        """
        Create access and refresh tokens for user.

        Args:
            user: User object

        Returns:
            TokenResponse with tokens and user info
        """
        # Create tokens with user and tenant claims
        additional_claims = {
            "tenant_id": str(user.tenant_id),
            "role": user.role,
            "email": user.email
        }

        access_token = create_access_token(
            subject=str(user.id),
            additional_claims=additional_claims
        )
        refresh_token = create_refresh_token(subject=str(user.id))

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.access_token_expire_minutes * 60,
            user=UserResponse.model_validate(user)
        )

    async def login(self, login_data: LoginRequest) -> TokenResponse:
        """
        Login user and return tokens.

        Args:
            login_data: Login request data

        Returns:
            TokenResponse with tokens and user info
        """
        user = await self.authenticate_user(login_data.email, login_data.password)
        return await self.create_user_tokens(user)

    async def refresh_token(self, refresh_token: str) -> Tuple[str, int]:
        """
        Refresh access token using refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            Tuple of (new_access_token, expires_in_seconds)

        Raises:
            AuthenticationError: If refresh token is invalid
        """
        try:
            # Verify refresh token
            payload = verify_token(refresh_token, "refresh_token")
            user_id = payload.get("sub")

            if not user_id:
                raise AuthenticationError("Invalid refresh token")

            # Get user to ensure they still exist and are active
            result = await self.db.execute(
                select(User).where(User.id == UUID(user_id))
            )
            user = result.scalar_one_or_none()

            if not user or not user.is_active or user.is_locked:
                raise AuthenticationError("User account is invalid")

            # Create new access token
            additional_claims = {
                "tenant_id": str(user.tenant_id),
                "role": user.role,
                "email": user.email
            }

            access_token = create_access_token(
                subject=user_id,
                additional_claims=additional_claims
            )

            logger.info("token_refreshed", user_id=user_id)

            return access_token, settings.access_token_expire_minutes * 60

        except Exception as e:
            logger.warning("token_refresh_failed", error=str(e))
            raise AuthenticationError("Invalid refresh token") from e

    async def signup(self, signup_data: SignupRequest) -> User:
        """
        Register a new user.

        Args:
            signup_data: Signup request data

        Returns:
            Created user object

        Raises:
            ResourceConflictError: If user already exists
            ResourceNotFoundError: If tenant doesn't exist
        """
        # Check if user already exists
        existing_user = await self.db.execute(
            select(User).where(User.email == signup_data.email.lower())
        )
        if existing_user.scalar_one_or_none():
            raise ResourceConflictError("User with this email already exists")

        # Get or create tenant
        tenant = None
        if signup_data.tenant_slug:
            # Join existing tenant
            result = await self.db.execute(
                select(Tenant).where(Tenant.slug == signup_data.tenant_slug)
            )
            tenant = result.scalar_one_or_none()
            if not tenant:
                raise ResourceNotFoundError(f"Organization '{signup_data.tenant_slug}' not found")
            if not tenant.is_active:
                raise ValidationError("Organization is inactive")
        else:
            # Create new tenant for the user
            tenant_name = f"{signup_data.email.split('@')[0]}'s Organization"
            tenant_slug = await self._generate_unique_tenant_slug(tenant_name)

            tenant = Tenant(
                name=tenant_name,
                slug=tenant_slug,
                description="Personal organization"
            )
            self.db.add(tenant)
            await self.db.flush()  # Get tenant ID

        # Check tenant user limit
        # Get current user count manually to avoid lazy loading issue
        result = await self.db.execute(
            select(func.count(User.id)).where(User.tenant_id == tenant.id)
        )
        current_user_count = result.scalar() or 0

        if current_user_count >= tenant.max_users:
            raise ValidationError("Organization has reached its user limit")

        # Create user
        password_hash = get_password_hash(signup_data.password)

        user = User(
            tenant_id=tenant.id,
            email=signup_data.email.lower(),
            password_hash=password_hash,
            first_name=signup_data.first_name,
            last_name=signup_data.last_name,
            role="admin" if not signup_data.tenant_slug else "viewer",  # First user in new tenant is admin
            is_verified=False  # Require email verification
        )

        self.db.add(user)
        await self.db.commit()

        logger.info("user_created", user_id=str(user.id), tenant_id=str(tenant.id))
        audit_log(
            action="user_signup",
            resource="user",
            user_id=str(user.id),
            tenant_id=str(user.id),
            success=True,
            details={"tenant_slug": tenant.slug}
        )

        return user

    async def create_user(self, user_data: UserCreate, creator: User) -> User:
        """
        Create a new user (admin only).

        Args:
            user_data: User creation data
            creator: User creating the new user

        Returns:
            Created user object

        Raises:
            ResourceConflictError: If user already exists
        """
        # Check if user already exists
        existing_user = await self.db.execute(
            select(User).where(User.email == user_data.email.lower())
        )
        if existing_user.scalar_one_or_none():
            raise ResourceConflictError("User with this email already exists")

        # Create password hash if password provided
        password_hash = None
        if user_data.password:
            password_hash = get_password_hash(user_data.password)

        # Create user in same tenant as creator
        user = User(
            tenant_id=creator.tenant_id,
            email=user_data.email.lower(),
            password_hash=password_hash,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            role=user_data.role,
            is_active=user_data.is_active,
            is_verified=not user_data.send_welcome_email  # Skip verification if not sending email
        )

        self.db.add(user)
        await self.db.commit()

        logger.info("user_created_by_admin", user_id=str(user.id), creator_id=str(creator.id))
        audit_log(
            action="user_create",
            resource="user",
            user_id=str(creator.id),
            tenant_id=str(creator.tenant_id),
            success=True,
            details={
                "created_user_id": str(user.id),
                "created_user_email": user.email,
                "role": user.role
            }
        )

        return user

    async def _generate_unique_tenant_slug(self, name: str) -> str:
        """Generate a unique tenant slug from name."""
        # Convert to slug format
        base_slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
        if not base_slug:
            base_slug = "organization"

        # Ensure uniqueness
        slug = base_slug
        counter = 1

        while True:
            result = await self.db.execute(
                select(Tenant).where(Tenant.slug == slug)
            )
            if not result.scalar_one_or_none():
                break

            slug = f"{base_slug}-{counter}"
            counter += 1

        return slug

    async def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        """Get user by ID."""
        result = await self.db.execute(
            select(User)
            .options(selectinload(User.tenant))
            .where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        result = await self.db.execute(
            select(User)
            .options(selectinload(User.tenant))
            .where(User.email == email.lower())
        )
        return result.scalar_one_or_none()