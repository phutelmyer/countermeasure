"""
Unit tests for AuthService.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from src.services.auth_service import AuthService
from src.core.exceptions import (
    AuthenticationError,
    ResourceConflictError,
    ResourceNotFoundError,
    ValidationError,
)
from src.schemas.auth import LoginRequest, SignupRequest, UserCreate
from tests.factories import UserFactory, TenantFactory


class TestAuthService:
    """Test suite for AuthService."""

    @pytest.fixture
    def auth_service(self, db_session: AsyncSession) -> AuthService:
        """Create AuthService instance for testing."""
        return AuthService(db_session)

    @pytest.mark.asyncio
    async def test_authenticate_user_success(
        self, auth_service: AuthService, test_user, db_session: AsyncSession
    ):
        """Test successful user authentication."""
        result = await auth_service.authenticate_user(test_user.email, "TestPassword123!")

        assert result.id == test_user.id
        assert result.email == test_user.email

        # Verify login was recorded
        await db_session.refresh(test_user)
        assert test_user.last_login is not None

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, auth_service: AuthService):
        """Test authentication with non-existent user."""
        with pytest.raises(AuthenticationError, match="Invalid email or password"):
            await auth_service.authenticate_user("nonexistent@test.com", "password")

    @pytest.mark.asyncio
    async def test_authenticate_user_inactive(
        self, auth_service: AuthService, db_session: AsyncSession, test_tenant
    ):
        """Test authentication with inactive user."""
        inactive_user = UserFactory(tenant=test_tenant, is_active=False)
        db_session.add(inactive_user)
        await db_session.commit()

        with pytest.raises(AuthenticationError, match="User account is inactive"):
            await auth_service.authenticate_user(inactive_user.email, "TestPassword123!")

    @pytest.mark.asyncio
    async def test_authenticate_user_locked(
        self, auth_service: AuthService, db_session: AsyncSession, test_tenant
    ):
        """Test authentication with locked user."""
        locked_user = UserFactory(tenant=test_tenant, failed_login_attempts=10)
        db_session.add(locked_user)
        await db_session.commit()

        with pytest.raises(AuthenticationError, match="User account is locked"):
            await auth_service.authenticate_user(locked_user.email, "TestPassword123!")

    @pytest.mark.asyncio
    async def test_authenticate_user_inactive_tenant(
        self, auth_service: AuthService, db_session: AsyncSession
    ):
        """Test authentication with inactive tenant."""
        inactive_tenant = TenantFactory(is_active=False)
        user = UserFactory(tenant=inactive_tenant)
        db_session.add_all([inactive_tenant, user])
        await db_session.commit()

        with pytest.raises(AuthenticationError, match="Organization account is inactive"):
            await auth_service.authenticate_user(user.email, "TestPassword123!")

    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(
        self, auth_service: AuthService, test_user, db_session: AsyncSession
    ):
        """Test authentication with wrong password."""
        with pytest.raises(AuthenticationError, match="Invalid email or password"):
            await auth_service.authenticate_user(test_user.email, "WrongPassword")

        # Verify failed login was recorded
        await db_session.refresh(test_user)
        assert test_user.failed_login_attempts > 0

    @pytest.mark.asyncio
    async def test_create_user_tokens(self, auth_service: AuthService, test_user):
        """Test token creation for user."""
        token_response = await auth_service.create_user_tokens(test_user)

        assert token_response.access_token is not None
        assert token_response.refresh_token is not None
        assert token_response.expires_in > 0
        assert token_response.user.id == test_user.id
        assert token_response.user.email == test_user.email

    @pytest.mark.asyncio
    async def test_login_success(self, auth_service: AuthService, test_user):
        """Test successful login."""
        login_data = LoginRequest(email=test_user.email, password="TestPassword123!")

        token_response = await auth_service.login(login_data)

        assert token_response.access_token is not None
        assert token_response.refresh_token is not None
        assert token_response.user.id == test_user.id

    @pytest.mark.asyncio
    async def test_login_failure(self, auth_service: AuthService, test_user):
        """Test failed login."""
        login_data = LoginRequest(email=test_user.email, password="WrongPassword")

        with pytest.raises(AuthenticationError):
            await auth_service.login(login_data)

    @pytest.mark.asyncio
    async def test_refresh_token_success(
        self, auth_service: AuthService, test_user
    ):
        """Test successful token refresh."""
        # Create a refresh token
        with patch("src.core.security.verify_token") as mock_verify:
            mock_verify.return_value = {"sub": str(test_user.id)}

            access_token, expires_in = await auth_service.refresh_token("valid_refresh_token")

            assert access_token is not None
            assert expires_in > 0

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, auth_service: AuthService):
        """Test refresh with invalid token."""
        with patch("src.core.security.verify_token") as mock_verify:
            mock_verify.side_effect = Exception("Invalid token")

            with pytest.raises(AuthenticationError, match="Invalid refresh token"):
                await auth_service.refresh_token("invalid_token")

    @pytest.mark.asyncio
    async def test_signup_new_tenant(
        self, auth_service: AuthService, db_session: AsyncSession
    ):
        """Test signup creating a new tenant."""
        signup_data = SignupRequest(
            email="newuser@test.com",
            password="NewPassword123!",
            first_name="New",
            last_name="User"
        )

        user = await auth_service.signup(signup_data)

        assert user.email == "newuser@test.com"
        assert user.first_name == "New"
        assert user.last_name == "User"
        assert user.role == "admin"  # First user in new tenant is admin
        assert not user.is_verified  # Requires email verification
        assert user.tenant is not None

    @pytest.mark.asyncio
    async def test_signup_existing_tenant(
        self, auth_service: AuthService, test_tenant, db_session: AsyncSession
    ):
        """Test signup joining existing tenant."""
        signup_data = SignupRequest(
            email="newuser@test.com",
            password="NewPassword123!",
            first_name="New",
            last_name="User",
            tenant_slug=test_tenant.slug
        )

        user = await auth_service.signup(signup_data)

        assert user.email == "newuser@test.com"
        assert user.role == "viewer"  # Joining user gets viewer role
        assert user.tenant_id == test_tenant.id

    @pytest.mark.asyncio
    async def test_signup_duplicate_email(
        self, auth_service: AuthService, test_user
    ):
        """Test signup with existing email."""
        signup_data = SignupRequest(
            email=test_user.email,
            password="Password123!",
            first_name="Test",
            last_name="User"
        )

        with pytest.raises(ResourceConflictError, match="User with this email already exists"):
            await auth_service.signup(signup_data)

    @pytest.mark.asyncio
    async def test_signup_nonexistent_tenant(self, auth_service: AuthService):
        """Test signup with non-existent tenant."""
        signup_data = SignupRequest(
            email="newuser@test.com",
            password="Password123!",
            first_name="New",
            last_name="User",
            tenant_slug="nonexistent-tenant"
        )

        with pytest.raises(ResourceNotFoundError, match="Organization 'nonexistent-tenant' not found"):
            await auth_service.signup(signup_data)

    @pytest.mark.asyncio
    async def test_signup_inactive_tenant(
        self, auth_service: AuthService, db_session: AsyncSession
    ):
        """Test signup with inactive tenant."""
        inactive_tenant = TenantFactory(is_active=False)
        db_session.add(inactive_tenant)
        await db_session.commit()

        signup_data = SignupRequest(
            email="newuser@test.com",
            password="Password123!",
            first_name="New",
            last_name="User",
            tenant_slug=inactive_tenant.slug
        )

        with pytest.raises(ValidationError, match="Organization is inactive"):
            await auth_service.signup(signup_data)

    @pytest.mark.asyncio
    async def test_signup_tenant_user_limit(
        self, auth_service: AuthService, db_session: AsyncSession
    ):
        """Test signup when tenant has reached user limit."""
        # Create tenant with max_users = 1
        tenant = TenantFactory(max_users=1)
        existing_user = UserFactory(tenant=tenant)
        db_session.add_all([tenant, existing_user])
        await db_session.commit()

        signup_data = SignupRequest(
            email="newuser@test.com",
            password="Password123!",
            first_name="New",
            last_name="User",
            tenant_slug=tenant.slug
        )

        with pytest.raises(ValidationError, match="Organization has reached its user limit"):
            await auth_service.signup(signup_data)

    @pytest.mark.asyncio
    async def test_create_user_success(
        self, auth_service: AuthService, admin_user, db_session: AsyncSession
    ):
        """Test successful user creation by admin."""
        user_data = UserCreate(
            email="created@test.com",
            password="Password123!",
            first_name="Created",
            last_name="User",
            role="viewer",
            is_active=True,
            send_welcome_email=False
        )

        user = await auth_service.create_user(user_data, admin_user)

        assert user.email == "created@test.com"
        assert user.first_name == "Created"
        assert user.last_name == "User"
        assert user.role == "viewer"
        assert user.tenant_id == admin_user.tenant_id
        assert user.is_verified  # No welcome email means verified

    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(
        self, auth_service: AuthService, admin_user, test_user
    ):
        """Test user creation with duplicate email."""
        user_data = UserCreate(
            email=test_user.email,
            password="Password123!",
            first_name="Test",
            last_name="User",
            role="viewer"
        )

        with pytest.raises(ResourceConflictError, match="User with this email already exists"):
            await auth_service.create_user(user_data, admin_user)

    @pytest.mark.asyncio
    async def test_create_user_no_password(
        self, auth_service: AuthService, admin_user
    ):
        """Test user creation without password."""
        user_data = UserCreate(
            email="nopass@test.com",
            first_name="No",
            last_name="Password",
            role="viewer"
        )

        user = await auth_service.create_user(user_data, admin_user)

        assert user.password_hash is None

    @pytest.mark.asyncio
    async def test_get_user_by_id(self, auth_service: AuthService, test_user):
        """Test getting user by ID."""
        result = await auth_service.get_user_by_id(test_user.id)

        assert result is not None
        assert result.id == test_user.id
        assert result.email == test_user.email

    @pytest.mark.asyncio
    async def test_get_user_by_id_not_found(self, auth_service: AuthService):
        """Test getting non-existent user by ID."""
        result = await auth_service.get_user_by_id(uuid4())

        assert result is None

    @pytest.mark.asyncio
    async def test_get_user_by_email(self, auth_service: AuthService, test_user):
        """Test getting user by email."""
        result = await auth_service.get_user_by_email(test_user.email)

        assert result is not None
        assert result.id == test_user.id
        assert result.email == test_user.email

    @pytest.mark.asyncio
    async def test_get_user_by_email_not_found(self, auth_service: AuthService):
        """Test getting non-existent user by email."""
        result = await auth_service.get_user_by_email("nonexistent@test.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_generate_unique_tenant_slug(
        self, auth_service: AuthService, db_session: AsyncSession
    ):
        """Test generating unique tenant slug."""
        # Create a tenant with a specific slug
        existing_tenant = TenantFactory(slug="test-org")
        db_session.add(existing_tenant)
        await db_session.commit()

        # Test generating unique slug
        slug = await auth_service._generate_unique_tenant_slug("Test Org")
        assert slug == "test-org-1"

        # Test with special characters
        slug2 = await auth_service._generate_unique_tenant_slug("Test Org & Co!")
        assert slug2 == "test-org-co"

    @pytest.mark.asyncio
    async def test_generate_unique_tenant_slug_empty_name(
        self, auth_service: AuthService
    ):
        """Test generating slug from empty name."""
        slug = await auth_service._generate_unique_tenant_slug("")
        assert slug == "organization"