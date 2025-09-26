"""
Unit tests for authentication system.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.security import create_access_token, get_password_hash, verify_password
from src.db.models.system.tenant import Tenant
from src.db.models.system.user import User


class TestAuthenticationEndpoints:
    """Test authentication endpoints."""

    @pytest.fixture
    async def test_tenant(self, db: AsyncSession) -> Tenant:
        """Create a test tenant."""
        tenant = Tenant(
            name="Test Organization",
            slug="test-org",
            description="Test tenant for authentication tests",
        )
        db.add(tenant)
        await db.commit()
        return tenant

    @pytest.fixture
    async def test_user(self, db: AsyncSession, test_tenant: Tenant) -> User:
        """Create a test user."""
        user = User(
            tenant_id=test_tenant.id,
            email="test@example.com",
            password_hash=get_password_hash("testpassword123"),
            first_name="Test",
            last_name="User",
            role="analyst",
            is_active=True,
            is_verified=True,
        )
        db.add(user)
        await db.commit()
        return user

    def test_login_success(self, client: TestClient, test_user: User) -> None:
        """Test successful login."""
        login_data = {"email": "test@example.com", "password": "testpassword123"}

        response = client.post("/api/v1/auth/login", json=login_data)

        assert response.status_code == 200
        data = response.json()

        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
        assert "user" in data

        user_data = data["user"]
        assert user_data["email"] == "test@example.com"
        assert user_data["role"] == "analyst"
        assert user_data["is_active"] is True

    def test_login_invalid_email(self, client: TestClient) -> None:
        """Test login with invalid email."""
        login_data = {"email": "nonexistent@example.com", "password": "password123"}

        response = client.post("/api/v1/auth/login", json=login_data)

        assert response.status_code == 401
        assert "Invalid email or password" in response.json()["detail"]

    def test_login_invalid_password(self, client: TestClient, test_user: User) -> None:
        """Test login with invalid password."""
        login_data = {"email": "test@example.com", "password": "wrongpassword"}

        response = client.post("/api/v1/auth/login", json=login_data)

        assert response.status_code == 401
        assert "Invalid email or password" in response.json()["detail"]

    def test_signup_success(self, client: TestClient) -> None:
        """Test successful user signup."""
        signup_data = {
            "email": "newuser@example.com",
            "password": "NewPassword123!",
            "first_name": "New",
            "last_name": "User",
        }

        response = client.post("/api/v1/auth/signup", json=signup_data)

        assert response.status_code == 201
        data = response.json()

        assert "message" in data
        assert data["verification_required"] is True
        assert "user" in data

        user_data = data["user"]
        assert user_data["email"] == "newuser@example.com"
        assert user_data["first_name"] == "New"
        assert user_data["last_name"] == "User"
        assert user_data["role"] == "admin"  # First user in new tenant

    def test_signup_duplicate_email(self, client: TestClient, test_user: User) -> None:
        """Test signup with duplicate email."""
        signup_data = {
            "email": "test@example.com",  # Email already exists
            "password": "Password123!",
            "first_name": "Duplicate",
            "last_name": "User",
        }

        response = client.post("/api/v1/auth/signup", json=signup_data)

        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

    def test_signup_weak_password(self, client: TestClient) -> None:
        """Test signup with weak password."""
        signup_data = {
            "email": "weakpass@example.com",
            "password": "123",  # Too weak
            "first_name": "Weak",
            "last_name": "Password",
        }

        response = client.post("/api/v1/auth/signup", json=signup_data)

        assert response.status_code == 422  # Validation error

    def test_get_current_user(self, client: TestClient, test_user: User) -> None:
        """Test getting current user information."""
        # Create access token
        token = create_access_token(
            subject=str(test_user.id),
            additional_claims={
                "tenant_id": str(test_user.tenant_id),
                "role": test_user.role,
                "email": test_user.email,
            },
        )

        headers = {"Authorization": f"Bearer {token}"}
        response = client.get("/api/v1/auth/me", headers=headers)

        assert response.status_code == 200
        data = response.json()

        assert data["email"] == "test@example.com"
        assert data["role"] == "analyst"
        assert data["is_active"] is True

    def test_get_current_user_invalid_token(self, client: TestClient) -> None:
        """Test getting current user with invalid token."""
        headers = {"Authorization": "Bearer invalid_token"}
        response = client.get("/api/v1/auth/me", headers=headers)

        assert response.status_code == 401

    def test_get_current_user_no_token(self, client: TestClient) -> None:
        """Test getting current user without token."""
        response = client.get("/api/v1/auth/me")

        assert response.status_code == 401

    def test_logout(self, client: TestClient, test_user: User) -> None:
        """Test user logout."""
        # Create access token
        token = create_access_token(
            subject=str(test_user.id),
            additional_claims={
                "tenant_id": str(test_user.tenant_id),
                "role": test_user.role,
                "email": test_user.email,
            },
        )

        headers = {"Authorization": f"Bearer {token}"}
        response = client.post("/api/v1/auth/logout", headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert "message" in data


class TestPasswordSecurity:
    """Test password security functions."""

    def test_password_hashing(self) -> None:
        """Test password hashing and verification."""
        password = "TestPassword123!"
        hashed = get_password_hash(password)

        # Hash should be different from original
        assert hashed != password

        # Verification should work
        assert verify_password(password, hashed) is True

        # Wrong password should fail
        assert verify_password("WrongPassword", hashed) is False

    def test_password_hash_unique(self) -> None:
        """Test that password hashes are unique."""
        password = "SamePassword123!"
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)

        # Should be different due to salt
        assert hash1 != hash2

        # But both should verify correctly
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True


class TestJWTTokens:
    """Test JWT token creation and verification."""

    def test_create_access_token(self) -> None:
        """Test access token creation."""
        user_id = "123e4567-e89b-12d3-a456-426614174000"
        token = create_access_token(subject=user_id)

        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens are reasonably long

    def test_create_access_token_with_claims(self) -> None:
        """Test access token creation with additional claims."""
        user_id = "123e4567-e89b-12d3-a456-426614174000"
        claims = {"tenant_id": "456e7890-e89b-12d3-a456-426614174000", "role": "admin"}

        token = create_access_token(subject=user_id, additional_claims=claims)

        assert isinstance(token, str)
        assert len(token) > 50

    def test_token_verification(self) -> None:
        """Test token verification."""
        from src.core.security import verify_token

        user_id = "123e4567-e89b-12d3-a456-426614174000"
        token = create_access_token(subject=user_id)

        payload = verify_token(token, "access_token")

        assert payload["sub"] == user_id
        assert payload["type"] == "access_token"
        assert "exp" in payload
        assert "iat" in payload

    def test_invalid_token_verification(self) -> None:
        """Test verification of invalid token."""
        from src.core.exceptions import AuthenticationError
        from src.core.security import verify_token

        with pytest.raises(AuthenticationError):
            verify_token("invalid_token", "access_token")

    def test_wrong_token_type(self) -> None:
        """Test verification with wrong token type."""
        from src.core.exceptions import AuthenticationError
        from src.core.security import create_refresh_token, verify_token

        user_id = "123e4567-e89b-12d3-a456-426614174000"
        refresh_token = create_refresh_token(subject=user_id)

        # Should fail when verifying refresh token as access token
        with pytest.raises(AuthenticationError):
            verify_token(refresh_token, "access_token")
