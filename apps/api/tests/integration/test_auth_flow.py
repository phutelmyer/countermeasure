"""
Integration tests for complete authentication flows.

Tests the full auth workflow including signup → login → refresh cycles,
password reset flows, and token lifecycle management.
"""

import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.security import create_access_token, verify_password, get_password_hash
from src.db.models.system.user import User
from src.db.models.system.tenant import Tenant
from src.schemas.auth import UserCreate


class TestCompleteAuthFlow:
    """Test complete authentication workflows."""

    async def test_signup_login_refresh_cycle(
        self, client: TestClient, db_session: AsyncSession
    ):
        """Test complete signup → login → refresh token cycle."""
        # Step 1: Sign up new user
        signup_data = {
            "email": "newuser@example.com",
            "password": "SecurePassword123!",
            "full_name": "New User",
            "company_name": "Test Company",
        }

        signup_response = client.post("/api/v1/auth/signup", json=signup_data)
        assert signup_response.status_code == 201
        signup_result = signup_response.json()

        assert "access_token" in signup_result
        assert "refresh_token" in signup_result
        assert signup_result["user"]["email"] == signup_data["email"]
        assert signup_result["user"]["full_name"] == signup_data["full_name"]

        initial_access_token = signup_result["access_token"]
        initial_refresh_token = signup_result["refresh_token"]

        # Step 2: Use access token to access protected endpoint
        headers = {"Authorization": f"Bearer {initial_access_token}"}
        profile_response = client.get("/api/v1/auth/me", headers=headers)
        assert profile_response.status_code == 200
        profile_data = profile_response.json()
        assert profile_data["email"] == signup_data["email"]

        # Step 3: Login with same credentials
        login_data = {
            "email": signup_data["email"],
            "password": signup_data["password"],
        }

        login_response = client.post("/api/v1/auth/login", json=login_data)
        assert login_response.status_code == 200
        login_result = login_response.json()

        assert "access_token" in login_result
        assert "refresh_token" in login_result
        # Should get new tokens
        assert login_result["access_token"] != initial_access_token

        new_access_token = login_result["access_token"]
        new_refresh_token = login_result["refresh_token"]

        # Step 4: Use refresh token to get new access token
        refresh_data = {"refresh_token": new_refresh_token}
        refresh_response = client.post("/api/v1/auth/refresh", json=refresh_data)
        assert refresh_response.status_code == 200
        refresh_result = refresh_response.json()

        assert "access_token" in refresh_result
        assert "refresh_token" in refresh_result
        # Should get fresh tokens
        assert refresh_result["access_token"] != new_access_token

        # Step 5: Verify old access token still works (not expired yet)
        old_headers = {"Authorization": f"Bearer {new_access_token}"}
        old_token_response = client.get("/api/v1/auth/me", headers=old_headers)
        assert old_token_response.status_code == 200

        # Step 6: Verify new access token works
        fresh_headers = {"Authorization": f"Bearer {refresh_result['access_token']}"}
        fresh_token_response = client.get("/api/v1/auth/me", headers=fresh_headers)
        assert fresh_token_response.status_code == 200

    async def test_password_reset_flow(
        self, client: TestClient, db_session: AsyncSession, test_user: User
    ):
        """Test complete password reset workflow."""
        original_password = "OriginalPassword123!"
        new_password = "NewPassword456!"

        # Step 1: Request password reset
        reset_request_data = {"email": test_user.email}
        reset_request_response = client.post(
            "/api/v1/auth/password-reset/request", json=reset_request_data
        )
        assert reset_request_response.status_code == 200

        # Check that reset token was set in database
        await db_session.refresh(test_user)
        assert test_user.reset_token is not None
        assert test_user.reset_token_expires is not None
        assert test_user.reset_token_expires > datetime.utcnow()

        # Step 2: Verify old password still works
        login_data = {"email": test_user.email, "password": original_password}
        login_response = client.post("/api/v1/auth/login", json=login_data)
        assert login_response.status_code == 200

        # Step 3: Confirm password reset with token
        reset_confirm_data = {
            "token": test_user.reset_token,
            "new_password": new_password,
        }
        reset_confirm_response = client.post(
            "/api/v1/auth/password-reset/confirm", json=reset_confirm_data
        )
        assert reset_confirm_response.status_code == 200

        # Step 4: Verify old password no longer works
        old_login_response = client.post("/api/v1/auth/login", json=login_data)
        assert old_login_response.status_code == 401

        # Step 5: Verify new password works
        new_login_data = {"email": test_user.email, "password": new_password}
        new_login_response = client.post("/api/v1/auth/login", json=new_login_data)
        assert new_login_response.status_code == 200

        # Step 6: Verify reset token was cleared
        await db_session.refresh(test_user)
        assert test_user.reset_token is None
        assert test_user.reset_token_expires is None

    async def test_invalid_refresh_token_handling(
        self, client: TestClient, test_user: User
    ):
        """Test handling of invalid or expired refresh tokens."""
        # Test with completely invalid token
        invalid_refresh_data = {"refresh_token": "invalid_token_123"}
        invalid_response = client.post("/api/v1/auth/refresh", json=invalid_refresh_data)
        assert invalid_response.status_code == 401

        # Test with expired token (simulate by creating token with past expiry)
        expired_token = create_access_token(
            data={"sub": str(test_user.id), "type": "refresh"},
            expires_delta=timedelta(minutes=-10)  # Expired 10 minutes ago
        )
        expired_refresh_data = {"refresh_token": expired_token}
        expired_response = client.post("/api/v1/auth/refresh", json=expired_refresh_data)
        assert expired_response.status_code == 401

    async def test_concurrent_login_attempts(
        self, client: TestClient, test_user: User
    ):
        """Test handling of concurrent login attempts."""
        login_data = {"email": test_user.email, "password": "TestPassword123!"}

        # Simulate multiple concurrent login attempts
        responses = []
        for _ in range(5):
            response = client.post("/api/v1/auth/login", json=login_data)
            responses.append(response)

        # All should succeed
        for response in responses:
            assert response.status_code == 200
            result = response.json()
            assert "access_token" in result
            assert "refresh_token" in result

        # Each should have unique tokens
        tokens = [r.json()["access_token"] for r in responses]
        assert len(set(tokens)) == len(tokens)  # All unique

    async def test_failed_login_tracking(
        self, client: TestClient, db_session: AsyncSession, test_user: User
    ):
        """Test failed login attempt tracking."""
        # Record initial failed login count
        initial_failed_count = test_user.failed_login_attempts
        initial_last_failed = test_user.last_failed_login

        # Attempt login with wrong password
        wrong_login_data = {"email": test_user.email, "password": "WrongPassword"}
        failed_response = client.post("/api/v1/auth/login", json=wrong_login_data)
        assert failed_response.status_code == 401

        # Check that failed login was recorded
        await db_session.refresh(test_user)
        assert test_user.failed_login_attempts == initial_failed_count + 1
        assert test_user.last_failed_login > initial_last_failed

        # Successful login should reset counter
        correct_login_data = {"email": test_user.email, "password": "TestPassword123!"}
        success_response = client.post("/api/v1/auth/login", json=correct_login_data)
        assert success_response.status_code == 200

        await db_session.refresh(test_user)
        assert test_user.failed_login_attempts == 0

    async def test_email_case_insensitive_login(
        self, client: TestClient, test_user: User
    ):
        """Test that email login is case insensitive."""
        login_variations = [
            test_user.email.upper(),
            test_user.email.lower(),
            test_user.email.title(),
        ]

        for email_variant in login_variations:
            login_data = {"email": email_variant, "password": "TestPassword123!"}
            response = client.post("/api/v1/auth/login", json=login_data)
            assert response.status_code == 200, f"Failed for email: {email_variant}"

    async def test_tenant_context_in_auth_flow(
        self, client: TestClient, db_session: AsyncSession
    ):
        """Test that tenant context is properly set during auth flow."""
        # Sign up new user (creates new tenant)
        signup_data = {
            "email": "tenant@example.com",
            "password": "SecurePassword123!",
            "full_name": "Tenant User",
            "company_name": "Tenant Company",
        }

        signup_response = client.post("/api/v1/auth/signup", json=signup_data)
        assert signup_response.status_code == 201
        signup_result = signup_response.json()

        access_token = signup_result["access_token"]
        user_id = signup_result["user"]["id"]

        # Use token to access user profile
        headers = {"Authorization": f"Bearer {access_token}"}
        profile_response = client.get("/api/v1/auth/me", headers=headers)
        assert profile_response.status_code == 200
        profile_data = profile_response.json()

        # Verify tenant information is included
        assert "tenant" in profile_data
        assert profile_data["tenant"]["name"] == signup_data["company_name"]

        # Verify user can only see their own tenant's data
        tenants_response = client.get("/api/v1/tenants/", headers=headers)
        assert tenants_response.status_code == 200
        tenants_data = tenants_response.json()

        # Should only see their own tenant
        assert len(tenants_data["items"]) == 1
        assert tenants_data["items"][0]["name"] == signup_data["company_name"]