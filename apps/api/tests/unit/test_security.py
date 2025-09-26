"""
Unit tests for security utilities.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from src.core.security import (
    create_access_token,
    create_refresh_token,
    create_password_reset_token,
    verify_token,
    get_password_hash,
    verify_password,
    validate_password_strength,
    generate_secure_random_string,
    RoleChecker,
)
from src.core.exceptions import AuthenticationError


class TestSecurity:
    """Test suite for security utilities."""

    def test_get_password_hash(self):
        """Test password hashing."""
        password = "TestPassword123!"
        hashed = get_password_hash(password)

        assert hashed != password
        assert len(hashed) > 0
        assert hashed.startswith("$2b$")

    def test_verify_password_success(self):
        """Test successful password verification."""
        password = "TestPassword123!"
        hashed = get_password_hash(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_failure(self):
        """Test failed password verification."""
        password = "TestPassword123!"
        wrong_password = "WrongPassword123!"
        hashed = get_password_hash(password)

        assert verify_password(wrong_password, hashed) is False

    def test_verify_password_empty_hash(self):
        """Test password verification with empty hash."""
        assert verify_password("password", "") is False
        assert verify_password("password", None) is False

    def test_create_access_token(self):
        """Test access token creation."""
        subject = "user123"
        additional_claims = {"role": "admin", "tenant_id": "tenant123"}

        token = create_access_token(subject, additional_claims=additional_claims)

        assert token is not None
        assert isinstance(token, str)
        assert len(token.split('.')) == 3  # JWT has 3 parts

    def test_create_access_token_with_expiry(self):
        """Test access token creation with custom expiry."""
        subject = "user123"
        expires_delta = timedelta(hours=1)

        token = create_access_token(subject, expires_delta=expires_delta)

        assert token is not None
        assert isinstance(token, str)

    def test_create_refresh_token(self):
        """Test refresh token creation."""
        subject = "user123"

        token = create_refresh_token(subject)

        assert token is not None
        assert isinstance(token, str)
        assert len(token.split('.')) == 3  # JWT has 3 parts

    def test_verify_token_success(self):
        """Test successful token verification."""
        subject = "user123"
        additional_claims = {"role": "admin"}

        token = create_access_token(subject, additional_claims=additional_claims)
        payload = verify_token(token)

        assert payload["sub"] == subject
        assert payload["role"] == "admin"
        assert "exp" in payload
        assert "iat" in payload

    def test_verify_token_with_type(self):
        """Test token verification with specific type."""
        subject = "user123"

        access_token = create_access_token(subject)
        refresh_token = create_refresh_token(subject)

        # Verify access token
        payload = verify_token(access_token, "access_token")
        assert payload["sub"] == subject
        assert payload["type"] == "access_token"

        # Verify refresh token
        payload = verify_token(refresh_token, "refresh_token")
        assert payload["sub"] == subject
        assert payload["type"] == "refresh_token"

    def test_verify_token_wrong_type(self):
        """Test token verification with wrong type."""
        subject = "user123"
        access_token = create_access_token(subject)

        with pytest.raises(AuthenticationError, match="Invalid token type"):
            verify_token(access_token, "refresh_token")

    def test_verify_token_invalid(self):
        """Test verification of invalid token."""
        with pytest.raises(AuthenticationError, match="Invalid token"):
            verify_token("invalid.token.here")

    def test_verify_token_expired(self):
        """Test verification of expired token."""
        subject = "user123"
        expires_delta = timedelta(seconds=-1)  # Already expired

        token = create_access_token(subject, expires_delta=expires_delta)

        with pytest.raises(AuthenticationError, match="Token has expired"):
            verify_token(token)

    def test_verify_token_malformed(self):
        """Test verification of malformed token."""
        malformed_tokens = [
            "not.a.token",
            "only.two.parts",
            "",
            "too.many.parts.here.extra",
            None,
        ]

        for token in malformed_tokens:
            with pytest.raises(AuthenticationError, match="Invalid token"):
                verify_token(token)

    def test_create_password_reset_token(self):
        """Test password reset token creation."""
        user_id = "test-user-id"
        token = create_password_reset_token(user_id)

        assert isinstance(token, str)
        assert len(token) > 0

        # Verify it's a valid JWT token by decoding
        payload = verify_token(token, "password_reset")
        assert payload["sub"] == user_id
        assert payload["type"] == "password_reset"

    def test_validate_password_strength_weak(self):
        """Test password strength validation with weak password."""
        weak_passwords = [
            "short",
            "12345678",
            "password",
            "PASSWORD",
            "abcdefgh",
        ]

        for password in weak_passwords:
            assert validate_password_strength(password) is False

    def test_validate_password_strength_strong(self):
        """Test password strength validation with strong password."""
        strong_passwords = [
            "StrongPassword123!",
            "MySecure@Pass99",
            "Complex#Password1",
            "ValidPass123$",
        ]

        for password in strong_passwords:
            assert validate_password_strength(password) is True

    def test_generate_secure_random_string(self):
        """Test secure random string generation."""
        # Test default length
        random_str = generate_secure_random_string()
        assert isinstance(random_str, str)

        # Test custom length
        custom_length = 16
        random_str_custom = generate_secure_random_string(custom_length)
        assert isinstance(random_str_custom, str)

        # Ensure different calls produce different strings
        random_str2 = generate_secure_random_string()
        assert random_str != random_str2

    def test_role_checker_has_role(self):
        """Test role hierarchy checking."""
        # Admin should have access to all roles
        assert RoleChecker.has_role("admin", "admin") is True
        assert RoleChecker.has_role("admin", "analyst") is True
        assert RoleChecker.has_role("admin", "viewer") is True
        assert RoleChecker.has_role("admin", "collector") is True

        # Analyst should have access to analyst and viewer
        assert RoleChecker.has_role("analyst", "analyst") is True
        assert RoleChecker.has_role("analyst", "viewer") is True
        assert RoleChecker.has_role("analyst", "admin") is False

        # Viewer should only have access to viewer
        assert RoleChecker.has_role("viewer", "viewer") is True
        assert RoleChecker.has_role("viewer", "analyst") is False

    def test_different_passwords_different_hashes(self):
        """Test that different passwords produce different hashes."""
        password1 = "Password123!"
        password2 = "DifferentPassword456!"

        hash1 = get_password_hash(password1)
        hash2 = get_password_hash(password2)

        assert hash1 != hash2

    def test_same_password_different_hashes(self):
        """Test that same password produces different hashes (due to salt)."""
        password = "SamePassword123!"

        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)

        # Hashes should be different due to random salt
        assert hash1 != hash2

        # But both should verify successfully
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True

    def test_token_claims_preserved(self):
        """Test that additional claims are preserved in tokens."""
        subject = "user123"
        claims = {
            "tenant_id": "tenant456",
            "role": "admin",
            "email": "user@example.com",
            "custom_claim": "custom_value"
        }

        token = create_access_token(subject, additional_claims=claims)
        payload = verify_token(token)

        assert payload["sub"] == subject
        assert payload["tenant_id"] == "tenant456"
        assert payload["role"] == "admin"
        assert payload["email"] == "user@example.com"
        assert payload["custom_claim"] == "custom_value"