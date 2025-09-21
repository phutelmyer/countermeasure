"""
Pydantic schemas for authentication and user management.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator


class TokenResponse(BaseModel):
    """Response for successful authentication."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expires
    user: "UserResponse"


class TokenRefreshRequest(BaseModel):
    """Request to refresh access token."""
    refresh_token: str


class TokenRefreshResponse(BaseModel):
    """Response for token refresh."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class LoginRequest(BaseModel):
    """User login request."""
    email: EmailStr
    password: str
    remember_me: bool = False

    @field_validator('email')
    @classmethod
    def email_must_be_lowercase(cls, v: str) -> str:
        return v.lower().strip()


class LoginResponse(BaseModel):
    """User login response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "UserResponse"


class SignupRequest(BaseModel):
    """User signup request."""
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    tenant_slug: Optional[str] = None  # For joining existing tenant

    @field_validator('email')
    @classmethod
    def email_must_be_lowercase(cls, v: str) -> str:
        return v.lower().strip()

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')

        # Check for at least 3 of 4 character types
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v)

        requirements_met = sum([has_upper, has_lower, has_digit, has_special])
        if requirements_met < 3:
            raise ValueError(
                'Password must contain at least 3 of: uppercase, lowercase, digits, special characters'
            )

        return v

    @field_validator('first_name', 'last_name')
    @classmethod
    def validate_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if len(v) < 1:
                raise ValueError('Name must not be empty')
            if len(v) > 100:
                raise ValueError('Name must be less than 100 characters')
        return v


class SignupResponse(BaseModel):
    """User signup response."""
    message: str
    user: "UserResponse"
    verification_required: bool = True


class PasswordResetRequest(BaseModel):
    """Password reset request."""
    email: EmailStr

    @field_validator('email')
    @classmethod
    def email_must_be_lowercase(cls, v: str) -> str:
        return v.lower().strip()


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation."""
    token: str
    new_password: str

    @field_validator('new_password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        # Reuse validation from SignupRequest
        return SignupRequest.model_validate({'password': v, 'email': 'test@example.com'}).password


class PasswordChangeRequest(BaseModel):
    """Password change request (for authenticated users)."""
    current_password: str
    new_password: str

    @field_validator('new_password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        # Reuse validation from SignupRequest
        return SignupRequest.model_validate({'password': v, 'email': 'test@example.com'}).password


class EmailVerificationRequest(BaseModel):
    """Email verification request."""
    token: str


class UserResponse(BaseModel):
    """User response schema."""
    id: UUID
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    full_name: str
    role: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    last_login: Optional[datetime] = None
    created_at: datetime
    tenant_id: UUID

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    """Schema for creating a new user (admin only)."""
    email: EmailStr
    password: Optional[str] = None  # Can be None for OAuth users
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: str = "viewer"
    is_active: bool = True
    send_welcome_email: bool = True

    @field_validator('email')
    @classmethod
    def email_must_be_lowercase(cls, v: str) -> str:
        return v.lower().strip()

    @field_validator('role')
    @classmethod
    def validate_role(cls, v: str) -> str:
        allowed_roles = ["admin", "analyst", "viewer", "collector"]
        if v not in allowed_roles:
            raise ValueError(f'Role must be one of: {", ".join(allowed_roles)}')
        return v


class UserUpdate(BaseModel):
    """Schema for updating user information."""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    settings: Optional[Dict[str, Any]] = None

    @field_validator('role')
    @classmethod
    def validate_role(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed_roles = ["admin", "analyst", "viewer", "collector"]
            if v not in allowed_roles:
                raise ValueError(f'Role must be one of: {", ".join(allowed_roles)}')
        return v


class UserListResponse(BaseModel):
    """Response for user list with pagination."""
    users: List[UserResponse]
    total: int
    page: int
    size: int
    pages: int


class TenantResponse(BaseModel):
    """Tenant response schema."""
    id: UUID
    name: str
    slug: str
    description: Optional[str] = None
    is_active: bool
    user_count: int
    max_users: int
    max_storage_gb: int
    created_at: datetime
    settings: Dict[str, Any]

    class Config:
        from_attributes = True


class TenantCreate(BaseModel):
    """Schema for creating a new tenant."""
    name: str = Field(..., min_length=2, max_length=255)
    slug: Optional[str] = None  # Auto-generated if not provided
    description: Optional[str] = None
    max_users: int = Field(default=100, ge=1, le=10000)
    max_storage_gb: int = Field(default=10, ge=1, le=1000)
    settings: Dict[str, Any] = Field(default_factory=dict)

    @field_validator('slug')
    @classmethod
    def validate_slug(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.lower().strip()
            if not re.match(r'^[a-z0-9-]+$', v):
                raise ValueError('Slug must contain only lowercase letters, numbers, and hyphens')
            if len(v) < 2 or len(v) > 100:
                raise ValueError('Slug must be between 2 and 100 characters')
        return v


class TenantUpdate(BaseModel):
    """Schema for updating tenant information."""
    name: Optional[str] = Field(None, min_length=2, max_length=255)
    description: Optional[str] = None
    max_users: Optional[int] = Field(None, ge=1, le=10000)
    max_storage_gb: Optional[int] = Field(None, ge=1, le=1000)
    is_active: Optional[bool] = None
    settings: Optional[Dict[str, Any]] = None


class MFASetupRequest(BaseModel):
    """MFA setup request."""
    password: str  # Current password for verification


class MFASetupResponse(BaseModel):
    """MFA setup response."""
    secret: str
    qr_code_url: str
    backup_codes: List[str]


class MFAVerifyRequest(BaseModel):
    """MFA verification request."""
    code: str
    backup_code: Optional[str] = None

    @field_validator('code')
    @classmethod
    def validate_code(cls, v: str) -> str:
        v = v.strip().replace(' ', '')
        if not re.match(r'^\d{6}$', v):
            raise ValueError('MFA code must be 6 digits')
        return v


class AuditLogResponse(BaseModel):
    """Audit log entry response."""
    id: UUID
    user_id: Optional[UUID] = None
    tenant_id: UUID
    action: str
    resource: str
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool
    details: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True