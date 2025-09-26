"""
Pydantic schemas for user management.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class UserListResponse(BaseModel):
    """Schema for user list responses."""

    id: UUID
    email: str
    first_name: str | None = None
    last_name: str | None = None
    full_name: str
    role: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    last_login: datetime | None = None
    created_at: datetime
    tenant_id: UUID

    model_config = ConfigDict(from_attributes=True)


class UserUpdateRequest(BaseModel):
    """Schema for updating user information."""

    first_name: str | None = Field(None, min_length=1, max_length=100)
    last_name: str | None = Field(None, min_length=1, max_length=100)
    role: str | None = Field(None, pattern=r"^(admin|analyst|viewer)$")
    is_active: bool | None = None


class UserStatsResponse(BaseModel):
    """Schema for user statistics."""

    total_users: int
    active_users: int
    inactive_users: int
    verified_users: int
    unverified_users: int
    users_with_mfa: int
    role_distribution: list[dict]
