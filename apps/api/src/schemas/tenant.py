"""
Pydantic schemas for tenant management.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TenantBase(BaseModel):
    """Base tenant schema."""

    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=100)
    description: str | None = Field(None, max_length=2000)
    max_users: int = Field(default=100, ge=1, le=10000)
    max_storage_gb: int = Field(default=10, ge=1, le=1000)
    is_active: bool = True
    settings: dict[str, Any] = Field(default_factory=dict)


class TenantCreate(TenantBase):
    """Schema for creating tenants."""



class TenantUpdate(BaseModel):
    """Schema for updating tenants."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    max_users: int | None = Field(None, ge=1, le=10000)
    max_storage_gb: int | None = Field(None, ge=1, le=1000)
    is_active: bool | None = None
    settings: dict[str, Any] | None = None


class TenantResponse(TenantBase):
    """Schema for tenant responses."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    user_count: int
    created_at: datetime
    updated_at: datetime


class TenantStatsResponse(BaseModel):
    """Schema for tenant statistics."""

    total_tenants: int
    active_tenants: int
    inactive_tenants: int
    total_users: int
    avg_users_per_tenant: float
    total_storage_used_gb: float
