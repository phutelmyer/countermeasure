"""
Pydantic schemas for actor API endpoints.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ActorBase(BaseModel):
    """Base actor schema with common fields."""

    name: str = Field(..., min_length=1, max_length=255)
    aliases: list[str] | None = Field(default=None, max_length=50)
    actor_type: str = Field(..., pattern=r"^(group|individual|cluster|campaign)$")
    attribution_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    attribution_rationale: str | None = Field(default=None, max_length=2000)
    primary_attribution: str | None = Field(default=None, max_length=255)
    sophistication_level: str = Field(
        default="unknown", pattern=r"^(unknown|low|medium|high|advanced)$"
    )
    threat_level: str = Field(
        default="unknown", pattern=r"^(unknown|low|medium|high|critical)$"
    )
    motivations: list[str] | None = Field(default=None, max_length=20)
    origin_country: str | None = Field(default=None, min_length=3, max_length=3)
    target_countries: list[str] | None = Field(default=None, max_length=50)
    target_sectors: list[str] | None = Field(default=None, max_length=50)
    suspected_attribution: str | None = Field(default=None, max_length=255)
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    status: str = Field(
        default="active", pattern=r"^(active|dormant|disbanded|unknown)$"
    )
    description: str | None = Field(default=None, max_length=10000)
    summary: str | None = Field(default=None, max_length=500)
    mitre_attack_id: str | None = Field(default=None, max_length=50)
    external_ids: dict[str, Any] | None = None
    references: list[str] | None = Field(default=None, max_length=100)
    analyst_notes: str | None = Field(default=None, max_length=5000)
    is_validated: bool = Field(default=False)
    validation_notes: str | None = Field(default=None, max_length=2000)
    custom_attributes: dict[str, Any] | None = None
    tags: list[str] | None = Field(default=None, max_length=50)


class ActorCreate(ActorBase):
    """Schema for creating actors."""



class ActorUpdate(BaseModel):
    """Schema for updating actors (all fields optional)."""

    name: str | None = Field(None, min_length=1, max_length=255)
    aliases: list[str] | None = Field(None, max_length=50)
    actor_type: str | None = Field(
        None, pattern=r"^(group|individual|cluster|campaign)$"
    )
    attribution_confidence: float | None = Field(None, ge=0.0, le=1.0)
    attribution_rationale: str | None = Field(None, max_length=2000)
    primary_attribution: str | None = Field(None, max_length=255)
    sophistication_level: str | None = Field(
        None, pattern=r"^(unknown|low|medium|high|advanced)$"
    )
    threat_level: str | None = Field(
        None, pattern=r"^(unknown|low|medium|high|critical)$"
    )
    motivations: list[str] | None = Field(None, max_length=20)
    origin_country: str | None = Field(None, min_length=3, max_length=3)
    target_countries: list[str] | None = Field(None, max_length=50)
    target_sectors: list[str] | None = Field(None, max_length=50)
    suspected_attribution: str | None = Field(None, max_length=255)
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    status: str | None = Field(None, pattern=r"^(active|dormant|disbanded|unknown)$")
    description: str | None = Field(None, max_length=10000)
    summary: str | None = Field(None, max_length=500)
    mitre_attack_id: str | None = Field(None, max_length=50)
    external_ids: dict[str, Any] | None = None
    references: list[str] | None = Field(None, max_length=100)
    analyst_notes: str | None = Field(None, max_length=5000)
    is_validated: bool | None = None
    validation_notes: str | None = Field(None, max_length=2000)
    custom_attributes: dict[str, Any] | None = None
    tags: list[str] | None = Field(None, max_length=50)


class ActorResponse(ActorBase):
    """Schema for actor responses."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    quality_score: float = Field(..., ge=0.0, le=1.0)
    created_at: datetime
    updated_at: datetime
    created_by: UUID | None = None
    updated_by: UUID | None = None


class ActorListResponse(BaseModel):
    """Schema for paginated actor list responses."""

    items: list[ActorResponse]
    total: int
    page: int
    per_page: int
    pages: int


class ActorSearchRequest(BaseModel):
    """Schema for actor search requests."""

    query: str | None = Field(None, max_length=255)
    actor_types: list[str] | None = Field(None, max_length=10)
    threat_levels: list[str] | None = Field(None, max_length=10)
    sophistication_levels: list[str] | None = Field(None, max_length=10)
    statuses: list[str] | None = Field(None, max_length=10)
    origin_countries: list[str] | None = Field(None, max_length=50)
    target_sectors: list[str] | None = Field(None, max_length=50)
    motivations: list[str] | None = Field(None, max_length=20)
    min_confidence: float | None = Field(None, ge=0.0, le=1.0)
    max_confidence: float | None = Field(None, ge=0.0, le=1.0)
    is_validated: bool | None = None
    tags: list[str] | None = Field(None, max_length=50)
    created_after: datetime | None = None
    created_before: datetime | None = None
    updated_after: datetime | None = None
    updated_before: datetime | None = None


# Campaign schemas
class CampaignBase(BaseModel):
    """Base campaign schema."""

    name: str = Field(..., min_length=1, max_length=255)
    aliases: list[str] | None = Field(default=None, max_length=50)
    start_date: datetime | None = None
    end_date: datetime | None = None
    status: str = Field(default="active", pattern=r"^(active|ended|dormant|unknown)$")
    actor_id: UUID | None = None
    attribution_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    objectives: list[str] | None = Field(default=None, max_length=50)
    target_sectors: list[str] | None = Field(default=None, max_length=50)
    target_countries: list[str] | None = Field(default=None, max_length=50)
    description: str | None = Field(default=None, max_length=10000)
    summary: str | None = Field(default=None, max_length=500)
    tactics_techniques: list[str] | None = Field(default=None, max_length=100)
    external_ids: dict[str, Any] | None = None
    references: list[str] | None = Field(default=None, max_length=100)
    analyst_notes: str | None = Field(default=None, max_length=5000)
    custom_attributes: dict[str, Any] | None = None
    tags: list[str] | None = Field(default=None, max_length=50)


class CampaignCreate(CampaignBase):
    """Schema for creating campaigns."""



class CampaignUpdate(BaseModel):
    """Schema for updating campaigns."""

    name: str | None = Field(None, min_length=1, max_length=255)
    aliases: list[str] | None = Field(None, max_length=50)
    start_date: datetime | None = None
    end_date: datetime | None = None
    status: str | None = Field(None, pattern=r"^(active|ended|dormant|unknown)$")
    actor_id: UUID | None = None
    attribution_confidence: float | None = Field(None, ge=0.0, le=1.0)
    objectives: list[str] | None = Field(None, max_length=50)
    target_sectors: list[str] | None = Field(None, max_length=50)
    target_countries: list[str] | None = Field(None, max_length=50)
    description: str | None = Field(None, max_length=10000)
    summary: str | None = Field(None, max_length=500)
    tactics_techniques: list[str] | None = Field(None, max_length=100)
    external_ids: dict[str, Any] | None = None
    references: list[str] | None = Field(None, max_length=100)
    analyst_notes: str | None = Field(None, max_length=5000)
    custom_attributes: dict[str, Any] | None = None
    tags: list[str] | None = Field(None, max_length=50)


class CampaignResponse(CampaignBase):
    """Schema for campaign responses."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    created_at: datetime
    updated_at: datetime
    created_by: UUID | None = None
    updated_by: UUID | None = None


# Malware family schemas
class MalwareBase(BaseModel):
    """Base malware family schema."""

    name: str = Field(..., min_length=1, max_length=255)
    aliases: list[str] | None = Field(default=None, max_length=50)
    family_type: str = Field(..., max_length=50)
    actor_id: UUID | None = None
    attribution_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    platforms: list[str] | None = Field(default=None, max_length=20)
    capabilities: list[str] | None = Field(default=None, max_length=100)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    status: str = Field(default="active", pattern=r"^(active|dormant|retired|unknown)$")
    description: str | None = Field(default=None, max_length=10000)
    summary: str | None = Field(default=None, max_length=500)
    external_ids: dict[str, Any] | None = None
    references: list[str] | None = Field(default=None, max_length=100)
    analyst_notes: str | None = Field(default=None, max_length=5000)
    custom_attributes: dict[str, Any] | None = None
    tags: list[str] | None = Field(default=None, max_length=50)


class MalwareCreate(MalwareBase):
    """Schema for creating malware families."""



class MalwareUpdate(BaseModel):
    """Schema for updating malware families."""

    name: str | None = Field(None, min_length=1, max_length=255)
    aliases: list[str] | None = Field(None, max_length=50)
    family_type: str | None = Field(None, max_length=50)
    actor_id: UUID | None = None
    attribution_confidence: float | None = Field(None, ge=0.0, le=1.0)
    platforms: list[str] | None = Field(None, max_length=20)
    capabilities: list[str] | None = Field(None, max_length=100)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    status: str | None = Field(None, pattern=r"^(active|dormant|retired|unknown)$")
    description: str | None = Field(None, max_length=10000)
    summary: str | None = Field(None, max_length=500)
    external_ids: dict[str, Any] | None = None
    references: list[str] | None = Field(None, max_length=100)
    analyst_notes: str | None = Field(None, max_length=5000)
    custom_attributes: dict[str, Any] | None = None
    tags: list[str] | None = Field(None, max_length=50)


class MalwareResponse(MalwareBase):
    """Schema for malware family responses."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    created_at: datetime
    updated_at: datetime
    created_by: UUID | None = None
    updated_by: UUID | None = None
