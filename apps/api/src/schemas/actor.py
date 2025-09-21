"""
Pydantic schemas for actor API endpoints.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class ActorBase(BaseModel):
    """Base actor schema with common fields."""
    name: str = Field(..., min_length=1, max_length=255)
    aliases: Optional[List[str]] = Field(default=None, max_length=50)
    actor_type: str = Field(..., pattern=r"^(group|individual|cluster|campaign)$")
    attribution_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    attribution_rationale: Optional[str] = Field(default=None, max_length=2000)
    primary_attribution: Optional[str] = Field(default=None, max_length=255)
    sophistication_level: str = Field(default="unknown", pattern=r"^(unknown|low|medium|high|advanced)$")
    threat_level: str = Field(default="unknown", pattern=r"^(unknown|low|medium|high|critical)$")
    motivations: Optional[List[str]] = Field(default=None, max_length=20)
    origin_country: Optional[str] = Field(default=None, min_length=3, max_length=3)
    target_countries: Optional[List[str]] = Field(default=None, max_length=50)
    target_sectors: Optional[List[str]] = Field(default=None, max_length=50)
    suspected_attribution: Optional[str] = Field(default=None, max_length=255)
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    status: str = Field(default="active", pattern=r"^(active|dormant|disbanded|unknown)$")
    description: Optional[str] = Field(default=None, max_length=10000)
    summary: Optional[str] = Field(default=None, max_length=500)
    mitre_attack_id: Optional[str] = Field(default=None, max_length=50)
    external_ids: Optional[Dict[str, Any]] = None
    references: Optional[List[str]] = Field(default=None, max_length=100)
    analyst_notes: Optional[str] = Field(default=None, max_length=5000)
    is_validated: bool = Field(default=False)
    validation_notes: Optional[str] = Field(default=None, max_length=2000)
    custom_attributes: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = Field(default=None, max_length=50)


class ActorCreate(ActorBase):
    """Schema for creating actors."""
    pass


class ActorUpdate(BaseModel):
    """Schema for updating actors (all fields optional)."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    aliases: Optional[List[str]] = Field(None, max_length=50)
    actor_type: Optional[str] = Field(None, pattern=r"^(group|individual|cluster|campaign)$")
    attribution_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    attribution_rationale: Optional[str] = Field(None, max_length=2000)
    primary_attribution: Optional[str] = Field(None, max_length=255)
    sophistication_level: Optional[str] = Field(None, pattern=r"^(unknown|low|medium|high|advanced)$")
    threat_level: Optional[str] = Field(None, pattern=r"^(unknown|low|medium|high|critical)$")
    motivations: Optional[List[str]] = Field(None, max_length=20)
    origin_country: Optional[str] = Field(None, min_length=3, max_length=3)
    target_countries: Optional[List[str]] = Field(None, max_length=50)
    target_sectors: Optional[List[str]] = Field(None, max_length=50)
    suspected_attribution: Optional[str] = Field(None, max_length=255)
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    status: Optional[str] = Field(None, pattern=r"^(active|dormant|disbanded|unknown)$")
    description: Optional[str] = Field(None, max_length=10000)
    summary: Optional[str] = Field(None, max_length=500)
    mitre_attack_id: Optional[str] = Field(None, max_length=50)
    external_ids: Optional[Dict[str, Any]] = None
    references: Optional[List[str]] = Field(None, max_length=100)
    analyst_notes: Optional[str] = Field(None, max_length=5000)
    is_validated: Optional[bool] = None
    validation_notes: Optional[str] = Field(None, max_length=2000)
    custom_attributes: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = Field(None, max_length=50)


class ActorResponse(ActorBase):
    """Schema for actor responses."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    quality_score: float = Field(..., ge=0.0, le=1.0)
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None
    updated_by: Optional[UUID] = None


class ActorListResponse(BaseModel):
    """Schema for paginated actor list responses."""
    items: List[ActorResponse]
    total: int
    page: int
    per_page: int
    pages: int


class ActorSearchRequest(BaseModel):
    """Schema for actor search requests."""
    query: Optional[str] = Field(None, max_length=255)
    actor_types: Optional[List[str]] = Field(None, max_length=10)
    threat_levels: Optional[List[str]] = Field(None, max_length=10)
    sophistication_levels: Optional[List[str]] = Field(None, max_length=10)
    statuses: Optional[List[str]] = Field(None, max_length=10)
    origin_countries: Optional[List[str]] = Field(None, max_length=50)
    target_sectors: Optional[List[str]] = Field(None, max_length=50)
    motivations: Optional[List[str]] = Field(None, max_length=20)
    min_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    max_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    is_validated: Optional[bool] = None
    tags: Optional[List[str]] = Field(None, max_length=50)
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    updated_after: Optional[datetime] = None
    updated_before: Optional[datetime] = None


# Campaign schemas
class CampaignBase(BaseModel):
    """Base campaign schema."""
    name: str = Field(..., min_length=1, max_length=255)
    aliases: Optional[List[str]] = Field(default=None, max_length=50)
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    status: str = Field(default="active", pattern=r"^(active|ended|dormant|unknown)$")
    actor_id: Optional[UUID] = None
    attribution_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    objectives: Optional[List[str]] = Field(default=None, max_length=50)
    target_sectors: Optional[List[str]] = Field(default=None, max_length=50)
    target_countries: Optional[List[str]] = Field(default=None, max_length=50)
    description: Optional[str] = Field(default=None, max_length=10000)
    summary: Optional[str] = Field(default=None, max_length=500)
    tactics_techniques: Optional[List[str]] = Field(default=None, max_length=100)
    external_ids: Optional[Dict[str, Any]] = None
    references: Optional[List[str]] = Field(default=None, max_length=100)
    analyst_notes: Optional[str] = Field(default=None, max_length=5000)
    custom_attributes: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = Field(default=None, max_length=50)


class CampaignCreate(CampaignBase):
    """Schema for creating campaigns."""
    pass


class CampaignUpdate(BaseModel):
    """Schema for updating campaigns."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    aliases: Optional[List[str]] = Field(None, max_length=50)
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    status: Optional[str] = Field(None, pattern=r"^(active|ended|dormant|unknown)$")
    actor_id: Optional[UUID] = None
    attribution_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    objectives: Optional[List[str]] = Field(None, max_length=50)
    target_sectors: Optional[List[str]] = Field(None, max_length=50)
    target_countries: Optional[List[str]] = Field(None, max_length=50)
    description: Optional[str] = Field(None, max_length=10000)
    summary: Optional[str] = Field(None, max_length=500)
    tactics_techniques: Optional[List[str]] = Field(None, max_length=100)
    external_ids: Optional[Dict[str, Any]] = None
    references: Optional[List[str]] = Field(None, max_length=100)
    analyst_notes: Optional[str] = Field(None, max_length=5000)
    custom_attributes: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = Field(None, max_length=50)


class CampaignResponse(CampaignBase):
    """Schema for campaign responses."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None
    updated_by: Optional[UUID] = None


# Malware family schemas
class MalwareBase(BaseModel):
    """Base malware family schema."""
    name: str = Field(..., min_length=1, max_length=255)
    aliases: Optional[List[str]] = Field(default=None, max_length=50)
    family_type: str = Field(..., max_length=50)
    actor_id: Optional[UUID] = None
    attribution_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    platforms: Optional[List[str]] = Field(default=None, max_length=20)
    capabilities: Optional[List[str]] = Field(default=None, max_length=100)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    status: str = Field(default="active", pattern=r"^(active|dormant|retired|unknown)$")
    description: Optional[str] = Field(default=None, max_length=10000)
    summary: Optional[str] = Field(default=None, max_length=500)
    external_ids: Optional[Dict[str, Any]] = None
    references: Optional[List[str]] = Field(default=None, max_length=100)
    analyst_notes: Optional[str] = Field(default=None, max_length=5000)
    custom_attributes: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = Field(default=None, max_length=50)


class MalwareCreate(MalwareBase):
    """Schema for creating malware families."""
    pass


class MalwareUpdate(BaseModel):
    """Schema for updating malware families."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    aliases: Optional[List[str]] = Field(None, max_length=50)
    family_type: Optional[str] = Field(None, max_length=50)
    actor_id: Optional[UUID] = None
    attribution_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    platforms: Optional[List[str]] = Field(None, max_length=20)
    capabilities: Optional[List[str]] = Field(None, max_length=100)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    status: Optional[str] = Field(None, pattern=r"^(active|dormant|retired|unknown)$")
    description: Optional[str] = Field(None, max_length=10000)
    summary: Optional[str] = Field(None, max_length=500)
    external_ids: Optional[Dict[str, Any]] = None
    references: Optional[List[str]] = Field(None, max_length=100)
    analyst_notes: Optional[str] = Field(None, max_length=5000)
    custom_attributes: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = Field(None, max_length=50)


class MalwareResponse(MalwareBase):
    """Schema for malware family responses."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None
    updated_by: Optional[UUID] = None