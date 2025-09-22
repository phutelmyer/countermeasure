"""
Pydantic schemas for MITRE ATT&CK framework data.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
import uuid


# MITRE Tactic Schemas
class MitreTacticBase(BaseModel):
    """Base schema for MITRE tactics."""
    tactic_id: str = Field(..., description="MITRE tactic ID (e.g., TA0001)")
    name: str = Field(..., description="Tactic name")
    description: str = Field(..., description="Tactic description")
    url: Optional[str] = Field(None, description="MITRE ATT&CK URL")
    stix_uuid: Optional[str] = Field(None, description="STIX UUID identifier")


class MitreTacticCreate(MitreTacticBase):
    """Schema for creating MITRE tactics."""
    pass


class MitreTacticUpdate(BaseModel):
    """Schema for updating MITRE tactics."""
    name: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    stix_uuid: Optional[str] = None


class MitreTacticResponse(MitreTacticBase):
    """Schema for MITRE tactic responses."""
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# MITRE Technique Schemas
class MitreTechniqueBase(BaseModel):
    """Base schema for MITRE techniques."""
    technique_id: str = Field(..., description="MITRE technique ID (e.g., T1055)")
    name: str = Field(..., description="Technique name")
    description: str = Field(..., description="Technique description")
    tactic_id: Optional[str] = Field(None, description="Primary tactic ID")
    parent_technique_id: Optional[str] = Field(None, description="Parent technique for sub-techniques")
    url: Optional[str] = Field(None, description="MITRE ATT&CK URL")
    stix_uuid: Optional[str] = Field(None, description="STIX UUID identifier")
    platforms: List[str] = Field(default_factory=list, description="Applicable platforms")
    data_sources: List[str] = Field(default_factory=list, description="Associated data sources")


class MitreTechniqueCreate(MitreTechniqueBase):
    """Schema for creating MITRE techniques."""
    pass


class MitreTechniqueUpdate(BaseModel):
    """Schema for updating MITRE techniques."""
    name: Optional[str] = None
    description: Optional[str] = None
    tactic_id: Optional[str] = None
    parent_technique_id: Optional[str] = None
    url: Optional[str] = None
    stix_uuid: Optional[str] = None
    platforms: Optional[List[str]] = None
    data_sources: Optional[List[str]] = None


class MitreTechniqueResponse(MitreTechniqueBase):
    """Schema for MITRE technique responses."""
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# MITRE Actor Group Schemas
class MitreActorGroupBase(BaseModel):
    """Base schema for MITRE actor groups."""
    name: str = Field(..., description="Actor group name")
    description: str = Field(..., description="Actor group description")
    aliases: List[str] = Field(default_factory=list, description="Known aliases")
    mitre_attack_id: str = Field(..., description="MITRE ATT&CK group ID (e.g., G0016)")
    stix_uuid: Optional[str] = Field(None, description="STIX UUID identifier")
    references: List[str] = Field(default_factory=list, description="Reference URLs")


class MitreActorGroupCreate(MitreActorGroupBase):
    """Schema for creating MITRE actor groups."""
    pass


class MitreActorGroupUpdate(BaseModel):
    """Schema for updating MITRE actor groups."""
    name: Optional[str] = None
    description: Optional[str] = None
    aliases: Optional[List[str]] = None
    stix_uuid: Optional[str] = None
    references: Optional[List[str]] = None


class MitreActorGroupResponse(BaseModel):
    """Schema for MITRE actor group responses."""
    id: uuid.UUID
    name: str
    description: str
    aliases: List[str]
    mitre_attack_id: Optional[str]
    stix_uuid: Optional[str]
    references: List[str]
    tenant_id: uuid.UUID
    created_by_id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Actor-Technique Mapping Schemas
class ActorTechniqueMappingBase(BaseModel):
    """Base schema for actor-technique mappings."""
    actor_id: uuid.UUID = Field(..., description="Actor UUID")
    technique_id: str = Field(..., description="MITRE technique ID")
    confidence_level: str = Field("suspected", description="Confidence level: confirmed, likely, suspected")
    first_observed: Optional[datetime] = Field(None, description="First observed date")
    last_observed: Optional[datetime] = Field(None, description="Last observed date")


class ActorTechniqueMappingCreate(ActorTechniqueMappingBase):
    """Schema for creating actor-technique mappings."""
    pass


class ActorTechniqueMappingUpdate(BaseModel):
    """Schema for updating actor-technique mappings."""
    confidence_level: Optional[str] = None
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None


class ActorTechniqueMappingResponse(ActorTechniqueMappingBase):
    """Schema for actor-technique mapping responses."""
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Bulk Operation Schemas
class BulkOperationResponse(BaseModel):
    """Schema for bulk operation responses."""
    message: str = Field(..., description="Operation summary message")
    created: int = Field(..., description="Number of items created")
    updated: int = Field(..., description="Number of items updated")
    failed: int = Field(0, description="Number of items that failed")
    errors: List[str] = Field(default_factory=list, description="Error messages")


# Collection Summary Schemas
class MitreCollectionSummary(BaseModel):
    """Schema for MITRE collection summary."""
    tactics_count: int = Field(..., description="Number of tactics")
    techniques_count: int = Field(..., description="Number of techniques")
    groups_count: int = Field(..., description="Number of groups")
    last_updated: Optional[datetime] = Field(None, description="Last collection timestamp")


class MitreFrameworkOverview(BaseModel):
    """Schema for MITRE framework overview."""
    summary: MitreCollectionSummary
    recent_tactics: List[MitreTacticResponse] = Field(description="Recently updated tactics")
    recent_techniques: List[MitreTechniqueResponse] = Field(description="Recently updated techniques")
    recent_groups: List[MitreActorGroupResponse] = Field(description="Recently updated groups")