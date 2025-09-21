"""
Pydantic schemas for detection API endpoints.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


# Severity schemas
class SeverityBase(BaseModel):
    """Base severity schema."""
    name: str = Field(..., min_length=1, max_length=50)
    level: int = Field(..., ge=1, le=4)
    color: str = Field(..., min_length=3, max_length=20)
    description: str = Field(..., min_length=1, max_length=255)


class SeverityResponse(SeverityBase):
    """Schema for severity responses."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


# Category schemas
class CategoryBase(BaseModel):
    """Base category schema."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    parent_id: Optional[UUID] = None


class CategoryCreate(CategoryBase):
    """Schema for creating categories."""
    pass


class CategoryUpdate(BaseModel):
    """Schema for updating categories."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    parent_id: Optional[UUID] = None


class CategoryResponse(CategoryBase):
    """Schema for category responses."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    level: int
    path: str
    created_at: datetime
    updated_at: datetime


# Tag schemas
class TagBase(BaseModel):
    """Base tag schema."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    color: Optional[str] = Field(None, max_length=20)


class TagCreate(TagBase):
    """Schema for creating tags."""
    pass


class TagUpdate(BaseModel):
    """Schema for updating tags."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    color: Optional[str] = Field(None, max_length=20)


class TagResponse(TagBase):
    """Schema for tag responses."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    created_at: datetime
    updated_at: datetime


# MITRE schemas
class MitreTacticResponse(BaseModel):
    """Schema for MITRE tactic responses."""
    model_config = ConfigDict(from_attributes=True)

    tactic_id: str
    name: str
    description: str
    url: str
    created_at: datetime
    updated_at: datetime


class MitreTechniqueResponse(BaseModel):
    """Schema for MITRE technique responses."""
    model_config = ConfigDict(from_attributes=True)

    technique_id: str
    name: str
    description: str
    tactic_id: str
    parent_technique_id: Optional[str] = None
    url: str
    platforms: List[str]
    data_sources: List[str]
    created_at: datetime
    updated_at: datetime


# Detection schemas
class DetectionBase(BaseModel):
    """Base detection schema."""
    name: str = Field(..., min_length=1, max_length=500)
    description: str = Field(..., min_length=1, max_length=10000)
    rule_content: str = Field(..., min_length=1)
    rule_format: str = Field(..., pattern=r"^(yara|sigma|yara-l|custom|suricata|snort)$")
    severity_id: UUID
    visibility: str = Field(default="private", pattern=r"^(public|private|community)$")
    performance_impact: str = Field(default="medium", pattern=r"^(low|medium|high)$")
    status: str = Field(default="testing", pattern=r"^(active|deprecated|testing|draft)$")
    version: str = Field(default="1.0.0", max_length=50)
    author: str = Field(..., min_length=1, max_length=255)
    source_url: Optional[str] = Field(None, max_length=1000)

    # Structured metadata fields
    platforms: Optional[List[str]] = Field(default=None, max_length=10)
    data_sources: Optional[List[str]] = Field(default=None, max_length=20)
    false_positives: Optional[List[str]] = Field(default=None, max_length=10)


class DetectionCreate(DetectionBase):
    """Schema for creating detections."""
    category_ids: Optional[List[UUID]] = Field(default=None, max_length=10)
    tag_ids: Optional[List[UUID]] = Field(default=None, max_length=20)
    mitre_technique_ids: Optional[List[str]] = Field(default=None, max_length=50)


class DetectionUpdate(BaseModel):
    """Schema for updating detections."""
    name: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = Field(None, min_length=1, max_length=10000)
    rule_content: Optional[str] = Field(None, min_length=1)
    rule_format: Optional[str] = Field(None, pattern=r"^(yara|sigma|yara-l|custom|suricata|snort)$")
    severity_id: Optional[UUID] = None
    visibility: Optional[str] = Field(None, pattern=r"^(public|private|community)$")
    performance_impact: Optional[str] = Field(None, pattern=r"^(low|medium|high)$")
    status: Optional[str] = Field(None, pattern=r"^(active|deprecated|testing|draft)$")
    version: Optional[str] = Field(None, max_length=50)
    author: Optional[str] = Field(None, min_length=1, max_length=255)
    source_url: Optional[str] = Field(None, max_length=1000)
    category_ids: Optional[List[UUID]] = Field(None, max_length=10)
    tag_ids: Optional[List[UUID]] = Field(None, max_length=20)
    mitre_technique_ids: Optional[List[str]] = Field(None, max_length=50)

    # Structured metadata fields
    platforms: Optional[List[str]] = Field(None, max_length=10)
    data_sources: Optional[List[str]] = Field(None, max_length=20)
    false_positives: Optional[List[str]] = Field(None, max_length=10)


class DetectionResponse(DetectionBase):
    """Schema for detection responses."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    created_by: UUID
    updated_by: UUID
    created_at: datetime
    updated_at: datetime

    # Related data
    severity: SeverityResponse
    categories: List[CategoryResponse] = []
    tags: List[TagResponse] = []
    mitre_techniques: List[MitreTechniqueResponse] = []


class DetectionListResponse(BaseModel):
    """Schema for paginated detection list responses."""
    items: List[DetectionResponse]
    total: int
    page: int
    per_page: int
    pages: int


class DetectionSearchRequest(BaseModel):
    """Schema for detection search requests."""
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=255)
    rule_format: Optional[str] = Field(None, pattern=r"^(yara|sigma|yara-l|custom|suricata|snort)$")
    category_ids: Optional[List[UUID]] = Field(None, max_length=20)
    tag_ids: Optional[List[UUID]] = Field(None, max_length=50)
    severity_levels: Optional[List[int]] = Field(None, ge=1, le=4, max_length=4)
    mitre_technique_ids: Optional[List[str]] = Field(None, max_length=100)
    author: Optional[str] = Field(None, max_length=255)
    confidence_min: Optional[float] = Field(None, ge=0.0, le=1.0)
    confidence_max: Optional[float] = Field(None, ge=0.0, le=1.0)
    status: Optional[str] = Field(None, pattern=r"^(active|deprecated|testing|draft)$")
    visibility: Optional[str] = Field(None, pattern=r"^(public|private|community)$")
    performance_impact: Optional[str] = Field(None, pattern=r"^(low|medium|high)$")
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    updated_after: Optional[datetime] = None
    updated_before: Optional[datetime] = None


class DetectionFormatStatsResponse(BaseModel):
    """Schema for detection format statistics."""
    format: str
    count: int
    percentage: float


class DetectionSeverityStatsResponse(BaseModel):
    """Schema for detection severity statistics."""
    severity_name: str
    severity_level: int
    count: int
    percentage: float


class DetectionStatsResponse(BaseModel):
    """Schema for detection statistics."""
    total_detections: int
    active_detections: int
    deprecated_detections: int
    testing_detections: int
    draft_detections: int
    formats: List[DetectionFormatStatsResponse]
    severities: List[DetectionSeverityStatsResponse]
    avg_confidence_score: float


class BulkDetectionOperation(BaseModel):
    """Schema for bulk detection operations."""
    detection_ids: List[UUID] = Field(..., min_length=1, max_length=100)
    operation: str = Field(..., pattern=r"^(activate|deactivate|deprecate|delete|update_status)$")
    new_status: Optional[str] = Field(None, pattern=r"^(active|deprecated|testing|draft)$")


class BulkDetectionOperationResponse(BaseModel):
    """Schema for bulk detection operation responses."""
    operation: str
    total_requested: int
    successful: int
    failed: int
    failed_detection_ids: List[UUID] = []
    error_message: Optional[str] = None


class DetectionValidationRequest(BaseModel):
    """Schema for detection validation requests."""
    rule_content: str = Field(..., min_length=1)
    rule_format: str = Field(..., pattern=r"^(yara|sigma|yara-l|custom|suricata|snort)$")


class DetectionValidationResponse(BaseModel):
    """Schema for detection validation responses."""
    is_valid: bool
    syntax_errors: List[str] = []
    warnings: List[str] = []
    suggestions: List[str] = []
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)


class DetectionConversionRequest(BaseModel):
    """Schema for detection format conversion requests."""
    rule_content: str = Field(..., min_length=1)
    source_format: str = Field(..., pattern=r"^(yara|sigma|yara-l|custom|suricata|snort)$")
    target_format: str = Field(..., pattern=r"^(yara|sigma|yara-l|custom|suricata|snort)$")


class DetectionConversionResponse(BaseModel):
    """Schema for detection format conversion responses."""
    success: bool
    converted_content: Optional[str] = None
    conversion_notes: List[str] = []
    limitations: List[str] = []
    error_message: Optional[str] = None