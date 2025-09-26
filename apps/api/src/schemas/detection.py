"""
Pydantic schemas for detection API endpoints.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


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
    description: str | None = Field(None, max_length=2000)
    parent_id: UUID | None = None


class CategoryCreate(CategoryBase):
    """Schema for creating categories."""



class CategoryUpdate(BaseModel):
    """Schema for updating categories."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    parent_id: UUID | None = None


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
    description: str | None = Field(None, max_length=500)
    color: str | None = Field(None, max_length=20)


class TagCreate(TagBase):
    """Schema for creating tags."""



class TagUpdate(BaseModel):
    """Schema for updating tags."""

    name: str | None = Field(None, min_length=1, max_length=100)
    description: str | None = Field(None, max_length=500)
    color: str | None = Field(None, max_length=20)


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
    parent_technique_id: str | None = None
    url: str
    platforms: list[str]
    data_sources: list[str]
    created_at: datetime
    updated_at: datetime


# Detection schemas
class DetectionBase(BaseModel):
    """Base detection schema."""

    name: str = Field(..., min_length=1, max_length=500)
    description: str = Field(..., min_length=1, max_length=10000)
    rule_content: str = Field(..., min_length=1)
    rule_format: str = Field(
        ..., pattern=r"^(yara|sigma|yara-l|custom|suricata|snort)$"
    )
    severity_id: UUID
    visibility: str = Field(default="private", pattern=r"^(public|private|community)$")
    performance_impact: str = Field(default="medium", pattern=r"^(low|medium|high)$")
    status: str = Field(
        default="testing", pattern=r"^(active|deprecated|testing|draft)$"
    )
    version: str = Field(default="1.0.0", max_length=50)
    author: str = Field(..., min_length=1, max_length=255)
    source_url: str | None = Field(None, max_length=1000)

    # Structured metadata fields
    platforms: list[str] | None = Field(default=None, max_length=10)
    data_sources: list[str] | None = Field(default=None, max_length=20)
    false_positives: list[str] | None = Field(default=None, max_length=10)


class DetectionCreate(DetectionBase):
    """Schema for creating detections."""

    category_ids: list[UUID] | None = Field(default=None, max_length=10)
    tag_ids: list[UUID] | None = Field(default=None, max_length=20)
    mitre_technique_ids: list[str] | None = Field(default=None, max_length=50)


class DetectionUpdate(BaseModel):
    """Schema for updating detections."""

    name: str | None = Field(None, min_length=1, max_length=500)
    description: str | None = Field(None, min_length=1, max_length=10000)
    rule_content: str | None = Field(None, min_length=1)
    rule_format: str | None = Field(
        None, pattern=r"^(yara|sigma|yara-l|custom|suricata|snort)$"
    )
    severity_id: UUID | None = None
    visibility: str | None = Field(None, pattern=r"^(public|private|community)$")
    performance_impact: str | None = Field(None, pattern=r"^(low|medium|high)$")
    status: str | None = Field(None, pattern=r"^(active|deprecated|testing|draft)$")
    version: str | None = Field(None, max_length=50)
    author: str | None = Field(None, min_length=1, max_length=255)
    source_url: str | None = Field(None, max_length=1000)
    category_ids: list[UUID] | None = Field(None, max_length=10)
    tag_ids: list[UUID] | None = Field(None, max_length=20)
    mitre_technique_ids: list[str] | None = Field(None, max_length=50)

    # Structured metadata fields
    platforms: list[str] | None = Field(None, max_length=10)
    data_sources: list[str] | None = Field(None, max_length=20)
    false_positives: list[str] | None = Field(None, max_length=10)


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
    categories: list[CategoryResponse] = []
    tags: list[TagResponse] = []
    mitre_techniques: list[MitreTechniqueResponse] = []


class DetectionListResponse(BaseModel):
    """Schema for paginated detection list responses."""

    items: list[DetectionResponse]
    total: int
    page: int
    per_page: int
    pages: int


class DetectionSearchRequest(BaseModel):
    """Schema for detection search requests."""

    name: str | None = Field(None, max_length=255)
    description: str | None = Field(None, max_length=255)
    rule_format: str | None = Field(
        None, pattern=r"^(yara|sigma|yara-l|custom|suricata|snort)$"
    )
    category_ids: list[UUID] | None = Field(None, max_length=20)
    tag_ids: list[UUID] | None = Field(None, max_length=50)
    severity_levels: list[int] | None = Field(None, ge=1, le=4, max_length=4)
    mitre_technique_ids: list[str] | None = Field(None, max_length=100)
    author: str | None = Field(None, max_length=255)
    confidence_min: float | None = Field(None, ge=0.0, le=1.0)
    confidence_max: float | None = Field(None, ge=0.0, le=1.0)
    status: str | None = Field(None, pattern=r"^(active|deprecated|testing|draft)$")
    visibility: str | None = Field(None, pattern=r"^(public|private|community)$")
    performance_impact: str | None = Field(None, pattern=r"^(low|medium|high)$")
    created_after: datetime | None = None
    created_before: datetime | None = None
    updated_after: datetime | None = None
    updated_before: datetime | None = None


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
    formats: list[DetectionFormatStatsResponse]
    severities: list[DetectionSeverityStatsResponse]
    avg_confidence_score: float


class BulkDetectionOperation(BaseModel):
    """Schema for bulk detection operations."""

    detection_ids: list[UUID] = Field(..., min_length=1, max_length=100)
    operation: str = Field(
        ..., pattern=r"^(activate|deactivate|deprecate|delete|update_status)$"
    )
    new_status: str | None = Field(
        None, pattern=r"^(active|deprecated|testing|draft)$"
    )


class BulkDetectionOperationResponse(BaseModel):
    """Schema for bulk detection operation responses."""

    operation: str
    total_requested: int
    successful: int
    failed: int
    failed_detection_ids: list[UUID] = []
    error_message: str | None = None


class DetectionValidationRequest(BaseModel):
    """Schema for detection validation requests."""

    rule_content: str = Field(..., min_length=1)
    rule_format: str = Field(
        ..., pattern=r"^(yara|sigma|yara-l|custom|suricata|snort)$"
    )


class DetectionValidationResponse(BaseModel):
    """Schema for detection validation responses."""

    is_valid: bool
    syntax_errors: list[str] = []
    warnings: list[str] = []
    suggestions: list[str] = []
    confidence_score: float | None = Field(None, ge=0.0, le=1.0)


class DetectionConversionRequest(BaseModel):
    """Schema for detection format conversion requests."""

    rule_content: str = Field(..., min_length=1)
    source_format: str = Field(
        ..., pattern=r"^(yara|sigma|yara-l|custom|suricata|snort)$"
    )
    target_format: str = Field(
        ..., pattern=r"^(yara|sigma|yara-l|custom|suricata|snort)$"
    )


class DetectionConversionResponse(BaseModel):
    """Schema for detection format conversion responses."""

    success: bool
    converted_content: str | None = None
    conversion_notes: list[str] = []
    limitations: list[str] = []
    error_message: str | None = None
