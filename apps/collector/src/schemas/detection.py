"""
Detection schemas for collector.
"""

from uuid import UUID

from pydantic import BaseModel, Field


class DetectionCreate(BaseModel):
    """Schema for creating detection rules."""

    name: str = Field(..., description="Detection rule name")
    description: str = Field(..., description="Detection rule description")
    rule_content: str = Field(..., description="Detection rule content")
    rule_format: str = Field(
        ..., description="Detection rule format (sigma, yara, snort, etc.)"
    )
    severity_id: UUID = Field(..., description="Severity level UUID")
    visibility: str = Field(default="community", description="Visibility level")
    performance_impact: str = Field(default="low", description="Performance impact")
    status: str = Field(default="testing", description="Rule status")
    version: str = Field(default="1.0.0", description="Rule version")
    author: str = Field(..., description="Rule author")
    source_url: str | None = Field(None, description="Source URL")
    category_ids: list[UUID] | None = Field(None, description="Category UUIDs")
    tag_ids: list[UUID] | None = Field(None, description="Tag UUIDs")
    mitre_technique_ids: list[str] | None = Field(
        None, description="MITRE technique IDs"
    )
    confidence_score: float | None = Field(None, description="Confidence score")

    # Structured metadata fields
    platforms: list[str] | None = Field(None, description="Target platforms")
    data_sources: list[str] | None = Field(None, description="Required data sources")
    false_positives: list[str] | None = Field(
        None, description="Known false positive scenarios"
    )

    class Config:
        from_attributes = True
