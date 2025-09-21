"""
Detection schemas for collector.
"""

from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class DetectionCreate(BaseModel):
    """Schema for creating detection rules."""

    name: str = Field(..., description="Detection rule name")
    description: str = Field(..., description="Detection rule description")
    rule_content: str = Field(..., description="Detection rule content")
    rule_format: str = Field(..., description="Detection rule format (sigma, yara, snort, etc.)")
    severity_id: UUID = Field(..., description="Severity level UUID")
    visibility: str = Field(default="community", description="Visibility level")
    performance_impact: str = Field(default="low", description="Performance impact")
    status: str = Field(default="testing", description="Rule status")
    version: str = Field(default="1.0.0", description="Rule version")
    author: str = Field(..., description="Rule author")
    source_url: Optional[str] = Field(None, description="Source URL")
    category_ids: Optional[List[UUID]] = Field(None, description="Category UUIDs")
    tag_ids: Optional[List[UUID]] = Field(None, description="Tag UUIDs")
    mitre_technique_ids: Optional[List[str]] = Field(None, description="MITRE technique IDs")
    confidence_score: Optional[float] = Field(None, description="Confidence score")

    # Structured metadata fields
    platforms: Optional[List[str]] = Field(None, description="Target platforms")
    data_sources: Optional[List[str]] = Field(None, description="Required data sources")
    false_positives: Optional[List[str]] = Field(None, description="Known false positive scenarios")

    class Config:
        from_attributes = True