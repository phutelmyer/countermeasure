"""
Business logic service for detection management.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from uuid import UUID

from sqlalchemy import select, func, and_, or_, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.exceptions import ValidationError, ResourceNotFoundError
from src.core.logging import get_logger
from src.core.rule_confidence import (
    calculate_rule_confidence_score,
    calculate_rule_content_quality,
    validate_rule_format
)
from src.db.models import (
    Detection, Severity, Category, Tag, MitreTechnique,
    DetectionCategoryMapping, DetectionTagMapping, DetectionMitreMapping
)
from src.schemas.detection import (
    DetectionCreate, DetectionUpdate, DetectionSearchRequest,
    CategoryCreate, CategoryUpdate, TagCreate, TagUpdate,
    BulkDetectionOperation, DetectionValidationRequest, DetectionConversionRequest
)

logger = get_logger(__name__)


class DetectionService:
    """Service for detection management and business logic."""

    @staticmethod
    async def create_detection(
        db: AsyncSession,
        detection_data: DetectionCreate,
        tenant_id: UUID,
        user_id: UUID
    ) -> Detection:
        """
        Create a new detection.

        Args:
            db: Database session
            detection_data: Detection creation data
            tenant_id: Current tenant ID
            user_id: Current user ID

        Returns:
            Detection: Created detection

        Raises:
            ValidationError: If validation fails
        """
        # Validate rule content format
        is_valid, errors = validate_rule_format(detection_data.rule_content, detection_data.rule_format)
        if not is_valid:
            raise ValidationError(f"Detection validation failed: {'; '.join(errors)}")

        # Check for duplicate names within tenant
        existing = await db.execute(
            select(Detection).where(
                and_(
                    Detection.tenant_id == tenant_id,
                    Detection.name == detection_data.name
                )
            )
        )
        if existing.scalar_one_or_none():
            raise ValidationError(f"Detection with name '{detection_data.name}' already exists")

        # Verify severity exists
        severity = await db.get(Severity, detection_data.severity_id)
        if not severity:
            raise ValidationError(f"Severity with ID {detection_data.severity_id} not found")

        # Create the detection
        detection_dict = detection_data.model_dump(exclude={'category_ids', 'tag_ids', 'mitre_technique_ids'})
        detection = Detection(
            **detection_dict,
            tenant_id=tenant_id,
            created_by=user_id,
            updated_by=user_id
        )

        # Calculate initial confidence score
        detection.confidence_score = calculate_rule_content_quality(
            detection_data.rule_content,
            detection_data.rule_format
        )

        db.add(detection)
        await db.flush()  # Get the detection ID

        # Add category mappings
        if detection_data.category_ids:
            await DetectionService._add_category_mappings(db, detection.id, detection_data.category_ids, tenant_id)

        # Add tag mappings
        if detection_data.tag_ids:
            await DetectionService._add_tag_mappings(db, detection.id, detection_data.tag_ids, tenant_id)

        # Add MITRE technique mappings
        if detection_data.mitre_technique_ids:
            await DetectionService._add_mitre_mappings(db, detection.id, detection_data.mitre_technique_ids)

        await db.commit()

        # Reload with relationships
        return await DetectionService.get_detection(db, detection.id, tenant_id)

    @staticmethod
    async def get_detection(
        db: AsyncSession,
        detection_id: UUID,
        tenant_id: UUID
    ) -> Detection:
        """
        Get detection by ID.

        Args:
            db: Database session
            detection_id: Detection ID
            tenant_id: Current tenant ID

        Returns:
            Detection: The detection

        Raises:
            ResourceNotFoundError: If detection not found
        """
        result = await db.execute(
            select(Detection)
            .options(
                selectinload(Detection.severity),
                selectinload(Detection.category_mappings).selectinload(DetectionCategoryMapping.category),
                selectinload(Detection.tag_mappings).selectinload(DetectionTagMapping.tag),
                selectinload(Detection.mitre_mappings).selectinload(DetectionMitreMapping.technique)
            )
            .where(
                and_(
                    Detection.id == detection_id,
                    Detection.tenant_id == tenant_id
                )
            )
        )
        detection = result.scalar_one_or_none()
        if not detection:
            raise ResourceNotFoundError(f"Detection with ID {detection_id} not found")

        return detection

    @staticmethod
    async def update_detection(
        db: AsyncSession,
        detection_id: UUID,
        detection_data: DetectionUpdate,
        tenant_id: UUID,
        user_id: UUID
    ) -> Detection:
        """
        Update detection.

        Args:
            db: Database session
            detection_id: Detection ID
            detection_data: Detection update data
            tenant_id: Current tenant ID
            user_id: Current user ID

        Returns:
            Detection: Updated detection

        Raises:
            ResourceNotFoundError: If detection not found
            ValidationError: If validation fails
        """
        detection = await DetectionService.get_detection(db, detection_id, tenant_id)

        # Validate rule content if provided
        if detection_data.rule_content and detection_data.rule_format:
            is_valid, errors = validate_rule_format(detection_data.rule_content, detection_data.rule_format)
            if not is_valid:
                raise ValidationError(f"Detection validation failed: {'; '.join(errors)}")

        # Update basic fields
        update_data = detection_data.model_dump(exclude_unset=True, exclude={'category_ids', 'tag_ids', 'mitre_technique_ids'})
        for field, value in update_data.items():
            setattr(detection, field, value)

        detection.updated_by = user_id

        # Recalculate confidence score if content changed
        if detection_data.rule_content or detection_data.rule_format:
            detection.confidence_score = calculate_rule_content_quality(
                detection.rule_content,
                detection.rule_format
            )

        # Update category mappings
        if detection_data.category_ids is not None:
            await DetectionService._update_category_mappings(db, detection_id, detection_data.category_ids, tenant_id)

        # Update tag mappings
        if detection_data.tag_ids is not None:
            await DetectionService._update_tag_mappings(db, detection_id, detection_data.tag_ids, tenant_id)

        # Update MITRE technique mappings
        if detection_data.mitre_technique_ids is not None:
            await DetectionService._update_mitre_mappings(db, detection_id, detection_data.mitre_technique_ids)

        await db.commit()

        # Reload with relationships
        return await DetectionService.get_detection(db, detection_id, tenant_id)

    @staticmethod
    async def delete_detection(
        db: AsyncSession,
        detection_id: UUID,
        tenant_id: UUID
    ) -> None:
        """
        Delete detection.

        Args:
            db: Database session
            detection_id: Detection ID
            tenant_id: Current tenant ID

        Raises:
            ResourceNotFoundError: If detection not found
        """
        detection = await DetectionService.get_detection(db, detection_id, tenant_id)
        await db.delete(detection)
        await db.commit()

    @staticmethod
    async def search_detections(
        db: AsyncSession,
        search_request: DetectionSearchRequest,
        tenant_id: UUID,
        page: int = 1,
        per_page: int = 50
    ) -> Tuple[List[Detection], int]:
        """
        Search detections with advanced filtering.

        Args:
            db: Database session
            search_request: Search criteria
            tenant_id: Current tenant ID
            page: Page number
            per_page: Items per page

        Returns:
            Tuple[List[Detection], int]: (detections, total_count)
        """
        query = select(Detection).where(Detection.tenant_id == tenant_id)

        # Apply filters
        if search_request.name:
            query = query.where(Detection.name.ilike(f"%{search_request.name}%"))

        if search_request.description:
            query = query.where(Detection.description.ilike(f"%{search_request.description}%"))

        if search_request.rule_format:
            query = query.where(Detection.rule_format == search_request.rule_format)

        if search_request.author:
            query = query.where(Detection.author.ilike(f"%{search_request.author}%"))

        if search_request.status:
            query = query.where(Detection.status == search_request.status)

        if search_request.visibility:
            query = query.where(Detection.visibility == search_request.visibility)

        if search_request.performance_impact:
            query = query.where(Detection.performance_impact == search_request.performance_impact)

        if search_request.confidence_min is not None:
            query = query.where(Detection.confidence_score >= search_request.confidence_min)

        if search_request.confidence_max is not None:
            query = query.where(Detection.confidence_score <= search_request.confidence_max)

        if search_request.created_after:
            query = query.where(Detection.created_at >= search_request.created_after)

        if search_request.created_before:
            query = query.where(Detection.created_at <= search_request.created_before)

        # Add relationships
        query = query.options(
            selectinload(Detection.severity),
            selectinload(Detection.category_mappings).selectinload(DetectionCategoryMapping.category),
            selectinload(Detection.tag_mappings).selectinload(DetectionTagMapping.tag),
            selectinload(Detection.mitre_mappings).selectinload(DetectionMitreMapping.technique)
        )

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)

        # Execute query
        result = await db.execute(query)
        detections = result.scalars().all()

        return list(detections), total

    @staticmethod
    async def validate_detection_content(
        rule_content: str,
        rule_format: str
    ) -> Dict[str, Any]:
        """
        Validate detection content and return validation results.

        Args:
            rule_content: Detection content to validate
            rule_format: Detection format

        Returns:
            Dict[str, Any]: Validation results
        """
        is_valid, errors = validate_rule_format(rule_content, rule_format)
        confidence_score = calculate_rule_content_quality(rule_content, rule_format)

        return {
            "is_valid": is_valid,
            "syntax_errors": errors,
            "warnings": [],
            "suggestions": [],
            "confidence_score": confidence_score
        }

    # Category management methods
    @staticmethod
    async def create_category(
        db: AsyncSession,
        category_data: CategoryCreate,
        tenant_id: UUID
    ) -> Category:
        """Create a new category."""
        # Build hierarchical path
        path = f"/{category_data.name.lower().replace(' ', '-')}"
        level = 0

        if category_data.parent_id:
            parent = await db.get(Category, category_data.parent_id)
            if not parent or parent.tenant_id != tenant_id:
                raise ValidationError("Invalid parent category")
            path = f"{parent.path}/{category_data.name.lower().replace(' ', '-')}"
            level = parent.level + 1

        category = Category(
            **category_data.model_dump(),
            tenant_id=tenant_id,
            level=level,
            path=path
        )

        db.add(category)
        await db.commit()
        return category

    @staticmethod
    async def create_tag(
        db: AsyncSession,
        tag_data: TagCreate,
        tenant_id: UUID
    ) -> Tag:
        """Create a new tag."""
        # Check for duplicate names within tenant
        existing = await db.execute(
            select(Tag).where(
                and_(
                    Tag.tenant_id == tenant_id,
                    Tag.name == tag_data.name
                )
            )
        )
        if existing.scalar_one_or_none():
            raise ValidationError(f"Tag with name '{tag_data.name}' already exists")

        tag = Tag(
            **tag_data.model_dump(),
            tenant_id=tenant_id
        )

        db.add(tag)
        await db.commit()
        return tag

    # Helper methods for relationship management
    @staticmethod
    async def _add_category_mappings(
        db: AsyncSession,
        detection_id: UUID,
        category_ids: List[UUID],
        tenant_id: UUID
    ) -> None:
        """Add category mappings for a detection."""
        for category_id in category_ids:
            # Verify category belongs to tenant
            category = await db.get(Category, category_id)
            if not category or category.tenant_id != tenant_id:
                continue

            mapping = DetectionCategoryMapping(detection_id=detection_id, category_id=category_id)
            db.add(mapping)

    @staticmethod
    async def _add_tag_mappings(
        db: AsyncSession,
        detection_id: UUID,
        tag_ids: List[UUID],
        tenant_id: UUID
    ) -> None:
        """Add tag mappings for a detection."""
        for tag_id in tag_ids:
            # Verify tag belongs to tenant
            tag = await db.get(Tag, tag_id)
            if not tag or tag.tenant_id != tenant_id:
                continue

            mapping = DetectionTagMapping(detection_id=detection_id, tag_id=tag_id)
            db.add(mapping)

    @staticmethod
    async def _add_mitre_mappings(
        db: AsyncSession,
        detection_id: UUID,
        technique_ids: List[str]
    ) -> None:
        """Add MITRE technique mappings for a detection."""
        for technique_id in technique_ids:
            # Verify technique exists
            technique = await db.get(MitreTechnique, technique_id)
            if not technique:
                continue

            mapping = DetectionMitreMapping(detection_id=detection_id, technique_id=technique_id)
            db.add(mapping)

    @staticmethod
    async def _update_category_mappings(
        db: AsyncSession,
        detection_id: UUID,
        category_ids: List[UUID],
        tenant_id: UUID
    ) -> None:
        """Update category mappings for a detection."""
        # Delete existing mappings
        await db.execute(
            delete(DetectionCategoryMapping).where(DetectionCategoryMapping.detection_id == detection_id)
        )
        # Add new mappings
        if category_ids:
            await DetectionService._add_category_mappings(db, detection_id, category_ids, tenant_id)

    @staticmethod
    async def _update_tag_mappings(
        db: AsyncSession,
        detection_id: UUID,
        tag_ids: List[UUID],
        tenant_id: UUID
    ) -> None:
        """Update tag mappings for a detection."""
        # Delete existing mappings
        await db.execute(
            delete(DetectionTagMapping).where(DetectionTagMapping.detection_id == detection_id)
        )
        # Add new mappings
        if tag_ids:
            await DetectionService._add_tag_mappings(db, detection_id, tag_ids, tenant_id)

    @staticmethod
    async def _update_mitre_mappings(
        db: AsyncSession,
        detection_id: UUID,
        technique_ids: List[str]
    ) -> None:
        """Update MITRE technique mappings for a detection."""
        # Delete existing mappings
        await db.execute(
            delete(DetectionMitreMapping).where(DetectionMitreMapping.detection_id == detection_id)
        )
        # Add new mappings
        if technique_ids:
            await DetectionService._add_mitre_mappings(db, detection_id, technique_ids)