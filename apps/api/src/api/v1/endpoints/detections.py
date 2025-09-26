"""
Detection API endpoints for CRUD operations and advanced features.
"""

import math
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.dependencies.auth import get_current_user
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.core.logging import get_logger
from src.db.models import User
from src.db.session import get_db
from src.schemas.detection import (
    BulkDetectionOperation,
    BulkDetectionOperationResponse,
    CategoryCreate,
    CategoryResponse,
    DetectionCreate,
    DetectionListResponse,
    DetectionResponse,
    DetectionSearchRequest,
    DetectionUpdate,
    DetectionValidationRequest,
    DetectionValidationResponse,
    MitreTacticResponse,
    MitreTechniqueResponse,
    SeverityResponse,
    TagCreate,
    TagResponse,
)
from src.services.detection_service import DetectionService


logger = get_logger(__name__)
router = APIRouter()


# Detection CRUD endpoints
@router.post("/", response_model=DetectionResponse, status_code=201)
async def create_detection(
    request: Request,
    detection_data: DetectionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DetectionResponse:
    """
    Create a new detection.

    Args:
        request: FastAPI request
        detection_data: Detection creation data
        db: Database session
        current_user: Current authenticated user

    Returns:
        DetectionResponse: Created detection

    Raises:
        HTTPException: 400 if validation fails, 403 if unauthorized
    """
    if not current_user.has_permission("write:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to create detections"
        )

    try:
        detection = await DetectionService.create_detection(
            db=db,
            detection_data=detection_data,
            tenant_id=current_user.tenant_id,
            user_id=current_user.id,
        )
        return DetectionResponse.model_validate(detection)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to create detection: {e!s}"
        )


@router.get("/{detection_id}", response_model=DetectionResponse)
async def get_detection(
    detection_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DetectionResponse:
    """
    Get detection by ID.

    Args:
        detection_id: Detection ID
        db: Database session
        current_user: Current authenticated user

    Returns:
        DetectionResponse: The detection

    Raises:
        HTTPException: 404 if detection not found, 403 if unauthorized
    """
    if not current_user.has_permission("read:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to read detections"
        )

    try:
        detection = await DetectionService.get_detection(
            db=db, detection_id=detection_id, tenant_id=current_user.tenant_id
        )
        return DetectionResponse.model_validate(detection)
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/{detection_id}", response_model=DetectionResponse)
async def update_detection(
    detection_id: UUID,
    detection_data: DetectionUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DetectionResponse:
    """
    Update detection.

    Args:
        detection_id: Detection ID
        detection_data: Detection update data
        db: Database session
        current_user: Current authenticated user

    Returns:
        DetectionResponse: Updated detection

    Raises:
        HTTPException: 400 if validation fails, 404 if not found, 403 if unauthorized
    """
    if not current_user.has_permission("write:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to update detections"
        )

    try:
        detection = await DetectionService.update_detection(
            db=db,
            detection_id=detection_id,
            detection_data=detection_data,
            tenant_id=current_user.tenant_id,
            user_id=current_user.id,
        )
        return DetectionResponse.model_validate(detection)
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{detection_id}", status_code=204)
async def delete_detection(
    detection_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """
    Delete detection.

    Args:
        detection_id: Detection ID
        db: Database session
        current_user: Current authenticated user

    Raises:
        HTTPException: 404 if detection not found, 403 if unauthorized
    """
    if not current_user.has_permission("write:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to delete detections"
        )

    try:
        await DetectionService.delete_detection(
            db=db, detection_id=detection_id, tenant_id=current_user.tenant_id
        )
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/", response_model=DetectionListResponse)
async def list_detections(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    name: str | None = Query(None, description="Filter by detection name"),
    description: str | None = Query(
        None, description="Filter by detection description"
    ),
    rule_format: str | None = Query(
        None, description="Filter by rule format (yara, sigma, etc.)"
    ),
    category_ids: list[UUID] | None = Query(
        None, description="Filter by category IDs"
    ),
    tag_ids: list[UUID] | None = Query(None, description="Filter by tag IDs"),
    severity_levels: list[int] | None = Query(
        None, description="Filter by severity levels (1-4)"
    ),
    mitre_technique_ids: list[str] | None = Query(
        None, description="Filter by MITRE technique IDs"
    ),
    author: str | None = Query(None, description="Filter by author"),
    confidence_min: float | None = Query(
        None, ge=0.0, le=1.0, description="Minimum confidence score"
    ),
    confidence_max: float | None = Query(
        None, ge=0.0, le=1.0, description="Maximum confidence score"
    ),
    status: str | None = Query(
        None, description="Filter by status (active, deprecated, testing, draft)"
    ),
    visibility: str | None = Query(
        None, description="Filter by visibility (public, private, community)"
    ),
    performance_impact: str | None = Query(
        None, description="Filter by performance impact (low, medium, high)"
    ),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DetectionListResponse:
    """
    List detections with pagination and filtering.

    Args:
        page: Page number
        per_page: Items per page
        name: Filter by detection name
        description: Filter by detection description
        rule_format: Filter by rule format
        category_ids: Filter by category IDs
        tag_ids: Filter by tag IDs
        severity_levels: Filter by severity levels
        mitre_technique_ids: Filter by MITRE technique IDs
        author: Filter by author
        confidence_min: Minimum confidence score
        confidence_max: Maximum confidence score
        status: Filter by status
        visibility: Filter by visibility
        performance_impact: Filter by performance impact
        db: Database session
        current_user: Current authenticated user

    Returns:
        DetectionListResponse: Paginated detections

    Raises:
        HTTPException: 403 if unauthorized
    """
    if not current_user.has_permission("read:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to read detections"
        )

    # Create search request from query parameters
    search_request = DetectionSearchRequest(
        name=name,
        description=description,
        rule_format=rule_format,
        category_ids=category_ids,
        tag_ids=tag_ids,
        severity_levels=severity_levels,
        mitre_technique_ids=mitre_technique_ids,
        author=author,
        confidence_min=confidence_min,
        confidence_max=confidence_max,
        status=status,
        visibility=visibility,
        performance_impact=performance_impact,
    )

    detections, total = await DetectionService.search_detections(
        db=db,
        search_request=search_request,
        tenant_id=current_user.tenant_id,
        page=page,
        per_page=per_page,
    )

    return DetectionListResponse(
        items=[DetectionResponse.model_validate(detection) for detection in detections],
        total=total,
        page=page,
        per_page=per_page,
        pages=math.ceil(total / per_page),
    )


@router.post("/search", response_model=DetectionListResponse)
async def search_detections(
    search_request: DetectionSearchRequest,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DetectionListResponse:
    """
    Search detections with advanced filtering.

    Args:
        search_request: Search criteria
        page: Page number
        per_page: Items per page
        db: Database session
        current_user: Current authenticated user

    Returns:
        DetectionListResponse: Filtered detections

    Raises:
        HTTPException: 403 if unauthorized
    """
    if not current_user.has_permission("read:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to read detections"
        )

    detections, total = await DetectionService.search_detections(
        db=db,
        search_request=search_request,
        tenant_id=current_user.tenant_id,
        page=page,
        per_page=per_page,
    )

    return DetectionListResponse(
        items=[DetectionResponse.model_validate(detection) for detection in detections],
        total=total,
        page=page,
        per_page=per_page,
        pages=math.ceil(total / per_page),
    )


@router.post("/validate", response_model=DetectionValidationResponse)
async def validate_detection_content(
    validation_request: DetectionValidationRequest,
    current_user: User = Depends(get_current_user),
) -> DetectionValidationResponse:
    """
    Validate detection content for syntax and quality.

    Args:
        validation_request: Detection validation request
        current_user: Current authenticated user

    Returns:
        DetectionValidationResponse: Validation results

    Raises:
        HTTPException: 403 if unauthorized
    """
    if not current_user.has_permission("read:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to validate detections"
        )

    validation_result = await DetectionService.validate_detection_content(
        rule_content=validation_request.rule_content,
        rule_format=validation_request.rule_format,
    )

    return DetectionValidationResponse(**validation_result)


# Category management endpoints
@router.post("/categories/", response_model=CategoryResponse, status_code=201)
async def create_category(
    category_data: CategoryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CategoryResponse:
    """Create a new detection category."""
    if not current_user.has_permission("write:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to create categories"
        )

    try:
        category = await DetectionService.create_category(
            db=db, category_data=category_data, tenant_id=current_user.tenant_id
        )
        return CategoryResponse.model_validate(category)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/categories/", response_model=list[CategoryResponse])
async def list_categories(
    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[CategoryResponse]:
    """List all detection categories."""
    if not current_user.has_permission("read:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to read categories"
        )

    from sqlalchemy import select

    from src.db.models import Category

    result = await db.execute(
        select(Category)
        .where(Category.tenant_id == current_user.tenant_id)
        .order_by(Category.path)
    )
    categories = result.scalars().all()

    return [CategoryResponse.model_validate(category) for category in categories]


# Tag management endpoints
@router.post("/tags/", response_model=TagResponse, status_code=201)
async def create_tag(
    tag_data: TagCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TagResponse:
    """Create a new detection tag."""
    if not current_user.has_permission("write:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to create tags"
        )

    try:
        tag = await DetectionService.create_tag(
            db=db, tag_data=tag_data, tenant_id=current_user.tenant_id
        )
        return TagResponse.model_validate(tag)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/tags/", response_model=list[TagResponse])
async def list_tags(
    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[TagResponse]:
    """List all detection tags."""
    if not current_user.has_permission("read:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to read tags"
        )

    from sqlalchemy import select

    from src.db.models import Tag

    result = await db.execute(
        select(Tag).where(Tag.tenant_id == current_user.tenant_id).order_by(Tag.name)
    )
    tags = result.scalars().all()

    return [TagResponse.model_validate(tag) for tag in tags]


# Severity and MITRE reference endpoints
@router.get("/severities/", response_model=list[SeverityResponse])
async def list_severities(
    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[SeverityResponse]:
    """List all severity levels."""
    if not current_user.has_permission("read:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to read severities"
        )

    from sqlalchemy import select

    from src.db.models import Severity

    result = await db.execute(select(Severity).order_by(Severity.level))
    severities = result.scalars().all()

    return [SeverityResponse.model_validate(severity) for severity in severities]


@router.get("/mitre/tactics/", response_model=list[MitreTacticResponse])
async def list_mitre_tactics(
    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> list[MitreTacticResponse]:
    """List all MITRE ATT&CK tactics."""
    if not current_user.has_permission("read:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to read MITRE data"
        )

    from sqlalchemy import select

    from src.db.models import MitreTactic

    result = await db.execute(select(MitreTactic).order_by(MitreTactic.tactic_id))
    tactics = result.scalars().all()

    return [MitreTacticResponse.model_validate(tactic) for tactic in tactics]


@router.get("/mitre/techniques/", response_model=list[MitreTechniqueResponse])
async def list_mitre_techniques(
    tactic_id: str | None = Query(None, description="Filter by tactic ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MitreTechniqueResponse]:
    """List MITRE ATT&CK techniques, optionally filtered by tactic."""
    if not current_user.has_permission("read:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to read MITRE data"
        )

    from sqlalchemy import select

    from src.db.models import MitreTechnique

    query = select(MitreTechnique).order_by(MitreTechnique.technique_id)

    if tactic_id:
        query = query.where(MitreTechnique.tactic_id == tactic_id)

    result = await db.execute(query)
    techniques = result.scalars().all()

    return [
        MitreTechniqueResponse.model_validate(technique) for technique in techniques
    ]


# Bulk Operations
@router.post("/bulk", response_model=BulkDetectionOperationResponse)
async def bulk_detection_operation(
    request: Request,
    bulk_data: BulkDetectionOperation,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BulkDetectionOperationResponse:
    """
    Perform bulk operations on detections.

    Supported operations:
    - activate: Set detections to active status
    - deactivate: Set detections to inactive status
    - deprecate: Set detections to deprecated status
    - delete: Delete detections
    - update_status: Update to specific status (requires new_status)

    Args:
        request: FastAPI request
        bulk_data: Bulk operation data
        db: Database session
        current_user: Current authenticated user

    Returns:
        BulkDetectionOperationResponse: Operation results

    Raises:
        HTTPException: 400 if validation fails, 403 if unauthorized
    """
    if not current_user.has_permission("write:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to modify detections"
        )

    try:
        from sqlalchemy import select, update

        from src.core.logging import audit_log
        from src.db.models import Detection

        successful = 0
        failed = 0

        # Validate operation-specific requirements
        if bulk_data.operation == "update_status" and not bulk_data.new_status:
            raise HTTPException(
                status_code=400,
                detail="new_status is required for update_status operation",
            )

        # Process each detection
        for detection_id in bulk_data.detection_ids:
            try:
                # Check if detection exists and user has access
                result = await db.execute(
                    select(Detection).where(
                        Detection.id == detection_id,
                        Detection.tenant_id == current_user.tenant_id,
                    )
                )
                detection = result.scalar_one_or_none()

                if not detection:
                    failed += 1
                    continue

                # Perform operation
                if bulk_data.operation == "delete":
                    await db.delete(detection)
                elif bulk_data.operation == "activate":
                    detection.status = "active"
                elif bulk_data.operation == "deactivate":
                    detection.status = "draft"
                elif bulk_data.operation == "deprecate":
                    detection.status = "deprecated"
                elif bulk_data.operation == "update_status":
                    detection.status = bulk_data.new_status

                successful += 1

                # Log the operation
                audit_log(
                    action=f"detection_{bulk_data.operation}",
                    resource="detection",
                    resource_id=str(detection_id),
                    user_id=str(current_user.id),
                    tenant_id=str(current_user.tenant_id),
                    success=True,
                    details={
                        "operation": bulk_data.operation,
                        "new_status": bulk_data.new_status,
                    },
                )

            except Exception as e:
                failed += 1
                logger.warning(
                    "bulk_operation_detection_failed",
                    detection_id=str(detection_id),
                    operation=bulk_data.operation,
                    error=str(e),
                )

        await db.commit()

        # Log overall operation
        audit_log(
            action="detections_bulk_operation",
            resource="detection",
            user_id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            success=True,
            details={
                "operation": bulk_data.operation,
                "total_requested": len(bulk_data.detection_ids),
                "successful": successful,
                "failed": failed,
            },
        )

        return BulkDetectionOperationResponse(
            operation=bulk_data.operation,
            total_requested=len(bulk_data.detection_ids),
            successful=successful,
            failed=failed,
        )

    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Bulk operation failed: {e!s}"
        )


@router.post("/import", response_model=BulkDetectionOperationResponse)
async def bulk_import_detections(
    request: Request,
    detections: list[DetectionCreate],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> BulkDetectionOperationResponse:
    """
    Bulk import detections.

    Args:
        request: FastAPI request
        detections: List of detections to import
        db: Database session
        current_user: Current authenticated user

    Returns:
        BulkDetectionOperationResponse: Import results

    Raises:
        HTTPException: 400 if validation fails, 403 if unauthorized
    """
    if not current_user.has_permission("write:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to import detections"
        )

    if len(detections) > 1000:
        raise HTTPException(
            status_code=400, detail="Cannot import more than 1000 detections at once"
        )

    successful = 0
    failed = 0

    try:
        for detection_data in detections:
            try:
                detection = await DetectionService.create_detection(
                    db=db,
                    detection_data=detection_data,
                    tenant_id=current_user.tenant_id,
                    user_id=current_user.id,
                )
                successful += 1

            except Exception as e:
                failed += 1
                logger.warning(
                    "bulk_import_detection_failed",
                    detection_name=detection_data.name,
                    error=str(e),
                )

        # Log overall import
        from src.core.logging import audit_log

        audit_log(
            action="detections_bulk_import",
            resource="detection",
            user_id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            success=True,
            details={
                "total_requested": len(detections),
                "successful": successful,
                "failed": failed,
            },
        )

        return BulkDetectionOperationResponse(
            operation="import",
            total_requested=len(detections),
            successful=successful,
            failed=failed,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk import failed: {e!s}")


@router.get("/export", response_model=list[DetectionResponse])
async def export_detections(
    detection_ids: list[UUID] = Query(None, description="Specific detection IDs to export"),
    category_ids: list[UUID] = Query(None, description="Export detections by category"),
    tag_ids: list[UUID] = Query(None, description="Export detections by tags"),
    format: str = Query("json", pattern="^(json|yaml|csv)$", description="Export format"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[DetectionResponse]:
    """
    Export detections in various formats.

    Args:
        detection_ids: Specific detection IDs to export
        category_ids: Export detections by category
        tag_ids: Export detections by tags
        format: Export format (json, yaml, csv)
        db: Database session
        current_user: Current authenticated user

    Returns:
        List[DetectionResponse]: Exported detections

    Raises:
        HTTPException: 403 if unauthorized
    """
    if not current_user.has_permission("read:rules"):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions to export detections"
        )

    try:
        from sqlalchemy import select

        from src.db.models import Detection

        # Build query
        query = select(Detection).where(Detection.tenant_id == current_user.tenant_id)

        if detection_ids:
            query = query.where(Detection.id.in_(detection_ids))

        if category_ids:
            query = query.join(Detection.categories).where(
                Detection.categories.any(id__in=category_ids)
            )

        if tag_ids:
            query = query.join(Detection.tags).where(
                Detection.tags.any(id__in=tag_ids)
            )

        # Limit export size
        query = query.limit(10000)

        result = await db.execute(query)
        detections = result.scalars().all()

        # Log export
        from src.core.logging import audit_log

        audit_log(
            action="detections_export",
            resource="detection",
            user_id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            success=True,
            details={
                "count": len(detections),
                "format": format,
                "filters": {
                    "detection_ids": len(detection_ids) if detection_ids else 0,
                    "category_ids": len(category_ids) if category_ids else 0,
                    "tag_ids": len(tag_ids) if tag_ids else 0,
                },
            },
        )

        return [DetectionResponse.model_validate(detection) for detection in detections]

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {e!s}")
