"""
Detection API endpoints for CRUD operations and advanced features.
"""

import math
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.dependencies.auth import get_current_user
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.db.models import User
from src.db.session import get_db
from src.schemas.detection import (
    DetectionCreate, DetectionUpdate, DetectionResponse,
    DetectionListResponse, DetectionSearchRequest,
    CategoryCreate, CategoryUpdate, CategoryResponse,
    TagCreate, TagUpdate, TagResponse,
    SeverityResponse, MitreTacticResponse, MitreTechniqueResponse,
    DetectionValidationRequest, DetectionValidationResponse,
    BulkDetectionOperation, BulkDetectionOperationResponse,
    DetectionStatsResponse
)
from src.services.detection_service import DetectionService

router = APIRouter()


# Detection CRUD endpoints
@router.post("/", response_model=DetectionResponse, status_code=201)
async def create_detection(
    request: Request,
    detection_data: DetectionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
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
        raise HTTPException(status_code=403, detail="Insufficient permissions to create detections")

    try:
        detection = await DetectionService.create_detection(
            db=db,
            detection_data=detection_data,
            tenant_id=current_user.tenant_id,
            user_id=current_user.id
        )
        return DetectionResponse.model_validate(detection)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create detection: {str(e)}")


@router.get("/{detection_id}", response_model=DetectionResponse)
async def get_detection(
    detection_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
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
        raise HTTPException(status_code=403, detail="Insufficient permissions to read detections")

    try:
        detection = await DetectionService.get_detection(
            db=db,
            detection_id=detection_id,
            tenant_id=current_user.tenant_id
        )
        return DetectionResponse.model_validate(detection)
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/{detection_id}", response_model=DetectionResponse)
async def update_detection(
    detection_id: UUID,
    detection_data: DetectionUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
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
        raise HTTPException(status_code=403, detail="Insufficient permissions to update detections")

    try:
        detection = await DetectionService.update_detection(
            db=db,
            detection_id=detection_id,
            detection_data=detection_data,
            tenant_id=current_user.tenant_id,
            user_id=current_user.id
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
    current_user: User = Depends(get_current_user)
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
        raise HTTPException(status_code=403, detail="Insufficient permissions to delete detections")

    try:
        await DetectionService.delete_detection(
            db=db,
            detection_id=detection_id,
            tenant_id=current_user.tenant_id
        )
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/", response_model=DetectionListResponse)
async def list_detections(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> DetectionListResponse:
    """
    List detections with pagination.

    Args:
        page: Page number
        per_page: Items per page
        db: Database session
        current_user: Current authenticated user

    Returns:
        DetectionListResponse: Paginated detections

    Raises:
        HTTPException: 403 if unauthorized
    """
    if not current_user.has_permission("read:rules"):
        raise HTTPException(status_code=403, detail="Insufficient permissions to read detections")

    # Create empty search request for basic listing
    search_request = DetectionSearchRequest()
    detections, total = await DetectionService.search_detections(
        db=db,
        search_request=search_request,
        tenant_id=current_user.tenant_id,
        page=page,
        per_page=per_page
    )

    return DetectionListResponse(
        items=[DetectionResponse.model_validate(detection) for detection in detections],
        total=total,
        page=page,
        per_page=per_page,
        pages=math.ceil(total / per_page)
    )


@router.post("/search", response_model=DetectionListResponse)
async def search_detections(
    search_request: DetectionSearchRequest,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
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
        raise HTTPException(status_code=403, detail="Insufficient permissions to read detections")

    detections, total = await DetectionService.search_detections(
        db=db,
        search_request=search_request,
        tenant_id=current_user.tenant_id,
        page=page,
        per_page=per_page
    )

    return DetectionListResponse(
        items=[DetectionResponse.model_validate(detection) for detection in detections],
        total=total,
        page=page,
        per_page=per_page,
        pages=math.ceil(total / per_page)
    )


@router.post("/validate", response_model=DetectionValidationResponse)
async def validate_detection_content(
    validation_request: DetectionValidationRequest,
    current_user: User = Depends(get_current_user)
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
        raise HTTPException(status_code=403, detail="Insufficient permissions to validate detections")

    validation_result = await DetectionService.validate_detection_content(
        rule_content=validation_request.rule_content,
        rule_format=validation_request.rule_format
    )

    return DetectionValidationResponse(**validation_result)


# Category management endpoints
@router.post("/categories/", response_model=CategoryResponse, status_code=201)
async def create_category(
    category_data: CategoryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> CategoryResponse:
    """Create a new detection category."""
    if not current_user.has_permission("write:rules"):
        raise HTTPException(status_code=403, detail="Insufficient permissions to create categories")

    try:
        category = await DetectionService.create_category(
            db=db,
            category_data=category_data,
            tenant_id=current_user.tenant_id
        )
        return CategoryResponse.model_validate(category)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/categories/", response_model=List[CategoryResponse])
async def list_categories(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> List[CategoryResponse]:
    """List all detection categories."""
    if not current_user.has_permission("read:rules"):
        raise HTTPException(status_code=403, detail="Insufficient permissions to read categories")

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
    current_user: User = Depends(get_current_user)
) -> TagResponse:
    """Create a new detection tag."""
    if not current_user.has_permission("write:rules"):
        raise HTTPException(status_code=403, detail="Insufficient permissions to create tags")

    try:
        tag = await DetectionService.create_tag(
            db=db,
            tag_data=tag_data,
            tenant_id=current_user.tenant_id
        )
        return TagResponse.model_validate(tag)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/tags/", response_model=List[TagResponse])
async def list_tags(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> List[TagResponse]:
    """List all detection tags."""
    if not current_user.has_permission("read:rules"):
        raise HTTPException(status_code=403, detail="Insufficient permissions to read tags")

    from sqlalchemy import select
    from src.db.models import Tag

    result = await db.execute(
        select(Tag)
        .where(Tag.tenant_id == current_user.tenant_id)
        .order_by(Tag.name)
    )
    tags = result.scalars().all()

    return [TagResponse.model_validate(tag) for tag in tags]


# Severity and MITRE reference endpoints
@router.get("/severities/", response_model=List[SeverityResponse])
async def list_severities(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> List[SeverityResponse]:
    """List all severity levels."""
    if not current_user.has_permission("read:rules"):
        raise HTTPException(status_code=403, detail="Insufficient permissions to read severities")

    from sqlalchemy import select
    from src.db.models import Severity

    result = await db.execute(
        select(Severity).order_by(Severity.level)
    )
    severities = result.scalars().all()

    return [SeverityResponse.model_validate(severity) for severity in severities]


@router.get("/mitre/tactics/", response_model=List[MitreTacticResponse])
async def list_mitre_tactics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> List[MitreTacticResponse]:
    """List all MITRE ATT&CK tactics."""
    if not current_user.has_permission("read:rules"):
        raise HTTPException(status_code=403, detail="Insufficient permissions to read MITRE data")

    from sqlalchemy import select
    from src.db.models import MitreTactic

    result = await db.execute(
        select(MitreTactic).order_by(MitreTactic.tactic_id)
    )
    tactics = result.scalars().all()

    return [MitreTacticResponse.model_validate(tactic) for tactic in tactics]


@router.get("/mitre/techniques/", response_model=List[MitreTechniqueResponse])
async def list_mitre_techniques(
    tactic_id: Optional[str] = Query(None, description="Filter by tactic ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> List[MitreTechniqueResponse]:
    """List MITRE ATT&CK techniques, optionally filtered by tactic."""
    if not current_user.has_permission("read:rules"):
        raise HTTPException(status_code=403, detail="Insufficient permissions to read MITRE data")

    from sqlalchemy import select
    from src.db.models import MitreTechnique

    query = select(MitreTechnique).order_by(MitreTechnique.technique_id)

    if tactic_id:
        query = query.where(MitreTechnique.tactic_id == tactic_id)

    result = await db.execute(query)
    techniques = result.scalars().all()

    return [MitreTechniqueResponse.model_validate(technique) for technique in techniques]