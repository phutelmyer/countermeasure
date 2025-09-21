"""
Actor API endpoints for CRUD operations and search.
"""

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.dependencies.auth import get_current_user
from src.core.exceptions import ResourceNotFoundError, ValidationError
from src.db.models import User
from src.db.session import get_db
from src.schemas.actor import (
    ActorCreate, ActorUpdate, ActorResponse,
    ActorListResponse, ActorSearchRequest
)
from src.services.actor_service import ActorService

router = APIRouter()


@router.post("/", response_model=ActorResponse, status_code=201)
async def create_actor(
    request: Request,
    actor_data: ActorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> ActorResponse:
    """
    Create a new actor.

    Args:
        request: FastAPI request
        actor_data: Actor creation data
        db: Database session
        current_user: Current authenticated user

    Returns:
        ActorResponse: Created actor

    Raises:
        HTTPException: 400 if validation fails
    """
    try:
        actor = await ActorService.create_actor(
            db=db,
            actor_data=actor_data,
            tenant_id=current_user.tenant_id,
            user_id=current_user.id
        )
        return ActorResponse.model_validate(actor)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create actor: {str(e)}")


@router.get("/{actor_id}", response_model=ActorResponse)
async def get_actor(
    actor_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> ActorResponse:
    """
    Get actor by ID.

    Args:
        actor_id: Actor ID
        db: Database session
        current_user: Current authenticated user

    Returns:
        ActorResponse: The actor

    Raises:
        HTTPException: 404 if actor not found
    """
    try:
        actor = await ActorService.get_actor(
            db=db,
            actor_id=actor_id,
            tenant_id=current_user.tenant_id
        )
        return ActorResponse.model_validate(actor)
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/{actor_id}", response_model=ActorResponse)
async def update_actor(
    actor_id: UUID,
    actor_data: ActorUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> ActorResponse:
    """
    Update actor.

    Args:
        actor_id: Actor ID
        actor_data: Actor update data
        db: Database session
        current_user: Current authenticated user

    Returns:
        ActorResponse: Updated actor

    Raises:
        HTTPException: 400 if validation fails, 404 if not found
    """
    try:
        actor = await ActorService.update_actor(
            db=db,
            actor_id=actor_id,
            actor_data=actor_data,
            tenant_id=current_user.tenant_id,
            user_id=current_user.id
        )
        return ActorResponse.model_validate(actor)
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{actor_id}", status_code=204)
async def delete_actor(
    actor_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> None:
    """
    Delete actor.

    Args:
        actor_id: Actor ID
        db: Database session
        current_user: Current authenticated user

    Raises:
        HTTPException: 404 if actor not found
    """
    try:
        await ActorService.delete_actor(
            db=db,
            actor_id=actor_id,
            tenant_id=current_user.tenant_id
        )
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/", response_model=ActorListResponse)
async def list_actors(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    include_related: bool = Query(False, description="Include related campaigns and malware"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> ActorListResponse:
    """
    List actors with pagination.

    Args:
        page: Page number
        per_page: Items per page
        include_related: Whether to include related entities
        db: Database session
        current_user: Current authenticated user

    Returns:
        ActorListResponse: Paginated actors
    """
    actors, total = await ActorService.list_actors(
        db=db,
        tenant_id=current_user.tenant_id,
        page=page,
        per_page=per_page,
        include_related=include_related
    )

    import math
    return ActorListResponse(
        items=[ActorResponse.model_validate(actor) for actor in actors],
        total=total,
        page=page,
        per_page=per_page,
        pages=math.ceil(total / per_page) if total > 0 else 0
    )


@router.post("/search", response_model=ActorListResponse)
async def search_actors(
    search_request: ActorSearchRequest,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> ActorListResponse:
    """
    Search actors with advanced filtering.

    Args:
        search_request: Search criteria
        page: Page number
        per_page: Items per page
        db: Database session
        current_user: Current authenticated user

    Returns:
        ActorListResponse: Filtered actors
    """
    actors, total = await ActorService.search_actors(
        db=db,
        search_request=search_request,
        tenant_id=current_user.tenant_id,
        page=page,
        per_page=per_page
    )

    import math
    return ActorListResponse(
        items=[ActorResponse.model_validate(actor) for actor in actors],
        total=total,
        page=page,
        per_page=per_page,
        pages=math.ceil(total / per_page) if total > 0 else 0
    )