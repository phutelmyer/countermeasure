"""
Tenant management endpoints for multi-tenancy administration.
"""

import math
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.dependencies.auth import require_admin
from src.db.models import Tenant, User
from src.db.session import get_db
from src.schemas.core import PaginatedResponse
from src.schemas.tenant import (
    TenantCreate,
    TenantResponse,
    TenantStatsResponse,
    TenantUpdate,
)


router = APIRouter()


@router.get("/", response_model=PaginatedResponse[TenantResponse])
async def list_tenants(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> PaginatedResponse[TenantResponse]:
    """
    List all tenants (admin only).

    Args:
        page: Page number
        per_page: Items per page
        db: Database session
        current_user: Current authenticated admin user

    Returns:
        PaginatedResponse[TenantResponse]: Paginated tenant list
    """
    # Count total tenants
    count_result = await db.execute(select(func.count(Tenant.id)))
    total = count_result.scalar() or 0

    # Get tenants with pagination
    offset = (page - 1) * per_page
    result = await db.execute(
        select(Tenant).order_by(Tenant.created_at.desc()).offset(offset).limit(per_page)
    )
    tenants = result.scalars().all()

    return PaginatedResponse(
        items=[TenantResponse.model_validate(tenant) for tenant in tenants],
        total=total,
        page=page,
        per_page=per_page,
        pages=math.ceil(total / per_page) if total > 0 else 0,
    )


@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> TenantResponse:
    """
    Get tenant by ID (admin only).

    Args:
        tenant_id: Tenant ID
        db: Database session
        current_user: Current authenticated admin user

    Returns:
        TenantResponse: Tenant details

    Raises:
        HTTPException: 404 if tenant not found
    """
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found"
        )

    return TenantResponse.model_validate(tenant)


@router.post("/", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    tenant_data: TenantCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> TenantResponse:
    """
    Create a new tenant (admin only).

    Args:
        tenant_data: Tenant creation data
        db: Database session
        current_user: Current authenticated admin user

    Returns:
        TenantResponse: Created tenant

    Raises:
        HTTPException: 400 if validation fails, 409 if slug already exists
    """
    # Check if slug already exists
    existing_result = await db.execute(
        select(Tenant).where(Tenant.slug == tenant_data.slug)
    )
    if existing_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Tenant with this slug already exists",
        )

    # Create tenant
    tenant = Tenant(**tenant_data.model_dump())
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)

    return TenantResponse.model_validate(tenant)


@router.put("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: UUID,
    tenant_data: TenantUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> TenantResponse:
    """
    Update tenant (admin only).

    Args:
        tenant_id: Tenant ID
        tenant_data: Tenant update data
        db: Database session
        current_user: Current authenticated admin user

    Returns:
        TenantResponse: Updated tenant

    Raises:
        HTTPException: 404 if tenant not found
    """
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found"
        )

    # Update fields
    update_data = tenant_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(tenant, field, value)

    await db.commit()
    await db.refresh(tenant)

    return TenantResponse.model_validate(tenant)


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(
    tenant_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> None:
    """
    Delete tenant (admin only).

    Args:
        tenant_id: Tenant ID
        db: Database session
        current_user: Current authenticated admin user

    Raises:
        HTTPException: 404 if tenant not found, 400 if tenant has users
    """
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found"
        )

    # Check if tenant has users
    user_count_result = await db.execute(
        select(func.count(User.id)).where(User.tenant_id == tenant_id)
    )
    user_count = user_count_result.scalar() or 0

    if user_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete tenant with {user_count} users. Remove users first.",
        )

    await db.delete(tenant)
    await db.commit()


@router.get("/statistics", response_model=TenantStatsResponse)
async def get_tenant_stats(
    db: AsyncSession = Depends(get_db), current_user: User = Depends(require_admin)
) -> TenantStatsResponse:
    """
    Get tenant statistics (admin only).

    Args:
        db: Database session
        current_user: Current authenticated admin user

    Returns:
        TenantStatsResponse: Tenant statistics
    """
    # Get tenant counts
    total_tenants_result = await db.execute(select(func.count(Tenant.id)))
    total_tenants = total_tenants_result.scalar() or 0

    active_tenants_result = await db.execute(
        select(func.count(Tenant.id)).where(Tenant.is_active == True)
    )
    active_tenants = active_tenants_result.scalar() or 0

    # Get user counts
    total_users_result = await db.execute(select(func.count(User.id)))
    total_users = total_users_result.scalar() or 0

    return TenantStatsResponse(
        total_tenants=total_tenants,
        active_tenants=active_tenants,
        inactive_tenants=total_tenants - active_tenants,
        total_users=total_users,
        avg_users_per_tenant=total_users / total_tenants if total_tenants > 0 else 0,
        total_storage_used_gb=0.0,  # TODO: Implement storage tracking
    )
