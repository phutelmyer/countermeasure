"""
User management endpoints for admin operations.
"""

import math
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.dependencies.auth import get_current_user, require_admin
from src.db.models import User
from src.db.session import get_db
from src.schemas.auth import UserResponse
from src.schemas.core import PaginatedResponse
from src.schemas.user import UserListResponse, UserStatsResponse, UserUpdateRequest


router = APIRouter()


@router.get("/", response_model=PaginatedResponse[UserListResponse])
async def list_users(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
    tenant_id: UUID = Query(None, description="Filter by tenant ID (admin only)"),
    role: str = Query(None, description="Filter by role"),
    is_active: bool = Query(None, description="Filter by active status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedResponse[UserListResponse]:
    """
    List users with filtering and pagination.

    Args:
        page: Page number
        per_page: Items per page
        tenant_id: Filter by tenant ID (admin only)
        role: Filter by role
        is_active: Filter by active status
        db: Database session
        current_user: Current authenticated user

    Returns:
        PaginatedResponse[UserListResponse]: Paginated user list
    """
    # Build query based on user permissions
    query = select(User)

    if current_user.role != "admin":
        # Non-admin users can only see users in their tenant
        query = query.where(User.tenant_id == current_user.tenant_id)
    elif tenant_id:
        # Admin can filter by specific tenant
        query = query.where(User.tenant_id == tenant_id)

    # Apply filters
    if role:
        query = query.where(User.role == role)
    if is_active is not None:
        query = query.where(User.is_active == is_active)

    # Count total users
    count_query = select(func.count()).select_from(query.subquery())
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Get users with pagination
    offset = (page - 1) * per_page
    query = query.order_by(User.created_at.desc()).offset(offset).limit(per_page)
    result = await db.execute(query)
    users = result.scalars().all()

    return PaginatedResponse(
        items=[UserListResponse.model_validate(user) for user in users],
        total=total,
        page=page,
        per_page=per_page,
        pages=math.ceil(total / per_page) if total > 0 else 0,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """
    Get current user's profile.

    Args:
        current_user: Current authenticated user

    Returns:
        UserResponse: Current user details
    """
    return UserResponse.model_validate(current_user)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """
    Get user by ID.

    Args:
        user_id: User ID
        db: Database session
        current_user: Current authenticated user

    Returns:
        UserResponse: User details

    Raises:
        HTTPException: 404 if user not found, 403 if not authorized
    """
    # Check if user can access this profile
    if current_user.role != "admin" and current_user.id != user_id:
        # Non-admin users can only access their own profile or users in their tenant
        query = select(User).where(
            User.id == user_id, User.tenant_id == current_user.tenant_id
        )
    else:
        query = select(User).where(User.id == user_id)

    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return UserResponse.model_validate(user)


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    user_data: UserUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """
    Update user information.

    Args:
        user_id: User ID
        user_data: User update data
        db: Database session
        current_user: Current authenticated user

    Returns:
        UserResponse: Updated user

    Raises:
        HTTPException: 404 if user not found, 403 if not authorized
    """
    # Check permissions
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to update this user",
        )

    # Get user
    if current_user.role != "admin":
        # Non-admin users can only update users in their tenant
        query = select(User).where(
            User.id == user_id, User.tenant_id == current_user.tenant_id
        )
    else:
        query = select(User).where(User.id == user_id)

    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Restrict role changes for non-admin users
    update_data = user_data.model_dump(exclude_unset=True)
    if current_user.role != "admin" and "role" in update_data:
        del update_data["role"]

    # Update fields
    for field, value in update_data.items():
        setattr(user, field, value)

    await db.commit()
    await db.refresh(user)

    return UserResponse.model_validate(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> None:
    """
    Delete user (admin only).

    Args:
        user_id: User ID
        db: Database session
        current_user: Current authenticated admin user

    Raises:
        HTTPException: 404 if user not found, 400 if trying to delete self
    """
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    await db.delete(user)
    await db.commit()


@router.get("/statistics", response_model=UserStatsResponse)
async def get_user_stats(
    tenant_id: UUID = Query(None, description="Filter by tenant ID (admin only)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserStatsResponse:
    """
    Get user statistics.

    Args:
        tenant_id: Filter by tenant ID (admin only)
        db: Database session
        current_user: Current authenticated user

    Returns:
        UserStatsResponse: User statistics
    """
    # Build base query
    query = select(User)

    if current_user.role != "admin":
        # Non-admin users can only see stats for their tenant
        query = query.where(User.tenant_id == current_user.tenant_id)
    elif tenant_id:
        # Admin can filter by specific tenant
        query = query.where(User.tenant_id == tenant_id)

    # Get user counts
    total_users_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total_users = total_users_result.scalar() or 0

    active_users_result = await db.execute(
        select(func.count()).select_from(query.where(User.is_active == True).subquery())
    )
    active_users = active_users_result.scalar() or 0

    verified_users_result = await db.execute(
        select(func.count()).select_from(
            query.where(User.is_verified == True).subquery()
        )
    )
    verified_users = verified_users_result.scalar() or 0

    mfa_users_result = await db.execute(
        select(func.count()).select_from(
            query.where(User.mfa_enabled == True).subquery()
        )
    )
    mfa_users = mfa_users_result.scalar() or 0

    # Get role distribution
    role_dist_result = await db.execute(
        select(User.role, func.count(User.id))
        .select_from(query.subquery())
        .group_by(User.role)
    )
    role_distribution = [
        {"role": role, "count": count} for role, count in role_dist_result.all()
    ]

    return UserStatsResponse(
        total_users=total_users,
        active_users=active_users,
        inactive_users=total_users - active_users,
        verified_users=verified_users,
        unverified_users=total_users - verified_users,
        users_with_mfa=mfa_users,
        role_distribution=role_distribution,
    )
