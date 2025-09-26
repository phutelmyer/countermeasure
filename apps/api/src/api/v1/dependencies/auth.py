"""
Authentication and authorization dependencies for FastAPI.
"""

from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.exceptions import AuthenticationError, AuthorizationError
from src.core.logging import audit_log, get_logger
from src.core.security import RoleChecker, verify_token
from src.db.models import User
from src.db.session import get_db
from src.schemas.auth import UserResponse


logger = get_logger(__name__)

# HTTP Bearer token scheme
security = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Get current authenticated user from JWT token.
    """
    if not credentials:
        logger.warning("authentication_failed", reason="no_credentials")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Verify JWT token
        payload = verify_token(credentials.credentials, "access_token")
        user_id = payload.get("sub")

        if not user_id:
            raise AuthenticationError("Invalid token payload")

        # Get user from database
        from sqlalchemy import select

        result = await db.execute(select(User).where(User.id == UUID(user_id)))
        user = result.scalar_one_or_none()

        if not user:
            logger.warning(
                "authentication_failed", reason="user_not_found", user_id=user_id
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            logger.warning(
                "authentication_failed", reason="user_inactive", user_id=user_id
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if user.is_locked:
            logger.warning(
                "authentication_failed", reason="user_locked", user_id=user_id
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is locked",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Update last activity
        user.update_last_activity()
        await db.commit()

        # Set tenant context for row-level security
        tenant_id = str(user.tenant_id)
        await db.execute(text(f"SET app.current_tenant_id = '{tenant_id}'"))

        # Populate request state for middleware use
        request.state.user_id = str(user.id)
        request.state.tenant_id = tenant_id

        logger.debug(
            "user_authenticated",
            user_id=str(user.id),
            tenant_id=tenant_id,
            role=user.role,
        )

        return user

    except AuthenticationError as e:
        logger.warning("authentication_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error("authentication_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Get current active user (alias for clarity).
    """
    return current_user


def require_role(required_role: str):
    """
    Dependency factory for role-based authorization.

    Args:
        required_role: The minimum role required to access the endpoint

    Returns:
        Dependency function that checks user role
    """

    async def check_role(current_user: User = Depends(get_current_user)) -> User:
        try:
            RoleChecker.check_role(current_user.role, required_role)

            audit_log(
                action="authorization_success",
                resource="endpoint",
                user_id=str(current_user.id),
                tenant_id=str(current_user.tenant_id),
                success=True,
                details={
                    "required_role": required_role,
                    "user_role": current_user.role,
                },
            )

            return current_user

        except AuthorizationError as e:
            audit_log(
                action="authorization_failed",
                resource="endpoint",
                user_id=str(current_user.id),
                tenant_id=str(current_user.tenant_id),
                success=False,
                details={
                    "required_role": required_role,
                    "user_role": current_user.role,
                    "error": str(e),
                },
            )

            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    return check_role


def require_permission(permission: str):
    """
    Dependency factory for permission-based authorization.

    Args:
        permission: The specific permission required (e.g., "write:actors")

    Returns:
        Dependency function that checks user permission
    """

    async def check_permission(current_user: User = Depends(get_current_user)) -> User:
        if not current_user.has_permission(permission):
            audit_log(
                action="authorization_failed",
                resource="endpoint",
                user_id=str(current_user.id),
                tenant_id=str(current_user.tenant_id),
                success=False,
                details={
                    "required_permission": permission,
                    "user_role": current_user.role,
                },
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required",
            )

        return current_user

    return check_permission


# Common role dependencies
require_admin = require_role("admin")
require_analyst = require_role("analyst")
require_viewer = require_role("viewer")

# Common permission dependencies
require_read_actors = require_permission("read:actors")
require_write_actors = require_permission("write:actors")
require_read_detections = require_permission("read:detections")
require_write_detections = require_permission("write:detections")
require_read_intelligence = require_permission("read:intelligence")
require_write_intelligence = require_permission("write:intelligence")


async def get_optional_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """
    Get current user if authenticated, otherwise return None.
    Useful for endpoints that have different behavior for authenticated vs anonymous users.
    """
    if not credentials:
        # Ensure request state is clean for unauthenticated requests
        request.state.user_id = None
        request.state.tenant_id = None
        return None

    try:
        return await get_current_user(request, credentials, db)
    except HTTPException:
        # Ensure request state is clean for failed authentication
        request.state.user_id = None
        request.state.tenant_id = None
        return None


async def get_tenant_id(current_user: User = Depends(get_current_user)) -> UUID:
    """
    Get current user's tenant ID.
    """
    return current_user.tenant_id


async def get_user_response(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """
    Get current user as response schema.
    """
    return UserResponse.model_validate(current_user)
