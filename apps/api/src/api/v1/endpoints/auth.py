"""
Authentication endpoints for login, signup, and token management.
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.dependencies.auth import get_current_user, get_current_active_user
from src.core.exceptions import (
    AuthenticationError,
    ResourceConflictError,
    ResourceNotFoundError,
    ValidationError
)
from src.core.logging import audit_log, get_logger
from src.db.models import User
from src.db.session import get_db
from src.schemas.auth import (
    LoginRequest,
    LoginResponse,
    PasswordChangeRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    SignupRequest,
    SignupResponse,
    TokenRefreshRequest,
    TokenRefreshResponse,
    UserResponse
)
from src.services.auth_service import AuthService

logger = get_logger(__name__)
router = APIRouter()


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="User Login",
    description="Authenticate user with email and password, return JWT tokens"
)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db)
) -> LoginResponse:
    """
    Login endpoint for user authentication.

    Args:
        request: FastAPI request object
        login_data: Login credentials
        db: Database session

    Returns:
        LoginResponse: JWT tokens and user information

    Raises:
        HTTPException: If authentication fails
    """
    try:
        auth_service = AuthService(db)
        token_response = await auth_service.login(login_data)

        # Convert to LoginResponse format
        return LoginResponse(
            access_token=token_response.access_token,
            refresh_token=token_response.refresh_token,
            token_type=token_response.token_type,
            expires_in=token_response.expires_in,
            user=token_response.user
        )

    except AuthenticationError as e:
        # Log failed login attempt with IP address
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("User-Agent")

        audit_log(
            action="login_failed",
            resource="auth",
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            details={"email": login_data.email, "error": str(e)}
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        logger.error("login_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )


@router.post(
    "/signup",
    response_model=SignupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="User Signup",
    description="Register a new user account"
)
async def signup(
    request: Request,
    signup_data: SignupRequest,
    db: AsyncSession = Depends(get_db)
) -> SignupResponse:
    """
    Signup endpoint for user registration.

    Args:
        request: FastAPI request object
        signup_data: User registration data
        db: Database session

    Returns:
        SignupResponse: Created user information

    Raises:
        HTTPException: If signup fails
    """
    try:
        auth_service = AuthService(db)
        user = await auth_service.signup(signup_data)

        # Log successful signup
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("User-Agent")

        audit_log(
            action="user_signup",
            resource="auth",
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={"email": user.email}
        )

        return SignupResponse(
            message="User account created successfully. Please verify your email address.",
            user=UserResponse.model_validate(user),
            verification_required=True
        )

    except ResourceConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )
    except (ResourceNotFoundError, ValidationError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error("signup_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Signup failed"
        )


@router.post(
    "/refresh",
    response_model=TokenRefreshResponse,
    summary="Refresh Token",
    description="Refresh access token using refresh token"
)
async def refresh_token(
    refresh_data: TokenRefreshRequest,
    db: AsyncSession = Depends(get_db)
) -> TokenRefreshResponse:
    """
    Refresh access token endpoint.

    Args:
        refresh_data: Refresh token request
        db: Database session

    Returns:
        TokenRefreshResponse: New access token

    Raises:
        HTTPException: If refresh fails
    """
    try:
        auth_service = AuthService(db)
        access_token, expires_in = await auth_service.refresh_token(refresh_data.refresh_token)

        return TokenRefreshResponse(
            access_token=access_token,
            expires_in=expires_in
        )

    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        logger.error("token_refresh_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get Current User",
    description="Get current authenticated user information"
)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
) -> UserResponse:
    """
    Get current user information.

    Args:
        current_user: Current authenticated user

    Returns:
        UserResponse: Current user information
    """
    return UserResponse.model_validate(current_user)


@router.post(
    "/logout",
    summary="User Logout",
    description="Logout user (invalidate tokens on client side)"
)
async def logout(
    request: Request,
    current_user: User = Depends(get_current_active_user)
) -> Dict[str, str]:
    """
    Logout endpoint.

    Note: Since we're using stateless JWT tokens, actual logout is handled
    client-side by removing tokens. This endpoint is for logging purposes.

    Args:
        request: FastAPI request object
        current_user: Current authenticated user

    Returns:
        Dict: Success message
    """
    # Log logout event
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("User-Agent")

    audit_log(
        action="user_logout",
        resource="auth",
        user_id=str(current_user.id),
        tenant_id=str(current_user.tenant_id),
        ip_address=ip_address,
        user_agent=user_agent,
        success=True
    )

    logger.info("user_logout", user_id=str(current_user.id))

    return {"message": "Logged out successfully"}


@router.post(
    "/password/change",
    summary="Change Password",
    description="Change password for authenticated user"
)
async def change_password(
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, str]:
    """
    Change password for current user.

    Args:
        password_data: Password change request
        current_user: Current authenticated user
        db: Database session

    Returns:
        Dict: Success message

    Raises:
        HTTPException: If password change fails
    """
    try:
        from src.core.security import verify_password, get_password_hash

        # Verify current password
        if not current_user.password_hash or not verify_password(
            password_data.current_password,
            current_user.password_hash
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )

        # Update password
        current_user.password_hash = get_password_hash(password_data.new_password)
        await db.commit()

        audit_log(
            action="password_change",
            resource="user",
            user_id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            success=True
        )

        logger.info("password_changed", user_id=str(current_user.id))

        return {"message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("password_change_error", user_id=str(current_user.id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )


@router.post(
    "/password/reset",
    summary="Request Password Reset",
    description="Request password reset email"
)
async def request_password_reset(
    reset_data: PasswordResetRequest,
    db: AsyncSession = Depends(get_db)
) -> Dict[str, str]:
    """
    Request password reset.

    Args:
        reset_data: Password reset request
        db: Database session

    Returns:
        Dict: Success message (always returns success for security)
    """
    try:
        auth_service = AuthService(db)
        user = await auth_service.get_user_by_email(reset_data.email)

        if user and user.is_active:
            # TODO: Generate reset token and send email
            # For now, just log the event
            audit_log(
                action="password_reset_requested",
                resource="user",
                user_id=str(user.id),
                tenant_id=str(user.tenant_id),
                success=True
            )

            logger.info("password_reset_requested", user_id=str(user.id))

        # Always return success to prevent email enumeration
        return {"message": "If an account with that email exists, a password reset link has been sent"}

    except Exception as e:
        logger.error("password_reset_request_error", error=str(e))
        # Still return success to prevent information leakage
        return {"message": "If an account with that email exists, a password reset link has been sent"}


@router.post(
    "/password/reset/confirm",
    summary="Confirm Password Reset",
    description="Confirm password reset with token"
)
async def confirm_password_reset(
    reset_data: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db)
) -> Dict[str, str]:
    """
    Confirm password reset with token.

    Args:
        reset_data: Password reset confirmation
        db: Database session

    Returns:
        Dict: Success message

    Raises:
        HTTPException: If reset fails
    """
    # TODO: Implement password reset token verification
    # For now, return not implemented
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Password reset not yet implemented"
    )