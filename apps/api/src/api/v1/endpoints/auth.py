"""
Authentication endpoints for login, signup, and token management.
"""


from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.dependencies.auth import get_current_active_user
from src.core.exceptions import (
    AuthenticationError,
    ResourceConflictError,
    ResourceNotFoundError,
    ValidationError,
)
from src.core.logging import audit_log, get_logger
from src.db.models import User
from src.db.session import get_db
from src.schemas.auth import (
    EmailVerificationRequest,
    LoginRequest,
    LoginResponse,
    PasswordChangeRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    SignupRequest,
    SignupResponse,
    TokenRefreshRequest,
    TokenRefreshResponse,
    UserResponse,
)
from src.services.auth_service import AuthService


logger = get_logger(__name__)
router = APIRouter()


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="User Login",
    description="Authenticate user with email and password, return JWT tokens",
)
async def login(
    request: Request, login_data: LoginRequest, db: AsyncSession = Depends(get_db)
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
            user=token_response.user,
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
            details={"email": login_data.email, "error": str(e)},
        )

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception as e:
        logger.error("login_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Login failed"
        )


@router.post(
    "/signup",
    response_model=SignupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="User Signup",
    description="Register a new user account",
)
async def signup(
    request: Request, signup_data: SignupRequest, db: AsyncSession = Depends(get_db)
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

        # Generate email verification token
        from src.core.security import create_email_verification_token

        verification_token = create_email_verification_token(str(user.id))

        audit_log(
            action="user_signup",
            resource="auth",
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={"email": user.email},
        )

        # TODO: In production, send email with verification token instead of returning it
        # For development/testing, include token in response
        from src.core.config import settings

        response_data = {
            "message": "User account created successfully. Please verify your email address.",
            "user": UserResponse.model_validate(user),
            "verification_required": True,
        }

        if settings.is_development:
            response_data["verification_token"] = verification_token  # Only for development/testing

        return SignupResponse(**response_data)

    except ResourceConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except (ResourceNotFoundError, ValidationError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error("signup_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Signup failed"
        )


@router.post(
    "/refresh",
    response_model=TokenRefreshResponse,
    summary="Refresh Token",
    description="Refresh access token using refresh token",
)
async def refresh_token(
    refresh_data: TokenRefreshRequest, db: AsyncSession = Depends(get_db)
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
        access_token, expires_in = await auth_service.refresh_token(
            refresh_data.refresh_token
        )

        return TokenRefreshResponse(access_token=access_token, expires_in=expires_in)

    except AuthenticationError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception as e:
        logger.error("token_refresh_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed",
        )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get Current User",
    description="Get current authenticated user information",
)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user),
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
    description="Logout user (invalidate tokens on client side)",
)
async def logout(
    request: Request, current_user: User = Depends(get_current_active_user)
) -> dict[str, str]:
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
        success=True,
    )

    logger.info("user_logout", user_id=str(current_user.id))

    return {"message": "Logged out successfully"}


@router.post(
    "/password/change",
    summary="Change Password",
    description="Change password for authenticated user",
)
async def change_password(
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
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
        from src.core.security import get_password_hash, verify_password

        # Verify current password
        if not current_user.password_hash or not verify_password(
            password_data.current_password, current_user.password_hash
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect",
            )

        # Update password
        current_user.password_hash = get_password_hash(password_data.new_password)
        await db.commit()

        audit_log(
            action="password_change",
            resource="user",
            user_id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            success=True,
        )

        logger.info("password_changed", user_id=str(current_user.id))

        return {"message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "password_change_error", user_id=str(current_user.id), error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed",
        )


@router.post(
    "/password/reset",
    summary="Request Password Reset",
    description="Request password reset email",
)
async def request_password_reset(
    reset_data: PasswordResetRequest, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
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
            from src.core.security import create_password_reset_token

            # Generate reset token
            reset_token = create_password_reset_token(str(user.id))

            # Log the event
            audit_log(
                action="password_reset_requested",
                resource="user",
                user_id=str(user.id),
                tenant_id=str(user.tenant_id),
                success=True,
            )

            logger.info("password_reset_requested", user_id=str(user.id))

            # TODO: In production, send email with reset token instead of returning it
            # For development/testing, include token in response
            from src.core.config import settings

            if settings.is_development:
                return {
                    "message": "If an account with that email exists, a password reset link has been sent",
                    "reset_token": reset_token,  # Only for development/testing
                }

        # Always return success to prevent email enumeration
        return {
            "message": "If an account with that email exists, a password reset link has been sent"
        }

    except Exception as e:
        logger.error("password_reset_request_error", error=str(e))
        # Still return success to prevent information leakage
        return {
            "message": "If an account with that email exists, a password reset link has been sent"
        }


@router.post(
    "/password/reset/confirm",
    summary="Confirm Password Reset",
    description="Confirm password reset with token",
)
async def confirm_password_reset(
    reset_data: PasswordResetConfirm, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
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
    try:
        from sqlalchemy import select

        from src.core.security import get_password_hash, verify_token

        # Verify the reset token
        try:
            payload = verify_token(reset_data.token, "password_reset")
            user_id = payload.get("sub")

            if not user_id:
                raise AuthenticationError("Invalid reset token")

        except Exception as e:
            logger.warning("password_reset_token_invalid", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token",
            )

        # Get user from database
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token",
            )

        # Update password
        user.password_hash = get_password_hash(reset_data.new_password)
        user.failed_login_attempts = 0  # Reset failed attempts
        user.locked_until = None  # Unlock account if locked
        await db.commit()

        # Log successful password reset
        audit_log(
            action="password_reset_completed",
            resource="user",
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            success=True,
        )

        logger.info("password_reset_completed", user_id=str(user.id))

        return {"message": "Password has been reset successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("password_reset_confirm_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset failed",
        )


@router.post(
    "/email/resend-verification",
    summary="Resend Email Verification",
    description="Resend email verification token",
)
async def resend_email_verification(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """
    Resend email verification token for current user.

    Args:
        request: FastAPI request object
        current_user: Current authenticated user
        db: Database session

    Returns:
        Dict: Success message

    Raises:
        HTTPException: If user is already verified or resend fails
    """
    try:
        if current_user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is already verified",
            )

        from src.core.security import create_email_verification_token

        # Generate verification token
        verification_token = create_email_verification_token(str(current_user.id))

        # Log the event
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("User-Agent")

        audit_log(
            action="email_verification_resent",
            resource="user",
            user_id=str(current_user.id),
            tenant_id=str(current_user.tenant_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
        )

        logger.info("email_verification_resent", user_id=str(current_user.id))

        # TODO: In production, send email with verification token instead of returning it
        # For development/testing, include token in response
        from src.core.config import settings

        if settings.is_development:
            return {
                "message": "Verification email has been sent",
                "verification_token": verification_token,  # Only for development/testing
            }

        return {"message": "Verification email has been sent"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "email_verification_resend_error",
            user_id=str(current_user.id),
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to resend verification email",
        )


@router.post(
    "/email/verify",
    summary="Verify Email",
    description="Verify user email with token",
)
async def verify_email(
    request: Request,
    verification_data: EmailVerificationRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """
    Verify user email with verification token.

    Args:
        request: FastAPI request object
        verification_data: Email verification data
        db: Database session

    Returns:
        Dict: Success message

    Raises:
        HTTPException: If verification fails
    """
    try:
        from sqlalchemy import select

        from src.core.security import verify_token

        # Verify the verification token
        try:
            payload = verify_token(verification_data.token, "email_verification")
            user_id = payload.get("sub")

            if not user_id:
                raise AuthenticationError("Invalid verification token")

        except Exception as e:
            logger.warning("email_verification_token_invalid", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token",
            )

        # Get user from database
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token",
            )

        if user.is_verified:
            return {"message": "Email is already verified"}

        # Mark user as verified
        user.is_verified = True
        await db.commit()

        # Log successful email verification
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("User-Agent")

        audit_log(
            action="email_verified",
            resource="user",
            user_id=str(user.id),
            tenant_id=str(user.tenant_id),
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
        )

        logger.info("email_verified", user_id=str(user.id))

        return {"message": "Email has been verified successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("email_verification_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Email verification failed",
        )
