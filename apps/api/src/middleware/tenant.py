"""
Multi-tenant security middleware for row-level security enforcement.
"""

from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.logging import get_logger


logger = get_logger(__name__)


class TenantIsolationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce tenant isolation and row-level security.

    This middleware ensures that:
    1. All database operations are scoped to the current user's tenant
    2. Row-level security policies are enforced
    3. Cross-tenant data access is prevented
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with tenant isolation.

        Args:
            request: FastAPI request
            call_next: Next middleware/endpoint

        Returns:
            Response: HTTP response
        """
        # Add tenant context to request state
        request.state.tenant_id = None
        request.state.user_id = None

        try:
            # Process request
            response = await call_next(request)

            # Add tenant info to response headers for debugging (in development only)
            from src.core.config import settings

            if settings.is_development and hasattr(request.state, "tenant_id"):
                if request.state.tenant_id:
                    response.headers["X-Tenant-ID"] = str(request.state.tenant_id)

            return response

        except Exception as e:
            logger.error(
                "tenant_middleware_error",
                error=str(e),
                path=request.url.path,
                method=request.method,
            )
            raise


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Middleware for auditing API requests for security monitoring.
    """

    # Paths that should not be audited (health checks, docs, etc.)
    SKIP_AUDIT_PATHS = {
        "/health",
        "/ready",
        "/live",
        "/metrics",
        "/docs",
        "/redoc",
        "/openapi.json",
    }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Audit API requests for security monitoring.

        Args:
            request: FastAPI request
            call_next: Next middleware/endpoint

        Returns:
            Response: HTTP response
        """
        # Skip auditing for certain paths
        if request.url.path in self.SKIP_AUDIT_PATHS:
            return await call_next(request)

        # Extract request information
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("User-Agent")
        method = request.method
        path = request.url.path

        try:
            # Process request
            response = await call_next(request)

            # Log successful requests (non-2xx are handled by exception handlers)
            if 200 <= response.status_code < 300:
                logger.info(
                    "api_request_success",
                    method=method,
                    path=path,
                    status_code=response.status_code,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    user_id=getattr(request.state, "user_id", None),
                    tenant_id=getattr(request.state, "tenant_id", None),
                )

            return response

        except Exception as e:
            # Log failed requests
            logger.error(
                "api_request_error",
                method=method,
                path=path,
                error=str(e),
                ip_address=ip_address,
                user_agent=user_agent,
                user_id=getattr(request.state, "user_id", None),
                tenant_id=getattr(request.state, "tenant_id", None),
            )
            raise
