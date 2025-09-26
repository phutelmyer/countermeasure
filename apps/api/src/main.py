"""
Main FastAPI application entry point for Countermeasure API.
Configures the application, middleware, routes, and error handling.
"""

import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from src.core.config import settings
from src.core.exceptions import CountermeasureException
from src.core.logging import get_logger, set_correlation_id, setup_logging


# Initialize logging
setup_logging()
logger = get_logger(__name__)

# Initialize Sentry for error tracking
if settings.sentry_dsn:
    import sentry_sdk
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
    from sentry_sdk.integrations.asyncio import AsyncioIntegration

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.sentry_environment or settings.environment,
        integrations=[
            FastApiIntegration(auto_enabling_integrations=False),
            SqlalchemyIntegration(),
            AsyncioIntegration(),
        ],
        traces_sample_rate=settings.sentry_traces_sample_rate,
        send_default_pii=False,  # Don't send sensitive data
        attach_stacktrace=True,
        debug=settings.is_development,
    )
    logger.info("Sentry error tracking initialized", environment=settings.sentry_environment)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler."""
    logger.info("Starting Countermeasure API", version=settings.app_version)

    # Startup tasks
    try:
        # Initialize database and create default tenant
        from src.db.init_db import init_database

        await init_database()

        logger.info("Application startup completed")
        yield
    except Exception as e:
        logger.error("Application startup failed", error=str(e))
        raise
    finally:
        # Shutdown tasks
        logger.info("Shutting down Countermeasure API")
        from src.db.session import close_db_connections

        await close_db_connections()


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="Enterprise Threat Detection Confidence Platform",
    version=settings.app_version,
    debug=settings.debug,
    lifespan=lifespan,
    docs_url="/docs" if settings.is_development else None,
    redoc_url="/redoc" if settings.is_development else None,
    openapi_url="/openapi.json" if settings.is_development else None,
)


# Import all middleware
from src.middleware.correlation import CorrelationMiddleware
from src.middleware.metrics import MetricsMiddleware
from src.middleware.tenant import AuditMiddleware, TenantIsolationMiddleware

# Add middleware in order (last added = first executed)
app.add_middleware(MetricsMiddleware)
app.add_middleware(CorrelationMiddleware)
app.add_middleware(AuditMiddleware)
app.add_middleware(TenantIsolationMiddleware)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=settings.allowed_methods,
    allow_headers=settings.allowed_headers,
)

# Trusted Host Middleware (security)
if settings.is_production:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"],  # TODO: Configure proper allowed hosts
    )


# Correlation ID middleware is now handled by CorrelationMiddleware class above


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next) -> Response:
    """Add security headers to responses."""
    response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    if settings.is_production:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    return response


@app.exception_handler(CountermeasureException)
async def countermeasure_exception_handler(
    request: Request, exc: CountermeasureException
) -> JSONResponse:
    """Handle custom Countermeasure exceptions."""
    logger.warning(
        "countermeasure_exception",
        error_code=exc.error_code,
        message=exc.message,
        details=exc.details,
    )

    return JSONResponse(
        status_code=400,  # Default to 400, specific handlers can override
        content={
            "error": {
                "code": exc.error_code,
                "message": exc.message,
                "details": exc.details,
            }
        },
    )


@app.exception_handler(500)
async def internal_server_error_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Handle internal server errors."""
    logger.error("internal_server_error", error=str(exc), exc_info=True)

    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An internal server error occurred",
                "details": {} if settings.is_production else {"error": str(exc)},
            }
        },
    )


# Health and metrics endpoints moved to dedicated router


# Readiness Check Endpoint
@app.get("/ready", tags=["Health"])
async def readiness_check() -> dict:
    """
    Readiness check endpoint for Kubernetes deployments.

    Returns:
        dict: Service readiness status
    """
    # TODO: Implement actual readiness checks
    return {
        "status": "ready",
        "service": settings.app_name,
        "version": settings.app_version,
    }


# Liveness Check Endpoint
@app.get("/live", tags=["Health"])
async def liveness_check() -> dict:
    """
    Liveness check endpoint for Kubernetes deployments.

    Returns:
        dict: Service liveness status
    """
    return {
        "status": "alive",
        "service": settings.app_name,
        "version": settings.app_version,
    }


# Metrics endpoint moved to dedicated router


# Root endpoint
@app.get("/", tags=["Root"])
async def root() -> dict:
    """
    Root endpoint providing API information.

    Returns:
        dict: API metadata and status
    """
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "documentation": "/docs" if settings.is_development else None,
        "status": "operational",
    }


# Include API routers
from src.api.v1.endpoints.metrics import router as metrics_router
from src.api.v1.router import api_router

# Include metrics and health endpoints at root level
app.include_router(metrics_router, tags=["Monitoring"])

# Include main API router
app.include_router(api_router, prefix="/api/v1")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
        workers=settings.api_workers if not settings.api_reload else 1,
        log_level=settings.log_level.lower(),
    )
