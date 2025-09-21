"""
Main FastAPI application entry point for Countermeasure API.
Configures the application, middleware, routes, and error handling.
"""

import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from src.core.config import settings
from src.core.exceptions import CountermeasureException
from src.core.logging import audit_log, get_logger, set_correlation_id, setup_logging

# Initialize logging
setup_logging()
logger = get_logger(__name__)


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


# Security and tenant middleware
from src.middleware.tenant import AuditMiddleware, TenantIsolationMiddleware

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
        allowed_hosts=["*"]  # TODO: Configure proper allowed hosts
    )


@app.middleware("http")
async def correlation_middleware(request: Request, call_next) -> Response:
    """Add correlation ID to requests and responses."""
    # Get or create correlation ID
    correlation_id = request.headers.get("X-Correlation-ID")
    request_id = set_correlation_id(correlation_id)

    # Process request
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time

    # Add correlation ID to response headers
    response.headers["X-Correlation-ID"] = request_id
    response.headers["X-Process-Time"] = str(process_time)

    # Log request
    logger.info(
        "http_request",
        method=request.method,
        url=str(request.url),
        status_code=response.status_code,
        process_time=process_time,
        user_agent=request.headers.get("User-Agent"),
        ip_address=request.client.host if request.client else None,
    )

    return response


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
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

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
async def internal_server_error_handler(request: Request, exc: Exception) -> JSONResponse:
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


# Health Check Endpoint
@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    """
    Health check endpoint for monitoring and load balancers.

    Returns:
        dict: Service health status and metadata
    """
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "timestamp": time.time(),
        "checks": {
            "api": "healthy",
            # TODO: Add database health check
            # TODO: Add Redis health check
            # TODO: Add external service health checks
        }
    }


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


# Metrics Endpoint (for Prometheus)
@app.get("/metrics", tags=["Monitoring"])
async def metrics() -> Response:
    """
    Prometheus metrics endpoint.

    Returns:
        Response: Prometheus-formatted metrics
    """
    # TODO: Implement Prometheus metrics collection
    return Response(
        content="# HELP countermeasure_info Application info\n"
                f"# TYPE countermeasure_info gauge\n"
                f"countermeasure_info{{version=\"{settings.app_version}\",environment=\"{settings.environment}\"}} 1\n",
        media_type="text/plain"
    )


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
from src.api.v1.router import api_router

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