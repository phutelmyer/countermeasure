"""
Prometheus metrics middleware for monitoring API performance and health.
"""

import time
from typing import Any, Callable

from fastapi import Request, Response
from prometheus_client import (
    Counter,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
)
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.logging import get_logger


logger = get_logger(__name__)

# Create custom registry for better control
metrics_registry = CollectorRegistry()

# HTTP request metrics
http_requests_total = Counter(
    "http_requests_total",
    "Total number of HTTP requests",
    ["method", "endpoint", "status_code", "tenant_id"],
    registry=metrics_registry,
)

http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint", "status_code"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=metrics_registry,
)

# Authentication metrics
auth_attempts_total = Counter(
    "auth_attempts_total",
    "Total authentication attempts",
    ["action", "success"],
    registry=metrics_registry,
)

# Database metrics
db_operations_total = Counter(
    "db_operations_total",
    "Total database operations",
    ["operation", "table", "success"],
    registry=metrics_registry,
)

db_operation_duration_seconds = Histogram(
    "db_operation_duration_seconds",
    "Database operation duration in seconds",
    ["operation", "table"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    registry=metrics_registry,
)

# Business metrics
detections_total = Counter(
    "detections_total",
    "Total number of detections",
    ["action", "tenant_id"],
    registry=metrics_registry,
)

collection_runs_total = Counter(
    "collection_runs_total",
    "Total collection runs",
    ["collector_type", "success"],
    registry=metrics_registry,
)

collection_duration_seconds = Histogram(
    "collection_duration_seconds",
    "Collection run duration in seconds",
    ["collector_type"],
    buckets=(1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0),
    registry=metrics_registry,
)


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware to collect HTTP request metrics."""

    def __init__(self, app: Any):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and collect metrics."""
        start_time = time.time()

        # Extract basic request info
        method = request.method
        path = request.url.path

        # Normalize endpoint for metrics (remove IDs)
        endpoint = self._normalize_endpoint(path)

        # Get tenant ID if available
        tenant_id = getattr(request.state, "tenant_id", "unknown")

        try:
            # Process request
            response = await call_next(request)
            status_code = str(response.status_code)

        except Exception as e:
            # Handle exceptions
            logger.error("request_processing_error", error=str(e), path=path)
            status_code = "500"
            raise

        finally:
            # Calculate duration
            duration = time.time() - start_time

            # Record metrics
            http_requests_total.labels(
                method=method,
                endpoint=endpoint,
                status_code=status_code,
                tenant_id=tenant_id,
            ).inc()

            http_request_duration_seconds.labels(
                method=method,
                endpoint=endpoint,
                status_code=status_code,
            ).observe(duration)

            # Log slow requests
            if duration > 1.0:
                logger.warning(
                    "slow_request",
                    method=method,
                    path=path,
                    duration=duration,
                    status_code=status_code,
                )

        return response

    def _normalize_endpoint(self, path: str) -> str:
        """Normalize endpoint path for metrics."""
        # Replace UUIDs and IDs with placeholders
        import re

        # Replace UUIDs
        path = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{uuid}",
            path,
            flags=re.IGNORECASE,
        )

        # Replace numeric IDs
        path = re.sub(r"/\d+", "/{id}", path)

        # Limit path length to prevent cardinality explosion
        if len(path) > 100:
            path = path[:100] + "..."

        return path


def get_metrics() -> str:
    """Generate Prometheus metrics output."""
    return generate_latest(metrics_registry).decode("utf-8")


def get_metrics_content_type() -> str:
    """Get the content type for Prometheus metrics."""
    return CONTENT_TYPE_LATEST


# Utility functions for business metrics
def record_auth_attempt(action: str, success: bool) -> None:
    """Record authentication attempt."""
    auth_attempts_total.labels(
        action=action,
        success=str(success).lower(),
    ).inc()


def record_db_operation(operation: str, table: str, duration: float, success: bool) -> None:
    """Record database operation."""
    db_operations_total.labels(
        operation=operation,
        table=table,
        success=str(success).lower(),
    ).inc()

    if success:
        db_operation_duration_seconds.labels(
            operation=operation,
            table=table,
        ).observe(duration)


def record_detection_action(action: str, tenant_id: str) -> None:
    """Record detection-related action."""
    detections_total.labels(
        action=action,
        tenant_id=tenant_id,
    ).inc()


def record_collection_run(collector_type: str, duration: float, success: bool) -> None:
    """Record collection run."""
    collection_runs_total.labels(
        collector_type=collector_type,
        success=str(success).lower(),
    ).inc()

    if success:
        collection_duration_seconds.labels(
            collector_type=collector_type,
        ).observe(duration)