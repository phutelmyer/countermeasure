"""
Correlation ID middleware for request tracing and logging.
"""

import uuid
from typing import Any, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.logging import get_logger, set_correlation_id


logger = get_logger(__name__)


class CorrelationMiddleware(BaseHTTPMiddleware):
    """Middleware to handle correlation IDs for request tracing."""

    def __init__(self, app: Any, header_name: str = "X-Correlation-ID"):
        """
        Initialize correlation middleware.

        Args:
            app: FastAPI application
            header_name: Header name for correlation ID
        """
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and manage correlation ID."""
        # Get correlation ID from header or generate new one
        correlation_id = request.headers.get(self.header_name)

        if not correlation_id:
            correlation_id = str(uuid.uuid4())

        # Set correlation ID in context
        set_correlation_id(correlation_id)

        # Store in request state for access in endpoints
        request.state.correlation_id = correlation_id

        # Process request
        response = await call_next(request)

        # Add correlation ID to response headers
        response.headers[self.header_name] = correlation_id

        # Log request completion
        logger.debug(
            "request_completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            correlation_id=correlation_id,
        )

        return response