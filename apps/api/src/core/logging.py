"""
Structured logging configuration for Countermeasure API.
Provides JSON logging with correlation IDs and security-conscious log handling.
"""

import logging
import sys
import uuid
from contextvars import ContextVar
from typing import Any

import structlog
from structlog.typing import EventDict, Processor

from .config import settings


# Context variable for request correlation ID
correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def add_correlation_id(
    logger: Any, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add correlation ID to log entries."""
    current_correlation_id = correlation_id.get()
    if current_correlation_id:
        event_dict["correlation_id"] = current_correlation_id
    return event_dict


def add_security_context(
    logger: Any, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add security context to log entries."""
    # Don't log sensitive fields
    sensitive_fields = {
        "password",
        "token",
        "secret",
        "key",
        "authorization",
        "cookie",
        "session",
        "api_key",
    }

    # Recursively sanitize event dictionary
    def sanitize_dict(d: dict[str, Any]) -> dict[str, Any]:
        sanitized = {}
        for key, value in d.items():
            lower_key = key.lower()
            if any(sensitive in lower_key for sensitive in sensitive_fields):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = sanitize_dict(value)
            elif isinstance(value, str) and len(value) > 1000:
                # Truncate very long strings to prevent log injection
                sanitized[key] = value[:1000] + "...[TRUNCATED]"
            else:
                sanitized[key] = value
        return sanitized

    return sanitize_dict(event_dict)


def setup_logging() -> None:
    """Configure structured logging for the application."""

    # Define processors based on environment
    processors: list[Processor] = [
        # Add correlation ID to all log entries
        add_correlation_id,
        # Add security context and sanitization
        add_security_context,
        # Add standard fields
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
    ]

    if settings.is_development:
        # Development: Pretty console output
        processors.extend([structlog.dev.ConsoleRenderer(colors=True)])
    else:
        # Production: JSON output
        processors.extend(
            [
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer(),
            ]
        )

    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(settings.log_level)
        ),
        logger_factory=structlog.WriteLoggerFactory(
            file=sys.stdout if settings.is_development else sys.stderr
        ),
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout if settings.is_development else sys.stderr,
        level=getattr(logging, settings.log_level),
    )

    # Silence noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a structured logger instance."""
    return structlog.get_logger(name)


def set_correlation_id(request_id: str | None = None) -> str:
    """Set correlation ID for the current context."""
    if request_id is None:
        request_id = str(uuid.uuid4())
    correlation_id.set(request_id)
    return request_id


def get_correlation_id() -> str | None:
    """Get current correlation ID."""
    return correlation_id.get()


# Security-focused audit logger
audit_logger = structlog.get_logger("audit")


def audit_log(
    action: str,
    resource: str,
    user_id: str | None = None,
    tenant_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    success: bool = True,
    details: dict[str, Any] | None = None,
) -> None:
    """Log security-relevant events for audit purposes."""
    audit_logger.info(
        "audit_event",
        action=action,
        resource=resource,
        user_id=user_id,
        tenant_id=tenant_id,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success,
        details=details or {},
    )
