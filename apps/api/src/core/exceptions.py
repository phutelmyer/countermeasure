"""
Custom exceptions for Countermeasure API.
Provides structured error handling with security considerations.
"""

from typing import Any, Dict, Optional


class CountermeasureException(Exception):
    """Base exception for all Countermeasure-specific errors."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        super().__init__(self.message)


class ValidationError(CountermeasureException):
    """Raised when data validation fails."""

    pass


class AuthenticationError(CountermeasureException):
    """Raised when authentication fails."""

    pass


class AuthorizationError(CountermeasureException):
    """Raised when authorization fails."""

    pass


class TenantIsolationError(CountermeasureException):
    """Raised when tenant isolation is violated."""

    pass


class ResourceNotFoundError(CountermeasureException):
    """Raised when a requested resource is not found."""

    pass


class ResourceConflictError(CountermeasureException):
    """Raised when a resource conflict occurs (e.g., duplicate creation)."""

    pass


class RateLimitExceededError(CountermeasureException):
    """Raised when rate limit is exceeded."""

    pass


class ExternalServiceError(CountermeasureException):
    """Raised when an external service fails."""

    pass


class DatabaseError(CountermeasureException):
    """Raised when a database operation fails."""

    pass


class ConfigurationError(CountermeasureException):
    """Raised when configuration is invalid."""

    pass


class SecurityError(CountermeasureException):
    """Raised when a security violation is detected."""

    pass