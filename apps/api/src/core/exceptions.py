"""
Custom exceptions for Countermeasure API.
Provides structured error handling with security considerations.
"""

from typing import Any


class CountermeasureException(Exception):
    """Base exception for all Countermeasure-specific errors."""

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        super().__init__(self.message)


class ValidationError(CountermeasureException):
    """Raised when data validation fails."""



class AuthenticationError(CountermeasureException):
    """Raised when authentication fails."""



class AuthorizationError(CountermeasureException):
    """Raised when authorization fails."""



class TenantIsolationError(CountermeasureException):
    """Raised when tenant isolation is violated."""



class ResourceNotFoundError(CountermeasureException):
    """Raised when a requested resource is not found."""



class ResourceConflictError(CountermeasureException):
    """Raised when a resource conflict occurs (e.g., duplicate creation)."""



class RateLimitExceededError(CountermeasureException):
    """Raised when rate limit is exceeded."""



class ExternalServiceError(CountermeasureException):
    """Raised when an external service fails."""



class DatabaseError(CountermeasureException):
    """Raised when a database operation fails."""



class ConfigurationError(CountermeasureException):
    """Raised when configuration is invalid."""



class SecurityError(CountermeasureException):
    """Raised when a security violation is detected."""

