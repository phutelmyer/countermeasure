"""
Core authentication functions and dependencies.
"""

# Re-export authentication dependencies from the v1 API
from src.api.v1.dependencies.auth import (
    get_current_user,
    get_current_active_user,
    require_role,
    RoleChecker
)

__all__ = [
    "get_current_user",
    "get_current_active_user",
    "require_role",
    "RoleChecker"
]