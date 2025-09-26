"""
Core authentication functions and dependencies.
"""

# Re-export authentication dependencies from the v1 API
from src.api.v1.dependencies.auth import (
    RoleChecker,
    get_current_active_user,
    get_current_user,
    require_role,
)


__all__ = ["RoleChecker", "get_current_active_user", "get_current_user", "require_role"]
