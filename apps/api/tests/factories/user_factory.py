"""
Factory for User model.
"""

import factory
from faker import Faker

from src.db.models.system.user import User
from src.core.security import get_password_hash
from .base_factory import BaseFactory
from .tenant_factory import TenantFactory

fake = Faker()


class UserFactory(BaseFactory):
    """Factory for creating test User instances."""

    class Meta:
        model = User

    tenant = factory.SubFactory(TenantFactory)
    email = factory.Sequence(lambda n: f"user{n}@test.com")
    password_hash = factory.LazyFunction(lambda: get_password_hash("TestPassword123!"))
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    role = "viewer"
    is_active = True
    is_verified = True
    is_superuser = False
    mfa_enabled = False
    settings = factory.Dict({
        "notifications": True,
        "timezone": "UTC",
        "language": "en"
    })
    failed_login_attempts = 0

    @factory.post_generation
    def set_tenant_id(self, create, extracted, **kwargs):
        """Set tenant_id from the created tenant."""
        if create and self.tenant:
            self.tenant_id = self.tenant.id


class AdminUserFactory(UserFactory):
    """Factory for creating admin test User instances."""

    role = "admin"
    is_superuser = True


class SuperUserFactory(UserFactory):
    """Factory for creating superuser test User instances."""

    role = "superuser"
    is_superuser = True