"""
Factory for Tenant model.
"""

import factory
from faker import Faker

from src.db.models.system.tenant import Tenant
from .base_factory import BaseFactory

fake = Faker()


class TenantFactory(BaseFactory):
    """Factory for creating test Tenant instances."""

    class Meta:
        model = Tenant

    name = factory.Sequence(lambda n: f"Test Tenant {n}")
    slug = factory.LazyAttribute(lambda obj: obj.name.lower().replace(" ", "-"))
    description = factory.Faker("text", max_nb_chars=200)
    settings = factory.Dict({
        "theme": "default",
        "features": ["detections", "actors", "mitre"],
        "retention_days": 90
    })
    is_active = True
    max_users = 100
    max_detections = 10000