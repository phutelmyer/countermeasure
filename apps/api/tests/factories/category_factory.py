"""
Factory for Category model.
"""

import factory
from faker import Faker

from src.db.models.taxonomy.category import Category
from .base_factory import BaseFactory
from .tenant_factory import TenantFactory

fake = Faker()


class CategoryFactory(BaseFactory):
    """Factory for creating test Category instances."""

    class Meta:
        model = Category

    tenant = factory.SubFactory(TenantFactory)
    name = factory.Iterator([
        "Malware", "APT", "Insider Threat", "Data Exfiltration",
        "Lateral Movement", "Persistence", "Defense Evasion"
    ])
    description = factory.LazyAttribute(
        lambda obj: f"Detection category for {obj.name}"
    )
    color = factory.Faker("color")
    icon = factory.Iterator([
        "shield-alt", "bug", "user-secret", "download",
        "arrows-alt", "clock", "eye-slash"
    ])
    is_active = True

    @factory.post_generation
    def set_tenant_id(self, create, extracted, **kwargs):
        """Set tenant_id from the created tenant."""
        if create and self.tenant:
            self.tenant_id = self.tenant.id