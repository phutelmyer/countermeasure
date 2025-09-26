"""
Factory for Tag model.
"""

import factory
from faker import Faker

from src.db.models.taxonomy.tag import Tag
from .base_factory import BaseFactory
from .tenant_factory import TenantFactory

fake = Faker()


class TagFactory(BaseFactory):
    """Factory for creating test Tag instances."""

    class Meta:
        model = Tag

    tenant = factory.SubFactory(TenantFactory)
    name = factory.Iterator([
        "attack.execution", "attack.persistence", "attack.defense-evasion",
        "attack.credential-access", "attack.discovery", "attack.lateral-movement",
        "attack.collection", "attack.command-and-control", "attack.exfiltration",
        "attack.impact", "windows", "linux", "macos", "network", "endpoint"
    ])
    description = factory.LazyAttribute(
        lambda obj: f"Tag for {obj.name}"
    )
    color = factory.Faker("color")
    is_active = True

    @factory.post_generation
    def set_tenant_id(self, create, extracted, **kwargs):
        """Set tenant_id from the created tenant."""
        if create and self.tenant:
            self.tenant_id = self.tenant.id