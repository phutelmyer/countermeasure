"""
Factory for Severity model.
"""

import factory
from faker import Faker

from src.db.models.taxonomy.severity import Severity
from .base_factory import BaseFactory
from .tenant_factory import TenantFactory

fake = Faker()


class SeverityFactory(BaseFactory):
    """Factory for creating test Severity instances."""

    class Meta:
        model = Severity

    tenant = factory.SubFactory(TenantFactory)
    name = factory.Iterator(["Critical", "High", "Medium", "Low", "Informational"])
    description = factory.LazyAttribute(
        lambda obj: f"Severity level: {obj.name}"
    )
    color = factory.Dict({
        "Critical": "#ff0000",
        "High": "#ff8800",
        "Medium": "#ffaa00",
        "Low": "#ffdd00",
        "Informational": "#0088ff"
    })
    score = factory.LazyAttribute(
        lambda obj: {
            "Critical": 90,
            "High": 70,
            "Medium": 50,
            "Low": 30,
            "Informational": 10
        }.get(obj.name, 50)
    )
    is_active = True

    @factory.post_generation
    def set_tenant_id(self, create, extracted, **kwargs):
        """Set tenant_id from the created tenant."""
        if create and self.tenant:
            self.tenant_id = self.tenant.id