"""
Factory for Actor model.
"""

import factory
from faker import Faker

from src.db.models.intel.actor import Actor
from .base_factory import BaseFactory
from .tenant_factory import TenantFactory

fake = Faker()


class ActorFactory(BaseFactory):
    """Factory for creating test Actor instances."""

    class Meta:
        model = Actor

    tenant = factory.SubFactory(TenantFactory)
    name = factory.Sequence(lambda n: f"APT{n:02d}")
    aliases = factory.List([
        factory.Faker("company")
        for _ in range(2)
    ])
    description = factory.Faker("text", max_nb_chars=1000)
    origin_country = factory.Faker("country_code")
    motivation = factory.Iterator([
        "Financial", "Espionage", "Hacktivism", "Nation-state", "Cyber-crime"
    ])
    sophistication = factory.Iterator(["Novice", "Practitioner", "Expert", "Innovator"])
    resource_level = factory.Iterator(["Individual", "Club", "Contest", "Team", "Organization", "Government"])
    first_seen = factory.Faker("date_time_this_decade")
    last_seen = factory.Faker("date_time_this_year")
    is_active = True
    confidence_level = factory.Faker("pyfloat", min_value=0.0, max_value=1.0)

    @factory.post_generation
    def set_tenant_id(self, create, extracted, **kwargs):
        """Set tenant_id from the created tenant."""
        if create and self.tenant:
            self.tenant_id = self.tenant.id


class NationStateActorFactory(ActorFactory):
    """Factory for nation-state actors."""

    motivation = "Nation-state"
    sophistication = "Expert"
    resource_level = "Government"
    confidence_level = 0.8


class CybercriminalActorFactory(ActorFactory):
    """Factory for cybercriminal actors."""

    motivation = "Financial"
    sophistication = "Practitioner"
    resource_level = "Organization"