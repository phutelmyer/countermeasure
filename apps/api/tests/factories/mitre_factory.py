"""
Factory for MITRE ATT&CK models.
"""

import factory
from faker import Faker

from src.db.models.framework.mitre import MitreTactic, MitreTechnique
from .base_factory import BaseFactory
from .tenant_factory import TenantFactory

fake = Faker()


class MitreTacticFactory(BaseFactory):
    """Factory for creating test MitreTactic instances."""

    class Meta:
        model = MitreTactic

    tactic_id = factory.Sequence(lambda n: f"TA{1000 + n:04d}")
    name = factory.Iterator([
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact"
    ])
    description = factory.LazyAttribute(
        lambda obj: f"MITRE ATT&CK tactic: {obj.name}"
    )
    url = factory.LazyAttribute(
        lambda obj: f"https://attack.mitre.org/tactics/{obj.tactic_id}/"
    )
    stix_uuid = factory.Faker("uuid4")


class MitreTechniqueFactory(BaseFactory):
    """Factory for creating test MitreTechnique instances."""

    class Meta:
        model = MitreTechnique

    technique_id = factory.Sequence(lambda n: f"T{1000 + n:04d}")
    name = factory.Iterator([
        "Spearphishing Attachment", "PowerShell", "Registry Run Keys",
        "Process Injection", "Obfuscated Files", "Credential Dumping",
        "Network Service Scanning", "Remote Desktop Protocol"
    ])
    description = factory.LazyAttribute(
        lambda obj: f"MITRE ATT&CK technique: {obj.name}"
    )
    tactic = factory.SubFactory(MitreTacticFactory)
    tactic_id = factory.LazyAttribute(lambda obj: obj.tactic.tactic_id)
    url = factory.LazyAttribute(
        lambda obj: f"https://attack.mitre.org/techniques/{obj.technique_id}/"
    )
    stix_uuid = factory.Faker("uuid4")
    platforms = factory.List([
        factory.Iterator(["Windows", "Linux", "macOS"])
        for _ in range(2)
    ])
    data_sources = factory.List([
        factory.Iterator(["Process monitoring", "Network traffic", "File monitoring"])
        for _ in range(2)
    ])


class MitreSubTechniqueFactory(MitreTechniqueFactory):
    """Factory for creating test sub-technique instances."""

    technique_id = factory.Sequence(lambda n: f"T{1000}.{n:03d}")
    parent_technique = factory.SubFactory(MitreTechniqueFactory)
    parent_technique_id = factory.LazyAttribute(lambda obj: obj.parent_technique.technique_id if obj.parent_technique else None)
    name = factory.Iterator([
        "Spearphishing via Service", "Windows Command Shell",
        "Startup Folder", "Dynamic-link Library Injection"
    ])
    description = factory.LazyAttribute(
        lambda obj: f"MITRE ATT&CK sub-technique: {obj.name}"
    )