"""
Factory for Detection model.
"""

import factory
from faker import Faker

from src.db.models.detection.detection import Detection
from .base_factory import BaseFactory
from .tenant_factory import TenantFactory
from .severity_factory import SeverityFactory

fake = Faker()


class DetectionFactory(BaseFactory):
    """Factory for creating test Detection instances."""

    class Meta:
        model = Detection

    tenant = factory.SubFactory(TenantFactory)
    severity = factory.SubFactory(SeverityFactory)

    name = factory.Sequence(lambda n: f"Test Detection Rule {n}")
    description = factory.Faker("text", max_nb_chars=500)
    rule_content = factory.LazyFunction(
        lambda: """
title: Test Detection Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
        Image|endswith: '\\test.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
"""
    )
    rule_format = "sigma"
    visibility = "private"
    confidence_score = factory.Faker("pyfloat", min_value=0.0, max_value=1.0)
    performance_impact = factory.Iterator(["low", "medium", "high"])
    status = factory.Iterator(["draft", "testing", "active", "deprecated"])
    version = "1.0.0"
    author = factory.Faker("name")
    source_url = factory.Faker("url")
    platforms = factory.List([
        factory.Iterator(["Windows", "Linux", "macOS"])
    ])
    data_sources = factory.List([
        factory.Iterator(["Process Creation", "Network Connection", "File Monitoring"])
    ])
    false_positives = factory.List([
        factory.Faker("sentence", nb_words=4)
        for _ in range(2)
    ])
    log_sources = factory.List([
        "product:windows | category:process_creation | service:sysmon"
    ])

    @factory.post_generation
    def set_ids(self, create, extracted, **kwargs):
        """Set foreign key IDs from created objects."""
        if create:
            if self.tenant:
                self.tenant_id = self.tenant.id
            if self.severity:
                self.severity_id = self.severity.id


class SigmaDetectionFactory(DetectionFactory):
    """Factory for SIGMA detection rules."""

    rule_format = "sigma"
    rule_content = """
title: Suspicious Process Creation
id: 12345678-1234-5678-9012-123456789012
description: Detects suspicious process creation activity
references:
    - https://example.com/reference
author: Test Author
date: 2024/01/01
modified: 2024/01/01
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
        CommandLine|contains:
            - '-encoded'
            - 'bypass'
    condition: selection
falsepositives:
    - Administrative scripts
    - Legitimate automation
level: medium
"""


class YaraDetectionFactory(DetectionFactory):
    """Factory for YARA detection rules."""

    rule_format = "yara"
    rule_content = """
rule SuspiciousBinary
{
    meta:
        description = "Detects suspicious binary patterns"
        author = "Test Author"
        date = "2024-01-01"

    strings:
        $s1 = "suspicious_string_1" ascii
        $s2 = "suspicious_string_2" wide
        $hex = { 48 65 6C 6C 6F }

    condition:
        any of ($s*) or $hex
}
"""


class SuricataDetectionFactory(DetectionFactory):
    """Factory for Suricata detection rules."""

    rule_format = "suricata"
    rule_content = 'alert tcp any any -> $HOME_NET any (msg:"Test Rule"; content:"test"; sid:1000001; rev:1;)'