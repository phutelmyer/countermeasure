"""
Factory for SIGMA rule data.
"""

import factory
from faker import Faker
from typing import Dict, Any, List

fake = Faker()


class SigmaRuleFactory(factory.DictFactory):
    """Factory for creating SIGMA rule dictionaries."""

    title = factory.Sequence(lambda n: f"Test SIGMA Rule {n}")
    id = factory.Faker("uuid4")
    description = factory.Faker("text", max_nb_chars=200)
    author = factory.Faker("name")
    date = "2024/01/01"
    modified = "2024/09/22"

    @factory.lazy_attribute
    def logsource(self) -> Dict[str, str]:
        """Generate logsource configuration."""
        return {
            "category": fake.random_element([
                "process_creation", "network_connection", "file_event",
                "registry_event", "image_load", "dns"
            ]),
            "product": fake.random_element(["windows", "linux", "macos"])
        }

    @factory.lazy_attribute
    def detection(self) -> Dict[str, Any]:
        """Generate detection logic."""
        return {
            "selection": {
                "EventID": fake.random_int(min=1, max=100),
                "Image|endswith": f"\\{fake.word()}.exe"
            },
            "condition": "selection"
        }

    @factory.lazy_attribute
    def falsepositives(self) -> List[str]:
        """Generate false positives list."""
        return [
            fake.sentence(nb_words=4),
            fake.sentence(nb_words=3)
        ]

    level = factory.Iterator(["critical", "high", "medium", "low", "informational"])

    @factory.lazy_attribute
    def tags(self) -> List[str]:
        """Generate MITRE ATT&CK tags."""
        tactics = ["execution", "persistence", "defense_evasion", "credential_access"]
        techniques = ["t1059", "t1547", "t1027", "t1003"]

        return [
            f"attack.{fake.random_element(tactics)}",
            f"attack.{fake.random_element(techniques)}"
        ]


class PowerShellSigmaRuleFactory(SigmaRuleFactory):
    """Factory for PowerShell-specific SIGMA rules."""

    title = factory.Sequence(lambda n: f"Suspicious PowerShell Activity {n}")

    @factory.lazy_attribute
    def logsource(self) -> Dict[str, str]:
        return {
            "category": "process_creation",
            "product": "windows"
        }

    @factory.lazy_attribute
    def detection(self) -> Dict[str, Any]:
        return {
            "selection_powershell": {
                "Image|endswith": ["\\powershell.exe", "\\pwsh.exe"]
            },
            "selection_suspicious": {
                "CommandLine|contains": ["-encoded", "bypass", "hidden"]
            },
            "condition": "selection_powershell and selection_suspicious"
        }

    tags = ["attack.execution", "attack.t1059.001", "attack.defense_evasion"]


class NetworkSigmaRuleFactory(SigmaRuleFactory):
    """Factory for network-related SIGMA rules."""

    title = factory.Sequence(lambda n: f"Suspicious Network Connection {n}")

    @factory.lazy_attribute
    def logsource(self) -> Dict[str, str]:
        return {
            "category": "network_connection",
            "product": "windows"
        }

    @factory.lazy_attribute
    def detection(self) -> Dict[str, Any]:
        return {
            "selection": {
                "EventID": 3,
                "Initiated": True,
                "DestinationPort": fake.random_element([4444, 8080, 9999])
            },
            "condition": "selection"
        }

    tags = ["attack.command_and_control", "attack.t1071"]


class MalwareSigmaRuleFactory(SigmaRuleFactory):
    """Factory for malware detection SIGMA rules."""

    title = factory.Sequence(lambda n: f"Malware Detection Rule {n}")
    level = "high"

    @factory.lazy_attribute
    def logsource(self) -> Dict[str, str]:
        return {
            "category": "file_event",
            "product": "windows"
        }

    @factory.lazy_attribute
    def detection(self) -> Dict[str, Any]:
        malware_names = ["mimikatz", "cobalt", "empire", "meterpreter"]
        return {
            "selection": {
                "EventID": 11,
                "TargetFilename|contains": fake.random_element(malware_names)
            },
            "condition": "selection"
        }

    tags = ["attack.credential_access", "attack.t1003"]