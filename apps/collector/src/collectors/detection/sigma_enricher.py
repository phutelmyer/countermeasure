"""
SIGMA rule enricher for auto-categorization and metadata enhancement.
"""

from typing import Dict, List, Optional, Any
from uuid import UUID

from src.core.logging import get_logger
from src.schemas.detection import DetectionCreate
from src.core.api_client import CountermeasureClient

logger = get_logger(__name__)


class SigmaEnricher:
    """Enricher for SIGMA rules with automatic categorization and tagging."""

    # Mapping SIGMA logsource categories to our categories
    CATEGORY_MAPPING = {
        # Process-related
        "process_creation": "Endpoint/Process",
        "process": "Endpoint/Process",
        "sysmon": "Endpoint/Process",

        # Network-related
        "firewall": "Network/Firewall",
        "network_connection": "Network/Connection",
        "proxy": "Network/Proxy",
        "dns": "Network/DNS",
        "dhcp": "Network/DHCP",

        # File system
        "file_access": "Endpoint/File",
        "file_change": "Endpoint/File",
        "file_delete": "Endpoint/File",
        "file_event": "Endpoint/File",

        # Registry
        "registry_add": "Endpoint/Registry",
        "registry_delete": "Endpoint/Registry",
        "registry_event": "Endpoint/Registry",
        "registry_set": "Endpoint/Registry",

        # Authentication
        "authentication": "Security/Authentication",
        "logon": "Security/Authentication",

        # Web
        "webserver": "Network/Web",
        "apache": "Network/Web",
        "nginx": "Network/Web",
        "iis": "Network/Web",

        # Cloud
        "cloud": "Cloud/General",
        "aws": "Cloud/AWS",
        "azure": "Cloud/Azure",
        "gcp": "Cloud/GCP",
        "office365": "Cloud/Office365",

        # Applications
        "application": "Application/General",
        "powershell": "Application/PowerShell",
        "cmd": "Application/Command",

        # System
        "system": "System/General",
        "driver": "System/Driver",
        "service": "System/Service",

        # Other
        "image_load": "Endpoint/Image",
        "pipe_created": "Endpoint/Pipe",
        "wmi_event": "Endpoint/WMI",
    }

    # Common tags to extract and create
    TAG_MAPPING = {
        # ATT&CK tactics
        "attack.initial_access": "MITRE/Initial Access",
        "attack.execution": "MITRE/Execution",
        "attack.persistence": "MITRE/Persistence",
        "attack.privilege_escalation": "MITRE/Privilege Escalation",
        "attack.defense_evasion": "MITRE/Defense Evasion",
        "attack.credential_access": "MITRE/Credential Access",
        "attack.discovery": "MITRE/Discovery",
        "attack.lateral_movement": "MITRE/Lateral Movement",
        "attack.collection": "MITRE/Collection",
        "attack.command_and_control": "MITRE/Command and Control",
        "attack.exfiltration": "MITRE/Exfiltration",
        "attack.impact": "MITRE/Impact",

        # Common threat types
        "attack.g": "Threat Group",
        "attack.s": "Software",

        # Log sources
        "sysmon": "Sysmon",
        "powershell": "PowerShell",
        "zeek": "Zeek",
        "suricata": "Suricata",

        # Platforms
        "windows": "Windows",
        "linux": "Linux",
        "macos": "macOS",

        # Criticality
        "critical": "Critical",
        "high": "High Severity",
        "low": "Low Severity",
    }

    def __init__(self, api_client: CountermeasureClient):
        """
        Initialize enricher with API client.

        Args:
            api_client: Countermeasure API client
        """
        self.api_client = api_client

    def _categorize_by_logsource(self, sigma_metadata: Dict[str, Any]) -> List[str]:
        """
        Determine categories based on SIGMA logsource.

        Args:
            sigma_metadata: SIGMA rule metadata

        Returns:
            List of category names
        """
        categories = []

        # Use structured logsource fields
        category = sigma_metadata.get('logsource_category', '').lower()
        product = sigma_metadata.get('logsource_product', '').lower()
        service = sigma_metadata.get('logsource_service', '').lower()

        # Check category
        if category in self.CATEGORY_MAPPING:
            categories.append(self.CATEGORY_MAPPING[category])

        # Enhanced product categorization
        if product == 'windows':
            if 'Endpoint' not in str(categories):
                categories.append('Endpoint/Windows')
        elif product == 'linux':
            if 'Endpoint' not in str(categories):
                categories.append('Endpoint/Linux')
        elif product == 'macos':
            if 'Endpoint' not in str(categories):
                categories.append('Endpoint/macOS')
        elif product in ['aws', 'azure', 'gcp', 'office365']:
            categories.append(f'Cloud/{product.upper()}')
        elif product in ['apache', 'nginx', 'iis']:
            categories.append('Network/Web')
        elif product in ['palo_alto', 'checkpoint', 'fortigate']:
            categories.append('Network/Firewall')

        # Enhanced service categorization
        if service in self.CATEGORY_MAPPING:
            categories.append(self.CATEGORY_MAPPING[service])
        elif service:
            # Custom service categorization
            if 'dns' in service:
                categories.append('Network/DNS')
            elif 'web' in service or 'http' in service:
                categories.append('Network/Web')
            elif 'auth' in service or 'login' in service:
                categories.append('Security/Authentication')
            elif 'powershell' in service:
                categories.append('Application/PowerShell')
            elif 'sysmon' in service:
                categories.append('Endpoint/Sysmon')

        # Add platform-specific categories based on file path
        file_path = sigma_metadata.get('file_path', '')
        if '/windows/' in file_path and 'Windows' not in str(categories):
            categories.append('Endpoint/Windows')
        elif '/linux/' in file_path and 'Linux' not in str(categories):
            categories.append('Endpoint/Linux')
        elif '/macos/' in file_path and 'macOS' not in str(categories):
            categories.append('Endpoint/macOS')
        elif '/cloud/' in file_path:
            categories.append('Cloud/General')
        elif '/network/' in file_path:
            categories.append('Network/General')

        # Default fallback
        if not categories:
            categories.append('SIGMA/Uncategorized')

        return list(set(categories))  # Remove duplicates

    def _extract_relevant_tags(self, sigma_metadata: Dict[str, Any]) -> List[str]:
        """
        Extract relevant tags from SIGMA rule metadata.

        Args:
            sigma_metadata: SIGMA rule metadata

        Returns:
            List of tag names
        """
        tags = []
        sigma_tags = sigma_metadata.get('all_tags', [])

        for tag in sigma_tags:
            # Direct mapping
            if tag in self.TAG_MAPPING:
                tags.append(self.TAG_MAPPING[tag])
            # Enhanced MITRE technique handling
            elif tag.startswith('attack.'):
                if tag.startswith('attack.t'):
                    # Technique ID - extract and format properly
                    technique_id = tag.replace('attack.', '').upper()
                    tags.append(f'MITRE/{technique_id}')
                elif any(tactic in tag for tactic in ['initial_access', 'execution', 'persistence',
                        'privilege_escalation', 'defense_evasion', 'credential_access',
                        'discovery', 'lateral_movement', 'collection', 'command_and_control',
                        'exfiltration', 'impact']):
                    # Already handled in TAG_MAPPING
                    pass
                else:
                    # Generic ATT&CK tag
                    tags.append('MITRE/ATT&CK')

        # Add product/platform tags from logsource
        product = sigma_metadata.get('logsource_product', '').lower()
        if product:
            if product == 'windows':
                tags.append('Windows')
            elif product == 'linux':
                tags.append('Linux')
            elif product == 'macos':
                tags.append('macOS')
            elif product in ['aws', 'azure', 'gcp']:
                tags.append('Cloud')
                tags.append(product.upper())

        # Add service tags from logsource
        service = sigma_metadata.get('logsource_service', '').lower()
        if service:
            if service == 'sysmon':
                tags.append('Sysmon')
            elif service == 'powershell':
                tags.append('PowerShell')
            elif 'dns' in service:
                tags.append('DNS')
            elif 'web' in service or 'http' in service:
                tags.append('Web')

        # Add tags based on file path
        file_path = sigma_metadata.get('file_path', '')
        if '/windows/' in file_path:
            tags.append('Windows')
        elif '/linux/' in file_path:
            tags.append('Linux')
        elif '/macos/' in file_path:
            tags.append('macOS')
        elif '/cloud/' in file_path:
            tags.append('Cloud')
        elif '/network/' in file_path:
            tags.append('Network')

        # Add SIGMA source and date info
        tags.append('SIGMA')
        sigma_date = sigma_metadata.get('sigma_date', '')
        if sigma_date:
            # Handle both string and date objects
            date_str = str(sigma_date) if sigma_date else ''
            if '2024' in date_str:
                tags.append('SIGMA/2024')
            elif '2023' in date_str:
                tags.append('SIGMA/2023')

        return list(set(tags))  # Remove duplicates

    async def enrich_detection(self, detection: DetectionCreate) -> DetectionCreate:
        """
        Enrich a single detection with categories and tags.

        Args:
            detection: Detection to enrich

        Returns:
            Enriched detection
        """
        try:
            # Get SIGMA metadata
            sigma_metadata = getattr(detection, '_sigma_metadata', {})

            # Determine categories
            category_names = self._categorize_by_logsource(sigma_metadata)
            category_ids = []

            for category_name in category_names:
                category_id = await self.api_client.get_or_create_category(
                    name=category_name,
                    description=f"Auto-generated category for {category_name} rules"
                )
                if category_id:
                    category_ids.append(category_id)

            # Determine tags
            tag_names = self._extract_relevant_tags(sigma_metadata)
            tag_ids = []

            for tag_name in tag_names:
                tag_id = await self.api_client.get_or_create_tag(
                    name=tag_name,
                    description=f"Auto-generated tag for {tag_name}"
                )
                if tag_id:
                    tag_ids.append(tag_id)

            # Update detection
            detection.category_ids = category_ids
            detection.tag_ids = tag_ids

            # Set confidence score if available
            confidence_score = sigma_metadata.get('confidence_score')
            if confidence_score is not None:
                detection.confidence_score = confidence_score

            logger.debug(
                f"Enriched detection '{detection.name}' with "
                f"{len(category_ids)} categories and {len(tag_ids)} tags"
            )

            return detection

        except Exception as e:
            logger.error(f"Error enriching detection '{detection.name}': {str(e)}")
            return detection

    async def enrich_detections(self, detections: List[DetectionCreate]) -> List[DetectionCreate]:
        """
        Enrich multiple detections with categories and tags.

        Args:
            detections: List of detections to enrich

        Returns:
            List of enriched detections
        """
        enriched = []

        for detection in detections:
            enriched_detection = await self.enrich_detection(detection)
            enriched.append(enriched_detection)

        logger.info(f"Enriched {len(enriched)} detections with metadata")
        return enriched