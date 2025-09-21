"""
SIGMA rule parser for converting YAML to Detection model.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from uuid import UUID

import yaml
from src.core.logging import get_logger
from src.schemas.detection import DetectionCreate

logger = get_logger(__name__)


class SigmaParser:
    """Parser for SIGMA rule YAML files."""

    # Mapping SIGMA levels to our severity names
    SEVERITY_MAPPING = {
        "informational": "Low",
        "low": "Medium",
        "medium": "High",
        "high": "Critical",
        "critical": "Critical"
    }

    # Mapping SIGMA statuses to our status values
    STATUS_MAPPING = {
        "stable": "active",
        "test": "testing",
        "experimental": "draft",
        "testing": "testing",
        "draft": "draft",
        "deprecated": "deprecated"
    }

    def __init__(self, severities: Dict[str, UUID]):
        """
        Initialize parser with severity mappings.

        Args:
            severities: Dict mapping severity names to UUIDs
        """
        self.severities = severities

    async def parse_rule_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse a single SIGMA rule YAML file.

        Args:
            file_path: Path to the YAML file

        Returns:
            Parsed rule data or None if parsing failed
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Parse YAML
            rule_data = yaml.safe_load(content)

            if not isinstance(rule_data, dict):
                logger.warning(f"Invalid YAML structure in {file_path}")
                return None

            # Add file metadata
            rule_data['_file_path'] = str(file_path)
            rule_data['_file_name'] = file_path.name
            rule_data['_original_content'] = content

            return rule_data

        except yaml.YAMLError as e:
            logger.warning(f"YAML parsing error in {file_path}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {str(e)}")
            return None

    def _extract_mitre_techniques(self, tags: List[str]) -> List[str]:
        """
        Extract MITRE ATT&CK technique IDs from tags.

        Args:
            tags: List of rule tags

        Returns:
            List of MITRE technique IDs
        """
        techniques = []

        for tag in tags:
            # Look for attack.t1234 or attack.t1234.001 patterns
            if tag.startswith('attack.t'):
                technique_id = tag.replace('attack.', '').upper()
                techniques.append(technique_id)
            # Also check for plain T1234 format
            elif re.match(r'^T\d{4}(\.\d{3})?$', tag.upper()):
                techniques.append(tag.upper())
            # Handle MITRE.T1234 format (some rules use this)
            elif tag.upper().startswith('MITRE.T'):
                technique_id = tag.replace('MITRE.', '').replace('mitre.', '').upper()
                if re.match(r'^T\d{4}(\.\d{3})?$', technique_id):
                    techniques.append(technique_id)
            # Handle technique.T1234 format
            elif 'T' in tag.upper() and re.search(r'T\d{4}(\.\d{3})?', tag.upper()):
                match = re.search(r'T\d{4}(\.\d{3})?', tag.upper())
                if match:
                    techniques.append(match.group())

        return list(set(techniques))  # Remove duplicates

    def _determine_confidence_score(self, rule_data: Dict[str, Any]) -> float:
        """
        Calculate confidence score based on rule quality indicators.

        Args:
            rule_data: Parsed rule data

        Returns:
            Confidence score between 0.0 and 1.0
        """
        score = 0.5  # Base score

        # Status indicators
        status = rule_data.get('status', '').lower()
        if status == 'stable':
            score += 0.3
        elif status == 'test':
            score += 0.1
        elif status == 'experimental':
            score -= 0.1

        # Has MITRE mapping
        tags = rule_data.get('tags', [])
        if any(tag.startswith('attack.') for tag in tags):
            score += 0.2

        # Has references
        if rule_data.get('references'):
            score += 0.1

        # Has detailed description
        description = rule_data.get('description', '')
        if len(description) > 100:
            score += 0.1

        # Detection complexity (more complex = higher confidence)
        detection = rule_data.get('detection', {})
        if len(detection) > 2:  # More than just condition and one selection
            score += 0.1

        # Ensure score is within bounds
        return max(0.0, min(1.0, score))

    def _map_performance_impact(self, rule_data: Dict[str, Any]) -> str:
        """
        Determine performance impact based on rule characteristics.

        Args:
            rule_data: Parsed rule data

        Returns:
            Performance impact: low, medium, or high
        """
        detection = rule_data.get('detection', {})

        # Check for wildcards and regex patterns
        rule_content = str(detection)
        wildcard_count = rule_content.count('*')
        regex_patterns = len(re.findall(r'[|\[\]{}()^$.]', rule_content))

        if wildcard_count > 5 or regex_patterns > 10:
            return "high"
        elif wildcard_count > 2 or regex_patterns > 5:
            return "medium"
        else:
            return "low"

    def _extract_platforms(self, rule_data: Dict[str, Any]) -> List[str]:
        """
        Extract platform information from SIGMA rule.

        Args:
            rule_data: Parsed rule data

        Returns:
            List of platforms
        """
        platforms = []

        # Check logsource product
        logsource = rule_data.get('logsource', {})
        product = logsource.get('product', '').lower()

        if product == 'windows':
            platforms.append('Windows')
        elif product == 'linux':
            platforms.append('Linux')
        elif product == 'macos':
            platforms.append('macOS')

        # Check tags for platform indicators
        tags = rule_data.get('tags', [])
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower == 'windows' and 'Windows' not in platforms:
                platforms.append('Windows')
            elif tag_lower == 'linux' and 'Linux' not in platforms:
                platforms.append('Linux')
            elif tag_lower == 'macos' and 'macOS' not in platforms:
                platforms.append('macOS')

        # Check file path for platform hints
        file_path = rule_data.get('_file_path', '').lower()
        if '/windows/' in file_path and 'Windows' not in platforms:
            platforms.append('Windows')
        elif '/linux/' in file_path and 'Linux' not in platforms:
            platforms.append('Linux')
        elif '/macos/' in file_path and 'macOS' not in platforms:
            platforms.append('macOS')

        return platforms

    def _extract_data_sources(self, rule_data: Dict[str, Any]) -> List[str]:
        """
        Extract data source information from SIGMA rule.

        Args:
            rule_data: Parsed rule data

        Returns:
            List of data sources
        """
        data_sources = []

        # Extract from logsource
        logsource = rule_data.get('logsource', {})
        category = logsource.get('category', '')
        service = logsource.get('service', '')
        product = logsource.get('product', '')

        # Map categories to data sources
        if category:
            if category == 'process_creation':
                data_sources.append('Process Creation')
            elif category == 'network_connection':
                data_sources.append('Network Connection')
            elif category == 'file_event':
                data_sources.append('File Monitoring')
            elif category == 'registry_event':
                data_sources.append('Windows Registry')
            elif category == 'dns':
                data_sources.append('DNS')
            elif category == 'authentication':
                data_sources.append('Authentication Logs')
            elif category == 'firewall':
                data_sources.append('Firewall')
            elif category == 'webserver':
                data_sources.append('Web Logs')
            elif category == 'image_load':
                data_sources.append('Image Load')
            elif category == 'create_remote_thread':
                data_sources.append('Process Thread Creation')
            elif category == 'wmi_event':
                data_sources.append('WMI Event')

        # Map services to data sources
        if service:
            if service == 'sysmon':
                data_sources.append('Sysmon')
            elif service == 'security':
                data_sources.append('Windows Security')
            elif service == 'system':
                data_sources.append('Windows System')
            elif service == 'powershell':
                data_sources.append('PowerShell')
            elif 'dns' in service.lower():
                data_sources.append('DNS')
            elif 'auth' in service.lower():
                data_sources.append('Authentication Logs')

        # Map products to data sources
        if product:
            if product == 'zeek':
                data_sources.append('Zeek')
            elif product == 'suricata':
                data_sources.append('Suricata')
            elif product == 'apache':
                data_sources.append('Apache Logs')
            elif product == 'nginx':
                data_sources.append('Nginx Logs')
            elif product in ['aws', 'azure', 'gcp', 'office365']:
                data_sources.append(f'{product.upper()} Logs')

        return list(set(data_sources))  # Remove duplicates

    def _extract_false_positives(self, rule_data: Dict[str, Any]) -> List[str]:
        """
        Extract false positive information from SIGMA rule.

        Args:
            rule_data: Parsed rule data

        Returns:
            List of false positive scenarios
        """
        false_positives = []

        # Direct falsepositives field
        fp_list = rule_data.get('falsepositives', [])
        if isinstance(fp_list, list):
            false_positives.extend([fp.strip() for fp in fp_list if fp and fp.strip()])
        elif isinstance(fp_list, str):
            false_positives.append(fp_list.strip())

        return false_positives


    async def build_detection_create(self, rule_data: Dict[str, Any]) -> Optional[DetectionCreate]:
        """
        Build DetectionCreate object from parsed SIGMA rule data.

        Args:
            rule_data: Parsed rule data

        Returns:
            DetectionCreate object or None if conversion failed
        """
        try:
            # Required fields
            title = rule_data.get('title', '').strip()
            if not title:
                logger.warning(f"Rule missing title: {rule_data.get('_file_name', 'unknown')}")
                return None

            description = rule_data.get('description', '').strip()
            if not description:
                description = f"SIGMA rule: {title}"

            # Map severity
            sigma_level = rule_data.get('level', 'medium').lower()
            our_severity = self.SEVERITY_MAPPING.get(sigma_level, 'medium')
            severity_id = self.severities.get(our_severity)

            if not severity_id:
                logger.warning(f"Unknown severity mapping: {sigma_level} -> {our_severity}")
                severity_id = self.severities.get('medium')  # fallback

            if not severity_id:
                logger.error("No severity mappings available")
                return None

            # Extract author
            author = rule_data.get('author', 'SIGMA Community')
            if isinstance(author, list):
                author = ', '.join(author)

            # Build source URL from actual file path
            source_url = None
            file_path = rule_data.get('_file_path', '')

            # Extract relative path from the cloned repo and build GitHub URL
            if file_path:
                # Convert to Path object for easier manipulation
                path_obj = Path(file_path)

                # Find the 'rules' directory in the path and get everything after it
                path_parts = path_obj.parts
                try:
                    rules_idx = path_parts.index('rules')
                    # Everything from 'rules' onwards is the relative path in the repo
                    relative_path = '/'.join(path_parts[rules_idx:])
                    source_url = f"https://github.com/SigmaHQ/sigma/blob/master/{relative_path}"
                except ValueError:
                    # Fallback if 'rules' not found in path
                    logger.debug(f"'rules' directory not found in path: {file_path}")

            # If still no source_url, check references as fallback
            if not source_url:
                references = rule_data.get('references', [])
                for ref in references:
                    if isinstance(ref, str) and 'github.com/SigmaHQ/sigma' in ref:
                        source_url = ref
                        break

            # Extract tags for MITRE mapping
            tags = rule_data.get('tags', [])
            mitre_techniques = self._extract_mitre_techniques(tags)

            # Extract structured metadata
            platforms = self._extract_platforms(rule_data)
            data_sources = self._extract_data_sources(rule_data)
            false_positives = self._extract_false_positives(rule_data)

            # Create detection object
            detection_create = DetectionCreate(
                name=title,
                description=description,
                rule_content=rule_data.get('_original_content', yaml.dump(rule_data)),
                rule_format="sigma",
                severity_id=severity_id,
                visibility="community",  # SIGMA rules are community rules
                performance_impact=self._map_performance_impact(rule_data),
                status=self.STATUS_MAPPING.get(rule_data.get('status', 'testing').lower(), 'testing'),
                version=rule_data.get('version', '1.0.0'),
                author=author,
                source_url=source_url,
                category_ids=None,  # Will be set by enricher
                tag_ids=None,      # Will be set by enricher
                mitre_technique_ids=mitre_techniques,
                platforms=platforms if platforms else [],
                data_sources=data_sources if data_sources else [],
                false_positives=false_positives if false_positives else [],
                confidence_score=self._determine_confidence_score(rule_data)
            )

            # Store additional metadata for enricher
            logsource = rule_data.get('logsource', {})
            detection_create.__dict__['_sigma_metadata'] = {
                'logsource': logsource,
                'logsource_category': logsource.get('category', ''),
                'logsource_product': logsource.get('product', ''),
                'logsource_service': logsource.get('service', ''),
                'all_tags': tags,
                'mitre_tags': [tag for tag in tags if tag.startswith('attack.')],
                'platform_tags': [tag for tag in tags if tag in ['windows', 'linux', 'macos']],
                'references': rule_data.get('references', []),
                'falsepositives': rule_data.get('falsepositives', []),
                'file_path': file_path,
                'sigma_id': rule_data.get('id', ''),
                'sigma_date': rule_data.get('date', ''),
                'confidence_score': self._determine_confidence_score(rule_data)
            }

            return detection_create

        except Exception as e:
            logger.error(f"Error building detection from rule: {str(e)}")
            return None

    async def parse_rules(self, rule_files: List[Path]) -> List[DetectionCreate]:
        """
        Parse multiple SIGMA rule files.

        Args:
            rule_files: List of YAML file paths

        Returns:
            List of DetectionCreate objects
        """
        detections = []
        failed_count = 0

        for file_path in rule_files:
            try:
                # Parse YAML
                rule_data = await self.parse_rule_file(file_path)
                if not rule_data:
                    failed_count += 1
                    continue

                # Build detection
                detection = await self.build_detection_create(rule_data)
                if detection:
                    detections.append(detection)
                else:
                    failed_count += 1

            except Exception as e:
                logger.error(f"Unexpected error parsing {file_path}: {str(e)}")
                failed_count += 1

        logger.info(f"Parsed {len(detections)} rules successfully, {failed_count} failed")
        return detections