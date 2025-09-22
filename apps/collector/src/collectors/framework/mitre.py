"""
MITRE ATT&CK Framework collector.

Fetches tactics, techniques, and threat actor groups from the official
MITRE ATT&CK STIX 2.1 data repository.
"""

import json
import aiohttp
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from ..base import AbstractCollector, CollectionResult
from src.core.api_client import CountermeasureClient
from src.core.config import load_mitre_config, MitreConfig
from src.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class MitreData:
    """Container for parsed MITRE ATT&CK data."""
    tactics: List[Dict[str, Any]]
    techniques: List[Dict[str, Any]]
    groups: List[Dict[str, Any]]


class MitreCollector(AbstractCollector):
    """
    Collector for MITRE ATT&CK framework data.

    Fetches official STIX 2.1 data from the MITRE ATT&CK repository
    and updates tactics, techniques, and threat actor groups.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize MITRE collector.

        Args:
            config: Configuration containing API credentials and settings
        """
        super().__init__(config)

        # Load enterprise configuration
        self.config = load_mitre_config(**config)

        # API client for Countermeasure
        self.api_client = CountermeasureClient(
            base_url=self.config.api_url,
            email=self.config.email,
            password=self.config.password
        )

    async def authenticate(self) -> bool:
        """
        Authenticate with Countermeasure API.

        Returns:
            True if authentication successful
        """
        try:
            success = await self.api_client.login()
            if success:
                self.logger.info("Successfully authenticated with Countermeasure API")
                return True
            else:
                self.logger.error("Failed to authenticate with Countermeasure API")
                return False
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            return False

    async def fetch(self) -> Dict[str, Any]:
        """
        Fetch MITRE ATT&CK STIX data from GitHub repository.

        Returns:
            Raw STIX JSON data
        """
        try:
            self.logger.info(f"Fetching MITRE ATT&CK data from {self.config.mitre_stix_url}")

            timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.config.mitre_stix_url) as response:
                    if response.status == 200:
                        # GitHub raw files return as text/plain, so we need to parse manually
                        text_data = await response.text()
                        data = json.loads(text_data)
                        self.logger.info(f"Successfully fetched STIX data with {len(data.get('objects', []))} objects")
                        return data
                    else:
                        raise Exception(f"Failed to fetch data: HTTP {response.status}")

        except Exception as e:
            self.logger.error(f"Failed to fetch MITRE data: {str(e)}")
            raise

    async def parse(self, raw_data: Dict[str, Any]) -> MitreData:
        """
        Parse STIX JSON data into structured MITRE objects.

        Args:
            raw_data: Raw STIX JSON data

        Returns:
            Parsed MITRE data organized by type
        """
        try:
            stix_objects = raw_data.get('objects', [])

            tactics = []
            techniques = []
            groups = []

            for obj in stix_objects:
                obj_type = obj.get('type')

                if obj_type == 'x-mitre-tactic':
                    tactics.append(self._parse_tactic(obj))
                elif obj_type == 'attack-pattern':
                    techniques.append(self._parse_technique(obj))
                elif obj_type == 'intrusion-set':
                    groups.append(self._parse_group(obj))

            self.logger.info(f"Parsed {len(tactics)} tactics, {len(techniques)} techniques, {len(groups)} groups")

            return MitreData(
                tactics=tactics,
                techniques=techniques,
                groups=groups
            )

        except Exception as e:
            self.logger.error(f"Failed to parse MITRE data: {str(e)}")
            raise

    def _parse_tactic(self, stix_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a MITRE tactic from STIX object."""
        external_refs = stix_obj.get('external_references', [])
        mitre_ref = next((ref for ref in external_refs if ref.get('source_name') == 'mitre-attack'), {})

        # Use the short name which matches the phase_name used in techniques
        phase_name = stix_obj.get('x_mitre_shortname', '')
        stix_id = stix_obj.get('id', '')
        stix_uuid = stix_id.replace('x-mitre-tactic--', '') if stix_id.startswith('x-mitre-tactic--') else ''

        return {
            'tactic_id': phase_name,  # Use phase name for consistency with techniques
            'name': stix_obj.get('name', ''),
            'description': stix_obj.get('description', ''),
            'url': mitre_ref.get('url', ''),
            'stix_uuid': stix_uuid  # Store the actual STIX UUID
        }

    def _parse_technique(self, stix_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a MITRE technique from STIX object."""
        external_refs = stix_obj.get('external_references', [])
        mitre_ref = next((ref for ref in external_refs if ref.get('source_name') == 'mitre-attack'), {})

        # Get tactic references (kill chain phases)
        kill_chain_phases = stix_obj.get('kill_chain_phases', [])
        tactic_ids = [phase.get('phase_name', '') for phase in kill_chain_phases if phase.get('kill_chain_name') == 'mitre-attack']
        primary_tactic = tactic_ids[0] if tactic_ids else ''

        # Extract platforms
        platforms = stix_obj.get('x_mitre_platforms', [])

        # Extract data sources
        data_sources = []
        for data_source in stix_obj.get('x_mitre_data_sources', []):
            if isinstance(data_source, str):
                data_sources.append(data_source)
            elif isinstance(data_source, dict) and 'data_source_name' in data_source:
                data_sources.append(data_source['data_source_name'])

        # Check if this is a sub-technique
        technique_id = mitre_ref.get('external_id', '')
        parent_technique_id = None
        if '.' in technique_id:
            parent_technique_id = technique_id.split('.')[0]

        return {
            'technique_id': technique_id,
            'name': stix_obj.get('name', ''),
            'description': stix_obj.get('description', ''),
            'tactic_id': primary_tactic,
            'parent_technique_id': parent_technique_id,
            'url': mitre_ref.get('url', ''),
            'stix_uuid': stix_obj.get('id', '').replace('attack-pattern--', ''),
            'platforms': platforms,
            'data_sources': data_sources
        }

    def _parse_group(self, stix_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a MITRE threat actor group from STIX object."""
        external_refs = stix_obj.get('external_references', [])
        mitre_ref = next((ref for ref in external_refs if ref.get('source_name') == 'mitre-attack'), {})

        # Extract aliases
        aliases = stix_obj.get('aliases', [])
        primary_name = aliases[0] if aliases else stix_obj.get('name', '')
        other_aliases = aliases[1:] if len(aliases) > 1 else []

        return {
            'name': primary_name,
            'aliases': other_aliases,
            'description': stix_obj.get('description', ''),
            'mitre_attack_id': mitre_ref.get('external_id', ''),
            'stix_uuid': stix_obj.get('id', '').replace('intrusion-set--', ''),
            'references': [ref.get('url') for ref in external_refs if ref.get('url')]
        }

    async def enrich(self, parsed_data: MitreData) -> MitreData:
        """
        Enrich parsed MITRE data with additional metadata.

        Args:
            parsed_data: Parsed MITRE data

        Returns:
            Enriched MITRE data
        """
        # For now, return data as-is. Future enrichment could include:
        # - Mapping techniques to tactics
        # - Adding confidence scores
        # - Cross-referencing with external threat intelligence

        self.logger.info("Enrichment completed (no additional processing applied)")
        return parsed_data

    async def submit(self, enriched_data: MitreData) -> CollectionResult:
        """
        Submit enriched MITRE data to Countermeasure API using unified import endpoint.

        Args:
            enriched_data: Enriched MITRE data

        Returns:
            Collection result with statistics
        """
        total_processed = 0
        successful = 0
        failed = 0
        errors = []

        try:
            # Prepare data for unified import endpoint
            import_data = {}

            if self.config.enable_tactics and enriched_data.tactics:
                import_data["tactics"] = enriched_data.tactics
                total_processed += len(enriched_data.tactics)

            if self.config.enable_techniques and enriched_data.techniques:
                import_data["techniques"] = enriched_data.techniques
                total_processed += len(enriched_data.techniques)

            if self.config.enable_groups and enriched_data.groups:
                import_data["groups"] = enriched_data.groups
                total_processed += len(enriched_data.groups)

            if not import_data:
                self.logger.info("No data to import (all types disabled in config)")
                return CollectionResult(
                    total_processed=0,
                    successful=0,
                    failed=0,
                    errors=[],
                    execution_time=0.0
                )

            self.logger.info(f"Submitting MITRE data via unified import endpoint...")

            # Submit all data via unified endpoint
            response = await self.api_client.post(
                "/api/v1/mitre/import",
                json=import_data
            )

            if response:
                # Parse response from unified endpoint
                total_created = response.get('total_created', 0)
                total_updated = response.get('total_updated', 0)
                details = response.get('details', {})

                successful = total_created + total_updated

                # Log detailed results
                if 'tactics' in details:
                    tactics_stats = details['tactics']
                    self.logger.info(f"Tactics: {tactics_stats.get('created', 0)} created, {tactics_stats.get('updated', 0)} updated")

                if 'techniques' in details:
                    techniques_stats = details['techniques']
                    self.logger.info(f"Techniques: {techniques_stats.get('created', 0)} created, {techniques_stats.get('updated', 0)} updated")

                if 'groups' in details:
                    groups_stats = details['groups']
                    self.logger.info(f"Groups: {groups_stats.get('created', 0)} created, {groups_stats.get('updated', 0)} updated")

                self.logger.info(f"Import completed: {total_created} created, {total_updated} updated")

            else:
                failed = total_processed
                errors.append("Failed to submit MITRE data via unified import endpoint")

            return CollectionResult(
                total_processed=total_processed,
                successful=successful,
                failed=failed,
                errors=errors,
                execution_time=0.0  # Will be set by base class
            )

        except Exception as e:
            self.logger.error(f"Submission failed: {str(e)}")
            return CollectionResult(
                total_processed=total_processed,
                successful=successful,
                failed=total_processed,
                errors=errors + [str(e)],
                execution_time=0.0
            )

    async def cleanup(self):
        """Cleanup resources after collection."""
        if self.api_client:
            await self.api_client.close()
        self.logger.info("Cleanup completed")


async def main():
    """Main entry point for running the MITRE collector."""
    import argparse
    import asyncio
    import os

    parser = argparse.ArgumentParser(description='MITRE ATT&CK Framework Collector')
    parser.add_argument('--api-url', default='http://localhost:8000', help='Countermeasure API URL')
    parser.add_argument('--email', default='admin@countermeasure.dev', help='API email')
    parser.add_argument('--password', help='API password')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--batch-size', type=int, default=50, help='Batch size for API submissions')
    parser.add_argument('--disable-tactics', action='store_true', help='Disable tactics collection')
    parser.add_argument('--disable-techniques', action='store_true', help='Disable techniques collection')
    parser.add_argument('--disable-groups', action='store_true', help='Disable groups collection')

    args = parser.parse_args()

    # Get password from args or environment
    password = args.password or os.getenv('COUNTERMEASURE_PASSWORD', 'CountermeasureAdmin123!')

    config = {
        'api_url': args.api_url,
        'email': args.email,
        'password': password,
        'batch_size': args.batch_size,
        'enable_tactics': not args.disable_tactics,
        'enable_techniques': not args.disable_techniques,
        'enable_groups': not args.disable_groups
    }

    # Override with config file if provided (enterprise configuration)
    if args.config:
        try:
            # Use enterprise config loading
            from src.core.config import ConfigManager, MitreConfig
            manager = ConfigManager(MitreConfig)
            loaded_config = manager.load_config(args.config, **config)
            config = loaded_config.dict()
        except Exception as e:
            print(f"Warning: Could not load config file {args.config}: {e}")
            print("Falling back to command line arguments")

    collector = MitreCollector(config)

    try:
        result = await collector.run()
        print(f"Collection completed:")
        print(f"  Total processed: {result.total_processed}")
        print(f"  Successful: {result.successful}")
        print(f"  Failed: {result.failed}")
        print(f"  Execution time: {result.execution_time:.2f}s")

        if result.errors:
            print(f"  Errors:")
            for error in result.errors:
                print(f"    - {error}")

    except KeyboardInterrupt:
        print("Collection interrupted by user")
    except Exception as e:
        print(f"Collection failed: {str(e)}")
    finally:
        await collector.cleanup()


if __name__ == '__main__':
    import asyncio
    asyncio.run(main())