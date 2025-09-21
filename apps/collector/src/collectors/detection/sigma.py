"""
Main SIGMA collector implementation.
"""

import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import git
from src.core.logging import get_logger
from src.schemas.detection import DetectionCreate

from src.core.api_client import CountermeasureClient
from src.collectors.base import AbstractCollector, CollectionResult
from .sigma_enricher import SigmaEnricher
from .sigma_parser import SigmaParser

logger = get_logger(__name__)


class SigmaCollector(AbstractCollector):
    """Collector for SIGMA rules from SigmaHQ repository."""

    DEFAULT_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
    RULES_DIRECTORY = "rules"

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize SIGMA collector.

        Args:
            config: Configuration dictionary with keys:
                - api_url: Countermeasure API base URL
                - email: Admin email
                - password: Admin password
                - repo_url: SIGMA repository URL (optional)
                - categories: List of rule categories to include (optional)
                - limit: Maximum number of rules to process (optional)
                - batch_size: Batch size for API submissions (optional)
                - dry_run: If True, don't submit to API (optional)
        """
        super().__init__(config)

        self.api_url = config["api_url"]
        self.email = config["email"]
        self.password = config["password"]
        self.repo_url = config.get("repo_url", self.DEFAULT_REPO_URL)
        self.categories = config.get("categories", [])
        self.limit = config.get("limit")
        self.batch_size = config.get("batch_size", 50)
        self.dry_run = config.get("dry_run", False)

        # Components
        self.api_client: Optional[CountermeasureClient] = None
        self.parser: Optional[SigmaParser] = None
        self.enricher: Optional[SigmaEnricher] = None

        # Working directory for git clone
        self.temp_dir: Optional[Path] = None

    async def authenticate(self) -> bool:
        """Authenticate with Countermeasure API."""
        try:
            self.api_client = CountermeasureClient(
                base_url=self.api_url,
                email=self.email,
                password=self.password
            )

            if not await self.api_client.login():
                return False

            # Initialize parser with severity mappings
            severities = await self.api_client.get_severities()
            if not severities:
                self.logger.error("Failed to fetch severity mappings")
                return False

            self.parser = SigmaParser(severities)
            self.enricher = SigmaEnricher(self.api_client)

            self.logger.info("Successfully authenticated and initialized components")
            return True

        except Exception as e:
            self.logger.error(f"Authentication failed: {str(e)}")
            return False

    async def fetch(self) -> List[Path]:
        """Fetch SIGMA rules from GitHub repository."""
        try:
            # Create temporary directory
            self.temp_dir = Path(tempfile.mkdtemp(prefix="sigma_rules_"))
            self.logger.info(f"Cloning SIGMA repository to {self.temp_dir}")

            # Clone repository
            repo = git.Repo.clone_from(
                self.repo_url,
                self.temp_dir,
                depth=1  # Shallow clone for efficiency
            )

            self.logger.info(f"Successfully cloned repository from {self.repo_url}")

            # Find rule files
            rules_dir = self.temp_dir / self.RULES_DIRECTORY
            if not rules_dir.exists():
                raise Exception(f"Rules directory not found: {rules_dir}")

            # Collect YAML files
            rule_files = list(rules_dir.rglob("*.yml"))
            rule_files.extend(rules_dir.rglob("*.yaml"))

            # Filter by categories if specified
            if self.categories:
                filtered_files = []
                for file_path in rule_files:
                    if any(category.lower() in str(file_path).lower() for category in self.categories):
                        filtered_files.append(file_path)
                rule_files = filtered_files

            # Apply limit
            if self.limit and len(rule_files) > self.limit:
                rule_files = rule_files[:self.limit]

            self.logger.info(f"Found {len(rule_files)} SIGMA rule files")
            return rule_files

        except Exception as e:
            self.logger.error(f"Failed to fetch SIGMA rules: {str(e)}")
            raise

    async def parse(self, raw_data: List[Path]) -> List[DetectionCreate]:
        """Parse SIGMA rule files into DetectionCreate objects."""
        if not self.parser:
            raise Exception("Parser not initialized")

        return await self.parser.parse_rules(raw_data)

    async def enrich(self, parsed_data: List[DetectionCreate]) -> List[DetectionCreate]:
        """Enrich DetectionCreate objects with categories and tags."""
        if not self.enricher:
            raise Exception("Enricher not initialized")

        if self.dry_run:
            # In dry run mode, don't actually call API for enrichment
            self.logger.info("Dry run mode: skipping enrichment API calls")
            return parsed_data

        return await self.enricher.enrich_detections(parsed_data)

    async def submit(self, enriched_data: List[DetectionCreate]) -> CollectionResult:
        """Submit enriched data to Countermeasure API."""
        if not self.api_client:
            raise Exception("API client not initialized")

        if self.dry_run:
            self.logger.info("Dry run mode: skipping submission to API")
            return CollectionResult(
                total_processed=len(enriched_data),
                successful=len(enriched_data),
                failed=0,
                errors=[],
                execution_time=0.0
            )

        try:
            # Convert DetectionCreate objects to dicts for API submission
            detection_dicts = []
            for detection in enriched_data:
                detection_dict = detection.model_dump(mode='json')
                detection_dicts.append(detection_dict)

            # Submit in batches
            result = await self.api_client.batch_create_detections(
                detection_dicts,
                batch_size=self.batch_size
            )

            return CollectionResult(
                total_processed=len(enriched_data),
                successful=result["successful"],
                failed=result["failed"],
                errors=result["errors"],
                execution_time=0.0  # Will be set by base class
            )

        except Exception as e:
            self.logger.error(f"Failed to submit detections: {str(e)}")
            return CollectionResult(
                total_processed=len(enriched_data),
                successful=0,
                failed=len(enriched_data),
                errors=[str(e)],
                execution_time=0.0
            )

    async def cleanup(self):
        """Clean up temporary resources."""
        try:
            if self.api_client:
                await self.api_client.close()

            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                self.logger.debug(f"Cleaned up temporary directory: {self.temp_dir}")

        except Exception as e:
            self.logger.warning(f"Error during cleanup: {str(e)}")

    async def run(self) -> CollectionResult:
        """Execute the full SIGMA collection pipeline with cleanup."""
        try:
            result = await super().run()
            return result
        finally:
            await self.cleanup()

    def print_summary(self, result: CollectionResult):
        """Print a formatted summary of the collection results."""
        print("\n" + "="*60)
        print("🎯 SIGMA COLLECTION SUMMARY")
        print("="*60)
        print(f"📂 Repository: {self.repo_url}")
        print(f"📊 Total Processed: {result.total_processed}")
        print(f"✅ Successfully Imported: {result.successful}")
        print(f"❌ Failed: {result.failed}")
        print(f"⏱️  Execution Time: {result.execution_time:.2f}s")

        if result.errors:
            print(f"\n🚨 Errors ({len(result.errors)}):")
            for i, error in enumerate(result.errors[:5], 1):
                print(f"  {i}. {error}")
            if len(result.errors) > 5:
                print(f"  ... and {len(result.errors) - 5} more errors")

        if result.successful > 0:
            success_rate = (result.successful / result.total_processed) * 100
            print(f"\n📈 Success Rate: {success_rate:.1f}%")

        print("="*60)