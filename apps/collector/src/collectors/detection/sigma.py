"""
Main SIGMA collector implementation.
"""

import json
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import git

from src.collectors.base import AbstractCollector, CollectionResult
from src.core.api_client import CountermeasureClient
from src.core.logging import get_logger
from src.schemas.detection import DetectionCreate

from .deduplicator import DetectionDeduplicator
from .sigma_enricher import SigmaEnricher
from .sigma_parser import SigmaParser
from src.models.collection_history import collection_history


logger = get_logger(__name__)


class SigmaCollector(AbstractCollector):
    """Collector for SIGMA rules from SigmaHQ repository."""

    DEFAULT_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
    RULES_DIRECTORY = "rules"

    def __init__(self, config: dict[str, Any]):
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
        self.incremental = config.get("incremental", False)
        self.state_file = Path(config.get("state_file", "sigma_collector_state.json"))
        self.deduplicate = config.get("deduplicate", True)
        self.dedup_strategy = config.get("dedup_strategy", "content_hash")

        # Components
        self.api_client: CountermeasureClient | None = None
        self.parser: SigmaParser | None = None
        self.enricher: SigmaEnricher | None = None
        self.deduplicator: DetectionDeduplicator | None = None

        # Working directory for git clone
        self.temp_dir: Path | None = None

        # State for incremental updates
        self.last_commit_hash: str | None = None
        self.last_update_time: datetime | None = None

        # History tracking
        self.run_id: str | None = None

    async def authenticate(self) -> bool:
        """Authenticate with Countermeasure API."""
        try:
            self.api_client = CountermeasureClient(
                base_url=self.api_url, email=self.email, password=self.password
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

            # Initialize deduplicator if enabled
            if self.deduplicate:
                self.deduplicator = DetectionDeduplicator(self.dedup_strategy)
                self.logger.info(f"Deduplication enabled with strategy: {self.dedup_strategy}")

            self.logger.info("Successfully authenticated and initialized components")
            return True

        except Exception as e:
            self.logger.error(f"Authentication failed: {e!s}")
            return False

    def load_state(self) -> dict[str, Any]:
        """Load collector state from file."""
        try:
            if self.state_file.exists():
                with open(self.state_file, "r") as f:
                    state = json.load(f)
                    self.last_commit_hash = state.get("last_commit_hash")
                    if state.get("last_update_time"):
                        self.last_update_time = datetime.fromisoformat(
                            state["last_update_time"]
                        )
                    self.logger.info(
                        f"Loaded state - Last commit: {self.last_commit_hash}, "
                        f"Last update: {self.last_update_time}"
                    )
                    return state
        except Exception as e:
            self.logger.warning(f"Failed to load state: {e}")

        return {}

    def save_state(self, commit_hash: str) -> None:
        """Save collector state to file."""
        try:
            state = {
                "last_commit_hash": commit_hash,
                "last_update_time": datetime.now().isoformat(),
                "repo_url": self.repo_url,
            }

            # Ensure parent directory exists
            self.state_file.parent.mkdir(parents=True, exist_ok=True)

            with open(self.state_file, "w") as f:
                json.dump(state, f, indent=2)

            self.logger.info(f"Saved state - Commit: {commit_hash}")
        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")

    async def fetch(self) -> list[Path]:
        """Fetch SIGMA rules from GitHub repository with incremental update support."""
        try:
            # Load previous state if incremental mode is enabled
            if self.incremental:
                self.load_state()

            # Create temporary directory
            self.temp_dir = Path(tempfile.mkdtemp(prefix="sigma_rules_"))
            self.logger.info(f"Cloning SIGMA repository to {self.temp_dir}")

            # Clone repository
            repo = git.Repo.clone_from(
                self.repo_url,
                self.temp_dir,
                depth=None if self.incremental else 1,  # Full clone for incremental
            )

            # Get current commit hash
            current_commit = repo.head.commit.hexsha
            self.logger.info(f"Current commit: {current_commit}")

            # Check if we need to process anything for incremental updates
            if self.incremental and self.last_commit_hash:
                if current_commit == self.last_commit_hash:
                    self.logger.info("No new commits since last update, skipping processing")
                    return []

                # Get changed files since last commit
                changed_files = self.get_changed_files(repo, self.last_commit_hash, current_commit)
                self.logger.info(f"Found {len(changed_files)} changed files since last update")
            else:
                # First run or full update
                changed_files = None

            # Find rule files
            rules_dir = self.temp_dir / self.RULES_DIRECTORY
            if not rules_dir.exists():
                raise Exception(f"Rules directory not found: {rules_dir}")

            # Collect YAML files
            if changed_files is not None:
                # Only process changed files
                rule_files = []
                for changed_file in changed_files:
                    file_path = self.temp_dir / changed_file
                    if (
                        file_path.exists()
                        and file_path.suffix.lower() in [".yml", ".yaml"]
                        and self.RULES_DIRECTORY in str(file_path)
                    ):
                        rule_files.append(file_path)
            else:
                # Process all files
                rule_files = list(rules_dir.rglob("*.yml"))
                rule_files.extend(rules_dir.rglob("*.yaml"))

            # Filter by categories if specified
            if self.categories:
                filtered_files = []
                for file_path in rule_files:
                    if any(
                        category.lower() in str(file_path).lower()
                        for category in self.categories
                    ):
                        filtered_files.append(file_path)
                rule_files = filtered_files

            # Apply limit
            if self.limit and len(rule_files) > self.limit:
                rule_files = rule_files[: self.limit]

            self.logger.info(f"Found {len(rule_files)} SIGMA rule files to process")

            # Save current commit hash for next incremental update
            if self.incremental:
                self.save_state(current_commit)

            return rule_files

        except Exception as e:
            self.logger.error(f"Failed to fetch SIGMA rules: {e!s}")
            raise

    def get_changed_files(self, repo: git.Repo, old_commit: str, new_commit: str) -> list[str]:
        """Get list of files changed between two commits."""
        try:
            # Get diff between commits
            diff = repo.git.diff("--name-only", old_commit, new_commit)
            changed_files = [f for f in diff.split("\n") if f.strip()]

            self.logger.debug(f"Changed files: {changed_files}")
            return changed_files

        except Exception as e:
            self.logger.warning(f"Failed to get changed files, falling back to full scan: {e}")
            return []

    async def parse(self, raw_data: list[Path]) -> list[DetectionCreate]:
        """Parse SIGMA rule files into DetectionCreate objects."""
        if not self.parser:
            raise Exception("Parser not initialized")

        parsed_detections = await self.parser.parse_rules(raw_data)

        # Apply deduplication if enabled
        if self.deduplicate and self.deduplicator:
            self.logger.info(f"Deduplicating {len(parsed_detections)} detections...")
            parsed_detections = self.deduplicator.deduplicate(parsed_detections)
            dedup_stats = self.deduplicator.get_stats()
            self.logger.info(f"Deduplication stats: {dedup_stats}")

        return parsed_detections

    async def enrich(self, parsed_data: list[DetectionCreate]) -> list[DetectionCreate]:
        """Enrich DetectionCreate objects with categories and tags."""
        if not self.enricher:
            raise Exception("Enricher not initialized")

        if self.dry_run:
            # In dry run mode, don't actually call API for enrichment
            self.logger.info("Dry run mode: skipping enrichment API calls")
            return parsed_data

        return await self.enricher.enrich_detections(parsed_data)

    async def submit(self, enriched_data: list[DetectionCreate]) -> CollectionResult:
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
                execution_time=0.0,
            )

        try:
            # Convert DetectionCreate objects to dicts for API submission
            detection_dicts = []
            for detection in enriched_data:
                detection_dict = detection.model_dump(mode="json")
                detection_dicts.append(detection_dict)

            # Submit in batches
            result = await self.api_client.batch_create_detections(
                detection_dicts, batch_size=self.batch_size
            )

            return CollectionResult(
                total_processed=len(enriched_data),
                successful=result["successful"],
                failed=result["failed"],
                errors=result["errors"],
                execution_time=0.0,  # Will be set by base class
            )

        except Exception as e:
            self.logger.error(f"Failed to submit detections: {e!s}")
            return CollectionResult(
                total_processed=len(enriched_data),
                successful=0,
                failed=len(enriched_data),
                errors=[str(e)],
                execution_time=0.0,
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
            self.logger.warning(f"Error during cleanup: {e!s}")

    async def run(self) -> CollectionResult:
        """Execute the full SIGMA collection pipeline with cleanup and history tracking."""
        # Start history tracking
        config_summary = {
            "repo_url": self.repo_url,
            "categories": self.categories,
            "limit": self.limit,
            "batch_size": self.batch_size,
            "incremental": self.incremental,
            "deduplicate": self.deduplicate,
            "dedup_strategy": self.dedup_strategy if self.deduplicate else None,
        }

        self.run_id = collection_history.start_run(
            collector_type="sigma",
            configuration=config_summary,
            tenant_id=getattr(self, 'tenant_id', None)
        )

        try:
            result = await super().run()

            # Complete history tracking
            duplicates_removed = 0
            if self.deduplicator:
                dedup_stats = self.deduplicator.get_stats()
                duplicates_removed = dedup_stats.get("duplicates_removed", 0)

            status = "completed" if result.failed == 0 else "completed_with_errors"

            collection_history.complete_run(
                run_id=self.run_id,
                status=status,
                total_processed=result.total_processed,
                successful=result.successful,
                failed=result.failed,
                duplicates_removed=duplicates_removed,
                errors=result.errors,
                metrics={
                    "execution_time": result.execution_time,
                    "success_rate": (result.successful / result.total_processed * 100) if result.total_processed > 0 else 0,
                    "incremental_update": self.incremental,
                    "commit_hash": getattr(self, 'current_commit_hash', None),
                }
            )

            return result

        except Exception as e:
            # Mark run as failed
            if self.run_id:
                collection_history.update_run(
                    run_id=self.run_id,
                    status="failed",
                    errors=[str(e)]
                )
            raise

        finally:
            await self.cleanup()

    def print_summary(self, result: CollectionResult):
        """Print a formatted summary of the collection results."""
        print("\n" + "=" * 60)
        print("🎯 SIGMA COLLECTION SUMMARY")
        print("=" * 60)
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

        # Show deduplication stats if enabled
        if self.deduplicate and self.deduplicator:
            dedup_stats = self.deduplicator.get_stats()
            print(f"\n🔄 Deduplication Stats:")
            print(f"  Strategy: {dedup_stats['strategy']}")
            print(f"  Duplicates Removed: {dedup_stats['duplicates_removed']}")

        # Show incremental update info
        if self.incremental:
            print(f"\n🔄 Incremental Update: {'Enabled' if self.incremental else 'Disabled'}")
            if self.last_commit_hash:
                print(f"  Last Commit: {self.last_commit_hash[:8]}...")

        print("=" * 60)
