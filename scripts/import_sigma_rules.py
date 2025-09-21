#!/usr/bin/env python3
"""
Countermeasure Platform - SIGMA Rules Import Utility

Enterprise-grade script for importing SIGMA detection rules into the Countermeasure platform.
Supports authentication, data validation, batch processing, and comprehensive logging.

Usage:
    python scripts/import_sigma_rules.py [options]

Examples:
    # Import 100 SIGMA rules with default settings
    python scripts/import_sigma_rules.py --limit 100

    # Import rules with custom API endpoint and credentials
    python scripts/import_sigma_rules.py \
        --api-url https://api.countermeasure.example.com \
        --email admin@company.com \
        --limit 500 \
        --batch-size 25

    # Dry run to preview what would be imported
    python scripts/import_sigma_rules.py --limit 50 --dry-run

    # Reset existing detections before importing
    python scripts/import_sigma_rules.py --limit 100 --reset

Author: Countermeasure Development Team
License: Proprietary
Version: 1.0.0
"""

import argparse
import asyncio
import getpass
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import json

# Add the collector source to path for imports
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent
COLLECTOR_DIR = PROJECT_ROOT / "apps" / "collector"
COLLECTOR_SRC_DIR = COLLECTOR_DIR / "src"

# Add collector source directory to Python path
if COLLECTOR_SRC_DIR.exists():
    sys.path.insert(0, str(COLLECTOR_SRC_DIR))
else:
    print(f"❌ Collector source directory not found: {COLLECTOR_SRC_DIR}")
    print("Please ensure you're running from the project root and the collector app exists.")
    sys.exit(1)

try:
    from core.api_client import CountermeasureClient
    from collectors.detection.sigma import SigmaCollector
    from core.logging import get_logger
except ImportError as e:
    print(f"❌ Error importing Countermeasure modules: {e}")
    print(f"Please ensure you're running from the project root and collector dependencies are installed.")
    sys.exit(1)


class SigmaImportManager:
    """
    Enterprise-grade SIGMA rules import manager.

    Handles authentication, validation, batch processing, error handling,
    and comprehensive reporting for SIGMA rule imports.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the import manager.

        Args:
            config: Configuration dictionary with API settings and import parameters
        """
        self.config = config
        self.logger = get_logger(__name__)
        self.client: Optional[CountermeasureClient] = None
        self.start_time: Optional[datetime] = None

        # Statistics tracking
        self.stats = {
            "total_processed": 0,
            "successful_imports": 0,
            "failed_imports": 0,
            "deleted_existing": 0,
            "execution_time_seconds": 0,
            "errors": []
        }

    async def authenticate(self) -> bool:
        """
        Authenticate with the Countermeasure API.

        Returns:
            True if authentication successful, False otherwise
        """
        try:
            self.logger.info("Authenticating with Countermeasure API", extra={
                "api_url": self.config["api_url"],
                "email": self.config["email"]
            })

            self.client = CountermeasureClient(
                base_url=self.config["api_url"],
                email=self.config["email"],
                password=self.config["password"]
            )

            success = await self.client.login()

            if success:
                self.logger.info("Authentication successful")
                return True
            else:
                self.logger.error("Authentication failed - invalid credentials")
                return False

        except Exception as e:
            self.logger.error("Authentication error", extra={"error": str(e)})
            return False

    async def reset_existing_detections(self) -> bool:
        """
        Delete all existing detections if reset option is enabled.

        Returns:
            True if reset successful or not needed, False if reset failed
        """
        if not self.config.get("reset", False):
            return True

        try:
            self.logger.info("Resetting existing detections")

            # Get all existing detections
            data = await self.client.get_detections(limit=10000)
            if not data:
                self.logger.warning("Failed to fetch existing detections")
                return False

            detections = data.get("items", [])
            total_count = len(detections)

            if total_count == 0:
                self.logger.info("No existing detections found")
                return True

            self.logger.info(f"Found {total_count} existing detections to delete")

            # Delete each detection
            deleted_count = 0
            for detection in detections:
                if await self.client.delete_detection(detection['id']):
                    deleted_count += 1
                else:
                    self.logger.warning(f"Failed to delete detection: {detection.get('name', 'unknown')}")

            self.stats["deleted_existing"] = deleted_count
            self.logger.info(f"Successfully deleted {deleted_count}/{total_count} detections")

            return True

        except Exception as e:
            self.logger.error("Error during detection reset", extra={"error": str(e)})
            return False

    async def import_sigma_rules(self) -> bool:
        """
        Import SIGMA rules using the collector.

        Returns:
            True if import successful, False otherwise
        """
        try:
            self.logger.info("Starting SIGMA rules import", extra={
                "limit": self.config["limit"],
                "batch_size": self.config["batch_size"],
                "dry_run": self.config["dry_run"]
            })

            # Initialize SIGMA collector
            collector = SigmaCollector(self.config)

            # Run collection
            result = await collector.run()

            # Update statistics
            self.stats["total_processed"] = result.successful + result.failed
            self.stats["successful_imports"] = result.successful
            self.stats["failed_imports"] = result.failed

            # Log detailed results
            self.logger.info("SIGMA import completed", extra={
                "total_processed": self.stats["total_processed"],
                "successful": result.successful,
                "failed": result.failed,
                "execution_time": f"{result.execution_time:.2f}s"
            })

            # Print summary for user
            collector.print_summary(result)

            return result.successful > 0

        except Exception as e:
            error_msg = f"SIGMA import failed: {str(e)}"
            self.logger.error(error_msg)
            self.stats["errors"].append(error_msg)
            return False

    async def verify_import(self) -> Dict[str, Any]:
        """
        Verify the imported rules by checking structured metadata.

        Returns:
            Dictionary with verification results
        """
        verification_results = {
            "total_detections": 0,
            "with_platforms": 0,
            "with_data_sources": 0,
            "with_false_positives": 0,
            "with_log_sources": 0,
            "sample_detections": []
        }

        try:
            self.logger.info("Verifying imported detections")

            # Get recent detections for verification
            data = await self.client.get_detections(limit=10)
            if not data:
                self.logger.warning("Failed to fetch detections for verification")
                return verification_results

            detections = data.get("items", [])
            verification_results["total_detections"] = len(detections)

            # Analyze structured metadata
            for detection in detections[:5]:  # Check first 5 for samples
                platforms = detection.get('platforms', [])
                data_sources = detection.get('data_sources', [])
                false_positives = detection.get('false_positives', [])
                log_sources = detection.get('log_sources')

                if platforms:
                    verification_results["with_platforms"] += 1
                if data_sources:
                    verification_results["with_data_sources"] += 1
                if false_positives:
                    verification_results["with_false_positives"] += 1
                if log_sources:
                    verification_results["with_log_sources"] += 1

                # Store sample for reporting
                verification_results["sample_detections"].append({
                    "name": detection.get('name', 'Unknown'),
                    "platforms": platforms,
                    "data_sources": data_sources,
                    "false_positives": false_positives,
                    "log_sources": log_sources
                })

            self.logger.info("Verification completed", extra=verification_results)
            return verification_results

        except Exception as e:
            self.logger.error("Error during verification", extra={"error": str(e)})
            return verification_results

    def print_verification_report(self, verification: Dict[str, Any]) -> None:
        """
        Print detailed verification report.

        Args:
            verification: Verification results dictionary
        """
        print("\n" + "="*70)
        print("🔍 IMPORT VERIFICATION REPORT")
        print("="*70)

        total = verification["total_detections"]
        if total == 0:
            print("❌ No detections found for verification")
            return

        print(f"📊 Total Detections: {total}")
        print(f"🖥️  With Platforms: {verification['with_platforms']}")
        print(f"📡 With Data Sources: {verification['with_data_sources']}")
        print(f"⚠️  With False Positives: {verification['with_false_positives']}")
        print(f"📝 With Log Sources: {verification['with_log_sources']}")

        # Show sample detections
        print(f"\n📋 Sample Detections:")
        for i, sample in enumerate(verification["sample_detections"], 1):
            print(f"\n--- Sample {i}: {sample['name']} ---")
            print(f"Platforms: {sample['platforms']}")
            print(f"Data Sources: {sample['data_sources']}")
            print(f"False Positives: {sample['false_positives']}")
            print(f"Log Sources: {sample['log_sources']}")

    def print_final_report(self, verification: Dict[str, Any]) -> None:
        """
        Print comprehensive final report.

        Args:
            verification: Verification results dictionary
        """
        print("\n" + "="*70)
        print("📈 SIGMA IMPORT FINAL REPORT")
        print("="*70)

        # Execution summary
        execution_time = (datetime.now() - self.start_time).total_seconds()
        self.stats["execution_time_seconds"] = execution_time

        print(f"⏱️  Total Execution Time: {execution_time:.1f} seconds")
        print(f"🔄 Total Rules Processed: {self.stats['total_processed']}")
        print(f"✅ Successfully Imported: {self.stats['successful_imports']}")
        print(f"❌ Failed Imports: {self.stats['failed_imports']}")

        if self.stats["deleted_existing"] > 0:
            print(f"🗑️  Existing Rules Deleted: {self.stats['deleted_existing']}")

        # Success rate
        if self.stats["total_processed"] > 0:
            success_rate = (self.stats["successful_imports"] / self.stats["total_processed"]) * 100
            print(f"📊 Success Rate: {success_rate:.1f}%")

        # Configuration used
        print(f"\n⚙️  Configuration Used:")
        print(f"   API URL: {self.config['api_url']}")
        print(f"   User: {self.config['email']}")
        print(f"   Rule Limit: {self.config['limit']}")
        print(f"   Batch Size: {self.config['batch_size']}")
        print(f"   Dry Run: {self.config['dry_run']}")
        print(f"   Reset Mode: {self.config.get('reset', False)}")

        # Errors if any
        if self.stats["errors"]:
            print(f"\n⚠️  Errors Encountered:")
            for error in self.stats["errors"]:
                print(f"   • {error}")

        print("="*70)

    async def run(self) -> int:
        """
        Execute the complete SIGMA import process.

        Returns:
            Exit code (0 for success, 1 for failure)
        """
        self.start_time = datetime.now()

        try:
            # Step 1: Authentication
            print("🚀 Starting Countermeasure SIGMA Rules Import")
            print("="*60)

            if not await self.authenticate():
                print("❌ Authentication failed. Please check your credentials.")
                return 1

            print("✅ Authentication successful")

            # Step 2: Reset existing detections (if requested)
            if not await self.reset_existing_detections():
                print("❌ Failed to reset existing detections")
                return 1

            # Step 3: Import SIGMA rules
            if not await self.import_sigma_rules():
                print("❌ SIGMA import failed")
                return 1

            print("✅ SIGMA import completed successfully")

            # Step 4: Verify import
            verification = await self.verify_import()
            self.print_verification_report(verification)

            # Step 5: Final report
            self.print_final_report(verification)

            return 0

        except KeyboardInterrupt:
            self.logger.warning("Import interrupted by user")
            print("\n⚠️  Import interrupted by user")
            return 1

        except Exception as e:
            self.logger.error("Unexpected error during import", extra={"error": str(e)})
            print(f"\n💥 Unexpected error: {str(e)}")
            return 1

        finally:
            if self.client:
                await self.client.close()


def get_configuration(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Build configuration from command line arguments and environment variables.

    Args:
        args: Parsed command line arguments

    Returns:
        Configuration dictionary
    """
    # Get password securely
    if args.password:
        password = args.password
    else:
        password = getpass.getpass(f"Password for {args.email}: ")

    return {
        "api_url": args.api_url,
        "email": args.email,
        "password": password,
        "repo_url": args.repo_url,
        "categories": args.categories or [],
        "limit": args.limit,
        "batch_size": args.batch_size,
        "dry_run": args.dry_run,
        "reset": args.reset
    }


def setup_logging(verbose: bool = False) -> None:
    """
    Configure logging for the script.

    Args:
        verbose: Enable verbose logging
    """
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(
                SCRIPT_DIR / "sigma_import.log",
                mode='a'
            )
        ]
    )


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure command line argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description="Import SIGMA detection rules into Countermeasure platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --limit 100
  %(prog)s --api-url https://api.example.com --email admin@company.com --limit 500
  %(prog)s --limit 50 --dry-run
  %(prog)s --limit 100 --reset
        """
    )

    # API Configuration
    api_group = parser.add_argument_group('API Configuration')
    api_group.add_argument(
        '--api-url',
        default=os.getenv('COUNTERMEASURE_API_URL', 'http://localhost:8000'),
        help='Countermeasure API base URL (default: http://localhost:8000)'
    )
    api_group.add_argument(
        '--email',
        default=os.getenv('COUNTERMEASURE_EMAIL', 'admin@countermeasure.dev'),
        help='API user email (default: admin@countermeasure.dev)'
    )
    api_group.add_argument(
        '--password',
        help='API user password (will prompt if not provided)'
    )

    # Import Configuration
    import_group = parser.add_argument_group('Import Configuration')
    import_group.add_argument(
        '--repo-url',
        default='https://github.com/SigmaHQ/sigma.git',
        help='SIGMA repository URL (default: SigmaHQ/sigma)'
    )
    import_group.add_argument(
        '--categories',
        nargs='*',
        help='Specific SIGMA categories to import (default: all)'
    )
    import_group.add_argument(
        '--limit',
        type=int,
        default=100,
        help='Maximum number of rules to import (default: 100)'
    )
    import_group.add_argument(
        '--batch-size',
        type=int,
        default=50,
        help='Number of rules to process per batch (default: 50)'
    )

    # Operation Mode
    mode_group = parser.add_argument_group('Operation Mode')
    mode_group.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview what would be imported without making changes'
    )
    mode_group.add_argument(
        '--reset',
        action='store_true',
        help='Delete existing detections before importing new ones'
    )

    # Logging
    logging_group = parser.add_argument_group('Logging')
    logging_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )

    return parser


async def main() -> int:
    """
    Main entry point for the SIGMA import script.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    parser = create_argument_parser()
    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    # Build configuration
    try:
        config = get_configuration(args)
    except KeyboardInterrupt:
        print("\n⚠️  Configuration cancelled by user")
        return 1

    # Validate configuration
    if not config["password"]:
        print("❌ Password is required")
        return 1

    # Run import
    import_manager = SigmaImportManager(config)
    return await import_manager.run()


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️  Script interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        sys.exit(1)