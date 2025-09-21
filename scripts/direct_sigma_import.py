#!/usr/bin/env python3
"""
Direct SIGMA import script that bypasses API authentication.
This script imports SIGMA rules directly into the database.
"""

import asyncio
import sys
import os
from pathlib import Path
from typing import List

# Add the collector src to path
collector_path = Path(__file__).parent.parent / "apps" / "collector" / "src"
api_path = Path(__file__).parent.parent / "apps" / "api" / "src"
sys.path.insert(0, str(collector_path))
sys.path.insert(0, str(api_path))

try:
    from collectors.detection.sigma_collector import SigmaCollector
    from db.database import get_db_session
    from db.models.detection.detection import Detection
    from db.models.system.severity import Severity
    from sqlalchemy import select
    print("✅ Successfully imported required modules")
except ImportError as e:
    print(f"❌ Failed to import modules: {e}")
    sys.exit(1)


async def get_severities() -> dict:
    """Get severity mappings from database."""
    async with get_db_session() as session:
        result = await session.execute(select(Severity))
        severities = result.scalars().all()
        return {severity.name: severity.id for severity in severities}


async def import_sigma_rules(limit: int = 100):
    """Import SIGMA rules directly into database."""
    print(f"🎯 Starting SIGMA import (limit: {limit} rules)...")

    # Get severities
    severities = await get_severities()
    if not severities:
        print("❌ No severities found in database")
        return

    print(f"✅ Found severities: {list(severities.keys())}")

    # Initialize collector
    collector = SigmaCollector()

    # Clone/update SIGMA repository
    print("📥 Cloning/updating SIGMA repository...")
    await collector.clone_or_update_repo()

    # Get rule files (limited)
    print(f"🔍 Finding SIGMA rule files (limit: {limit})...")
    rule_files = await collector.get_rule_files(limit=limit)
    print(f"✅ Found {len(rule_files)} rule files")

    # Parse rules
    print("🔧 Parsing SIGMA rules...")
    detections = await collector.parser.parse_rules(rule_files)
    print(f"✅ Parsed {len(detections)} valid rules")

    # Save to database directly
    print("💾 Saving detections to database...")
    async with get_db_session() as session:
        saved_count = 0
        for detection_create in detections:
            try:
                # Convert to database model
                detection_dict = detection_create.model_dump(mode='json')
                detection = Detection(**detection_dict)

                session.add(detection)
                saved_count += 1

                if saved_count % 10 == 0:
                    print(f"  💾 Saved {saved_count}/{len(detections)} detections...")

            except Exception as e:
                print(f"❌ Failed to save detection '{detection_create.name}': {e}")
                continue

        # Commit all changes
        await session.commit()
        print(f"✅ Successfully saved {saved_count} detections to database")

    print("🎉 SIGMA import completed!")


async def main():
    """Main function."""
    import argparse

    parser = argparse.ArgumentParser(description="Direct SIGMA import script")
    parser.add_argument("--limit", type=int, default=100, help="Number of rules to import")
    args = parser.parse_args()

    try:
        await import_sigma_rules(limit=args.limit)
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())