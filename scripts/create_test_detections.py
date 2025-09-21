#!/usr/bin/env python3
"""
Create test detections using the SIGMA parser to verify our fixes.
"""

import asyncio
import sys
import os
from pathlib import Path
from typing import List
import tempfile
import yaml
import uuid

# Add the collector and API src to path
collector_src = str(Path(__file__).parent.parent / "apps" / "collector" / "src")
api_src = str(Path(__file__).parent.parent / "apps" / "api" / "src")
sys.path.insert(0, collector_src)
sys.path.insert(0, api_src)

try:
    from collectors.detection.sigma_parser import SigmaParser
    from src.db.database import get_db_session
    from src.db.models.detection.detection import Detection
    from src.db.models.system.severity import Severity
    from sqlalchemy import select
    print("✅ Successfully imported required modules")
except ImportError as e:
    print(f"❌ Failed to import modules: {e}")
    print(f"Collector src: {collector_src}")
    print(f"API src: {api_src}")
    import traceback
    traceback.print_exc()
    sys.exit(1)


async def get_severities() -> dict:
    """Get severity mappings from database."""
    async with get_db_session() as session:
        result = await session.execute(select(Severity))
        severities = result.scalars().all()
        return {severity.name: severity.id for severity in severities}


def create_test_sigma_rule(index: int) -> dict:
    """Create a test SIGMA rule YAML structure."""
    return {
        'title': f'Test SIGMA Rule {index:03d}',
        'description': f'Test description for rule {index} demonstrating our fixes',
        'level': 'medium',
        'status': 'testing',
        'author': 'Claude Code Test',
        'date': '2025/09/21',
        'id': str(uuid.uuid4()),
        'tags': ['attack.t1055', f'test.rule.{index}'],
        'detection': {
            'selection': {
                'EventID': 1,
                'Image|endswith': '\\test.exe'
            },
            'condition': 'selection'
        },
        'logsource': {
            'category': 'process_creation',
            'product': 'windows'
        },
        'falsepositives': [
            'Legitimate test applications',
            f'Test scenario {index}'
        ],
        'references': [
            f'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/test_rule_{index:03d}.yml'
        ],
        '_file_path': f'/tmp/sigma_rules_test/rules/windows/process_creation/test_rule_{index:03d}.yml',
        '_file_name': f'test_rule_{index:03d}.yml',
        '_original_content': f'# Test SIGMA rule {index}'
    }


async def create_test_detections(count: int = 100):
    """Create test detections using our SIGMA parser."""
    print(f"🎯 Creating {count} test detections...")

    # Get severities
    severities = await get_severities()
    if not severities:
        print("❌ No severities found in database")
        return

    print(f"✅ Found severities: {list(severities.keys())}")

    # Initialize parser
    parser = SigmaParser(severities)

    # Create test rules
    test_rules = []
    for i in range(1, count + 1):
        rule_data = create_test_sigma_rule(i)
        test_rules.append(rule_data)

    print(f"✅ Created {len(test_rules)} test rules")

    # Parse rules into detections
    print("🔧 Parsing test rules...")
    detections = []
    for rule_data in test_rules:
        detection = await parser.build_detection_create(rule_data)
        if detection:
            detections.append(detection)

    print(f"✅ Parsed {len(detections)} valid detections")

    # Verify our fixes
    print("🔍 Verifying fixes...")
    for i, detection in enumerate(detections[:5]):  # Check first 5
        print(f"  Detection {i+1}:")
        print(f"    ✅ Source URL: {detection.source_url}")
        print(f"    ✅ Platforms: {detection.platforms}")
        print(f"    ✅ Data Sources: {detection.data_sources}")
        print(f"    ✅ False Positives: {detection.false_positives}")
        print(f"    ✅ MITRE Techniques: {detection.mitre_technique_ids}")

    # Save to database
    print("💾 Saving detections to database...")
    async with get_db_session() as session:
        saved_count = 0
        for detection_create in detections:
            try:
                # Convert to database model using proper JSON serialization
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

    print("🎉 Test detection creation completed!")


async def main():
    """Main function."""
    import argparse

    parser = argparse.ArgumentParser(description="Create test detections")
    parser.add_argument("--count", type=int, default=100, help="Number of test detections to create")
    args = parser.parse_args()

    try:
        await create_test_detections(count=args.count)
    except Exception as e:
        print(f"💥 Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())