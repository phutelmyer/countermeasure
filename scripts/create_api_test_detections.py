#!/usr/bin/env python3
"""
Create test detections via API to verify our fixes.
"""

import asyncio
import json
import uuid
import requests
from typing import List


def create_test_detection_data(index: int) -> dict:
    """Create test detection data that demonstrates our fixes."""
    return {
        "name": f"Test SIGMA Rule {index:03d}",
        "description": f"Test description for rule {index} demonstrating source_url and array fixes",
        "rule_content": f"""title: Test SIGMA Rule {index:03d}
description: Test description for rule {index}
level: medium
status: testing
author: Claude Code Test
tags:
  - attack.t1055
  - test.rule.{index}
detection:
  selection:
    EventID: 1
    Image|endswith: '\\\\test.exe'
  condition: selection
logsource:
  category: process_creation
  product: windows
falsepositives:
  - Legitimate test applications
  - Test scenario {index}
references:
  - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/test_rule_{index:03d}.yml""",
        "rule_format": "sigma",
        "severity_id": "placeholder",  # Will be filled with actual severity ID
        "visibility": "community",
        "performance_impact": "low",
        "status": "testing",
        "version": "1.0.0",
        "author": "Claude Code Test",
        "source_url": f"https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/test_rule_{index:03d}.yml",
        "mitre_technique_ids": ["T1055"],
        "platforms": ["Windows"],  # This should be stored as a proper array
        "data_sources": ["Process Creation", "Sysmon"],  # This should be stored as a proper array
        "false_positives": ["Legitimate test applications", f"Test scenario {index}"],  # This should be stored as a proper array
        "confidence_score": 0.8
    }


def get_severities() -> dict:
    """Get severity mappings from API."""
    try:
        response = requests.get("http://localhost:8000/api/v1/detections/severities/")
        if response.status_code == 200:
            severities = response.json()
            return {severity["name"]: severity["id"] for severity in severities}
        else:
            print(f"❌ Failed to get severities: {response.status_code}")
            return {}
    except Exception as e:
        print(f"❌ Failed to get severities: {e}")
        return {}


def create_detection_via_api(detection_data: dict) -> bool:
    """Create a detection via API."""
    try:
        response = requests.post(
            "http://localhost:8000/api/v1/detections",
            json=detection_data,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 201:
            return True
        else:
            print(f"❌ Failed to create detection '{detection_data['name']}': {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"❌ Failed to create detection '{detection_data['name']}': {e}")
        return False


def verify_detection_data() -> None:
    """Verify that our created detections have proper data."""
    try:
        response = requests.get("http://localhost:8000/api/v1/detections?limit=5")
        if response.status_code == 200:
            data = response.json()
            detections = data.get("items", [])

            print(f"🔍 Verifying data for {len(detections)} detections...")
            for i, detection in enumerate(detections):
                print(f"  Detection {i+1}: {detection['name']}")
                print(f"    ✅ Source URL: {detection.get('source_url', 'NOT SET')}")
                print(f"    ✅ Platforms: {detection.get('platforms', [])} (type: {type(detection.get('platforms', []))})")
                print(f"    ✅ Data Sources: {detection.get('data_sources', [])} (type: {type(detection.get('data_sources', []))})")
                print(f"    ✅ False Positives: {detection.get('false_positives', [])} (type: {type(detection.get('false_positives', []))})")
                print(f"    ✅ MITRE Techniques: {detection.get('mitre_technique_ids', [])}")
                print()
        else:
            print(f"❌ Failed to verify detections: {response.status_code}")
    except Exception as e:
        print(f"❌ Failed to verify detections: {e}")


def main():
    """Main function."""
    count = 100
    print(f"🎯 Creating {count} test detections via API...")

    # Get severities
    severities = get_severities()
    if not severities:
        print("❌ No severities found")
        return

    print(f"✅ Found severities: {list(severities.keys())}")

    # Use "Medium" severity as default
    default_severity_id = severities.get("Medium")
    if not default_severity_id:
        default_severity_id = list(severities.values())[0]  # Use first available

    # Create test detections
    print(f"🚀 Creating {count} test detections...")
    created_count = 0

    for i in range(1, count + 1):
        detection_data = create_test_detection_data(i)
        detection_data["severity_id"] = default_severity_id

        if create_detection_via_api(detection_data):
            created_count += 1
            if created_count % 10 == 0:
                print(f"  ✅ Created {created_count}/{count} detections...")

    print(f"✅ Successfully created {created_count}/{count} detections")

    # Verify the data
    print("🔍 Verifying detection data...")
    verify_detection_data()

    print("🎉 Test detection creation completed!")


if __name__ == "__main__":
    main()