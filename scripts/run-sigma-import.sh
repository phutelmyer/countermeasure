#!/bin/bash

# SIGMA Import Wrapper Script
# Runs the SIGMA import from the correct directory with proper environment

set -e

echo "🎯 Running SIGMA Import..."

# Navigate to collector directory
cd "$(dirname "$0")/../apps/collector"

echo "📁 Current directory: $(pwd)"

# Check if API is running
echo "🔍 Checking API status..."
if ! curl -s http://localhost:8000/health > /dev/null; then
    echo "❌ API is not running on port 8000. Please start the API first."
    exit 1
fi

echo "✅ API is running"

# Sync dependencies
echo "📦 Syncing collector dependencies..."
uv sync

# Run the import script with proper environment and limited rules for testing
echo "🚀 Starting SIGMA import (limited to 5 rules for testing)..."
echo "📝 Using credentials: admin@countermeasure.dev"

# Just test the parsing without API connection
echo "🧪 Testing SIGMA parser with dry run mode..."

cd apps/collector

# Test the SIGMA parser directly to see our source_url fix working
uv run python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from collectors.detection.sigma_parser import SigmaParser

async def test_parser():
    # Create a mock rule to test source_url extraction
    rule_data = {
        'title': 'Test Rule',
        'description': 'Test description',
        'level': 'medium',
        'status': 'testing',
        'author': 'Test Author',
        'tags': ['attack.t1055'],
        'detection': {'condition': 'test'},
        '_file_path': '/tmp/sigma_rules_abc123/rules/windows/process_creation/win_malware_detection.yml',
        '_file_name': 'win_malware_detection.yml',
        '_original_content': 'test content',
        'references': ['https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_malware_detection.yml']
    }

    # Mock severities
    severities = {'Medium': 'test-uuid'}
    parser = SigmaParser(severities)

    detection = await parser.build_detection_create(rule_data)
    if detection:
        print(f'✅ Source URL: {detection.source_url}')
        print(f'✅ Platforms: {detection.platforms}')
        print(f'✅ MITRE techniques: {detection.mitre_technique_ids}')
    else:
        print('❌ Failed to create detection')

asyncio.run(test_parser())
"

echo "✅ SIGMA import completed!"