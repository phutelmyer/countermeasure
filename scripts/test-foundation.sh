#!/bin/bash

# 🧪 Foundation Testing Script for Milestone 1
# Tests the basic structure and Docker environment

set -e  # Exit on any error

echo "🎯 Testing Countermeasure Foundation - Milestone 1"
echo "=================================================="

# Test 1: Directory Structure
echo "📁 Testing directory structure..."
directories=(
    "apps/api/src/core"
    "apps/api/src/api/v1/endpoints"
    "apps/api/tests/unit"
    "apps/collector/src/collectors"
    "packages/shared-types"
    "infrastructure/docker"
    "docs"
    ".github/workflows"
)

for dir in "${directories[@]}"; do
    if [ -d "$dir" ]; then
        echo "  ✅ $dir exists"
    else
        echo "  ❌ $dir missing"
        exit 1
    fi
done

# Test 2: Required Files
echo ""
echo "📄 Testing required files..."
files=(
    "pyproject.toml"
    "Makefile"
    "README.md"
    ".env.example"
    "COUNTERMEASURE_PRD.md"
    "MILESTONE_1_CHECKLIST.md"
    "apps/api/Dockerfile"
    "apps/api/pyproject.toml"
    "apps/api/src/main.py"
    "infrastructure/docker/docker-compose.dev.yml"
)

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✅ $file exists"
    else
        echo "  ❌ $file missing"
        exit 1
    fi
done

# Test 3: Docker Compose Validation
echo ""
echo "🐳 Testing Docker Compose configuration..."
if command -v docker-compose &> /dev/null; then
    if docker-compose -f infrastructure/docker/docker-compose.dev.yml config > /dev/null; then
        echo "  ✅ Docker Compose configuration is valid"
    else
        echo "  ❌ Docker Compose configuration is invalid"
        exit 1
    fi
else
    echo "  ⚠️ Docker Compose not available, skipping validation"
fi

# Test 4: Python Syntax Check
echo ""
echo "🐍 Testing Python syntax..."
python_files=(
    "apps/api/src/main.py"
    "apps/api/src/core/config.py"
    "apps/api/src/core/logging.py"
    "apps/api/src/core/exceptions.py"
)

for file in "${python_files[@]}"; do
    if python -m py_compile "$file" 2>/dev/null; then
        echo "  ✅ $file syntax is valid"
    else
        echo "  ❌ $file has syntax errors"
        exit 1
    fi
done

# Test 5: Configuration Validation
echo ""
echo "⚙️ Testing configuration..."
if [ -f ".env.example" ]; then
    # Check for required environment variables
    required_vars=(
        "DATABASE_URL"
        "REDIS_URL"
        "SECRET_KEY"
        "API_HOST"
        "API_PORT"
    )

    for var in "${required_vars[@]}"; do
        if grep -q "$var=" .env.example; then
            echo "  ✅ $var configured in .env.example"
        else
            echo "  ❌ $var missing from .env.example"
            exit 1
        fi
    done
fi

echo ""
echo "🎉 Foundation testing completed successfully!"
echo ""
echo "Next steps:"
echo "1. Install dependencies: make setup"
echo "2. Start development environment: make dev-up"
echo "3. Run full test suite: make test"
echo ""
echo "🔗 Access URLs (after starting):"
echo "  - API: http://localhost:8000"
echo "  - API Docs: http://localhost:8000/docs"
echo "  - Flower: http://localhost:5555"