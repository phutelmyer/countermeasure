#!/bin/bash

# API Restart Script for Countermeasure
# Restarts the API server cleanly

set -e

echo "🔄 Restarting Countermeasure API..."

# Kill any existing uvicorn processes
echo "🛑 Stopping existing API processes..."
pkill -f uvicorn || true
sleep 2

# Navigate to API directory
cd "$(dirname "$0")/../apps/api"

echo "📁 Current directory: $(pwd)"

# Check if virtual environment exists and sync dependencies
echo "📦 Syncing dependencies..."
uv sync

# Run database migrations if needed
echo "🗄️  Running database migrations..."
uv run alembic upgrade head

# Start the API server
echo "🚀 Starting API server..."
uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

echo "✅ API restart complete!"