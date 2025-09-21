.PHONY: help setup dev-up dev-down test test-api test-collector lint format security clean docs

# Default target
help:
	@echo "🚀 Countermeasure Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  setup          Install dependencies and setup development environment"
	@echo "  dev-up         Start development environment with Docker Compose"
	@echo "  dev-down       Stop development environment"
	@echo ""
	@echo "Development:"
	@echo "  test           Run all tests"
	@echo "  test-api       Run API tests only"
	@echo "  test-collector Run collector tests only"
	@echo "  lint           Run linting checks"
	@echo "  format         Format code with Black"
	@echo "  security       Run security scans"
	@echo ""
	@echo "Utilities:"
	@echo "  clean          Clean up build artifacts"
	@echo "  docs           Generate documentation"
	@echo "  migrate        Run database migrations"
	@echo "  shell-api      Open shell in API container"
	@echo "  shell-collector Open shell in collector container"

# Setup development environment
setup:
	@echo "🔧 Setting up development environment..."
	uv sync
	uv run pre-commit install
	@echo "✅ Setup complete!"

# Docker development environment
dev-up:
	@echo "🚀 Starting development environment..."
	docker-compose -f infrastructure/docker/docker-compose.dev.yml up -d
	@echo "✅ Development environment started!"
	@echo "🔗 API: http://localhost:8000"
	@echo "🔗 API Docs: http://localhost:8000/docs"
	@echo "🔗 Flower: http://localhost:5555"

dev-down:
	@echo "🛑 Stopping development environment..."
	docker-compose -f infrastructure/docker/docker-compose.dev.yml down
	@echo "✅ Development environment stopped!"

# Testing
test:
	@echo "🧪 Running all tests..."
	uv run pytest apps/ -v --cov=apps --cov-report=term-missing --cov-report=html
	@echo "✅ All tests completed!"

test-api:
	@echo "🧪 Running API tests..."
	cd apps/api && uv run pytest tests/ -v --cov=src --cov-report=term-missing

test-collector:
	@echo "🧪 Running Collector tests..."
	cd apps/collector && uv run pytest tests/ -v --cov=src --cov-report=term-missing

# Code quality
lint:
	@echo "🔍 Running linting checks..."
	uv run ruff check apps/
	uv run mypy apps/
	@echo "✅ Linting checks completed!"

format:
	@echo "🎨 Formatting code..."
	uv run ruff format apps/ packages/
	@echo "✅ Code formatting completed!"

security:
	@echo "🔒 Running security scans..."
	uv run bandit -r apps/ -f json -o security-report.json
	uv run safety check --json --output security-deps.json
	@echo "✅ Security scans completed!"

# Database
migrate:
	@echo "🗃️ Running database migrations..."
	docker-compose -f infrastructure/docker/docker-compose.dev.yml exec api alembic upgrade head
	@echo "✅ Database migrations completed!"

# Utilities
clean:
	@echo "🧹 Cleaning up..."
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	@echo "✅ Cleanup completed!"

docs:
	@echo "📚 Generating documentation..."
	# Add documentation generation commands here
	@echo "✅ Documentation generated!"

shell-api:
	@echo "🐚 Opening API shell..."
	docker-compose -f infrastructure/docker/docker-compose.dev.yml exec api bash

shell-collector:
	@echo "🐚 Opening Collector shell..."
	docker-compose -f infrastructure/docker/docker-compose.dev.yml exec collector bash

# Load testing
load-test:
	@echo "⚡ Running load tests..."
	docker-compose -f infrastructure/docker/docker-compose.dev.yml exec api locust -f tests/load/locustfile.py --headless -u 10 -r 2 -t 30s --host http://localhost:8000

# Milestone testing
milestone-1-test:
	@echo "🎯 Running Milestone 1 comprehensive tests..."
	@echo "1. Starting development environment..."
	make dev-up
	@echo "2. Waiting for services to be ready..."
	sleep 30
	@echo "3. Running health checks..."
	curl -f http://localhost:8000/health || (echo "❌ Health check failed" && exit 1)
	@echo "4. Running database migrations..."
	make migrate
	@echo "5. Running test suite..."
	make test
	@echo "6. Running security scans..."
	make security
	@echo "7. Running load tests..."
	make load-test
	@echo "✅ Milestone 1 tests completed successfully!"

# Production builds
build-api:
	@echo "🏗️ Building API Docker image..."
	docker build -t countermeasure/api:latest -f apps/api/Dockerfile apps/api/

build-collector:
	@echo "🏗️ Building Collector Docker image..."
	docker build -t countermeasure/collector:latest -f apps/collector/Dockerfile apps/collector/