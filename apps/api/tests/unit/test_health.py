"""
Unit tests for health check endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_health_check(self, client: TestClient) -> None:
        """Test health check endpoint returns correct status."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert data["service"] == "Countermeasure API"
        assert data["version"] == "0.1.0"
        assert data["environment"] is not None
        assert "timestamp" in data
        assert "checks" in data
        assert data["checks"]["api"] == "healthy"

    def test_readiness_check(self, client: TestClient) -> None:
        """Test readiness check endpoint."""
        response = client.get("/ready")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "ready"
        assert data["service"] == "Countermeasure API"
        assert data["version"] == "0.1.0"

    def test_liveness_check(self, client: TestClient) -> None:
        """Test liveness check endpoint."""
        response = client.get("/live")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "alive"
        assert data["service"] == "Countermeasure API"
        assert data["version"] == "0.1.0"

    async def test_health_check_async(self, async_client: AsyncClient) -> None:
        """Test health check endpoint with async client."""
        response = await async_client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_metrics_endpoint(self, client: TestClient) -> None:
        """Test metrics endpoint returns Prometheus format."""
        response = client.get("/metrics")

        assert response.status_code == 200
        assert response.headers["content-type"] == "text/plain; charset=utf-8"

        content = response.text
        assert "countermeasure_info" in content
        assert "version=" in content
        assert "environment=" in content

    def test_root_endpoint(self, client: TestClient) -> None:
        """Test root endpoint returns API information."""
        response = client.get("/")

        assert response.status_code == 200
        data = response.json()

        assert data["service"] == "Countermeasure API"
        assert data["version"] == "0.1.0"
        assert data["status"] == "operational"