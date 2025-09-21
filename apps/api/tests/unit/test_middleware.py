"""
Unit tests for middleware components.
"""

import pytest
from fastapi.testclient import TestClient


class TestMiddleware:
    """Test middleware functionality."""

    def test_correlation_id_middleware(self, client: TestClient, sample_correlation_id: str) -> None:
        """Test correlation ID middleware adds and returns correlation ID."""
        # Test with provided correlation ID
        response = client.get(
            "/health",
            headers={"X-Correlation-ID": sample_correlation_id}
        )

        assert response.status_code == 200
        assert response.headers["X-Correlation-ID"] == sample_correlation_id
        assert "X-Process-Time" in response.headers

    def test_correlation_id_generation(self, client: TestClient) -> None:
        """Test correlation ID is generated when not provided."""
        response = client.get("/health")

        assert response.status_code == 200
        assert "X-Correlation-ID" in response.headers
        assert len(response.headers["X-Correlation-ID"]) > 0
        assert "X-Process-Time" in response.headers

    def test_security_headers(self, client: TestClient) -> None:
        """Test security headers are added to responses."""
        response = client.get("/health")

        assert response.status_code == 200

        # Check security headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    def test_cors_headers(self, client: TestClient) -> None:
        """Test CORS headers are properly configured."""
        # Test preflight request
        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            }
        )

        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers