"""
Unit tests for middleware components.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import Request, Response
from fastapi.testclient import TestClient

from src.middleware.tenant import TenantIsolationMiddleware, AuditMiddleware


class TestTenantIsolationMiddleware:
    """Test suite for TenantIsolationMiddleware."""

    @pytest.fixture
    def middleware(self):
        """Create middleware instance for testing."""
        return TenantIsolationMiddleware(app=MagicMock())

    @pytest.fixture
    def mock_request(self):
        """Create mock request for testing."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.url = MagicMock()
        request.url.path = "/api/v1/detections"
        request.method = "GET"
        return request

    @pytest.fixture
    def mock_response(self):
        """Create mock response for testing."""
        response = MagicMock(spec=Response)
        response.headers = {}
        response.status_code = 200
        return response

    @pytest.mark.asyncio
    async def test_dispatch_success(self, middleware, mock_request, mock_response):
        """Test successful request processing."""
        # Mock call_next
        async def mock_call_next(request):
            return mock_response

        response = await middleware.dispatch(mock_request, mock_call_next)

        assert response == mock_response
        assert mock_request.state.tenant_id is None
        assert mock_request.state.user_id is None

    @pytest.mark.asyncio
    async def test_dispatch_adds_debug_header_in_development(
        self, middleware, mock_request, mock_response
    ):
        """Test that debug headers are added in development mode."""
        mock_request.state.tenant_id = "test-tenant-id"

        with patch("src.middleware.tenant.settings") as mock_settings:
            mock_settings.is_development = True

            async def mock_call_next(request):
                return mock_response

            response = await middleware.dispatch(mock_request, mock_call_next)

            assert response.headers["X-Tenant-ID"] == "test-tenant-id"

    @pytest.mark.asyncio
    async def test_dispatch_no_debug_header_in_production(
        self, middleware, mock_request, mock_response
    ):
        """Test that debug headers are not added in production mode."""
        mock_request.state.tenant_id = "test-tenant-id"

        with patch("src.middleware.tenant.settings") as mock_settings:
            mock_settings.is_development = False

            async def mock_call_next(request):
                return mock_response

            response = await middleware.dispatch(mock_request, mock_call_next)

            assert "X-Tenant-ID" not in response.headers

    @pytest.mark.asyncio
    async def test_dispatch_handles_exception(self, middleware, mock_request):
        """Test exception handling in middleware."""
        test_exception = Exception("Test error")

        async def mock_call_next(request):
            raise test_exception

        with patch("src.middleware.tenant.logger") as mock_logger:
            with pytest.raises(Exception, match="Test error"):
                await middleware.dispatch(mock_request, mock_call_next)

            mock_logger.error.assert_called_once()
            call_args = mock_logger.error.call_args[1]
            assert call_args["error"] == "Test error"
            assert call_args["path"] == "/api/v1/detections"
            assert call_args["method"] == "GET"

    @pytest.mark.asyncio
    async def test_dispatch_initializes_request_state(self, middleware, mock_request):
        """Test that request state is properly initialized."""
        async def mock_call_next(request):
            # Verify state was initialized
            assert hasattr(request.state, 'tenant_id')
            assert hasattr(request.state, 'user_id')
            assert request.state.tenant_id is None
            assert request.state.user_id is None
            return MagicMock(spec=Response)

        await middleware.dispatch(mock_request, mock_call_next)


class TestAuditMiddleware:
    """Test suite for AuditMiddleware."""

    @pytest.fixture
    def middleware(self):
        """Create middleware instance for testing."""
        return AuditMiddleware(app=MagicMock())

    @pytest.fixture
    def mock_request(self):
        """Create mock request for testing."""
        request = MagicMock(spec=Request)
        request.url = MagicMock()
        request.url.path = "/api/v1/detections"
        request.method = "POST"
        request.client = MagicMock()
        request.client.host = "192.168.1.100"
        request.headers = {"User-Agent": "test-client/1.0"}
        request.state = MagicMock()
        request.state.user_id = "user-123"
        request.state.tenant_id = "tenant-456"
        return request

    @pytest.fixture
    def mock_response(self):
        """Create mock response for testing."""
        response = MagicMock(spec=Response)
        response.status_code = 200
        return response

    @pytest.mark.asyncio
    async def test_dispatch_success_logs_request(
        self, middleware, mock_request, mock_response
    ):
        """Test successful request logging."""
        async def mock_call_next(request):
            return mock_response

        with patch("src.middleware.tenant.logger") as mock_logger:
            response = await middleware.dispatch(mock_request, mock_call_next)

            assert response == mock_response
            mock_logger.info.assert_called_once_with(
                "api_request_success",
                method="POST",
                path="/api/v1/detections",
                status_code=200,
                ip_address="192.168.1.100",
                user_agent="test-client/1.0",
                user_id="user-123",
                tenant_id="tenant-456",
            )

    @pytest.mark.asyncio
    async def test_dispatch_skips_audit_paths(self, middleware):
        """Test that certain paths are skipped for auditing."""
        skip_paths = ["/health", "/docs", "/redoc", "/openapi.json", "/metrics"]

        for path in skip_paths:
            request = MagicMock(spec=Request)
            request.url = MagicMock()
            request.url.path = path

            response = MagicMock(spec=Response)

            async def mock_call_next(request):
                return response

            with patch("src.middleware.tenant.logger") as mock_logger:
                result = await middleware.dispatch(request, mock_call_next)

                assert result == response
                mock_logger.info.assert_not_called()
                mock_logger.error.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_non_2xx_response_no_log(
        self, middleware, mock_request
    ):
        """Test that non-2xx responses are not logged as success."""
        response = MagicMock(spec=Response)
        response.status_code = 400

        async def mock_call_next(request):
            return response

        with patch("src.middleware.tenant.logger") as mock_logger:
            result = await middleware.dispatch(mock_request, mock_call_next)

            assert result == response
            mock_logger.info.assert_not_called()

    @pytest.mark.asyncio
    async def test_dispatch_handles_exception(self, middleware, mock_request):
        """Test exception handling and logging."""
        test_exception = Exception("Test error")

        async def mock_call_next(request):
            raise test_exception

        with patch("src.middleware.tenant.logger") as mock_logger:
            with pytest.raises(Exception, match="Test error"):
                await middleware.dispatch(mock_request, mock_call_next)

            mock_logger.error.assert_called_once_with(
                "api_request_error",
                method="POST",
                path="/api/v1/detections",
                error="Test error",
                ip_address="192.168.1.100",
                user_agent="test-client/1.0",
                user_id="user-123",
                tenant_id="tenant-456",
            )

    @pytest.mark.asyncio
    async def test_dispatch_no_client_info(self, middleware, mock_response):
        """Test handling request without client information."""
        request = MagicMock(spec=Request)
        request.url = MagicMock()
        request.url.path = "/api/v1/detections"
        request.method = "GET"
        request.client = None
        request.headers = {}
        request.state = MagicMock()
        request.state.user_id = None
        request.state.tenant_id = None

        async def mock_call_next(request):
            return mock_response

        with patch("src.middleware.tenant.logger") as mock_logger:
            response = await middleware.dispatch(request, mock_call_next)

            assert response == mock_response
            mock_logger.info.assert_called_once_with(
                "api_request_success",
                method="GET",
                path="/api/v1/detections",
                status_code=200,
                ip_address=None,
                user_agent=None,
                user_id=None,
                tenant_id=None,
            )

    @pytest.mark.asyncio
    async def test_dispatch_missing_state_attributes(self, middleware, mock_request, mock_response):
        """Test handling request with missing state attributes."""
        # Remove state attributes
        delattr(mock_request.state, 'user_id')
        delattr(mock_request.state, 'tenant_id')

        async def mock_call_next(request):
            return mock_response

        with patch("src.middleware.tenant.logger") as mock_logger:
            response = await middleware.dispatch(mock_request, mock_call_next)

            assert response == mock_response
            mock_logger.info.assert_called_once_with(
                "api_request_success",
                method="POST",
                path="/api/v1/detections",
                status_code=200,
                ip_address="192.168.1.100",
                user_agent="test-client/1.0",
                user_id=None,
                tenant_id=None,
            )

    @pytest.mark.asyncio
    async def test_skip_audit_paths_constant(self, middleware):
        """Test that the SKIP_AUDIT_PATHS constant contains expected paths."""
        expected_paths = {
            "/health",
            "/ready",
            "/live",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
        }

        assert middleware.SKIP_AUDIT_PATHS == expected_paths


class TestMiddleware:
    """Test middleware functionality with TestClient."""

    def test_correlation_id_middleware(
        self, client: TestClient, sample_correlation_id: str
    ) -> None:
        """Test correlation ID middleware adds and returns correlation ID."""
        # Test with provided correlation ID
        response = client.get(
            "/health", headers={"X-Correlation-ID": sample_correlation_id}
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
            },
        )

        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers