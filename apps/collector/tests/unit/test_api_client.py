"""
Unit tests for CountermeasureClient API client.
"""

import pytest
from unittest.mock import AsyncMock, patch, Mock
import aiohttp
from aiohttp import ClientError

from src.core.api_client import CountermeasureClient


class APIError(Exception):
    """Mock API error for testing."""
    pass


class TestCountermeasureClient:
    """Test suite for CountermeasureClient."""

    @pytest.fixture
    def client(self):
        """Create a CountermeasureClient instance."""
        return CountermeasureClient(
            base_url="http://test-api:8000",
            email="test@example.com",
            password="test-password"
        )

    @pytest.fixture
    def mock_response(self):
        """Create a mock HTTP response."""
        response = AsyncMock()
        response.status = 200
        response.json = AsyncMock(return_value={"success": True})
        response.text = AsyncMock(return_value='{"success": true}')
        response.headers = {"content-type": "application/json"}
        return response

    @pytest.fixture
    def mock_session(self, mock_response):
        """Create a mock aiohttp session."""
        session = AsyncMock()
        session.post.return_value.__aenter__.return_value = mock_response
        session.get.return_value.__aenter__.return_value = mock_response
        session.put.return_value.__aenter__.return_value = mock_response
        session.delete.return_value.__aenter__.return_value = mock_response
        return session

    @pytest.mark.asyncio
    async def test_login_success(self, client, mock_session):
        """Test successful login."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {
            "access_token": "test-access-token",
            "token_type": "bearer"
        }

        mock_session.post.return_value.__aenter__.return_value = mock_response

        with patch('aiohttp.ClientSession', return_value=mock_session):
            result = await client.login()

        assert result is True
        assert client.access_token == "test-access-token"
        assert client.is_authenticated is True

    @pytest.mark.asyncio
    async def test_login_failure(self, client, mock_session):
        """Test failed login."""
        mock_response = AsyncMock()
        mock_response.status = 401
        mock_response.json.return_value = {"detail": "Invalid credentials"}

        mock_session.post.return_value.__aenter__.return_value = mock_response

        with patch('aiohttp.ClientSession', return_value=mock_session):
            result = await client.login()

        assert result is False
        assert client.access_token is None
        assert client.is_authenticated is False

    @pytest.mark.asyncio
    async def test_health_check_success(self, client, mock_session):
        """Test successful health check."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {"status": "healthy"}

        mock_session.get.return_value.__aenter__.return_value = mock_response

        with patch('aiohttp.ClientSession', return_value=mock_session):
            result = await client.health_check()

        assert result == {"status": "healthy"}

    @pytest.mark.asyncio
    async def test_health_check_failure(self, client, mock_session):
        """Test health check failure."""
        mock_response = AsyncMock()
        mock_response.status = 503
        mock_response.json.return_value = {"status": "unhealthy"}

        mock_session.get.return_value.__aenter__.return_value = mock_response

        with patch('aiohttp.ClientSession', return_value=mock_session):
            with pytest.raises(APIError, match="API health check failed"):
                await client.health_check()

    @pytest.mark.asyncio
    async def test_create_detection_success(self, client, mock_session):
        """Test successful detection creation."""
        client.access_token = "test-token"

        mock_response = AsyncMock()
        mock_response.status = 201
        mock_response.json.return_value = {
            "id": "detection-123",
            "name": "Test Detection"
        }

        mock_session.post.return_value.__aenter__.return_value = mock_response

        detection_data = {
            "name": "Test Detection",
            "description": "Test description",
            "rule_content": "test rule",
            "rule_format": "sigma"
        }

        with patch('aiohttp.ClientSession', return_value=mock_session):
            result = await client.create_detection(detection_data)

        assert result["id"] == "detection-123"
        assert result["name"] == "Test Detection"

    @pytest.mark.asyncio
    async def test_create_detection_unauthorized(self, client, mock_session):
        """Test detection creation without authentication."""
        mock_response = AsyncMock()
        mock_response.status = 401
        mock_response.json.return_value = {"detail": "Unauthorized"}

        mock_session.post.return_value.__aenter__.return_value = mock_response

        detection_data = {
            "name": "Test Detection",
            "rule_content": "test rule"
        }

        with patch('aiohttp.ClientSession', return_value=mock_session):
            with pytest.raises(APIError, match="Authentication required"):
                await client.create_detection(detection_data)

    @pytest.mark.asyncio
    async def test_get_detections_success(self, client, mock_session):
        """Test successful detection retrieval."""
        client.access_token = "test-token"

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {
            "items": [
                {"id": "detection-1", "name": "Detection 1"},
                {"id": "detection-2", "name": "Detection 2"}
            ],
            "total": 2,
            "page": 1,
            "per_page": 10
        }

        mock_session.get.return_value.__aenter__.return_value = mock_response

        with patch('aiohttp.ClientSession', return_value=mock_session):
            result = await client.get_detections(per_page=10)

        assert len(result["items"]) == 2
        assert result["total"] == 2

    @pytest.mark.asyncio
    async def test_get_detections_with_filters(self, client, mock_session):
        """Test detection retrieval with filters."""
        client.access_token = "test-token"

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {
            "items": [{"id": "detection-1", "name": "Filtered Detection"}],
            "total": 1
        }

        mock_session.get.return_value.__aenter__.return_value = mock_response

        with patch('aiohttp.ClientSession', return_value=mock_session):
            result = await client.get_detections(
                search="test",
                status="active",
                per_page=5
            )

        # Verify the correct URL parameters were used
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args[1]
        assert "params" in call_args
        params = call_args["params"]
        assert params["search"] == "test"
        assert params["status"] == "active"
        assert params["per_page"] == 5

    @pytest.mark.asyncio
    async def test_update_detection_success(self, client, mock_session):
        """Test successful detection update."""
        client.access_token = "test-token"

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {
            "id": "detection-123",
            "name": "Updated Detection"
        }

        mock_session.put.return_value.__aenter__.return_value = mock_response

        update_data = {
            "name": "Updated Detection",
            "description": "Updated description"
        }

        with patch('aiohttp.ClientSession', return_value=mock_session):
            result = await client.update_detection("detection-123", update_data)

        assert result["name"] == "Updated Detection"

    @pytest.mark.asyncio
    async def test_delete_detection_success(self, client, mock_session):
        """Test successful detection deletion."""
        client.access_token = "test-token"

        mock_response = AsyncMock()
        mock_response.status = 204

        mock_session.delete.return_value.__aenter__.return_value = mock_response

        with patch('aiohttp.ClientSession', return_value=mock_session):
            result = await client.delete_detection("detection-123")

        assert result is True

    @pytest.mark.asyncio
    async def test_delete_detection_not_found(self, client, mock_session):
        """Test detection deletion when not found."""
        client.access_token = "test-token"

        mock_response = AsyncMock()
        mock_response.status = 404
        mock_response.json.return_value = {"detail": "Detection not found"}

        mock_session.delete.return_value.__aenter__.return_value = mock_response

        with patch('aiohttp.ClientSession', return_value=mock_session):
            with pytest.raises(APIError, match="API request failed"):
                await client.delete_detection("nonexistent")

    @pytest.mark.asyncio
    async def test_request_with_retry(self, client):
        """Test request retry mechanism."""
        client.access_token = "test-token"

        # Mock session that fails twice then succeeds
        mock_session = AsyncMock()

        # First two calls fail with connection error
        connection_error = ClientError("Connection failed")
        success_response = AsyncMock()
        success_response.status = 200
        success_response.json.return_value = {"success": True}

        mock_session.get.side_effect = [
            connection_error,
            connection_error,
            AsyncMock(__aenter__=AsyncMock(return_value=success_response))
        ]

        with patch('aiohttp.ClientSession', return_value=mock_session):
            with patch('asyncio.sleep', new=AsyncMock()):  # Mock sleep to speed up test
                result = await client._request_with_retry("GET", "/test")

        assert result == {"success": True}
        assert mock_session.get.call_count == 3

    @pytest.mark.asyncio
    async def test_request_with_retry_exhausted(self, client):
        """Test request retry mechanism when retries are exhausted."""
        client.access_token = "test-token"

        mock_session = AsyncMock()
        connection_error = ClientError("Connection failed")
        mock_session.get.side_effect = connection_error

        with patch('aiohttp.ClientSession', return_value=mock_session):
            with patch('asyncio.sleep', new=AsyncMock()):
                with pytest.raises(APIError, match="Max retries exceeded"):
                    await client._request_with_retry("GET", "/test")

    @pytest.mark.asyncio
    async def test_logout(self, client):
        """Test logout functionality."""
        client.access_token = "test-token"
        client.is_authenticated = True

        await client.logout()

        assert client.access_token is None
        assert client.is_authenticated is False

    @pytest.mark.asyncio
    async def test_close(self, client):
        """Test closing the client."""
        mock_session = AsyncMock()
        client._session = mock_session

        await client.close()

        mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test using client as context manager."""
        async with CountermeasureClient("http://test", "user", "pass") as client:
            assert client is not None

        # Session should be closed after context exit
        # (We can't easily test this without more complex mocking)

    def test_auth_headers(self, client):
        """Test authentication header generation."""
        client.access_token = "test-token"

        headers = client._get_auth_headers()

        assert headers["Authorization"] == "Bearer test-token"
        assert headers["Content-Type"] == "application/json"

    def test_auth_headers_without_token(self, client):
        """Test header generation without authentication."""
        headers = client._get_auth_headers(include_auth=False)

        assert "Authorization" not in headers
        assert headers["Content-Type"] == "application/json"

    @pytest.mark.asyncio
    async def test_batch_create_detections(self, client, mock_session):
        """Test batch detection creation."""
        client.access_token = "test-token"

        mock_response = AsyncMock()
        mock_response.status = 201
        mock_response.json.return_value = {
            "created": 2,
            "failed": 0,
            "items": [
                {"id": "detection-1", "name": "Detection 1"},
                {"id": "detection-2", "name": "Detection 2"}
            ]
        }

        mock_session.post.return_value.__aenter__.return_value = mock_response

        detections = [
            {"name": "Detection 1", "rule_content": "rule 1"},
            {"name": "Detection 2", "rule_content": "rule 2"}
        ]

        with patch('aiohttp.ClientSession', return_value=mock_session):
            result = await client.batch_create_detections(detections)

        assert result["created"] == 2
        assert result["failed"] == 0
        assert len(result["items"]) == 2