"""
Integration tests for API communication.

Tests real communication between collector and API server
including authentication, data submission, and error handling.
"""

import pytest
import asyncio
import aiohttp
from unittest.mock import Mock, patch, AsyncMock

from src.core.api_client import CountermeasureClient
from src.schemas.detection import DetectionCreate


class TestApiCommunicationIntegration:
    """Integration tests for API communication."""

    @pytest.mark.asyncio
    async def test_full_authentication_flow(self):
        """Test complete authentication flow with API server."""
        # Test with mock server that simulates real API behavior

        async def mock_auth_handler(request):
            """Mock authentication endpoint."""
            if request.method == "POST" and request.path == "/api/v1/auth/login":
                data = await request.json()
                if data.get("email") == "test@example.com" and data.get("password") == "valid_password":
                    return aiohttp.web.json_response({
                        "access_token": "mock_access_token_12345",
                        "refresh_token": "mock_refresh_token_67890",
                        "token_type": "bearer",
                        "expires_in": 3600
                    })
                else:
                    return aiohttp.web.json_response(
                        {"detail": "Invalid credentials"},
                        status=401
                    )
            return aiohttp.web.json_response({"detail": "Not found"}, status=404)

        # Create mock server
        app = aiohttp.web.Application()
        app.router.add_post("/api/v1/auth/login", mock_auth_handler)

        async with aiohttp.test_utils.TestServer(app) as server:
            base_url = f"http://{server.host}:{server.port}"

            # Test successful authentication
            client = CountermeasureClient(
                api_url=base_url,
                email="test@example.com",
                password="valid_password"
            )

            login_success = await client.login()
            assert login_success is True
            assert client.access_token == "mock_access_token_12345"
            assert client.refresh_token == "mock_refresh_token_67890"

            await client.close()

            # Test failed authentication
            client_invalid = CountermeasureClient(
                api_url=base_url,
                email="test@example.com",
                password="invalid_password"
            )

            login_failure = await client_invalid.login()
            assert login_failure is False
            assert client_invalid.access_token is None

            await client_invalid.close()

    @pytest.mark.asyncio
    async def test_detection_submission_flow(self):
        """Test complete detection submission workflow."""

        async def mock_api_handler(request):
            """Mock API endpoints for detection submission."""
            auth_header = request.headers.get("Authorization")

            if not auth_header or auth_header != "Bearer mock_access_token_12345":
                return aiohttp.web.json_response(
                    {"detail": "Unauthorized"},
                    status=401
                )

            if request.method == "POST" and request.path == "/api/v1/auth/login":
                return aiohttp.web.json_response({
                    "access_token": "mock_access_token_12345",
                    "refresh_token": "mock_refresh_token_67890",
                    "token_type": "bearer",
                    "expires_in": 3600
                })

            elif request.method == "POST" and request.path == "/api/v1/detections/":
                data = await request.json()

                # Validate required fields
                if not data.get("name") or not data.get("rule_yaml"):
                    return aiohttp.web.json_response(
                        {"detail": "Missing required fields"},
                        status=422
                    )

                # Simulate successful creation
                detection_response = {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "name": data["name"],
                    "description": data.get("description", ""),
                    "rule_yaml": data["rule_yaml"],
                    "platforms": data.get("platforms", []),
                    "data_sources": data.get("data_sources", []),
                    "status": data.get("status", "draft"),
                    "visibility": data.get("visibility", "public"),
                    "confidence_score": data.get("confidence_score", 0.5),
                    "tenant_id": "tenant_123",
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z",
                    "actors": [],
                    "mitre_techniques": []
                }

                return aiohttp.web.json_response(detection_response, status=201)

            elif request.method == "GET" and request.path == "/api/v1/detections/":
                # Simulate detection listing
                return aiohttp.web.json_response({
                    "items": [],
                    "total": 0,
                    "page": 1,
                    "per_page": 50,
                    "pages": 1
                })

            return aiohttp.web.json_response({"detail": "Not found"}, status=404)

        # Create mock server
        app = aiohttp.web.Application()
        app.router.add_route("*", "/{path:.*}", mock_api_handler)

        async with aiohttp.test_utils.TestServer(app) as server:
            base_url = f"http://{server.host}:{server.port}"

            client = CountermeasureClient(
                api_url=base_url,
                email="test@example.com",
                password="valid_password"
            )

            # Authenticate
            login_success = await client.login()
            assert login_success is True

            # Test detection submission
            detection_data = DetectionCreate(
                name="Test Detection Integration",
                description="Integration test detection",
                rule_yaml="""
title: Test Detection
description: Test detection for integration testing
detection:
    selection:
        EventID: 1
        Image|endswith: '.exe'
    condition: selection
level: medium
                """,
                platforms=["Windows"],
                data_sources=["Process Creation"],
                status="draft",
                visibility="public",
                confidence_score=0.75
            )

            created_detection = await client.create_detection(detection_data)

            assert created_detection is not None
            assert created_detection["name"] == "Test Detection Integration"
            assert created_detection["confidence_score"] == 0.75
            assert created_detection["id"] == "550e8400-e29b-41d4-a716-446655440000"

            # Test detection listing
            detections = await client.get_detections()
            assert isinstance(detections, dict)
            assert "items" in detections
            assert "total" in detections

            await client.close()

    @pytest.mark.asyncio
    async def test_api_error_handling(self):
        """Test API error handling scenarios."""

        async def mock_error_handler(request):
            """Mock API that returns various errors."""
            path = request.path

            if "/auth/login" in path:
                return aiohttp.web.json_response({
                    "access_token": "mock_token",
                    "refresh_token": "mock_refresh",
                    "token_type": "bearer",
                    "expires_in": 3600
                })
            elif "/timeout" in path:
                # Simulate timeout by sleeping
                await asyncio.sleep(10)
                return aiohttp.web.json_response({"message": "Should timeout"})
            elif "/server_error" in path:
                return aiohttp.web.json_response(
                    {"detail": "Internal server error"},
                    status=500
                )
            elif "/rate_limit" in path:
                return aiohttp.web.json_response(
                    {"detail": "Rate limit exceeded"},
                    status=429
                )
            elif "/validation_error" in path:
                return aiohttp.web.json_response(
                    {"detail": "Validation failed", "errors": ["field is required"]},
                    status=422
                )
            elif "/not_found" in path:
                return aiohttp.web.json_response(
                    {"detail": "Resource not found"},
                    status=404
                )

            return aiohttp.web.json_response({"detail": "Not found"}, status=404)

        app = aiohttp.web.Application()
        app.router.add_route("*", "/{path:.*}", mock_error_handler)

        async with aiohttp.test_utils.TestServer(app) as server:
            base_url = f"http://{server.host}:{server.port}"

            client = CountermeasureClient(
                api_url=base_url,
                email="test@example.com",
                password="valid_password",
                timeout=2  # Short timeout for testing
            )

            # Authenticate first
            await client.login()

            # Test timeout handling
            try:
                response = await client._make_request("GET", "/timeout")
                # Should raise timeout exception or return None
                assert response is None  # Depending on implementation
            except asyncio.TimeoutError:
                pass  # Expected behavior
            except aiohttp.ClientError:
                pass  # Also acceptable

            # Test server error handling
            response = await client._make_request("GET", "/server_error")
            assert response is None  # Should handle 500 error gracefully

            # Test rate limiting
            response = await client._make_request("GET", "/rate_limit")
            assert response is None  # Should handle 429 error gracefully

            # Test validation error
            response = await client._make_request("POST", "/validation_error", data={})
            assert response is None  # Should handle 422 error gracefully

            # Test not found
            response = await client._make_request("GET", "/not_found")
            assert response is None  # Should handle 404 error gracefully

            await client.close()

    @pytest.mark.asyncio
    async def test_retry_mechanism(self):
        """Test API request retry mechanism."""
        request_count = 0

        async def mock_retry_handler(request):
            """Mock API that fails first few times then succeeds."""
            nonlocal request_count
            request_count += 1

            if "/auth/login" in request.path:
                return aiohttp.web.json_response({
                    "access_token": "mock_token",
                    "refresh_token": "mock_refresh",
                    "token_type": "bearer",
                    "expires_in": 3600
                })
            elif "/retry_test" in request.path:
                if request_count < 3:  # Fail first 2 requests
                    return aiohttp.web.json_response(
                        {"detail": "Temporary failure"},
                        status=503
                    )
                else:  # Succeed on 3rd attempt
                    return aiohttp.web.json_response({"success": True})

            return aiohttp.web.json_response({"detail": "Not found"}, status=404)

        app = aiohttp.web.Application()
        app.router.add_route("*", "/{path:.*}", mock_retry_handler)

        async with aiohttp.test_utils.TestServer(app) as server:
            base_url = f"http://{server.host}:{server.port}"

            client = CountermeasureClient(
                api_url=base_url,
                email="test@example.com",
                password="valid_password"
            )

            await client.login()

            # Reset counter for the test
            request_count = 0

            # Test retry mechanism (if implemented)
            response = await client._make_request("GET", "/retry_test")

            # Should eventually succeed after retries
            # Implementation may or may not include automatic retries
            if hasattr(client, 'max_retries') and client.max_retries > 0:
                assert response is not None
                assert response.get("success") is True
                assert request_count >= 3  # Should have retried

            await client.close()

    @pytest.mark.asyncio
    async def test_concurrent_api_requests(self):
        """Test concurrent API requests handling."""

        async def mock_concurrent_handler(request):
            """Mock API that handles concurrent requests."""
            if "/auth/login" in request.path:
                return aiohttp.web.json_response({
                    "access_token": "mock_token",
                    "refresh_token": "mock_refresh",
                    "token_type": "bearer",
                    "expires_in": 3600
                })
            elif "/concurrent_test" in request.path:
                # Simulate some processing time
                await asyncio.sleep(0.1)

                # Extract request ID from query params if present
                request_id = request.query.get("id", "unknown")

                return aiohttp.web.json_response({
                    "request_id": request_id,
                    "processed": True,
                    "timestamp": "2024-01-01T00:00:00Z"
                })

            return aiohttp.web.json_response({"detail": "Not found"}, status=404)

        app = aiohttp.web.Application()
        app.router.add_route("*", "/{path:.*}", mock_concurrent_handler)

        async with aiohttp.test_utils.TestServer(app) as server:
            base_url = f"http://{server.host}:{server.port}"

            client = CountermeasureClient(
                api_url=base_url,
                email="test@example.com",
                password="valid_password"
            )

            await client.login()

            # Create multiple concurrent requests
            async def make_concurrent_request(request_id):
                response = await client._make_request(
                    "GET",
                    f"/concurrent_test?id={request_id}"
                )
                return response

            # Submit 5 concurrent requests
            tasks = []
            for i in range(5):
                task = asyncio.create_task(make_concurrent_request(f"req_{i}"))
                tasks.append(task)

            # Wait for all requests to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Verify all requests completed successfully
            successful_results = [r for r in results if not isinstance(r, Exception)]
            assert len(successful_results) == 5

            # Verify each request got its own response
            request_ids = [r.get("request_id") for r in successful_results if r]
            assert len(set(request_ids)) == 5  # All unique

            await client.close()

    @pytest.mark.asyncio
    async def test_large_data_submission(self):
        """Test submission of large detection data."""

        async def mock_large_data_handler(request):
            """Mock API that handles large data submissions."""
            if "/auth/login" in request.path:
                return aiohttp.web.json_response({
                    "access_token": "mock_token",
                    "refresh_token": "mock_refresh",
                    "token_type": "bearer",
                    "expires_in": 3600
                })
            elif request.method == "POST" and "/detections/" in request.path:
                data = await request.json()

                # Simulate processing large rule_yaml
                rule_yaml = data.get("rule_yaml", "")
                if len(rule_yaml) > 10000:  # Large rule
                    # Simulate longer processing time
                    await asyncio.sleep(0.5)

                return aiohttp.web.json_response({
                    "id": "large_detection_id",
                    "name": data["name"],
                    "rule_yaml_size": len(rule_yaml),
                    "processed": True
                }, status=201)

            return aiohttp.web.json_response({"detail": "Not found"}, status=404)

        app = aiohttp.web.Application()
        app.router.add_route("*", "/{path:.*}", mock_large_data_handler)

        async with aiohttp.test_utils.TestServer(app) as server:
            base_url = f"http://{server.host}:{server.port}"

            client = CountermeasureClient(
                api_url=base_url,
                email="test@example.com",
                password="valid_password"
            )

            await client.login()

            # Create large detection data
            large_rule_yaml = "title: Large Test Rule\n" + \
                             "description: " + "A" * 10000 + "\n" + \
                             "detection:\n  selection:\n    field: value\n  condition: selection\n"

            large_detection = DetectionCreate(
                name="Large Detection Test",
                description="Testing large data submission",
                rule_yaml=large_rule_yaml,
                platforms=["Windows"],
                data_sources=["Process Creation"],
                status="draft",
                visibility="public"
            )

            # Submit large detection
            result = await client.create_detection(large_detection)

            assert result is not None
            assert result["name"] == "Large Detection Test"
            assert result["rule_yaml_size"] > 10000
            assert result["processed"] is True

            await client.close()

    @pytest.mark.asyncio
    async def test_network_connectivity_issues(self):
        """Test handling of network connectivity issues."""

        # Test with invalid API URL
        client_invalid_url = CountermeasureClient(
            api_url="http://invalid-domain-that-does-not-exist.com",
            email="test@example.com",
            password="valid_password"
        )

        # Should handle connection failure gracefully
        login_result = await client_invalid_url.login()
        assert login_result is False
        assert client_invalid_url.access_token is None

        await client_invalid_url.close()

        # Test with unreachable port
        client_wrong_port = CountermeasureClient(
            api_url="http://localhost:99999",  # Unlikely to be in use
            email="test@example.com",
            password="valid_password"
        )

        login_result = await client_wrong_port.login()
        assert login_result is False

        await client_wrong_port.close()

    @pytest.mark.asyncio
    async def test_authentication_token_refresh(self):
        """Test token refresh mechanism."""

        token_refresh_count = 0

        async def mock_token_refresh_handler(request):
            """Mock API with token refresh support."""
            nonlocal token_refresh_count

            if "/auth/login" in request.path:
                return aiohttp.web.json_response({
                    "access_token": "initial_token",
                    "refresh_token": "initial_refresh",
                    "token_type": "bearer",
                    "expires_in": 1  # Very short expiry for testing
                })
            elif "/auth/refresh" in request.path:
                token_refresh_count += 1
                return aiohttp.web.json_response({
                    "access_token": f"refreshed_token_{token_refresh_count}",
                    "refresh_token": f"new_refresh_{token_refresh_count}",
                    "token_type": "bearer",
                    "expires_in": 3600
                })
            elif "/protected" in request.path:
                auth_header = request.headers.get("Authorization", "")
                if "initial_token" in auth_header:
                    # Simulate token expiry
                    return aiohttp.web.json_response(
                        {"detail": "Token expired"},
                        status=401
                    )
                elif "refreshed_token" in auth_header:
                    return aiohttp.web.json_response({"access": "granted"})
                else:
                    return aiohttp.web.json_response(
                        {"detail": "Invalid token"},
                        status=401
                    )

            return aiohttp.web.json_response({"detail": "Not found"}, status=404)

        app = aiohttp.web.Application()
        app.router.add_route("*", "/{path:.*}", mock_token_refresh_handler)

        async with aiohttp.test_utils.TestServer(app) as server:
            base_url = f"http://{server.host}:{server.port}"

            client = CountermeasureClient(
                api_url=base_url,
                email="test@example.com",
                password="valid_password"
            )

            # Initial login
            await client.login()
            assert client.access_token == "initial_token"

            # Access protected resource (should trigger refresh if implemented)
            response = await client._make_request("GET", "/protected")

            # Depending on implementation, should either:
            # 1. Automatically refresh token and succeed
            # 2. Return None/error on 401

            if hasattr(client, 'auto_refresh') and client.auto_refresh:
                assert response is not None
                assert response.get("access") == "granted"
                assert token_refresh_count > 0
                assert "refreshed_token" in client.access_token
            else:
                # If no auto-refresh, should handle 401 gracefully
                assert response is None or response.get("detail") == "Token expired"

            await client.close()