"""
End-to-end tests for error handling scenarios.

Tests system behavior under various error conditions including
network failures, invalid data, concurrent operations, and recovery.
"""

import pytest
import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models.system.user import User


class TestErrorHandlingE2E:
    """End-to-end tests for error handling and recovery."""

    async def test_authentication_error_scenarios(self, client: TestClient):
        """Test various authentication error scenarios and recovery."""

        # Test 1: Invalid credentials
        invalid_login = client.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent@example.com", "password": "WrongPassword"}
        )
        assert invalid_login.status_code == 401
        error_detail = invalid_login.json()
        assert "detail" in error_detail

        # Test 2: Malformed email
        malformed_email = client.post(
            "/api/v1/auth/login",
            json={"email": "not-an-email", "password": "SomePassword123!"}
        )
        assert malformed_email.status_code == 422  # Validation error

        # Test 3: Missing required fields
        missing_fields = client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com"}  # Missing password
        )
        assert missing_fields.status_code == 422

        # Test 4: Create valid user for further testing
        valid_signup = {
            "email": "errortest@example.com",
            "password": "ValidPassword123!",
            "full_name": "Error Test User",
            "company_name": "Error Testing Corp",
        }

        signup_response = client.post("/api/v1/auth/signup", json=valid_signup)
        assert signup_response.status_code == 201
        signup_result = signup_response.json()
        valid_token = signup_result["access_token"]
        valid_headers = {"Authorization": f"Bearer {valid_token}"}

        # Test 5: Expired/invalid token usage
        invalid_token_headers = {"Authorization": "Bearer invalid_token_here"}
        protected_request = client.get("/api/v1/auth/me", headers=invalid_token_headers)
        assert protected_request.status_code == 401

        # Test 6: Valid token should work
        valid_protected_request = client.get("/api/v1/auth/me", headers=valid_headers)
        assert valid_protected_request.status_code == 200

        # Test 7: Multiple failed login attempts
        for _ in range(5):
            failed_attempt = client.post(
                "/api/v1/auth/login",
                json={"email": valid_signup["email"], "password": "WrongPassword"}
            )
            assert failed_attempt.status_code == 401

        # Successful login should still work (no account lockout in basic implementation)
        successful_login = client.post(
            "/api/v1/auth/login",
            json={"email": valid_signup["email"], "password": valid_signup["password"]}
        )
        assert successful_login.status_code == 200

    async def test_data_validation_error_scenarios(self, client: TestClient):
        """Test comprehensive data validation error handling."""

        # Setup authenticated user
        signup_data = {
            "email": "validation@example.com",
            "password": "ValidationTest123!",
            "full_name": "Validation Test User",
            "company_name": "Validation Corp",
        }

        signup_response = client.post("/api/v1/auth/signup", json=signup_data)
        headers = {"Authorization": f"Bearer {signup_response.json()['access_token']}"}

        # Test 1: Invalid actor data
        invalid_actor_tests = [
            # Missing required fields
            {"description": "Missing name"},
            # Invalid enum values
            {"name": "Test Actor", "actor_type": "invalid_type", "country": "Unknown"},
            # Invalid data types
            {"name": 123, "description": "Name should be string"},
            # Empty required fields
            {"name": "", "description": "Empty name"},
        ]

        for invalid_data in invalid_actor_tests:
            response = client.post("/api/v1/actors/", json=invalid_data, headers=headers)
            assert response.status_code == 422

        # Test 2: Invalid detection data
        invalid_detection_tests = [
            # Missing required fields
            {"description": "Missing name and rule"},
            # Invalid confidence score
            {"name": "Test", "rule_yaml": "rule", "confidence_score": 1.5},
            # Invalid status
            {"name": "Test", "rule_yaml": "rule", "status": "invalid_status"},
            # Empty arrays where content expected
            {"name": "Test", "rule_yaml": "rule", "platforms": []},
            # Invalid UUID format for relationships
            {"name": "Test", "rule_yaml": "rule", "actor_ids": ["not-a-uuid"]},
        ]

        for invalid_data in invalid_detection_tests:
            response = client.post("/api/v1/detections/", json=invalid_data, headers=headers)
            assert response.status_code == 422

        # Test 3: Valid data should work after errors
        valid_actor = {
            "name": "Valid Actor",
            "description": "This actor should be created successfully",
            "country": "Unknown",
            "actor_type": "unknown",
        }

        valid_actor_response = client.post("/api/v1/actors/", json=valid_actor, headers=headers)
        assert valid_actor_response.status_code == 201
        created_actor = valid_actor_response.json()

        valid_detection = {
            "name": "Valid Detection",
            "description": "This detection should be created successfully",
            "rule_yaml": "detection:\n  selection:\n    field: value\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "actor_ids": [created_actor["id"]],
            "status": "draft",
            "visibility": "public",
        }

        valid_detection_response = client.post("/api/v1/detections/", json=valid_detection, headers=headers)
        assert valid_detection_response.status_code == 201

    async def test_concurrent_operation_error_scenarios(self, client: TestClient):
        """Test error handling in concurrent operation scenarios."""

        # Setup multiple users
        users = []
        for i in range(3):
            signup_data = {
                "email": f"concurrent{i}@example.com",
                "password": f"ConcurrentTest{i}123!",
                "full_name": f"Concurrent User {i}",
                "company_name": f"Concurrent Corp {i}",
            }

            signup_response = client.post("/api/v1/auth/signup", json=signup_data)
            token = signup_response.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            users.append((signup_data["email"], headers))

        # Test 1: Concurrent creation of similar resources
        def create_actor(user_headers, actor_name):
            actor_data = {
                "name": actor_name,
                "description": f"Actor created concurrently",
                "country": "Unknown",
                "actor_type": "unknown",
            }
            return client.post("/api/v1/actors/", json=actor_data, headers=user_headers)

        # Create actors concurrently with same name (should be allowed as they're in different tenants)
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for i, (email, headers) in enumerate(users):
                future = executor.submit(create_actor, headers, "Concurrent Actor")
                futures.append(future)

            results = [future.result() for future in futures]

        # All should succeed (different tenants)
        for result in results:
            assert result.status_code == 201

        # Test 2: Concurrent updates to same resource (within tenant)
        # Create detection for first user
        detection_data = {
            "name": "Concurrent Update Test",
            "description": "Testing concurrent updates",
            "rule_yaml": "detection:\n  selection:\n    field: value\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "status": "draft",
            "visibility": "public",
        }

        create_response = client.post("/api/v1/detections/", json=detection_data, headers=users[0][1])
        detection_id = create_response.json()["id"]

        def update_detection(headers, update_data):
            return client.put(f"/api/v1/detections/{detection_id}", json=update_data, headers=headers)

        # Try concurrent updates from same user
        update_data_1 = {"description": "Updated by operation 1"}
        update_data_2 = {"description": "Updated by operation 2"}

        with ThreadPoolExecutor(max_workers=2) as executor:
            future1 = executor.submit(update_detection, users[0][1], update_data_1)
            future2 = executor.submit(update_detection, users[0][1], update_data_2)

            result1 = future1.result()
            result2 = future2.result()

        # Both updates should succeed (last one wins)
        assert result1.status_code == 200
        assert result2.status_code == 200

        # Verify final state
        final_state = client.get(f"/api/v1/detections/{detection_id}", headers=users[0][1])
        final_detection = final_state.json()
        # Should have one of the update descriptions
        assert "Updated by operation" in final_detection["description"]

        # Test 3: Concurrent operations across tenants (should not interfere)
        def create_detection_for_user(headers, detection_name):
            detection = {
                "name": detection_name,
                "description": "Concurrent cross-tenant detection",
                "rule_yaml": "detection:\n  selection:\n    field: value\n  condition: selection",
                "platforms": ["Windows"],
                "data_sources": ["Process Creation"],
                "status": "active",
                "visibility": "public",
            }
            return client.post("/api/v1/detections/", json=detection, headers=headers)

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for i, (email, headers) in enumerate(users):
                future = executor.submit(create_detection_for_user, headers, f"Cross-Tenant Detection {i}")
                futures.append(future)

            cross_tenant_results = [future.result() for future in futures]

        # All should succeed
        for result in cross_tenant_results:
            assert result.status_code == 201

        # Verify each user only sees their own detection
        for i, (email, headers) in enumerate(users):
            detections_response = client.get("/api/v1/detections/", headers=headers)
            detections = detections_response.json()["items"]

            # Find detections with cross-tenant pattern
            cross_tenant_detections = [d for d in detections if "Cross-Tenant Detection" in d["name"]]
            # Should only see their own
            assert len(cross_tenant_detections) == 1
            assert f"Cross-Tenant Detection {i}" in cross_tenant_detections[0]["name"]

    async def test_resource_not_found_error_scenarios(self, client: TestClient):
        """Test handling of resource not found scenarios."""

        # Setup user
        signup_data = {
            "email": "notfound@example.com",
            "password": "NotFoundTest123!",
            "full_name": "Not Found Test User",
            "company_name": "Not Found Corp",
        }

        signup_response = client.post("/api/v1/auth/signup", json=signup_data)
        headers = {"Authorization": f"Bearer {signup_response.json()['access_token']}"}

        # Test 1: Non-existent resource access
        fake_uuid = "00000000-0000-0000-0000-000000000000"

        not_found_tests = [
            ("GET", f"/api/v1/actors/{fake_uuid}"),
            ("PUT", f"/api/v1/actors/{fake_uuid}", {"name": "Updated"}),
            ("DELETE", f"/api/v1/actors/{fake_uuid}"),
            ("GET", f"/api/v1/detections/{fake_uuid}"),
            ("PUT", f"/api/v1/detections/{fake_uuid}", {"name": "Updated"}),
            ("DELETE", f"/api/v1/detections/{fake_uuid}"),
        ]

        for method, url, *body in not_found_tests:
            if method == "GET":
                response = client.get(url, headers=headers)
            elif method == "PUT":
                response = client.put(url, json=body[0], headers=headers)
            elif method == "DELETE":
                response = client.delete(url, headers=headers)

            assert response.status_code == 404

        # Test 2: Valid resource creation and then deletion
        actor_data = {
            "name": "Temporary Actor",
            "description": "Actor to be deleted",
            "country": "Unknown",
            "actor_type": "unknown",
        }

        create_response = client.post("/api/v1/actors/", json=actor_data, headers=headers)
        actor_id = create_response.json()["id"]

        # Verify it exists
        get_response = client.get(f"/api/v1/actors/{actor_id}", headers=headers)
        assert get_response.status_code == 200

        # Delete it
        delete_response = client.delete(f"/api/v1/actors/{actor_id}", headers=headers)
        assert delete_response.status_code == 204

        # Verify it's gone
        gone_response = client.get(f"/api/v1/actors/{actor_id}", headers=headers)
        assert gone_response.status_code == 404

        # Try to delete again
        double_delete_response = client.delete(f"/api/v1/actors/{actor_id}", headers=headers)
        assert double_delete_response.status_code == 404

        # Test 3: Malformed UUID handling
        malformed_uuids = [
            "not-a-uuid",
            "123",
            "00000000-0000-0000-0000",  # Too short
            "00000000-0000-0000-0000-000000000000-extra",  # Too long
        ]

        for malformed_uuid in malformed_uuids:
            malformed_response = client.get(f"/api/v1/actors/{malformed_uuid}", headers=headers)
            # Should be 422 (validation error) or 404, depending on implementation
            assert malformed_response.status_code in [404, 422]

    async def test_system_recovery_scenarios(self, client: TestClient):
        """Test system recovery from various error states."""

        # Setup user
        signup_data = {
            "email": "recovery@example.com",
            "password": "RecoveryTest123!",
            "full_name": "Recovery Test User",
            "company_name": "Recovery Corp",
        }

        signup_response = client.post("/api/v1/auth/signup", json=signup_data)
        headers = {"Authorization": f"Bearer {signup_response.json()['access_token']}"}

        # Test 1: Partial operation failure recovery
        # Create actor successfully
        actor_data = {
            "name": "Recovery Test Actor",
            "description": "Actor for recovery testing",
            "country": "Unknown",
            "actor_type": "unknown",
        }

        actor_response = client.post("/api/v1/actors/", json=actor_data, headers=headers)
        assert actor_response.status_code == 201
        actor_id = actor_response.json()["id"]

        # Try to create detection with invalid actor reference
        invalid_detection = {
            "name": "Invalid Reference Detection",
            "description": "Detection with invalid actor reference",
            "rule_yaml": "detection:\n  selection:\n    field: value\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "actor_ids": [actor_id, "00000000-0000-0000-0000-000000000000"],  # One valid, one invalid
            "status": "draft",
            "visibility": "public",
        }

        invalid_detection_response = client.post("/api/v1/detections/", json=invalid_detection, headers=headers)
        # Should fail due to invalid actor reference
        assert invalid_detection_response.status_code in [400, 422, 404]

        # Create valid detection after failure
        valid_detection = {
            "name": "Valid Recovery Detection",
            "description": "Detection created after failure",
            "rule_yaml": "detection:\n  selection:\n    field: value\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "actor_ids": [actor_id],  # Only valid actor
            "status": "draft",
            "visibility": "public",
        }

        valid_detection_response = client.post("/api/v1/detections/", json=valid_detection, headers=headers)
        assert valid_detection_response.status_code == 201

        # Verify system state is consistent
        actors_response = client.get("/api/v1/actors/", headers=headers)
        detections_response = client.get("/api/v1/detections/", headers=headers)

        actors = actors_response.json()["items"]
        detections = detections_response.json()["items"]

        assert len(actors) == 1  # One actor created
        assert len(detections) == 1  # One detection created (invalid one failed)
        assert detections[0]["name"] == "Valid Recovery Detection"

        # Test 2: Cascade operation recovery
        # Delete actor (should not affect detection if properly designed)
        delete_actor_response = client.delete(f"/api/v1/actors/{actor_id}", headers=headers)
        assert delete_actor_response.status_code == 204

        # Check detection still exists but relationship is handled gracefully
        remaining_detections = client.get("/api/v1/detections/", headers=headers)
        detections_after_actor_delete = remaining_detections.json()["items"]

        assert len(detections_after_actor_delete) == 1
        # The detection should either:
        # 1. Still exist with empty actors array (soft reference)
        # 2. Be automatically deleted (cascade delete)
        # We'll verify it still exists for this test
        detection = detections_after_actor_delete[0]
        assert detection["name"] == "Valid Recovery Detection"

        # Test 3: Bulk operation partial failure recovery
        bulk_actors = []
        for i in range(5):
            bulk_actor_data = {
                "name": f"Bulk Actor {i}",
                "description": f"Actor {i} for bulk testing",
                "country": "Unknown",
                "actor_type": "unknown",
            }

            # Create first 3 successfully
            if i < 3:
                bulk_response = client.post("/api/v1/actors/", json=bulk_actor_data, headers=headers)
                assert bulk_response.status_code == 201
                bulk_actors.append(bulk_response.json())

            # Try to create 4th with invalid data
            elif i == 3:
                invalid_bulk_data = {
                    "name": f"Bulk Actor {i}",
                    "description": f"Actor {i} for bulk testing",
                    "country": "Unknown",
                    "actor_type": "invalid_type",  # Invalid
                }

                invalid_bulk_response = client.post("/api/v1/actors/", json=invalid_bulk_data, headers=headers)
                assert invalid_bulk_response.status_code == 422

            # Create 5th successfully after failure
            else:
                recovery_response = client.post("/api/v1/actors/", json=bulk_actor_data, headers=headers)
                assert recovery_response.status_code == 201
                bulk_actors.append(recovery_response.json())

        # Verify final state: 4 actors created (3 + 1 after failure)
        final_actors_response = client.get("/api/v1/actors/", headers=headers)
        final_actors = final_actors_response.json()["items"]

        # Should have 4 bulk actors (original actor was deleted)
        bulk_actor_count = len([a for a in final_actors if "Bulk Actor" in a["name"]])
        assert bulk_actor_count == 4

        # Test 4: System state consistency after mixed operations
        # Perform various operations to verify system remains consistent
        operations_log = []

        # Create detection
        final_detection = {
            "name": "Final Consistency Test",
            "description": "Testing final system consistency",
            "rule_yaml": "detection:\n  selection:\n    final: test\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "status": "active",
            "visibility": "public",
        }

        final_detection_response = client.post("/api/v1/detections/", json=final_detection, headers=headers)
        operations_log.append(("create_detection", final_detection_response.status_code))

        # Update detection
        update_response = client.put(
            f"/api/v1/detections/{final_detection_response.json()['id']}",
            json={"description": "Updated for consistency test"},
            headers=headers
        )
        operations_log.append(("update_detection", update_response.status_code))

        # List all resources
        final_actors_list = client.get("/api/v1/actors/", headers=headers)
        final_detections_list = client.get("/api/v1/detections/", headers=headers)

        operations_log.append(("list_actors", final_actors_list.status_code))
        operations_log.append(("list_detections", final_detections_list.status_code))

        # All operations should succeed
        for operation, status_code in operations_log:
            assert status_code in [200, 201], f"Operation {operation} failed with status {status_code}"

        # Verify final counts
        final_actor_count = final_actors_list.json()["total"]
        final_detection_count = final_detections_list.json()["total"]

        assert final_actor_count == 4  # 4 bulk actors
        assert final_detection_count == 2  # Recovery detection + final detection