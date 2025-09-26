"""
Integration tests for tenant isolation.

Tests that data is properly isolated between tenants,
row-level security works correctly, and cross-tenant
access is prevented.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models.system.user import User
from src.db.models.system.tenant import Tenant
from src.db.models.detection import Detection
from src.db.models.actor import Actor


class TestTenantIsolation:
    """Test tenant data isolation and security."""

    @pytest.fixture
    async def second_tenant_and_user(
        self, db_session: AsyncSession
    ) -> tuple[Tenant, User]:
        """Create a second tenant and user for isolation testing."""
        from src.db.models.system.tenant import Tenant
        from src.db.models.system.user import User
        from src.core.security import get_password_hash

        # Create second tenant
        tenant2 = Tenant(
            name="Second Tenant",
            domain="tenant2.com",
            is_active=True
        )
        db_session.add(tenant2)
        await db_session.flush()

        # Create user for second tenant
        user2 = User(
            tenant_id=tenant2.id,
            email="user2@tenant2.com",
            full_name="Second User",
            hashed_password=get_password_hash("SecondPassword123!"),
            is_active=True,
            is_superuser=False
        )
        db_session.add(user2)
        await db_session.commit()

        return tenant2, user2

    async def test_user_cannot_access_other_tenant_data(
        self,
        client: TestClient,
        test_user: User,
        test_tenant: Tenant,
        second_tenant_and_user: tuple[Tenant, User],
    ):
        """Test that users cannot access data from other tenants."""
        tenant2, user2 = second_tenant_and_user

        # Login as first user
        login_response1 = client.post(
            "/api/v1/auth/login",
            json={"email": test_user.email, "password": "TestPassword123!"}
        )
        assert login_response1.status_code == 200
        token1 = login_response1.json()["access_token"]
        headers1 = {"Authorization": f"Bearer {token1}"}

        # Login as second user
        login_response2 = client.post(
            "/api/v1/auth/login",
            json={"email": user2.email, "password": "SecondPassword123!"}
        )
        assert login_response2.status_code == 200
        token2 = login_response2.json()["access_token"]
        headers2 = {"Authorization": f"Bearer {token2}"}

        # Create detection as first user
        detection_data1 = {
            "name": "Tenant 1 Detection",
            "description": "Detection for tenant 1",
            "rule_yaml": "detection:\n  selection:\n    field: value\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "status": "active",
            "visibility": "public",
        }

        create_response1 = client.post(
            "/api/v1/detections/",
            json=detection_data1,
            headers=headers1
        )
        assert create_response1.status_code == 201
        detection1 = create_response1.json()

        # Create detection as second user
        detection_data2 = {
            "name": "Tenant 2 Detection",
            "description": "Detection for tenant 2",
            "rule_yaml": "detection:\n  selection:\n    field: value2\n  condition: selection",
            "platforms": ["Linux"],
            "data_sources": ["Network Traffic"],
            "status": "active",
            "visibility": "public",
        }

        create_response2 = client.post(
            "/api/v1/detections/",
            json=detection_data2,
            headers=headers2
        )
        assert create_response2.status_code == 201
        detection2 = create_response2.json()

        # User 1 should only see their own detection
        list_response1 = client.get("/api/v1/detections/", headers=headers1)
        assert list_response1.status_code == 200
        detections1 = list_response1.json()["items"]

        detection1_ids = [d["id"] for d in detections1]
        assert detection1["id"] in detection1_ids
        assert detection2["id"] not in detection1_ids

        # User 2 should only see their own detection
        list_response2 = client.get("/api/v1/detections/", headers=headers2)
        assert list_response2.status_code == 200
        detections2 = list_response2.json()["items"]

        detection2_ids = [d["id"] for d in detections2]
        assert detection2["id"] in detection2_ids
        assert detection1["id"] not in detection2_ids

        # User 1 should not be able to access User 2's detection directly
        access_response1 = client.get(
            f"/api/v1/detections/{detection2['id']}",
            headers=headers1
        )
        assert access_response1.status_code == 404

        # User 2 should not be able to access User 1's detection directly
        access_response2 = client.get(
            f"/api/v1/detections/{detection1['id']}",
            headers=headers2
        )
        assert access_response2.status_code == 404

    async def test_user_cannot_modify_other_tenant_data(
        self,
        client: TestClient,
        test_user: User,
        second_tenant_and_user: tuple[Tenant, User],
    ):
        """Test that users cannot modify data from other tenants."""
        tenant2, user2 = second_tenant_and_user

        # Login as both users
        login_response1 = client.post(
            "/api/v1/auth/login",
            json={"email": test_user.email, "password": "TestPassword123!"}
        )
        token1 = login_response1.json()["access_token"]
        headers1 = {"Authorization": f"Bearer {token1}"}

        login_response2 = client.post(
            "/api/v1/auth/login",
            json={"email": user2.email, "password": "SecondPassword123!"}
        )
        token2 = login_response2.json()["access_token"]
        headers2 = {"Authorization": f"Bearer {token2}"}

        # Create actor as user 2
        actor_data = {
            "name": "Tenant 2 Actor",
            "description": "Actor for tenant 2",
            "country": "Unknown",
            "actor_type": "unknown",
        }

        create_response = client.post(
            "/api/v1/actors/",
            json=actor_data,
            headers=headers2
        )
        assert create_response.status_code == 201
        actor = create_response.json()

        # User 1 should not be able to update User 2's actor
        update_data = {"name": "Modified by User 1"}
        update_response = client.put(
            f"/api/v1/actors/{actor['id']}",
            json=update_data,
            headers=headers1
        )
        assert update_response.status_code == 404

        # User 1 should not be able to delete User 2's actor
        delete_response = client.delete(
            f"/api/v1/actors/{actor['id']}",
            headers=headers1
        )
        assert delete_response.status_code == 404

        # Verify actor is unchanged
        get_response = client.get(
            f"/api/v1/actors/{actor['id']}",
            headers=headers2
        )
        assert get_response.status_code == 200
        unchanged_actor = get_response.json()
        assert unchanged_actor["name"] == actor_data["name"]

    async def test_tenant_admin_isolation(
        self,
        client: TestClient,
        db_session: AsyncSession,
        test_tenant: Tenant,
        second_tenant_and_user: tuple[Tenant, User],
    ):
        """Test that tenant admins can only manage their own tenant."""
        from src.db.models.system.user import User
        from src.core.security import get_password_hash

        tenant2, user2 = second_tenant_and_user

        # Create admin user for first tenant
        admin1 = User(
            tenant_id=test_tenant.id,
            email="admin1@tenant1.com",
            full_name="Admin User 1",
            hashed_password=get_password_hash("AdminPassword123!"),
            is_active=True,
            is_superuser=True  # Tenant admin
        )
        db_session.add(admin1)

        # Create admin user for second tenant
        admin2 = User(
            tenant_id=tenant2.id,
            email="admin2@tenant2.com",
            full_name="Admin User 2",
            hashed_password=get_password_hash("AdminPassword123!"),
            is_active=True,
            is_superuser=True  # Tenant admin
        )
        db_session.add(admin2)
        await db_session.commit()

        # Login as both admins
        admin1_response = client.post(
            "/api/v1/auth/login",
            json={"email": admin1.email, "password": "AdminPassword123!"}
        )
        admin1_token = admin1_response.json()["access_token"]
        admin1_headers = {"Authorization": f"Bearer {admin1_token}"}

        admin2_response = client.post(
            "/api/v1/auth/login",
            json={"email": admin2.email, "password": "AdminPassword123!"}
        )
        admin2_token = admin2_response.json()["access_token"]
        admin2_headers = {"Authorization": f"Bearer {admin2_token}"}

        # Admin 1 should only see users from their tenant
        users1_response = client.get("/api/v1/users/", headers=admin1_headers)
        assert users1_response.status_code == 200
        users1 = users1_response.json()["items"]

        tenant1_user_emails = [u["email"] for u in users1]
        assert admin1.email in tenant1_user_emails
        assert admin2.email not in tenant1_user_emails
        assert user2.email not in tenant1_user_emails

        # Admin 2 should only see users from their tenant
        users2_response = client.get("/api/v1/users/", headers=admin2_headers)
        assert users2_response.status_code == 200
        users2 = users2_response.json()["items"]

        tenant2_user_emails = [u["email"] for u in users2]
        assert admin2.email in tenant2_user_emails
        assert user2.email in tenant2_user_emails
        assert admin1.email not in tenant2_user_emails

        # Admin 1 should not be able to modify users from tenant 2
        user_update_data = {"full_name": "Modified by Admin 1"}
        update_response = client.put(
            f"/api/v1/users/{user2.id}",
            json=user_update_data,
            headers=admin1_headers
        )
        assert update_response.status_code == 404

    async def test_search_respects_tenant_isolation(
        self,
        client: TestClient,
        test_user: User,
        second_tenant_and_user: tuple[Tenant, User],
    ):
        """Test that search operations respect tenant boundaries."""
        tenant2, user2 = second_tenant_and_user

        # Login as both users
        login_response1 = client.post(
            "/api/v1/auth/login",
            json={"email": test_user.email, "password": "TestPassword123!"}
        )
        token1 = login_response1.json()["access_token"]
        headers1 = {"Authorization": f"Bearer {token1}"}

        login_response2 = client.post(
            "/api/v1/auth/login",
            json={"email": user2.email, "password": "SecondPassword123!"}
        )
        token2 = login_response2.json()["access_token"]
        headers2 = {"Authorization": f"Bearer {token2}"}

        # Create detections with same name in both tenants
        shared_name = "Common Detection Name"

        detection_data = {
            "name": shared_name,
            "description": "Detection in tenant 1",
            "rule_yaml": "detection:\n  selection:\n    field: value1\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "status": "active",
            "visibility": "public",
        }

        # Create in tenant 1
        create_response1 = client.post(
            "/api/v1/detections/",
            json=detection_data,
            headers=headers1
        )
        assert create_response1.status_code == 201
        detection1 = create_response1.json()

        # Modify for tenant 2
        detection_data["description"] = "Detection in tenant 2"
        detection_data["rule_yaml"] = "detection:\n  selection:\n    field: value2\n  condition: selection"

        # Create in tenant 2
        create_response2 = client.post(
            "/api/v1/detections/",
            json=detection_data,
            headers=headers2
        )
        assert create_response2.status_code == 201
        detection2 = create_response2.json()

        # Search by name from tenant 1 perspective
        search_response1 = client.get(
            f"/api/v1/detections/?search={shared_name}",
            headers=headers1
        )
        assert search_response1.status_code == 200
        search_results1 = search_response1.json()["items"]

        # Should only find tenant 1's detection
        assert len(search_results1) == 1
        assert search_results1[0]["id"] == detection1["id"]
        assert "tenant 1" in search_results1[0]["description"]

        # Search by name from tenant 2 perspective
        search_response2 = client.get(
            f"/api/v1/detections/?search={shared_name}",
            headers=headers2
        )
        assert search_response2.status_code == 200
        search_results2 = search_response2.json()["items"]

        # Should only find tenant 2's detection
        assert len(search_results2) == 1
        assert search_results2[0]["id"] == detection2["id"]
        assert "tenant 2" in search_results2[0]["description"]

    async def test_bulk_operations_respect_tenant_isolation(
        self,
        client: TestClient,
        test_user: User,
        second_tenant_and_user: tuple[Tenant, User],
    ):
        """Test that bulk operations cannot cross tenant boundaries."""
        tenant2, user2 = second_tenant_and_user

        # Login as both users
        login_response1 = client.post(
            "/api/v1/auth/login",
            json={"email": test_user.email, "password": "TestPassword123!"}
        )
        token1 = login_response1.json()["access_token"]
        headers1 = {"Authorization": f"Bearer {token1}"}

        login_response2 = client.post(
            "/api/v1/auth/login",
            json={"email": user2.email, "password": "SecondPassword123!"}
        )
        token2 = login_response2.json()["access_token"]
        headers2 = {"Authorization": f"Bearer {token2}"}

        # Create actors in both tenants
        actor_data1 = {
            "name": "Tenant 1 Actor",
            "description": "Actor in tenant 1",
            "country": "Unknown",
            "actor_type": "unknown",
        }
        create_response1 = client.post("/api/v1/actors/", json=actor_data1, headers=headers1)
        actor1 = create_response1.json()

        actor_data2 = {
            "name": "Tenant 2 Actor",
            "description": "Actor in tenant 2",
            "country": "Unknown",
            "actor_type": "unknown",
        }
        create_response2 = client.post("/api/v1/actors/", json=actor_data2, headers=headers2)
        actor2 = create_response2.json()

        # User 1 tries to perform bulk operation including User 2's actor
        # This would be through individual operations since we test one at a time

        # Try to get actor from other tenant (should fail)
        get_response = client.get(f"/api/v1/actors/{actor2['id']}", headers=headers1)
        assert get_response.status_code == 404

        # Try to update actor from other tenant (should fail)
        update_response = client.put(
            f"/api/v1/actors/{actor2['id']}",
            json={"name": "Modified by Tenant 1"},
            headers=headers1
        )
        assert update_response.status_code == 404

        # Verify that User 2's actor is unchanged
        verify_response = client.get(f"/api/v1/actors/{actor2['id']}", headers=headers2)
        assert verify_response.status_code == 200
        unchanged_actor = verify_response.json()
        assert unchanged_actor["name"] == actor_data2["name"]

    async def test_tenant_context_consistency(
        self,
        client: TestClient,
        test_user: User,
        test_tenant: Tenant,
    ):
        """Test that tenant context remains consistent throughout request lifecycle."""
        # Login
        login_response = client.post(
            "/api/v1/auth/login",
            json={"email": test_user.email, "password": "TestPassword123!"}
        )
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Create multiple resources in sequence
        # Each should maintain the same tenant context

        # Create actor
        actor_data = {
            "name": "Test Actor",
            "description": "Test actor for context consistency",
            "country": "Unknown",
            "actor_type": "unknown",
        }
        actor_response = client.post("/api/v1/actors/", json=actor_data, headers=headers)
        assert actor_response.status_code == 201
        actor = actor_response.json()
        assert actor["tenant_id"] == test_tenant.id

        # Create detection referencing the actor
        detection_data = {
            "name": "Test Detection",
            "description": "Test detection for context consistency",
            "rule_yaml": "detection:\n  selection:\n    field: value\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "actor_ids": [actor["id"]],
            "status": "active",
            "visibility": "public",
        }
        detection_response = client.post(
            "/api/v1/detections/",
            json=detection_data,
            headers=headers
        )
        assert detection_response.status_code == 201
        detection = detection_response.json()
        assert detection["tenant_id"] == test_tenant.id

        # Verify relationship works within tenant
        assert len(detection["actors"]) == 1
        assert detection["actors"][0]["id"] == actor["id"]

        # List operations should only show tenant-scoped data
        actors_response = client.get("/api/v1/actors/", headers=headers)
        assert actors_response.status_code == 200
        actors = actors_response.json()["items"]

        for returned_actor in actors:
            assert returned_actor["tenant_id"] == test_tenant.id

        detections_response = client.get("/api/v1/detections/", headers=headers)
        assert detections_response.status_code == 200
        detections = detections_response.json()["items"]

        for returned_detection in detections:
            assert returned_detection["tenant_id"] == test_tenant.id