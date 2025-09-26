"""
Integration tests for audit logging.

Tests that user actions are properly logged for compliance
and security monitoring purposes.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from src.db.models.system.user import User
from src.db.models.system.tenant import Tenant


class TestAuditLogging:
    """Test comprehensive audit logging functionality."""

    async def test_auth_events_are_logged(
        self,
        client: TestClient,
        db_session: AsyncSession,
        test_user: User,
        test_tenant: Tenant,
    ):
        """Test that authentication events generate audit logs."""
        # Clear any existing audit logs for clean testing
        await db_session.execute(text("DELETE FROM audit_logs WHERE user_id = :user_id"), {"user_id": test_user.id})
        await db_session.commit()

        # Test successful login
        login_response = client.post(
            "/api/v1/auth/login",
            json={"email": test_user.email, "password": "TestPassword123!"}
        )
        assert login_response.status_code == 200

        # Check that login was logged
        audit_logs = await db_session.execute(
            text("""
                SELECT action, resource_type, resource_id, tenant_id, details
                FROM audit_logs
                WHERE user_id = :user_id AND action = 'login'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"user_id": test_user.id}
        )
        log_entry = audit_logs.fetchone()

        assert log_entry is not None
        assert log_entry[0] == "login"  # action
        assert log_entry[1] == "auth"   # resource_type
        assert log_entry[3] == test_tenant.id  # tenant_id

        # Test failed login
        failed_login_response = client.post(
            "/api/v1/auth/login",
            json={"email": test_user.email, "password": "WrongPassword"}
        )
        assert failed_login_response.status_code == 401

        # Check that failed login was logged
        failed_logs = await db_session.execute(
            text("""
                SELECT action, details
                FROM audit_logs
                WHERE user_id = :user_id AND action = 'login_failed'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"user_id": test_user.id}
        )
        failed_log = failed_logs.fetchone()

        assert failed_log is not None
        assert failed_log[0] == "login_failed"

    async def test_signup_events_are_logged(
        self, client: TestClient, db_session: AsyncSession
    ):
        """Test that user signup events generate audit logs."""
        signup_data = {
            "email": "newuser@example.com",
            "password": "NewPassword123!",
            "full_name": "New User",
            "company_name": "Test Company",
        }

        signup_response = client.post("/api/v1/auth/signup", json=signup_data)
        assert signup_response.status_code == 201
        signup_result = signup_response.json()

        new_user_id = signup_result["user"]["id"]
        new_tenant_id = signup_result["user"]["tenant_id"]

        # Check that signup was logged
        signup_logs = await db_session.execute(
            text("""
                SELECT action, resource_type, resource_id, tenant_id, user_id, details
                FROM audit_logs
                WHERE user_id = :user_id AND action = 'signup'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"user_id": new_user_id}
        )
        log_entry = signup_logs.fetchone()

        assert log_entry is not None
        assert log_entry[0] == "signup"     # action
        assert log_entry[1] == "user"       # resource_type
        assert log_entry[2] == new_user_id  # resource_id
        assert log_entry[3] == new_tenant_id  # tenant_id
        assert log_entry[4] == new_user_id  # user_id

        # Check that tenant creation was also logged
        tenant_logs = await db_session.execute(
            text("""
                SELECT action, resource_type, resource_id, tenant_id
                FROM audit_logs
                WHERE tenant_id = :tenant_id AND action = 'create' AND resource_type = 'tenant'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"tenant_id": new_tenant_id}
        )
        tenant_log = tenant_logs.fetchone()

        assert tenant_log is not None
        assert tenant_log[0] == "create"      # action
        assert tenant_log[1] == "tenant"      # resource_type
        assert tenant_log[2] == new_tenant_id  # resource_id

    async def test_detection_crud_events_are_logged(
        self,
        client: TestClient,
        db_session: AsyncSession,
        authenticated_headers: dict,
        test_user: User,
        test_tenant: Tenant,
    ):
        """Test that detection CRUD operations generate audit logs."""
        # Clear existing logs
        await db_session.execute(
            text("DELETE FROM audit_logs WHERE user_id = :user_id"),
            {"user_id": test_user.id}
        )
        await db_session.commit()

        # Test detection creation
        detection_data = {
            "name": "Test Detection for Audit",
            "description": "Detection created for audit logging test",
            "rule_yaml": "detection:\n  selection:\n    field: value\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "status": "active",
            "visibility": "public",
        }

        create_response = client.post(
            "/api/v1/detections/",
            json=detection_data,
            headers=authenticated_headers
        )
        assert create_response.status_code == 201
        created_detection = create_response.json()
        detection_id = created_detection["id"]

        # Check creation was logged
        create_logs = await db_session.execute(
            text("""
                SELECT action, resource_type, resource_id, tenant_id, details
                FROM audit_logs
                WHERE user_id = :user_id AND action = 'create' AND resource_type = 'detection'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"user_id": test_user.id}
        )
        create_log = create_logs.fetchone()

        assert create_log is not None
        assert create_log[0] == "create"
        assert create_log[1] == "detection"
        assert create_log[2] == detection_id
        assert create_log[3] == test_tenant.id

        # Test detection update
        update_data = {
            "name": "Updated Detection Name",
            "description": "Updated description",
        }

        update_response = client.put(
            f"/api/v1/detections/{detection_id}",
            json=update_data,
            headers=authenticated_headers
        )
        assert update_response.status_code == 200

        # Check update was logged
        update_logs = await db_session.execute(
            text("""
                SELECT action, resource_type, resource_id, details
                FROM audit_logs
                WHERE user_id = :user_id AND action = 'update' AND resource_type = 'detection'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"user_id": test_user.id}
        )
        update_log = update_logs.fetchone()

        assert update_log is not None
        assert update_log[0] == "update"
        assert update_log[1] == "detection"
        assert update_log[2] == detection_id

        # Test detection deletion
        delete_response = client.delete(
            f"/api/v1/detections/{detection_id}",
            headers=authenticated_headers
        )
        assert delete_response.status_code == 204

        # Check deletion was logged
        delete_logs = await db_session.execute(
            text("""
                SELECT action, resource_type, resource_id, details
                FROM audit_logs
                WHERE user_id = :user_id AND action = 'delete' AND resource_type = 'detection'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"user_id": test_user.id}
        )
        delete_log = delete_logs.fetchone()

        assert delete_log is not None
        assert delete_log[0] == "delete"
        assert delete_log[1] == "detection"
        assert delete_log[2] == detection_id

    async def test_actor_crud_events_are_logged(
        self,
        client: TestClient,
        db_session: AsyncSession,
        authenticated_headers: dict,
        test_user: User,
        test_tenant: Tenant,
    ):
        """Test that actor CRUD operations generate audit logs."""
        # Clear existing logs
        await db_session.execute(
            text("DELETE FROM audit_logs WHERE user_id = :user_id"),
            {"user_id": test_user.id}
        )
        await db_session.commit()

        # Test actor creation
        actor_data = {
            "name": "Audit Test Actor",
            "description": "Actor created for audit testing",
            "country": "Unknown",
            "actor_type": "unknown",
        }

        create_response = client.post(
            "/api/v1/actors/",
            json=actor_data,
            headers=authenticated_headers
        )
        assert create_response.status_code == 201
        created_actor = create_response.json()
        actor_id = created_actor["id"]

        # Check creation was logged
        create_logs = await db_session.execute(
            text("""
                SELECT action, resource_type, resource_id, tenant_id
                FROM audit_logs
                WHERE user_id = :user_id AND action = 'create' AND resource_type = 'actor'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"user_id": test_user.id}
        )
        create_log = create_logs.fetchone()

        assert create_log is not None
        assert create_log[0] == "create"
        assert create_log[1] == "actor"
        assert create_log[2] == actor_id
        assert create_log[3] == test_tenant.id

        # Test actor update
        update_data = {"name": "Updated Actor Name"}

        update_response = client.put(
            f"/api/v1/actors/{actor_id}",
            json=update_data,
            headers=authenticated_headers
        )
        assert update_response.status_code == 200

        # Check update was logged
        update_logs = await db_session.execute(
            text("""
                SELECT action, resource_type, resource_id
                FROM audit_logs
                WHERE user_id = :user_id AND action = 'update' AND resource_type = 'actor'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"user_id": test_user.id}
        )
        update_log = update_logs.fetchone()

        assert update_log is not None
        assert update_log[0] == "update"
        assert update_log[1] == "actor"
        assert update_log[2] == actor_id

    async def test_audit_log_details_contain_relevant_data(
        self,
        client: TestClient,
        db_session: AsyncSession,
        authenticated_headers: dict,
        test_user: User,
    ):
        """Test that audit log details contain relevant information."""
        # Clear existing logs
        await db_session.execute(
            text("DELETE FROM audit_logs WHERE user_id = :user_id"),
            {"user_id": test_user.id}
        )
        await db_session.commit()

        # Create detection with specific data
        detection_data = {
            "name": "Detailed Audit Test Detection",
            "description": "Testing audit detail capture",
            "rule_yaml": "detection:\n  selection:\n    EventID: 4624\n  condition: selection",
            "platforms": ["Windows", "Linux"],
            "data_sources": ["Authentication Logs"],
            "status": "active",
            "visibility": "private",
            "confidence_score": 0.75,
        }

        create_response = client.post(
            "/api/v1/detections/",
            json=detection_data,
            headers=authenticated_headers
        )
        assert create_response.status_code == 201
        detection_id = create_response.json()["id"]

        # Check creation log details
        create_logs = await db_session.execute(
            text("""
                SELECT details
                FROM audit_logs
                WHERE user_id = :user_id AND action = 'create' AND resource_type = 'detection'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"user_id": test_user.id}
        )
        create_log = create_logs.fetchone()

        assert create_log is not None
        details = create_log[0]  # details column

        # Details should contain key information (format depends on implementation)
        assert "Detailed Audit Test Detection" in details
        assert "active" in details

        # Update with changes
        update_data = {
            "status": "testing",
            "confidence_score": 0.85,
        }

        update_response = client.put(
            f"/api/v1/detections/{detection_id}",
            json=update_data,
            headers=authenticated_headers
        )
        assert update_response.status_code == 200

        # Check update log details
        update_logs = await db_session.execute(
            text("""
                SELECT details
                FROM audit_logs
                WHERE user_id = :user_id AND action = 'update' AND resource_type = 'detection'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"user_id": test_user.id}
        )
        update_log = update_logs.fetchone()

        assert update_log is not None
        update_details = update_log[0]

        # Should contain information about what changed
        assert "testing" in update_details

    async def test_audit_logs_respect_tenant_isolation(
        self,
        client: TestClient,
        db_session: AsyncSession,
        test_user: User,
        test_tenant: Tenant,
    ):
        """Test that audit logs respect tenant boundaries."""
        from src.db.models.system.user import User
        from src.db.models.system.tenant import Tenant
        from src.core.security import get_password_hash

        # Create second tenant and user
        tenant2 = Tenant(
            name="Second Tenant for Audit",
            domain="audit2.com",
            is_active=True
        )
        db_session.add(tenant2)
        await db_session.flush()

        user2 = User(
            tenant_id=tenant2.id,
            email="user2@audit2.com",
            full_name="User 2 Audit",
            hashed_password=get_password_hash("User2Password123!"),
            is_active=True,
            is_superuser=False
        )
        db_session.add(user2)
        await db_session.commit()

        # Clear all audit logs
        await db_session.execute(text("DELETE FROM audit_logs"))
        await db_session.commit()

        # Login as first user and create detection
        login1_response = client.post(
            "/api/v1/auth/login",
            json={"email": test_user.email, "password": "TestPassword123!"}
        )
        token1 = login1_response.json()["access_token"]
        headers1 = {"Authorization": f"Bearer {token1}"}

        detection_data1 = {
            "name": "Tenant 1 Detection",
            "description": "Detection for tenant 1",
            "rule_yaml": "detection:\n  selection:\n    field: value1\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "status": "active",
            "visibility": "public",
        }

        client.post("/api/v1/detections/", json=detection_data1, headers=headers1)

        # Login as second user and create detection
        login2_response = client.post(
            "/api/v1/auth/login",
            json={"email": user2.email, "password": "User2Password123!"}
        )
        token2 = login2_response.json()["access_token"]
        headers2 = {"Authorization": f"Bearer {token2}"}

        detection_data2 = {
            "name": "Tenant 2 Detection",
            "description": "Detection for tenant 2",
            "rule_yaml": "detection:\n  selection:\n    field: value2\n  condition: selection",
            "platforms": ["Linux"],
            "data_sources": ["Network Traffic"],
            "status": "active",
            "visibility": "public",
        }

        client.post("/api/v1/detections/", json=detection_data2, headers=headers2)

        # Check that audit logs are tenant-specific
        tenant1_logs = await db_session.execute(
            text("""
                SELECT COUNT(*), tenant_id
                FROM audit_logs
                WHERE tenant_id = :tenant_id
                GROUP BY tenant_id
            """),
            {"tenant_id": test_tenant.id}
        )
        tenant1_count = tenant1_logs.fetchone()

        tenant2_logs = await db_session.execute(
            text("""
                SELECT COUNT(*), tenant_id
                FROM audit_logs
                WHERE tenant_id = :tenant_id
                GROUP BY tenant_id
            """),
            {"tenant_id": tenant2.id}
        )
        tenant2_count = tenant2_logs.fetchone()

        # Both tenants should have audit logs
        assert tenant1_count is not None
        assert tenant2_count is not None
        assert tenant1_count[1] == test_tenant.id
        assert tenant2_count[1] == tenant2.id

        # Cross-check: tenant 1 user shouldn't see tenant 2 logs
        # This would be tested through an audit log viewing endpoint
        # For now, verify at database level
        cross_tenant_logs = await db_session.execute(
            text("""
                SELECT COUNT(*)
                FROM audit_logs
                WHERE user_id = :user1_id AND tenant_id = :tenant2_id
            """),
            {"user1_id": test_user.id, "tenant2_id": tenant2.id}
        )
        cross_count = cross_tenant_logs.scalar()
        assert cross_count == 0

    async def test_bulk_operations_audit_logging(
        self,
        client: TestClient,
        db_session: AsyncSession,
        authenticated_headers: dict,
        test_user: User,
    ):
        """Test that bulk operations generate appropriate audit logs."""
        # Clear existing logs
        await db_session.execute(
            text("DELETE FROM audit_logs WHERE user_id = :user_id"),
            {"user_id": test_user.id}
        )
        await db_session.commit()

        # Create multiple detections
        detection_ids = []
        for i in range(3):
            detection_data = {
                "name": f"Bulk Test Detection {i + 1}",
                "description": f"Detection {i + 1} for bulk testing",
                "rule_yaml": f"detection:\n  selection:\n    field{i}: value{i}\n  condition: selection",
                "platforms": ["Windows"],
                "data_sources": ["Process Creation"],
                "status": "draft",
                "visibility": "public",
            }

            response = client.post(
                "/api/v1/detections/",
                json=detection_data,
                headers=authenticated_headers
            )
            assert response.status_code == 201
            detection_ids.append(response.json()["id"])

        # Update all detections individually (simulating bulk operation)
        for detection_id in detection_ids:
            update_response = client.put(
                f"/api/v1/detections/{detection_id}",
                json={"status": "active"},
                headers=authenticated_headers
            )
            assert update_response.status_code == 200

        # Check that all operations were logged
        total_logs = await db_session.execute(
            text("""
                SELECT COUNT(*)
                FROM audit_logs
                WHERE user_id = :user_id AND resource_type = 'detection'
            """),
            {"user_id": test_user.id}
        )
        log_count = total_logs.scalar()

        # Should have 3 create + 3 update = 6 logs
        assert log_count == 6

        # Check specific operation counts
        create_logs = await db_session.execute(
            text("""
                SELECT COUNT(*)
                FROM audit_logs
                WHERE user_id = :user_id AND action = 'create' AND resource_type = 'detection'
            """),
            {"user_id": test_user.id}
        )
        create_count = create_logs.scalar()
        assert create_count == 3

        update_logs = await db_session.execute(
            text("""
                SELECT COUNT(*)
                FROM audit_logs
                WHERE user_id = :user_id AND action = 'update' AND resource_type = 'detection'
            """),
            {"user_id": test_user.id}
        )
        update_count = update_logs.scalar()
        assert update_count == 3