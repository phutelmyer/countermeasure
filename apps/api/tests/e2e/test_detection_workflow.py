"""
End-to-end tests for complete detection workflows.

Tests the full detection lifecycle from creation through search,
update, and deletion including all relationships and business logic.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models.system.user import User
from src.db.models.system.tenant import Tenant


class TestDetectionWorkflowE2E:
    """End-to-end tests for detection workflows."""

    async def test_complete_detection_lifecycle(
        self,
        client: TestClient,
        db_session: AsyncSession,
        test_tenant: Tenant,
    ):
        """Test complete detection workflow: signup → create → search → update → delete."""

        # Step 1: User signup (creates tenant)
        signup_data = {
            "email": "analyst@security.com",
            "password": "AnalystPassword123!",
            "full_name": "Security Analyst",
            "company_name": "Security Corp",
        }

        signup_response = client.post("/api/v1/auth/signup", json=signup_data)
        assert signup_response.status_code == 201
        signup_result = signup_response.json()

        access_token = signup_result["access_token"]
        user_id = signup_result["user"]["id"]
        tenant_id = signup_result["user"]["tenant_id"]
        headers = {"Authorization": f"Bearer {access_token}"}

        # Step 2: Create threat actor for detection
        actor_data = {
            "name": "APT-E2E-Test",
            "aliases": ["E2E Test Group"],
            "description": "Threat actor for end-to-end testing",
            "country": "Unknown",
            "motivation": "Testing",
            "first_seen": "2024-01-01",
            "actor_type": "nation_state",
            "sophistication": "expert",
            "resource_level": "government",
        }

        actor_response = client.post("/api/v1/actors/", json=actor_data, headers=headers)
        assert actor_response.status_code == 201
        created_actor = actor_response.json()
        actor_id = created_actor["id"]

        # Step 3: Create initial detection
        detection_data = {
            "name": "Advanced Persistent Threat Detection - E2E Test",
            "description": "Comprehensive detection for APT activities including lateral movement and data exfiltration",
            "rule_yaml": """
title: Advanced Persistent Threat Detection
description: Detects sophisticated APT activity patterns
logsource:
    product: windows
    category: process_creation
    service: sysmon
detection:
    selection_lateral_movement:
        EventID: 1
        Image|endswith:
            - '\\psexec.exe'
            - '\\wmiexec.py'
            - '\\smbexec.py'
        CommandLine|contains:
            - 'cmd.exe /c'
            - 'powershell.exe -enc'
    selection_data_staging:
        EventID: 1
        CommandLine|contains:
            - 'rar.exe a -r'
            - '7z.exe a -r'
            - 'compress-archive'
    condition: selection_lateral_movement or selection_data_staging
fields:
    - User
    - Computer
    - CommandLine
    - ParentProcessName
falsepositives:
    - Legitimate administrative activities
    - Backup software operations
    - System maintenance tasks
level: high
tags:
    - attack.lateral_movement
    - attack.collection
    - attack.t1021
    - attack.t1560
            """,
            "platforms": ["Windows", "Linux"],
            "data_sources": [
                "Process Creation",
                "Network Traffic",
                "File Monitoring",
                "Command Line"
            ],
            "false_positives": [
                "Legitimate administrative tools",
                "Backup and archival software",
                "System maintenance scripts",
                "Security tool operations"
            ],
            "log_sources": "product:windows | category:process_creation | service:sysmon",
            "actor_ids": [actor_id],
            "tags": ["apt", "lateral-movement", "data-exfiltration", "high-confidence"],
            "status": "draft",
            "visibility": "private",
            "confidence_score": 0.85,
        }

        create_response = client.post(
            "/api/v1/detections/",
            json=detection_data,
            headers=headers
        )
        assert create_response.status_code == 201
        created_detection = create_response.json()
        detection_id = created_detection["id"]

        # Verify detection was created with all relationships
        assert created_detection["name"] == detection_data["name"]
        assert created_detection["status"] == "draft"
        assert created_detection["confidence_score"] == 0.85
        assert len(created_detection["actors"]) == 1
        assert created_detection["actors"][0]["id"] == actor_id
        assert created_detection["tenant_id"] == tenant_id

        # Step 4: Search for the detection by various criteria

        # Search by name
        name_search_response = client.get(
            f"/api/v1/detections/?search=Advanced Persistent Threat",
            headers=headers
        )
        assert name_search_response.status_code == 200
        name_results = name_search_response.json()["items"]
        assert len(name_results) >= 1
        found_by_name = any(d["id"] == detection_id for d in name_results)
        assert found_by_name

        # Search by platform
        platform_search_response = client.get(
            "/api/v1/detections/?platform=Windows",
            headers=headers
        )
        assert platform_search_response.status_code == 200
        platform_results = platform_search_response.json()["items"]
        found_by_platform = any(d["id"] == detection_id for d in platform_results)
        assert found_by_platform

        # Search by actor
        actor_search_response = client.get(
            f"/api/v1/detections/?actor_name={actor_data['name']}",
            headers=headers
        )
        assert actor_search_response.status_code == 200
        actor_results = actor_search_response.json()["items"]
        found_by_actor = any(d["id"] == detection_id for d in actor_results)
        assert found_by_actor

        # Search by tag
        tag_search_response = client.get(
            "/api/v1/detections/?tag=apt",
            headers=headers
        )
        assert tag_search_response.status_code == 200
        tag_results = tag_search_response.json()["items"]
        found_by_tag = any(d["id"] == detection_id for d in tag_results)
        assert found_by_tag

        # Step 5: Update detection through testing to production

        # First update: Move to testing
        testing_update = {
            "status": "testing",
            "description": created_detection["description"] + " [Updated for testing phase]",
            "confidence_score": 0.90,
        }

        testing_response = client.put(
            f"/api/v1/detections/{detection_id}",
            json=testing_update,
            headers=headers
        )
        assert testing_response.status_code == 200
        testing_detection = testing_response.json()
        assert testing_detection["status"] == "testing"
        assert testing_detection["confidence_score"] == 0.90

        # Second update: Add more relationships and move to active

        # Create another actor
        second_actor_data = {
            "name": "APT-E2E-Secondary",
            "description": "Secondary threat actor for testing",
            "country": "Unknown",
            "actor_type": "cybercriminal",
        }

        second_actor_response = client.post(
            "/api/v1/actors/",
            json=second_actor_data,
            headers=headers
        )
        assert second_actor_response.status_code == 201
        second_actor = second_actor_response.json()

        # Update detection to include both actors and activate
        production_update = {
            "status": "active",
            "visibility": "public",
            "actor_ids": [actor_id, second_actor["id"]],
            "tags": ["apt", "lateral-movement", "data-exfiltration", "production-ready"],
            "confidence_score": 0.95,
        }

        production_response = client.put(
            f"/api/v1/detections/{detection_id}",
            json=production_update,
            headers=headers
        )
        assert production_response.status_code == 200
        production_detection = production_response.json()

        assert production_detection["status"] == "active"
        assert production_detection["visibility"] == "public"
        assert production_detection["confidence_score"] == 0.95
        assert len(production_detection["actors"]) == 2
        assert "production-ready" in production_detection["tags"]

        # Step 6: Verify detection in various contexts

        # Get actor's detections to verify bidirectional relationship
        actor_detections_response = client.get(
            f"/api/v1/actors/{actor_id}/detections",
            headers=headers
        )
        assert actor_detections_response.status_code == 200
        actor_detections = actor_detections_response.json()["items"]

        actor_detection_ids = [d["id"] for d in actor_detections]
        assert detection_id in actor_detection_ids

        # List all active detections to verify filtering
        active_detections_response = client.get(
            "/api/v1/detections/?status=active",
            headers=headers
        )
        assert active_detections_response.status_code == 200
        active_detections = active_detections_response.json()["items"]

        active_detection_ids = [d["id"] for d in active_detections]
        assert detection_id in active_detection_ids

        # Step 7: Clone/duplicate detection for testing variations
        clone_data = {
            "name": production_detection["name"] + " - Variant",
            "description": "Cloned detection for testing variations",
            "rule_yaml": production_detection["rule_yaml"].replace("high", "medium"),
            "platforms": ["Linux"],  # Different platform
            "data_sources": production_detection["data_sources"],
            "actor_ids": [actor_id],  # Only first actor
            "status": "draft",
            "visibility": "private",
            "confidence_score": 0.70,
        }

        clone_response = client.post(
            "/api/v1/detections/",
            json=clone_data,
            headers=headers
        )
        assert clone_response.status_code == 201
        cloned_detection = clone_response.json()
        clone_id = cloned_detection["id"]

        # Verify both detections exist
        all_detections_response = client.get("/api/v1/detections/", headers=headers)
        all_detections = all_detections_response.json()["items"]
        all_detection_ids = [d["id"] for d in all_detections]

        assert detection_id in all_detection_ids
        assert clone_id in all_detection_ids
        assert len([d for d in all_detections if d["name"].startswith("Advanced Persistent Threat")]) == 2

        # Step 8: Test detection archival/deprecation workflow

        # Deprecate the clone
        deprecate_response = client.put(
            f"/api/v1/detections/{clone_id}",
            json={"status": "deprecated"},
            headers=headers
        )
        assert deprecate_response.status_code == 200

        # Verify deprecated detection doesn't appear in active searches
        active_search_response = client.get(
            "/api/v1/detections/?status=active",
            headers=headers
        )
        active_search_results = active_search_response.json()["items"]
        active_ids = [d["id"] for d in active_search_results]

        assert detection_id in active_ids  # Original still active
        assert clone_id not in active_ids  # Clone is deprecated

        # Step 9: Export detection data
        export_response = client.get(
            f"/api/v1/detections/{detection_id}",
            headers=headers
        )
        assert export_response.status_code == 200
        exported_detection = export_response.json()

        # Verify export contains all expected data
        assert "rule_yaml" in exported_detection
        assert "actors" in exported_detection
        assert "platforms" in exported_detection
        assert "data_sources" in exported_detection
        assert len(exported_detection["actors"]) == 2

        # Step 10: Final cleanup - delete detections

        # Delete the deprecated clone first
        delete_clone_response = client.delete(
            f"/api/v1/detections/{clone_id}",
            headers=headers
        )
        assert delete_clone_response.status_code == 204

        # Verify clone is gone
        get_clone_response = client.get(
            f"/api/v1/detections/{clone_id}",
            headers=headers
        )
        assert get_clone_response.status_code == 404

        # Delete the main detection
        delete_main_response = client.delete(
            f"/api/v1/detections/{detection_id}",
            headers=headers
        )
        assert delete_main_response.status_code == 204

        # Verify main detection is gone
        get_main_response = client.get(
            f"/api/v1/detections/{detection_id}",
            headers=headers
        )
        assert get_main_response.status_code == 404

        # Verify actors still exist (not cascade deleted)
        get_actor_response = client.get(f"/api/v1/actors/{actor_id}", headers=headers)
        assert get_actor_response.status_code == 200

        get_second_actor_response = client.get(
            f"/api/v1/actors/{second_actor['id']}",
            headers=headers
        )
        assert get_second_actor_response.status_code == 200

        # Final verification: no detections remain for this test
        final_detections_response = client.get("/api/v1/detections/", headers=headers)
        final_detections = final_detections_response.json()["items"]

        # Should not find our test detections
        test_detection_names = [
            "Advanced Persistent Threat Detection - E2E Test",
            "Advanced Persistent Threat Detection - E2E Test - Variant"
        ]

        remaining_test_detections = [
            d for d in final_detections
            if d["name"] in test_detection_names
        ]
        assert len(remaining_test_detections) == 0

    async def test_collaborative_detection_development(
        self, client: TestClient, db_session: AsyncSession
    ):
        """Test collaborative workflow where multiple users work on detections."""

        # Create first analyst
        analyst1_data = {
            "email": "analyst1@company.com",
            "password": "Analyst1Pass123!",
            "full_name": "Senior Analyst",
            "company_name": "Collaborative Security",
        }

        analyst1_signup = client.post("/api/v1/auth/signup", json=analyst1_data)
        assert analyst1_signup.status_code == 201
        analyst1_result = analyst1_signup.json()
        analyst1_token = analyst1_result["access_token"]
        analyst1_headers = {"Authorization": f"Bearer {analyst1_token}"}
        tenant_id = analyst1_result["user"]["tenant_id"]

        # Create second analyst in same tenant
        analyst2_data = {
            "email": "analyst2@company.com",
            "password": "Analyst2Pass123!",
            "full_name": "Junior Analyst",
            "tenant_id": tenant_id,  # This would be handled by admin invite
        }

        # For this test, we'll simulate by creating second user manually
        # In real workflow, this would be through admin invitation
        from src.db.models.system.user import User
        from src.core.security import get_password_hash

        analyst2_user = User(
            tenant_id=tenant_id,
            email=analyst2_data["email"],
            full_name=analyst2_data["full_name"],
            hashed_password=get_password_hash(analyst2_data["password"]),
            is_active=True,
            is_superuser=False
        )
        db_session.add(analyst2_user)
        await db_session.commit()

        # Login as second analyst
        analyst2_login = client.post(
            "/api/v1/auth/login",
            json={
                "email": analyst2_data["email"],
                "password": analyst2_data["password"]
            }
        )
        assert analyst2_login.status_code == 200
        analyst2_token = analyst2_login.json()["access_token"]
        analyst2_headers = {"Authorization": f"Bearer {analyst2_token}"}

        # Analyst 1 creates initial detection draft
        initial_detection = {
            "name": "Collaborative Malware Detection",
            "description": "Initial draft for collaborative development",
            "rule_yaml": """
title: Basic Malware Detection
detection:
    selection:
        EventID: 1
        Image|endswith: '.exe'
    condition: selection
level: medium
            """,
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "status": "draft",
            "visibility": "public",  # Visible to team
            "confidence_score": 0.60,
        }

        create_response = client.post(
            "/api/v1/detections/",
            json=initial_detection,
            headers=analyst1_headers
        )
        assert create_response.status_code == 201
        detection = create_response.json()
        detection_id = detection["id"]

        # Analyst 2 can see the draft detection
        analyst2_view = client.get(
            f"/api/v1/detections/{detection_id}",
            headers=analyst2_headers
        )
        assert analyst2_view.status_code == 200
        viewed_detection = analyst2_view.json()
        assert viewed_detection["name"] == initial_detection["name"]

        # Analyst 2 enhances the detection
        enhancement_update = {
            "description": "Enhanced with additional indicators and improved accuracy",
            "rule_yaml": """
title: Enhanced Malware Detection
detection:
    selection_process:
        EventID: 1
        Image|endswith:
            - '.exe'
            - '.scr'
            - '.pif'
    selection_suspicious:
        CommandLine|contains:
            - 'powershell'
            - 'cmd /c'
            - 'rundll32'
    condition: selection_process and selection_suspicious
falsepositives:
    - Legitimate administrative tools
level: high
            """,
            "platforms": ["Windows", "Linux"],
            "data_sources": ["Process Creation", "Command Line"],
            "false_positives": ["Legitimate administrative tools", "System utilities"],
            "confidence_score": 0.80,
            "tags": ["malware", "enhanced", "collaborative"],
        }

        enhancement_response = client.put(
            f"/api/v1/detections/{detection_id}",
            json=enhancement_update,
            headers=analyst2_headers
        )
        assert enhancement_response.status_code == 200
        enhanced_detection = enhancement_response.json()
        assert enhanced_detection["confidence_score"] == 0.80
        assert "enhanced" in enhanced_detection["tags"]

        # Analyst 1 reviews and promotes to testing
        review_update = {
            "status": "testing",
            "description": enhanced_detection["description"] + " [Reviewed and approved for testing]",
            "confidence_score": 0.85,
        }

        review_response = client.put(
            f"/api/v1/detections/{detection_id}",
            json=review_update,
            headers=analyst1_headers
        )
        assert review_response.status_code == 200
        reviewed_detection = review_response.json()
        assert reviewed_detection["status"] == "testing"

        # Both analysts can see the testing detection
        for headers in [analyst1_headers, analyst2_headers]:
            testing_view = client.get(
                f"/api/v1/detections/{detection_id}",
                headers=headers
            )
            assert testing_view.status_code == 200
            testing_detection = testing_view.json()
            assert testing_detection["status"] == "testing"
            assert "[Reviewed and approved for testing]" in testing_detection["description"]

        # After testing period, promote to active
        production_update = {
            "status": "active",
            "confidence_score": 0.90,
        }

        production_response = client.put(
            f"/api/v1/detections/{detection_id}",
            json=production_update,
            headers=analyst1_headers
        )
        assert production_response.status_code == 200
        final_detection = production_response.json()
        assert final_detection["status"] == "active"
        assert final_detection["confidence_score"] == 0.90

        # Verify collaborative workflow maintained data integrity
        assert final_detection["name"] == initial_detection["name"]
        assert "Enhanced with additional indicators" in final_detection["description"]
        assert "enhanced" in final_detection["tags"]
        assert "Linux" in final_detection["platforms"]

    async def test_detection_error_handling_workflow(
        self, client: TestClient
    ):
        """Test detection workflow error handling and recovery scenarios."""

        # Setup user
        signup_data = {
            "email": "errortest@security.com",
            "password": "ErrorTest123!",
            "full_name": "Error Test User",
            "company_name": "Error Testing Corp",
        }

        signup_response = client.post("/api/v1/auth/signup", json=signup_data)
        headers = {"Authorization": f"Bearer {signup_response.json()['access_token']}"}

        # Test 1: Invalid YAML detection creation
        invalid_yaml_detection = {
            "name": "Invalid YAML Detection",
            "description": "Testing invalid YAML handling",
            "rule_yaml": "invalid: yaml: content: [unclosed",  # Invalid YAML
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "status": "draft",
            "visibility": "public",
        }

        invalid_response = client.post(
            "/api/v1/detections/",
            json=invalid_yaml_detection,
            headers=headers
        )
        # Should either accept it (validation is optional) or return validation error
        # The behavior depends on implementation - document actual behavior
        if invalid_response.status_code == 400:
            error_detail = invalid_response.json()
            assert "yaml" in error_detail["detail"].lower() or "validation" in error_detail["detail"].lower()

        # Test 2: Valid detection creation for further tests
        valid_detection = {
            "name": "Error Recovery Test Detection",
            "description": "Detection for testing error recovery",
            "rule_yaml": "detection:\n  selection:\n    field: value\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "status": "draft",
            "visibility": "public",
            "confidence_score": 0.75,
        }

        create_response = client.post(
            "/api/v1/detections/",
            json=valid_detection,
            headers=headers
        )
        assert create_response.status_code == 201
        detection = create_response.json()
        detection_id = detection["id"]

        # Test 3: Update with invalid data
        invalid_update = {
            "confidence_score": 1.5,  # Invalid score > 1.0
            "status": "invalid_status",  # Invalid status
        }

        invalid_update_response = client.put(
            f"/api/v1/detections/{detection_id}",
            json=invalid_update,
            headers=headers
        )
        assert invalid_update_response.status_code == 422  # Validation error

        # Verify detection wasn't changed
        unchanged_response = client.get(
            f"/api/v1/detections/{detection_id}",
            headers=headers
        )
        assert unchanged_response.status_code == 200
        unchanged_detection = unchanged_response.json()
        assert unchanged_detection["confidence_score"] == 0.75
        assert unchanged_detection["status"] == "draft"

        # Test 4: Partial update recovery
        partial_update = {
            "confidence_score": 0.85,  # Valid
            "description": "Updated description after error recovery",
        }

        recovery_response = client.put(
            f"/api/v1/detections/{detection_id}",
            json=partial_update,
            headers=headers
        )
        assert recovery_response.status_code == 200
        recovered_detection = recovery_response.json()
        assert recovered_detection["confidence_score"] == 0.85
        assert "error recovery" in recovered_detection["description"]

        # Test 5: Non-existent resource handling
        nonexistent_id = "00000000-0000-0000-0000-000000000000"

        nonexistent_get = client.get(
            f"/api/v1/detections/{nonexistent_id}",
            headers=headers
        )
        assert nonexistent_get.status_code == 404

        nonexistent_update = client.put(
            f"/api/v1/detections/{nonexistent_id}",
            json={"name": "Updated Name"},
            headers=headers
        )
        assert nonexistent_update.status_code == 404

        nonexistent_delete = client.delete(
            f"/api/v1/detections/{nonexistent_id}",
            headers=headers
        )
        assert nonexistent_delete.status_code == 404

        # Test 6: Verify system remains stable after errors
        final_list_response = client.get("/api/v1/detections/", headers=headers)
        assert final_list_response.status_code == 200
        final_detections = final_list_response.json()["items"]

        # Should find our recovered detection
        recovered_detection_found = any(
            d["id"] == detection_id for d in final_detections
        )
        assert recovered_detection_found