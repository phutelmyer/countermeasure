"""
Integration tests for detection creation with all relationships.

Tests detection CRUD operations with related entities like actors,
MITRE techniques, severities, and proper tenant isolation.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models.system.user import User
from src.db.models.system.tenant import Tenant
from src.db.models.detection import Detection
from src.db.models.actor import Actor
from src.db.models.mitre import MitreTechnique
from src.schemas.detection import DetectionCreate


class TestDetectionRelationships:
    """Test detection operations with all relationships."""

    async def test_create_detection_with_all_relationships(
        self,
        client: TestClient,
        db_session: AsyncSession,
        authenticated_headers: dict,
        test_tenant: Tenant,
        test_actor: Actor,
        test_mitre_technique: MitreTechnique,
    ):
        """Test creating detection with all possible relationships."""
        detection_data = {
            "name": "Advanced Persistent Threat Detection",
            "description": "Detects sophisticated APT activity using multiple indicators",
            "rule_yaml": """
detection:
  selection:
    EventID: 4624
    LogonType: 3
  condition: selection
fields:
  - User
  - WorkstationName
falsepositives:
  - Legitimate remote access
level: high
            """,
            "platforms": ["Windows", "Linux"],
            "data_sources": ["Authentication Logs", "Network Traffic"],
            "false_positives": ["Legitimate admin access", "Automated tools"],
            "log_sources": "product:windows | category:process_creation | service:sysmon",
            "severity_id": 1,  # Assume Critical severity exists
            "actor_ids": [test_actor.id],
            "mitre_technique_ids": [test_mitre_technique.id],
            "tags": ["apt", "lateral-movement", "credential-access"],
            "status": "active",
            "visibility": "public",
            "confidence_score": 0.85,
        }

        # Create detection
        response = client.post(
            "/api/v1/detections/",
            json=detection_data,
            headers=authenticated_headers
        )
        assert response.status_code == 201
        created_detection = response.json()

        # Verify basic fields
        assert created_detection["name"] == detection_data["name"]
        assert created_detection["description"] == detection_data["description"]
        assert created_detection["platforms"] == detection_data["platforms"]
        assert created_detection["confidence_score"] == detection_data["confidence_score"]

        # Verify relationships were created
        assert len(created_detection["actors"]) == 1
        assert created_detection["actors"][0]["id"] == test_actor.id
        assert created_detection["actors"][0]["name"] == test_actor.name

        assert len(created_detection["mitre_techniques"]) == 1
        assert created_detection["mitre_techniques"][0]["id"] == test_mitre_technique.id
        assert created_detection["mitre_techniques"][0]["technique_id"] == test_mitre_technique.technique_id

        # Verify tenant isolation
        assert created_detection["tenant_id"] == test_tenant.id

        detection_id = created_detection["id"]

        # Test retrieving the detection with relationships
        get_response = client.get(
            f"/api/v1/detections/{detection_id}",
            headers=authenticated_headers
        )
        assert get_response.status_code == 200
        retrieved_detection = get_response.json()

        # Verify all relationships are still there
        assert len(retrieved_detection["actors"]) == 1
        assert len(retrieved_detection["mitre_techniques"]) == 1
        assert retrieved_detection["actors"][0]["name"] == test_actor.name

    async def test_update_detection_relationships(
        self,
        client: TestClient,
        db_session: AsyncSession,
        authenticated_headers: dict,
        test_detection: Detection,
        test_actor: Actor,
        test_mitre_technique: MitreTechnique,
    ):
        """Test updating detection relationships."""
        # Create a second actor and technique for testing
        new_actor_data = {
            "name": "APT29",
            "aliases": ["Cozy Bear"],
            "description": "Russian APT group",
            "country": "Russia",
            "motivation": "Espionage",
            "first_seen": "2014-01-01",
            "actor_type": "nation_state",
        }
        create_actor_response = client.post(
            "/api/v1/actors/",
            json=new_actor_data,
            headers=authenticated_headers
        )
        assert create_actor_response.status_code == 201
        new_actor = create_actor_response.json()

        # Update detection to add new relationships
        update_data = {
            "name": test_detection.name + " - Updated",
            "actor_ids": [test_actor.id, new_actor["id"]],
            "mitre_technique_ids": [test_mitre_technique.id],
            "tags": ["updated", "multi-actor"],
        }

        update_response = client.put(
            f"/api/v1/detections/{test_detection.id}",
            json=update_data,
            headers=authenticated_headers,
        )
        assert update_response.status_code == 200
        updated_detection = update_response.json()

        # Verify relationships were updated
        assert len(updated_detection["actors"]) == 2
        actor_names = [actor["name"] for actor in updated_detection["actors"]]
        assert test_actor.name in actor_names
        assert new_actor["name"] in actor_names

        assert updated_detection["tags"] == ["updated", "multi-actor"]

    async def test_detection_search_with_relationships(
        self,
        client: TestClient,
        authenticated_headers: dict,
        test_detection: Detection,
        test_actor: Actor,
    ):
        """Test searching detections by related entities."""
        # Search by actor name
        actor_search_response = client.get(
            f"/api/v1/detections/?actor_name={test_actor.name}",
            headers=authenticated_headers,
        )
        assert actor_search_response.status_code == 200
        actor_results = actor_search_response.json()

        # Should find detections associated with this actor
        detection_ids = [d["id"] for d in actor_results["items"]]
        assert test_detection.id in detection_ids

        # Search by platform
        platform_search_response = client.get(
            "/api/v1/detections/?platform=Windows",
            headers=authenticated_headers,
        )
        assert platform_search_response.status_code == 200
        platform_results = platform_search_response.json()

        # Should find detections for Windows platform
        assert len(platform_results["items"]) >= 1

        # Search by severity
        severity_search_response = client.get(
            f"/api/v1/detections/?severity_id={test_detection.severity_id}",
            headers=authenticated_headers,
        )
        assert severity_search_response.status_code == 200
        severity_results = severity_search_response.json()

        detection_ids = [d["id"] for d in severity_results["items"]]
        assert test_detection.id in detection_ids

    async def test_delete_detection_with_relationships(
        self,
        client: TestClient,
        db_session: AsyncSession,
        authenticated_headers: dict,
        test_detection: Detection,
        test_actor: Actor,
    ):
        """Test deleting detection removes relationships but not related entities."""
        detection_id = test_detection.id
        actor_id = test_actor.id

        # Delete the detection
        delete_response = client.delete(
            f"/api/v1/detections/{detection_id}",
            headers=authenticated_headers
        )
        assert delete_response.status_code == 204

        # Verify detection is gone
        get_response = client.get(
            f"/api/v1/detections/{detection_id}",
            headers=authenticated_headers
        )
        assert get_response.status_code == 404

        # Verify actor still exists (not cascade deleted)
        actor_response = client.get(
            f"/api/v1/actors/{actor_id}",
            headers=authenticated_headers
        )
        assert actor_response.status_code == 200

    async def test_bulk_detection_operations_with_relationships(
        self,
        client: TestClient,
        authenticated_headers: dict,
        test_actor: Actor,
        test_mitre_technique: MitreTechnique,
    ):
        """Test bulk operations on detections with relationships."""
        # Create multiple detections with relationships
        detection_data_list = []
        for i in range(3):
            detection_data = {
                "name": f"Bulk Detection {i + 1}",
                "description": f"Bulk detection number {i + 1}",
                "rule_yaml": f"detection:\n  selection:\n    field{i}: value{i}\n  condition: selection",
                "platforms": ["Windows"],
                "data_sources": ["Process Creation"],
                "actor_ids": [test_actor.id],
                "mitre_technique_ids": [test_mitre_technique.id],
                "status": "active",
                "visibility": "public",
            }
            detection_data_list.append(detection_data)

        # Create all detections
        created_detections = []
        for detection_data in detection_data_list:
            response = client.post(
                "/api/v1/detections/",
                json=detection_data,
                headers=authenticated_headers,
            )
            assert response.status_code == 201
            created_detections.append(response.json())

        # Verify all have the same actor relationship
        for detection in created_detections:
            assert len(detection["actors"]) == 1
            assert detection["actors"][0]["id"] == test_actor.id

        # Test bulk update (change status)
        detection_ids = [d["id"] for d in created_detections]
        bulk_update_data = {
            "detection_ids": detection_ids,
            "updates": {"status": "testing"},
        }

        # Note: This endpoint might not exist yet, so we'll test individual updates
        for detection_id in detection_ids:
            update_response = client.put(
                f"/api/v1/detections/{detection_id}",
                json={"status": "testing"},
                headers=authenticated_headers,
            )
            assert update_response.status_code == 200
            updated = update_response.json()
            assert updated["status"] == "testing"

    async def test_detection_actor_many_to_many(
        self,
        client: TestClient,
        authenticated_headers: dict,
        test_tenant: Tenant,
    ):
        """Test many-to-many relationships between detections and actors."""
        # Create two actors
        actor1_data = {
            "name": "APT28",
            "aliases": ["Fancy Bear"],
            "description": "Russian military APT",
            "country": "Russia",
            "actor_type": "nation_state",
        }
        actor2_data = {
            "name": "APT29",
            "aliases": ["Cozy Bear"],
            "description": "Russian intelligence APT",
            "country": "Russia",
            "actor_type": "nation_state",
        }

        actor1_response = client.post("/api/v1/actors/", json=actor1_data, headers=authenticated_headers)
        actor2_response = client.post("/api/v1/actors/", json=actor2_data, headers=authenticated_headers)

        assert actor1_response.status_code == 201
        assert actor2_response.status_code == 201

        actor1 = actor1_response.json()
        actor2 = actor2_response.json()

        # Create detection associated with both actors
        detection_data = {
            "name": "Multi-Actor Detection",
            "description": "Detection targeting multiple threat actors",
            "rule_yaml": "detection:\n  selection:\n    field: value\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "actor_ids": [actor1["id"], actor2["id"]],
            "status": "active",
            "visibility": "public",
        }

        detection_response = client.post(
            "/api/v1/detections/",
            json=detection_data,
            headers=authenticated_headers,
        )
        assert detection_response.status_code == 201
        detection = detection_response.json()

        # Verify both actors are associated
        assert len(detection["actors"]) == 2
        actor_names = [actor["name"] for actor in detection["actors"]]
        assert "APT28" in actor_names
        assert "APT29" in actor_names

        # Create another detection with just one of the actors
        detection2_data = {
            "name": "Single Actor Detection",
            "description": "Detection for one actor only",
            "rule_yaml": "detection:\n  selection:\n    field2: value2\n  condition: selection",
            "platforms": ["Linux"],
            "data_sources": ["Network Traffic"],
            "actor_ids": [actor1["id"]],
            "status": "active",
            "visibility": "public",
        }

        detection2_response = client.post(
            "/api/v1/detections/",
            json=detection2_data,
            headers=authenticated_headers,
        )
        assert detection2_response.status_code == 201
        detection2 = detection2_response.json()

        # Check each actor's detections
        actor1_detections_response = client.get(
            f"/api/v1/actors/{actor1['id']}/detections",
            headers=authenticated_headers,
        )
        assert actor1_detections_response.status_code == 200
        actor1_detections = actor1_detections_response.json()

        # Actor1 should be in both detections
        detection_names = [d["name"] for d in actor1_detections["items"]]
        assert "Multi-Actor Detection" in detection_names
        assert "Single Actor Detection" in detection_names

        actor2_detections_response = client.get(
            f"/api/v1/actors/{actor2['id']}/detections",
            headers=authenticated_headers,
        )
        assert actor2_detections_response.status_code == 200
        actor2_detections = actor2_detections_response.json()

        # Actor2 should only be in the multi-actor detection
        detection_names = [d["name"] for d in actor2_detections["items"]]
        assert "Multi-Actor Detection" in detection_names
        assert "Single Actor Detection" not in detection_names