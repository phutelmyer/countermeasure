"""
End-to-end tests for multi-tenant scenarios.

Tests complex multi-tenant workflows including data isolation,
cross-tenant operations, and tenant management scenarios.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models.system.user import User
from src.db.models.system.tenant import Tenant


class TestMultiTenantScenariosE2E:
    """End-to-end tests for multi-tenant scenarios."""

    async def test_enterprise_multi_tenant_setup(
        self, client: TestClient, db_session: AsyncSession
    ):
        """Test enterprise scenario with multiple tenants and complex relationships."""

        # Create Enterprise Tenant 1: Large Security Firm
        enterprise1_signup = {
            "email": "admin@securityfirm.com",
            "password": "EnterpriseAdmin123!",
            "full_name": "Enterprise Admin",
            "company_name": "Global Security Firm",
        }

        enterprise1_response = client.post("/api/v1/auth/signup", json=enterprise1_signup)
        assert enterprise1_response.status_code == 201
        enterprise1_result = enterprise1_response.json()
        enterprise1_admin_token = enterprise1_result["access_token"]
        enterprise1_tenant_id = enterprise1_result["user"]["tenant_id"]
        enterprise1_admin_headers = {"Authorization": f"Bearer {enterprise1_admin_token}"}

        # Create Enterprise Tenant 2: Financial Institution
        enterprise2_signup = {
            "email": "security@bank.com",
            "password": "BankSecurity123!",
            "full_name": "Bank Security Officer",
            "company_name": "Global Bank Corp",
        }

        enterprise2_response = client.post("/api/v1/auth/signup", json=enterprise2_signup)
        assert enterprise2_response.status_code == 201
        enterprise2_result = enterprise2_response.json()
        enterprise2_admin_token = enterprise2_result["access_token"]
        enterprise2_tenant_id = enterprise2_result["user"]["tenant_id"]
        enterprise2_admin_headers = {"Authorization": f"Bearer {enterprise2_admin_token}"}

        # Create Startup Tenant: Small Security Company
        startup_signup = {
            "email": "founder@startupsec.com",
            "password": "StartupSec123!",
            "full_name": "Startup Founder",
            "company_name": "Innovative Security Startup",
        }

        startup_response = client.post("/api/v1/auth/signup", json=startup_signup)
        assert startup_response.status_code == 201
        startup_result = startup_response.json()
        startup_admin_token = startup_result["access_token"]
        startup_tenant_id = startup_result["user"]["tenant_id"]
        startup_admin_headers = {"Authorization": f"Bearer {startup_admin_token}"}

        # Verify tenants are isolated
        assert enterprise1_tenant_id != enterprise2_tenant_id
        assert enterprise2_tenant_id != startup_tenant_id
        assert enterprise1_tenant_id != startup_tenant_id

        # Each tenant creates their own threat actors

        # Enterprise 1: Focus on APT groups
        apt_actor_data = {
            "name": "APT-Enterprise-Analysis",
            "aliases": ["Advanced Persistent Threat Group"],
            "description": "Sophisticated nation-state actor targeting enterprises",
            "country": "Unknown",
            "motivation": "Espionage",
            "first_seen": "2020-01-01",
            "actor_type": "nation_state",
            "sophistication": "expert",
            "resource_level": "government",
        }

        enterprise1_actor_response = client.post(
            "/api/v1/actors/",
            json=apt_actor_data,
            headers=enterprise1_admin_headers
        )
        assert enterprise1_actor_response.status_code == 201
        enterprise1_actor = enterprise1_actor_response.json()

        # Enterprise 2: Focus on financial threats
        fintech_actor_data = {
            "name": "FinTech-Threat-Actor",
            "aliases": ["Banking Trojan Group"],
            "description": "Cybercriminal group targeting financial institutions",
            "country": "Unknown",
            "motivation": "Financial Gain",
            "actor_type": "cybercriminal",
            "sophistication": "intermediate",
        }

        enterprise2_actor_response = client.post(
            "/api/v1/actors/",
            json=fintech_actor_data,
            headers=enterprise2_admin_headers
        )
        assert enterprise2_actor_response.status_code == 201
        enterprise2_actor = enterprise2_actor_response.json()

        # Startup: Focus on emerging threats
        emerging_actor_data = {
            "name": "Emerging-Threat-Group",
            "description": "New threat actor identified by startup research",
            "country": "Unknown",
            "actor_type": "unknown",
        }

        startup_actor_response = client.post(
            "/api/v1/actors/",
            json=emerging_actor_data,
            headers=startup_admin_headers
        )
        assert startup_actor_response.status_code == 201
        startup_actor = startup_actor_response.json()

        # Each tenant creates specialized detections

        # Enterprise 1: APT Detection
        apt_detection_data = {
            "name": "Enterprise APT Lateral Movement Detection",
            "description": "Advanced detection for APT lateral movement in enterprise environments",
            "rule_yaml": """
title: APT Lateral Movement Detection
detection:
    selection_tools:
        Image|endswith:
            - '\\psexec.exe'
            - '\\wmic.exe'
            - '\\powershell.exe'
        CommandLine|contains:
            - 'invoke-command'
            - 'enter-pssession'
    selection_network:
        EventID: 3
        DestinationPort:
            - 445
            - 135
            - 3389
    condition: selection_tools or selection_network
level: high
            """,
            "platforms": ["Windows"],
            "data_sources": ["Process Creation", "Network Connection"],
            "actor_ids": [enterprise1_actor["id"]],
            "status": "active",
            "visibility": "private",  # Proprietary detection
            "confidence_score": 0.92,
            "tags": ["apt", "lateral-movement", "enterprise"],
        }

        enterprise1_detection_response = client.post(
            "/api/v1/detections/",
            json=apt_detection_data,
            headers=enterprise1_admin_headers
        )
        assert enterprise1_detection_response.status_code == 201
        enterprise1_detection = enterprise1_detection_response.json()

        # Enterprise 2: Financial Fraud Detection
        financial_detection_data = {
            "name": "Banking Trojan Transaction Monitoring",
            "description": "Detection for financial fraud and banking trojan activity",
            "rule_yaml": """
title: Banking Trojan Detection
detection:
    selection_processes:
        Image|contains:
            - 'browser'
            - 'finance'
        CommandLine|contains:
            - 'transaction'
            - 'account'
    selection_network:
        DestinationHostname|contains:
            - 'bank'
            - 'finance'
            - 'payment'
    condition: selection_processes and selection_network
level: critical
            """,
            "platforms": ["Windows", "macOS"],
            "data_sources": ["Process Creation", "Network Traffic", "Browser Activity"],
            "actor_ids": [enterprise2_actor["id"]],
            "status": "active",
            "visibility": "private",
            "confidence_score": 0.88,
            "tags": ["banking", "fraud", "financial"],
        }

        enterprise2_detection_response = client.post(
            "/api/v1/detections/",
            json=financial_detection_data,
            headers=enterprise2_admin_headers
        )
        assert enterprise2_detection_response.status_code == 201
        enterprise2_detection = enterprise2_detection_response.json()

        # Startup: Innovative Detection
        innovative_detection_data = {
            "name": "AI-Powered Anomaly Detection",
            "description": "Machine learning based anomaly detection for emerging threats",
            "rule_yaml": """
title: ML Anomaly Detection
detection:
    selection:
        ml_score: '>0.8'
        anomaly_type: 'behavioral'
    condition: selection
level: medium
            """,
            "platforms": ["Windows", "Linux", "macOS"],
            "data_sources": ["Behavioral Analytics", "ML Indicators"],
            "actor_ids": [startup_actor["id"]],
            "status": "testing",  # Still experimental
            "visibility": "public",  # Open source approach
            "confidence_score": 0.75,
            "tags": ["ml", "behavioral", "experimental"],
        }

        startup_detection_response = client.post(
            "/api/v1/detections/",
            json=innovative_detection_data,
            headers=startup_admin_headers
        )
        assert startup_detection_response.status_code == 201
        startup_detection = startup_detection_response.json()

        # Test tenant isolation - each tenant should only see their own data

        # Enterprise 1 should only see their data
        enterprise1_actors_response = client.get("/api/v1/actors/", headers=enterprise1_admin_headers)
        enterprise1_actors = enterprise1_actors_response.json()["items"]
        enterprise1_actor_names = [a["name"] for a in enterprise1_actors]

        assert "APT-Enterprise-Analysis" in enterprise1_actor_names
        assert "FinTech-Threat-Actor" not in enterprise1_actor_names
        assert "Emerging-Threat-Group" not in enterprise1_actor_names

        # Enterprise 2 should only see their data
        enterprise2_detections_response = client.get("/api/v1/detections/", headers=enterprise2_admin_headers)
        enterprise2_detections = enterprise2_detections_response.json()["items"]
        enterprise2_detection_names = [d["name"] for d in enterprise2_detections]

        assert "Banking Trojan Transaction Monitoring" in enterprise2_detection_names
        assert "Enterprise APT Lateral Movement Detection" not in enterprise2_detection_names
        assert "AI-Powered Anomaly Detection" not in enterprise2_detection_names

        # Startup should only see their data
        startup_actors_response = client.get("/api/v1/actors/", headers=startup_admin_headers)
        startup_actors = startup_actors_response.json()["items"]

        assert len(startup_actors) == 1
        assert startup_actors[0]["name"] == "Emerging-Threat-Group"

        # Test cross-tenant operation failures

        # Enterprise 1 tries to access Enterprise 2's detection
        cross_tenant_access = client.get(
            f"/api/v1/detections/{enterprise2_detection['id']}",
            headers=enterprise1_admin_headers
        )
        assert cross_tenant_access.status_code == 404

        # Enterprise 2 tries to update Startup's actor
        cross_tenant_update = client.put(
            f"/api/v1/actors/{startup_actor['id']}",
            json={"name": "Modified by Enterprise 2"},
            headers=enterprise2_admin_headers
        )
        assert cross_tenant_update.status_code == 404

        # Startup tries to delete Enterprise 1's detection
        cross_tenant_delete = client.delete(
            f"/api/v1/detections/{enterprise1_detection['id']}",
            headers=startup_admin_headers
        )
        assert cross_tenant_delete.status_code == 404

        # Test search isolation

        # Search for "APT" across all tenants should return different results
        enterprise1_apt_search = client.get(
            "/api/v1/detections/?search=APT",
            headers=enterprise1_admin_headers
        )
        enterprise1_apt_results = enterprise1_apt_search.json()["items"]

        enterprise2_apt_search = client.get(
            "/api/v1/detections/?search=APT",
            headers=enterprise2_admin_headers
        )
        enterprise2_apt_results = enterprise2_apt_search.json()["items"]

        startup_apt_search = client.get(
            "/api/v1/detections/?search=APT",
            headers=startup_admin_headers
        )
        startup_apt_results = startup_apt_search.json()["items"]

        # Only Enterprise 1 should find APT-related detections
        enterprise1_has_apt = any("APT" in d["name"] for d in enterprise1_apt_results)
        enterprise2_has_apt = any("APT" in d["name"] for d in enterprise2_apt_results)
        startup_has_apt = any("APT" in d["name"] for d in startup_apt_results)

        assert enterprise1_has_apt
        assert not enterprise2_has_apt
        assert not startup_has_apt

        # Test tenant-specific statistics

        # Each tenant should have their own detection counts
        enterprise1_stats = client.get("/api/v1/detections/?per_page=1", headers=enterprise1_admin_headers)
        enterprise1_total = enterprise1_stats.json()["total"]

        enterprise2_stats = client.get("/api/v1/detections/?per_page=1", headers=enterprise2_admin_headers)
        enterprise2_total = enterprise2_stats.json()["total"]

        startup_stats = client.get("/api/v1/detections/?per_page=1", headers=startup_admin_headers)
        startup_total = startup_stats.json()["total"]

        # Each should have exactly 1 detection
        assert enterprise1_total == 1
        assert enterprise2_total == 1
        assert startup_total == 1

        # Test tenant resource limits (if implemented)
        # This would test that tenants can't exceed their allocated resources

        # Create many actors to test limits (if enforced)
        for i in range(5):  # Create additional actors
            additional_actor = {
                "name": f"Additional Actor {i}",
                "description": f"Actor number {i} for testing",
                "country": "Unknown",
                "actor_type": "unknown",
            }

            # Each tenant creates additional actors
            for headers in [enterprise1_admin_headers, enterprise2_admin_headers, startup_admin_headers]:
                actor_response = client.post("/api/v1/actors/", json=additional_actor, headers=headers)
                # Should succeed unless tenant limits are enforced
                assert actor_response.status_code in [201, 429]  # 429 if rate limited

        # Final verification: tenant data remains isolated after all operations
        final_enterprise1_data = client.get("/api/v1/detections/", headers=enterprise1_admin_headers)
        final_enterprise2_data = client.get("/api/v1/detections/", headers=enterprise2_admin_headers)
        final_startup_data = client.get("/api/v1/detections/", headers=startup_admin_headers)

        # Each tenant should still only see their own detections
        enterprise1_final_detections = final_enterprise1_data.json()["items"]
        enterprise2_final_detections = final_enterprise2_data.json()["items"]
        startup_final_detections = final_startup_data.json()["items"]

        # Verify tenant IDs match
        for detection in enterprise1_final_detections:
            assert detection["tenant_id"] == enterprise1_tenant_id

        for detection in enterprise2_final_detections:
            assert detection["tenant_id"] == enterprise2_tenant_id

        for detection in startup_final_detections:
            assert detection["tenant_id"] == startup_tenant_id

    async def test_tenant_scaling_scenarios(
        self, client: TestClient, db_session: AsyncSession
    ):
        """Test scenarios with varying tenant sizes and usage patterns."""

        # Create small tenant with minimal usage
        small_tenant_data = {
            "email": "admin@smallcompany.com",
            "password": "SmallTenant123!",
            "full_name": "Small Company Admin",
            "company_name": "Small Security Company",
        }

        small_response = client.post("/api/v1/auth/signup", json=small_tenant_data)
        small_headers = {"Authorization": f"Bearer {small_response.json()['access_token']}"}

        # Create medium tenant with moderate usage
        medium_tenant_data = {
            "email": "admin@mediumcorp.com",
            "password": "MediumTenant123!",
            "full_name": "Medium Corp Admin",
            "company_name": "Medium Security Corp",
        }

        medium_response = client.post("/api/v1/auth/signup", json=medium_tenant_data)
        medium_headers = {"Authorization": f"Bearer {medium_response.json()['access_token']}"}

        # Small tenant: Create minimal data
        small_actor = {
            "name": "Small Tenant Actor",
            "description": "Single actor for small tenant",
            "country": "Unknown",
            "actor_type": "unknown",
        }

        small_actor_response = client.post("/api/v1/actors/", json=small_actor, headers=small_headers)
        small_actor_result = small_actor_response.json()

        small_detection = {
            "name": "Basic Detection",
            "description": "Simple detection for small tenant",
            "rule_yaml": "detection:\n  selection:\n    field: value\n  condition: selection",
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "actor_ids": [small_actor_result["id"]],
            "status": "active",
            "visibility": "public",
        }

        client.post("/api/v1/detections/", json=small_detection, headers=small_headers)

        # Medium tenant: Create moderate amount of data
        medium_actors = []
        for i in range(10):  # 10 actors
            actor_data = {
                "name": f"Medium Tenant Actor {i + 1}",
                "description": f"Actor {i + 1} for medium tenant testing",
                "country": "Unknown",
                "actor_type": "cybercriminal" if i % 2 == 0 else "nation_state",
            }

            actor_response = client.post("/api/v1/actors/", json=actor_data, headers=medium_headers)
            medium_actors.append(actor_response.json())

        # Create 20 detections for medium tenant
        for i in range(20):
            detection_data = {
                "name": f"Medium Detection {i + 1}",
                "description": f"Detection {i + 1} for medium tenant",
                "rule_yaml": f"detection:\n  selection:\n    field{i}: value{i}\n  condition: selection",
                "platforms": ["Windows" if i % 2 == 0 else "Linux"],
                "data_sources": ["Process Creation"],
                "actor_ids": [medium_actors[i % len(medium_actors)]["id"]],
                "status": "active" if i < 15 else "draft",
                "visibility": "public",
                "confidence_score": 0.5 + (i * 0.02),  # Varying scores
            }

            client.post("/api/v1/detections/", json=detection_data, headers=medium_headers)

        # Test performance with different data volumes

        # Small tenant: Fast queries
        import time

        start_time = time.time()
        small_list_response = client.get("/api/v1/detections/", headers=small_headers)
        small_query_time = time.time() - start_time

        assert small_list_response.status_code == 200
        small_detections = small_list_response.json()
        assert small_detections["total"] == 1
        assert small_query_time < 1.0  # Should be very fast

        # Medium tenant: Reasonable performance
        start_time = time.time()
        medium_list_response = client.get("/api/v1/detections/", headers=medium_headers)
        medium_query_time = time.time() - start_time

        assert medium_list_response.status_code == 200
        medium_detections = medium_list_response.json()
        assert medium_detections["total"] == 20
        assert medium_query_time < 5.0  # Should still be reasonable

        # Test pagination with medium tenant
        page1_response = client.get("/api/v1/detections/?page=1&per_page=10", headers=medium_headers)
        page1_data = page1_response.json()
        assert len(page1_data["items"]) == 10
        assert page1_data["page"] == 1
        assert page1_data["total"] == 20

        page2_response = client.get("/api/v1/detections/?page=2&per_page=10", headers=medium_headers)
        page2_data = page2_response.json()
        assert len(page2_data["items"]) == 10
        assert page2_data["page"] == 2

        # Verify no overlap between pages
        page1_ids = [d["id"] for d in page1_data["items"]]
        page2_ids = [d["id"] for d in page2_data["items"]]
        assert len(set(page1_ids) & set(page2_ids)) == 0

        # Test filtering with different data volumes
        medium_active_response = client.get("/api/v1/detections/?status=active", headers=medium_headers)
        medium_active_data = medium_active_response.json()
        assert medium_active_data["total"] == 15  # 15 active, 5 draft

        medium_draft_response = client.get("/api/v1/detections/?status=draft", headers=medium_headers)
        medium_draft_data = medium_draft_response.json()
        assert medium_draft_data["total"] == 5

        # Test search performance
        start_time = time.time()
        search_response = client.get("/api/v1/detections/?search=Medium Detection", headers=medium_headers)
        search_time = time.time() - start_time

        assert search_response.status_code == 200
        search_results = search_response.json()
        assert search_results["total"] == 20  # All match "Medium Detection"
        assert search_time < 3.0  # Search should be reasonably fast

        # Test actor relationship queries
        first_actor_id = medium_actors[0]["id"]
        actor_detections_response = client.get(
            f"/api/v1/actors/{first_actor_id}/detections",
            headers=medium_headers
        )
        assert actor_detections_response.status_code == 200
        actor_detections = actor_detections_response.json()
        # Should have 2 detections (actor used every 10th detection)
        assert actor_detections["total"] >= 2

    async def test_tenant_data_migration_scenarios(
        self, client: TestClient, db_session: AsyncSession
    ):
        """Test scenarios involving tenant data migration and merging."""

        # Create source tenant
        source_tenant_data = {
            "email": "admin@source.com",
            "password": "SourceTenant123!",
            "full_name": "Source Admin",
            "company_name": "Source Company",
        }

        source_response = client.post("/api/v1/auth/signup", json=source_tenant_data)
        source_headers = {"Authorization": f"Bearer {source_response.json()['access_token']}"}
        source_tenant_id = source_response.json()["user"]["tenant_id"]

        # Create destination tenant
        dest_tenant_data = {
            "email": "admin@destination.com",
            "password": "DestTenant123!",
            "full_name": "Destination Admin",
            "company_name": "Destination Company",
        }

        dest_response = client.post("/api/v1/auth/signup", json=dest_tenant_data)
        dest_headers = {"Authorization": f"Bearer {dest_response.json()['access_token']}"}
        dest_tenant_id = dest_response.json()["user"]["tenant_id"]

        # Create data in source tenant
        source_actors = []
        for i in range(3):
            actor_data = {
                "name": f"Source Actor {i + 1}",
                "description": f"Actor {i + 1} from source tenant",
                "country": "Unknown",
                "actor_type": "unknown",
            }

            actor_response = client.post("/api/v1/actors/", json=actor_data, headers=source_headers)
            source_actors.append(actor_response.json())

        source_detections = []
        for i in range(5):
            detection_data = {
                "name": f"Source Detection {i + 1}",
                "description": f"Detection {i + 1} from source tenant",
                "rule_yaml": f"detection:\n  selection:\n    source_field{i}: value{i}\n  condition: selection",
                "platforms": ["Windows"],
                "data_sources": ["Process Creation"],
                "actor_ids": [source_actors[i % len(source_actors)]["id"]],
                "status": "active",
                "visibility": "public",
            }

            detection_response = client.post("/api/v1/detections/", json=detection_data, headers=source_headers)
            source_detections.append(detection_response.json())

        # Simulate data export from source tenant
        source_actors_export = client.get("/api/v1/actors/", headers=source_headers)
        source_detections_export = client.get("/api/v1/detections/", headers=source_headers)

        exported_actors = source_actors_export.json()["items"]
        exported_detections = source_detections_export.json()["items"]

        assert len(exported_actors) == 3
        assert len(exported_detections) == 5

        # Verify data is isolated before migration
        dest_initial_actors = client.get("/api/v1/actors/", headers=dest_headers)
        dest_initial_detections = client.get("/api/v1/detections/", headers=dest_headers)

        assert dest_initial_actors.json()["total"] == 0
        assert dest_initial_detections.json()["total"] == 0

        # Simulate manual data recreation in destination tenant
        # (In a real scenario, this would be done through a migration API)

        dest_actor_mapping = {}  # Map old IDs to new IDs

        for exported_actor in exported_actors:
            # Create actor in destination tenant (excluding tenant-specific fields)
            new_actor_data = {
                "name": exported_actor["name"] + " (Migrated)",
                "description": exported_actor["description"] + " [Migrated from source]",
                "country": exported_actor["country"],
                "actor_type": exported_actor["actor_type"],
                # Note: aliases, motivation, etc. would be included if present
            }

            new_actor_response = client.post("/api/v1/actors/", json=new_actor_data, headers=dest_headers)
            assert new_actor_response.status_code == 201
            new_actor = new_actor_response.json()

            dest_actor_mapping[exported_actor["id"]] = new_actor["id"]

        # Migrate detections with updated actor references
        for exported_detection in exported_detections:
            # Map old actor IDs to new actor IDs
            old_actor_ids = [actor["id"] for actor in exported_detection["actors"]]
            new_actor_ids = [dest_actor_mapping[old_id] for old_id in old_actor_ids if old_id in dest_actor_mapping]

            new_detection_data = {
                "name": exported_detection["name"] + " (Migrated)",
                "description": exported_detection["description"] + " [Migrated from source]",
                "rule_yaml": exported_detection["rule_yaml"],
                "platforms": exported_detection["platforms"],
                "data_sources": exported_detection["data_sources"],
                "actor_ids": new_actor_ids,
                "status": exported_detection["status"],
                "visibility": exported_detection["visibility"],
                "confidence_score": exported_detection.get("confidence_score", 0.5),
            }

            new_detection_response = client.post("/api/v1/detections/", json=new_detection_data, headers=dest_headers)
            assert new_detection_response.status_code == 201

        # Verify migration completed successfully
        dest_final_actors = client.get("/api/v1/actors/", headers=dest_headers)
        dest_final_detections = client.get("/api/v1/detections/", headers=dest_headers)

        migrated_actors = dest_final_actors.json()["items"]
        migrated_detections = dest_final_detections.json()["items"]

        assert len(migrated_actors) == 3
        assert len(migrated_detections) == 5

        # Verify migrated data has correct tenant IDs
        for actor in migrated_actors:
            assert actor["tenant_id"] == dest_tenant_id
            assert "(Migrated)" in actor["name"]

        for detection in migrated_detections:
            assert detection["tenant_id"] == dest_tenant_id
            assert "(Migrated)" in detection["name"]

        # Verify relationships were preserved
        for detection in migrated_detections:
            assert len(detection["actors"]) > 0
            for actor in detection["actors"]:
                assert actor["tenant_id"] == dest_tenant_id

        # Verify source tenant data is unchanged
        source_final_actors = client.get("/api/v1/actors/", headers=source_headers)
        source_final_detections = client.get("/api/v1/detections/", headers=source_headers)

        assert source_final_actors.json()["total"] == 3
        assert source_final_detections.json()["total"] == 5

        # Verify tenants remain isolated after migration
        source_cannot_access_dest = client.get(
            f"/api/v1/actors/{migrated_actors[0]['id']}",
            headers=source_headers
        )
        assert source_cannot_access_dest.status_code == 404

        dest_cannot_access_source = client.get(
            f"/api/v1/actors/{source_actors[0]['id']}",
            headers=dest_headers
        )
        assert dest_cannot_access_source.status_code == 404