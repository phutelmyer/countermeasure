"""
Locust performance test scenarios for Countermeasure API.

Tests various API endpoints under load to identify performance bottlenecks
and validate system behavior under concurrent usage.

Usage:
    locust -f locustfile.py --host=http://localhost:8000
    locust -f locustfile.py --host=http://localhost:8000 --users=50 --spawn-rate=5 --run-time=300s
"""

import json
import random
import string
from locust import HttpUser, task, between, events
from faker import Faker

fake = Faker()


class CountermeasureApiUser(HttpUser):
    """Base user class for Countermeasure API testing."""

    wait_time = between(1, 5)  # Wait 1-5 seconds between requests

    def on_start(self):
        """Setup user session - authenticate and store tokens."""
        self.access_token = None
        self.user_data = None
        self.tenant_id = None
        self.created_resources = {
            'actors': [],
            'detections': [],
            'users': []
        }

        # Authenticate user
        self.authenticate()

    def on_stop(self):
        """Cleanup resources created during testing."""
        # Clean up created resources
        for actor_id in self.created_resources['actors']:
            try:
                self.client.delete(
                    f"/api/v1/actors/{actor_id}",
                    headers=self.auth_headers()
                )
            except:
                pass  # Ignore cleanup errors

        for detection_id in self.created_resources['detections']:
            try:
                self.client.delete(
                    f"/api/v1/detections/{detection_id}",
                    headers=self.auth_headers()
                )
            except:
                pass  # Ignore cleanup errors

    def authenticate(self):
        """Authenticate user and store access token."""
        # Create unique user for this test session
        user_email = f"loadtest_{self.generate_random_string(8)}@example.com"
        user_password = f"LoadTest123!{self.generate_random_string(4)}"

        signup_data = {
            "email": user_email,
            "password": user_password,
            "full_name": fake.name(),
            "company_name": f"{fake.company()} Load Test Corp",
        }

        # Sign up new user
        with self.client.post(
            "/api/v1/auth/signup",
            json=signup_data,
            catch_response=True
        ) as response:
            if response.status_code == 201:
                result = response.json()
                self.access_token = result["access_token"]
                self.user_data = result["user"]
                self.tenant_id = result["user"]["tenant_id"]
                response.success()
            else:
                response.failure(f"Authentication failed: {response.status_code}")

    def auth_headers(self):
        """Return authentication headers."""
        if self.access_token:
            return {"Authorization": f"Bearer {self.access_token}"}
        return {}

    def generate_random_string(self, length=10):
        """Generate random string for unique identifiers."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    @task(5)
    def get_user_profile(self):
        """Test user profile retrieval."""
        with self.client.get(
            "/api/v1/auth/me",
            headers=self.auth_headers(),
            name="Get User Profile",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Profile retrieval failed: {response.status_code}")

    @task(10)
    def list_detections(self):
        """Test detection listing with various parameters."""
        params = random.choice([
            {},  # No parameters
            {"page": random.randint(1, 5)},
            {"per_page": random.choice([10, 25, 50])},
            {"status": random.choice(["active", "draft", "testing"])},
            {"platform": random.choice(["Windows", "Linux", "macOS"])},
            {"search": random.choice(["test", "malware", "suspicious", "attack"])},
        ])

        with self.client.get(
            "/api/v1/detections/",
            params=params,
            headers=self.auth_headers(),
            name="List Detections",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                data = response.json()
                if "items" in data and "total" in data:
                    response.success()
                else:
                    response.failure("Invalid response format")
            else:
                response.failure(f"Detection listing failed: {response.status_code}")

    @task(8)
    def list_actors(self):
        """Test actor listing."""
        params = random.choice([
            {},
            {"page": random.randint(1, 3)},
            {"search": random.choice(["APT", "Group", "Actor"])},
            {"actor_type": random.choice(["nation_state", "cybercriminal", "hacktivist"])},
        ])

        with self.client.get(
            "/api/v1/actors/",
            params=params,
            headers=self.auth_headers(),
            name="List Actors",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Actor listing failed: {response.status_code}")

    @task(3)
    def create_actor(self):
        """Test actor creation."""
        actor_data = {
            "name": f"Load Test Actor {self.generate_random_string(8)}",
            "aliases": [f"Alias {self.generate_random_string(6)}"],
            "description": fake.text(max_nb_chars=200),
            "country": fake.country(),
            "motivation": random.choice(["Financial Gain", "Espionage", "Hacktivism", "Testing"]),
            "first_seen": "2024-01-01",
            "actor_type": random.choice(["nation_state", "cybercriminal", "hacktivist", "unknown"]),
            "sophistication": random.choice(["novice", "intermediate", "advanced", "expert"]),
            "resource_level": random.choice(["individual", "club", "contest", "team", "organization", "government"]),
        }

        with self.client.post(
            "/api/v1/actors/",
            json=actor_data,
            headers=self.auth_headers(),
            name="Create Actor",
            catch_response=True
        ) as response:
            if response.status_code == 201:
                created_actor = response.json()
                self.created_resources['actors'].append(created_actor["id"])
                response.success()
            else:
                response.failure(f"Actor creation failed: {response.status_code}")

    @task(4)
    def create_detection(self):
        """Test detection creation."""
        detection_data = {
            "name": f"Load Test Detection {self.generate_random_string(8)}",
            "description": fake.text(max_nb_chars=300),
            "rule_yaml": f"""
title: {fake.sentence()}
description: {fake.text(max_nb_chars=100)}
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: '.exe'
        CommandLine|contains: '{self.generate_random_string(10)}'
    condition: selection
falsepositives:
    - {fake.sentence()}
    - {fake.sentence()}
level: {random.choice(['low', 'medium', 'high', 'critical'])}
tags:
    - attack.execution
    - attack.t1059
    - load_test
            """,
            "platforms": random.sample(["Windows", "Linux", "macOS"], k=random.randint(1, 3)),
            "data_sources": random.sample([
                "Process Creation", "Network Traffic", "File Monitoring",
                "Registry", "Authentication Logs", "Command Line"
            ], k=random.randint(1, 4)),
            "false_positives": [fake.sentence() for _ in range(random.randint(1, 3))],
            "tags": [f"tag_{self.generate_random_string(6)}" for _ in range(random.randint(1, 5))],
            "status": random.choice(["draft", "testing", "active"]),
            "visibility": random.choice(["public", "private"]),
            "confidence_score": round(random.uniform(0.1, 1.0), 2),
        }

        # Randomly associate with existing actors
        if self.created_resources['actors'] and random.choice([True, False]):
            detection_data["actor_ids"] = random.sample(
                self.created_resources['actors'],
                k=min(2, len(self.created_resources['actors']))
            )

        with self.client.post(
            "/api/v1/detections/",
            json=detection_data,
            headers=self.auth_headers(),
            name="Create Detection",
            catch_response=True
        ) as response:
            if response.status_code == 201:
                created_detection = response.json()
                self.created_resources['detections'].append(created_detection["id"])
                response.success()
            else:
                response.failure(f"Detection creation failed: {response.status_code}")

    @task(6)
    def get_detection_by_id(self):
        """Test individual detection retrieval."""
        if self.created_resources['detections']:
            detection_id = random.choice(self.created_resources['detections'])

            with self.client.get(
                f"/api/v1/detections/{detection_id}",
                headers=self.auth_headers(),
                name="Get Detection by ID",
                catch_response=True
            ) as response:
                if response.status_code == 200:
                    detection = response.json()
                    if "id" in detection and "name" in detection:
                        response.success()
                    else:
                        response.failure("Invalid detection format")
                elif response.status_code == 404:
                    # Resource might have been deleted by another user
                    response.success()
                else:
                    response.failure(f"Detection retrieval failed: {response.status_code}")

    @task(4)
    def get_actor_by_id(self):
        """Test individual actor retrieval."""
        if self.created_resources['actors']:
            actor_id = random.choice(self.created_resources['actors'])

            with self.client.get(
                f"/api/v1/actors/{actor_id}",
                headers=self.auth_headers(),
                name="Get Actor by ID",
                catch_response=True
            ) as response:
                if response.status_code == 200:
                    response.success()
                elif response.status_code == 404:
                    response.success()  # Resource might have been deleted
                else:
                    response.failure(f"Actor retrieval failed: {response.status_code}")

    @task(2)
    def update_detection(self):
        """Test detection updates."""
        if self.created_resources['detections']:
            detection_id = random.choice(self.created_resources['detections'])

            update_data = {
                "description": f"Updated: {fake.text(max_nb_chars=200)}",
                "confidence_score": round(random.uniform(0.1, 1.0), 2),
                "status": random.choice(["draft", "testing", "active"]),
            }

            with self.client.put(
                f"/api/v1/detections/{detection_id}",
                json=update_data,
                headers=self.auth_headers(),
                name="Update Detection",
                catch_response=True
            ) as response:
                if response.status_code == 200:
                    response.success()
                elif response.status_code == 404:
                    response.success()  # Resource might have been deleted
                else:
                    response.failure(f"Detection update failed: {response.status_code}")

    @task(1)
    def search_detections(self):
        """Test detection search functionality."""
        search_terms = [
            "malware", "suspicious", "attack", "powershell", "network",
            "file", "registry", "process", "credential", "persistence"
        ]

        search_term = random.choice(search_terms)

        with self.client.get(
            "/api/v1/detections/",
            params={"search": search_term, "per_page": 20},
            headers=self.auth_headers(),
            name="Search Detections",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                data = response.json()
                if "items" in data:
                    response.success()
                else:
                    response.failure("Invalid search response format")
            else:
                response.failure(f"Detection search failed: {response.status_code}")


class AdminUser(CountermeasureApiUser):
    """Admin user with additional administrative tasks."""

    weight = 1  # Lower weight - fewer admin users

    @task(3)
    def list_users(self):
        """Test user listing (admin operation)."""
        with self.client.get(
            "/api/v1/users/",
            headers=self.auth_headers(),
            name="List Users (Admin)",
            catch_response=True
        ) as response:
            if response.status_code in [200, 403]:  # 403 if not admin
                response.success()
            else:
                response.failure(f"User listing failed: {response.status_code}")

    @task(2)
    def get_tenant_info(self):
        """Test tenant information retrieval."""
        with self.client.get(
            "/api/v1/tenants/",
            headers=self.auth_headers(),
            name="Get Tenant Info",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Tenant info failed: {response.status_code}")


class HighVolumeReadUser(CountermeasureApiUser):
    """User that performs high-volume read operations."""

    weight = 2  # More read-heavy users

    wait_time = between(0.5, 2)  # Faster requests

    @task(20)
    def rapid_detection_listing(self):
        """Rapid detection listing to test read performance."""
        params = {
            "per_page": random.choice([10, 25, 50, 100]),
            "page": random.randint(1, 10)
        }

        with self.client.get(
            "/api/v1/detections/",
            params=params,
            headers=self.auth_headers(),
            name="Rapid Detection Listing",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Rapid listing failed: {response.status_code}")

    @task(15)
    def rapid_actor_listing(self):
        """Rapid actor listing."""
        with self.client.get(
            "/api/v1/actors/",
            params={"per_page": random.choice([25, 50, 100])},
            headers=self.auth_headers(),
            name="Rapid Actor Listing",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Rapid actor listing failed: {response.status_code}")


class BulkDataUser(CountermeasureApiUser):
    """User that creates and manages bulk data."""

    weight = 1  # Fewer bulk users

    def on_start(self):
        """Setup with bulk data creation."""
        super().on_start()
        self.bulk_create_actors()
        self.bulk_create_detections()

    def bulk_create_actors(self):
        """Create multiple actors for testing."""
        for i in range(5):
            actor_data = {
                "name": f"Bulk Actor {i + 1} - {self.generate_random_string(6)}",
                "description": f"Bulk created actor for load testing - {fake.text(max_nb_chars=100)}",
                "country": fake.country(),
                "actor_type": random.choice(["nation_state", "cybercriminal", "hacktivist"]),
            }

            try:
                response = self.client.post(
                    "/api/v1/actors/",
                    json=actor_data,
                    headers=self.auth_headers()
                )
                if response.status_code == 201:
                    created_actor = response.json()
                    self.created_resources['actors'].append(created_actor["id"])
            except:
                pass  # Continue with other creations

    def bulk_create_detections(self):
        """Create multiple detections for testing."""
        for i in range(10):
            detection_data = {
                "name": f"Bulk Detection {i + 1} - {self.generate_random_string(6)}",
                "description": f"Bulk created detection - {fake.text(max_nb_chars=150)}",
                "rule_yaml": f"""
title: Bulk Test Detection {i + 1}
description: Generated for bulk load testing
detection:
    selection:
        EventID: {random.randint(1, 20)}
        Field: 'bulk_test_value_{i}'
    condition: selection
level: medium
                """,
                "platforms": ["Windows"],
                "data_sources": ["Process Creation"],
                "status": "testing",
                "visibility": "public",
                "confidence_score": round(random.uniform(0.5, 0.9), 2),
            }

            # Associate with random actors
            if self.created_resources['actors']:
                detection_data["actor_ids"] = random.sample(
                    self.created_resources['actors'],
                    k=min(2, len(self.created_resources['actors']))
                )

            try:
                response = self.client.post(
                    "/api/v1/detections/",
                    json=detection_data,
                    headers=self.auth_headers()
                )
                if response.status_code == 201:
                    created_detection = response.json()
                    self.created_resources['detections'].append(created_detection["id"])
            except:
                pass  # Continue with other creations

    @task(5)
    def bulk_update_detections(self):
        """Update multiple detections."""
        if len(self.created_resources['detections']) >= 3:
            detection_ids = random.sample(self.created_resources['detections'], 3)

            for detection_id in detection_ids:
                update_data = {
                    "confidence_score": round(random.uniform(0.1, 1.0), 2),
                    "status": random.choice(["active", "testing"]),
                }

                try:
                    self.client.put(
                        f"/api/v1/detections/{detection_id}",
                        json=update_data,
                        headers=self.auth_headers()
                    )
                except:
                    pass  # Continue with other updates


# Event handlers for performance monitoring
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Log test start."""
    print(f"Starting load test with {environment.runner.user_count} users")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Log test completion and summary."""
    print("Load test completed")
    print(f"Total requests: {environment.runner.stats.total.num_requests}")
    print(f"Failed requests: {environment.runner.stats.total.num_failures}")
    print(f"Average response time: {environment.runner.stats.total.avg_response_time:.2f}ms")
    print(f"RPS: {environment.runner.stats.total.current_rps:.2f}")


# Configure user classes
if __name__ == "__main__":
    # This allows running specific scenarios
    import sys

    if len(sys.argv) > 1:
        scenario = sys.argv[1]
        if scenario == "read_heavy":
            # Read-heavy scenario
            from locust import User
            User.user_classes = [HighVolumeReadUser]
        elif scenario == "write_heavy":
            # Write-heavy scenario
            User.user_classes = [BulkDataUser]
        elif scenario == "admin":
            # Admin scenario
            User.user_classes = [AdminUser]
        else:
            # Default mixed scenario
            User.user_classes = [CountermeasureApiUser, AdminUser, HighVolumeReadUser, BulkDataUser]
    else:
        # Default configuration with mixed users
        pass  # Locust will use the defined classes with their weights