"""
API client for Countermeasure authentication and data submission.
"""

import asyncio
from typing import Any
from uuid import UUID

import httpx

from src.core.logging import get_logger


logger = get_logger(__name__)


class CountermeasureClient:
    """Client for interacting with Countermeasure API."""

    def __init__(self, base_url: str, email: str, password: str):
        """
        Initialize the API client.

        Args:
            base_url: Base URL of the Countermeasure API
            email: User email for authentication
            password: User password for authentication
        """
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        self.access_token: str | None = None
        self.client = httpx.AsyncClient(timeout=30.0)

        # Cache for API lookups
        self._severities_cache: dict[str, UUID] | None = None
        self._categories_cache: dict[str, UUID] = {}
        self._tags_cache: dict[str, UUID] = {}

    async def login(self) -> bool:
        """
        Authenticate with the API and get access token.

        Returns:
            True if authentication successful, False otherwise
        """
        try:
            # Use JSON for login
            login_data = {
                "email": self.email,
                "password": self.password,
                "remember_me": False,
            }
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/login", json=login_data
            )

            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                logger.info("Successfully authenticated with Countermeasure API")
                return True
            logger.error(
                f"Authentication failed: {response.status_code} - {response.text}"
            )
            return False

        except Exception as e:
            logger.error(f"Authentication error: {e!s}")
            return False

    def _get_auth_headers(self) -> dict[str, str]:
        """Get headers with authentication token."""
        if not self.access_token:
            raise Exception("Not authenticated - call login() first")

        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

    async def get_severities(self) -> dict[str, UUID]:
        """
        Get severity levels and cache them.

        Returns:
            Dict mapping severity names to UUIDs
        """
        if self._severities_cache is not None:
            return self._severities_cache

        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/detections/severities/",
                headers=self._get_auth_headers(),
            )

            if response.status_code == 200:
                severities = response.json()
                self._severities_cache = {
                    sev["name"]: UUID(sev["id"]) for sev in severities
                }
                logger.debug(f"Cached {len(self._severities_cache)} severities")
                return self._severities_cache
            logger.error(f"Failed to fetch severities: {response.status_code}")
            return {}

        except Exception as e:
            logger.error(f"Error fetching severities: {e!s}")
            return {}

    async def get_or_create_category(
        self, name: str, description: str = ""
    ) -> UUID | None:
        """
        Get or create a category by name.

        Args:
            name: Category name
            description: Category description

        Returns:
            Category UUID if successful, None otherwise
        """
        # Check cache first
        if name in self._categories_cache:
            return self._categories_cache[name]

        try:
            # Try to find existing category
            response = await self.client.get(
                f"{self.base_url}/api/v1/detections/categories/",
                headers=self._get_auth_headers(),
                params={"search": name},
            )

            if response.status_code == 200:
                data = response.json()
                # Handle both list and paginated response formats
                categories = data.get("items", data) if isinstance(data, dict) else data
                for cat in categories:
                    if cat["name"] == name:
                        category_id = UUID(cat["id"])
                        self._categories_cache[name] = category_id
                        return category_id

            # Create new category if not found
            response = await self.client.post(
                f"{self.base_url}/api/v1/detections/categories/",
                headers=self._get_auth_headers(),
                json={"name": name, "description": description},
            )

            if response.status_code == 201:
                category = response.json()
                category_id = UUID(category["id"])
                self._categories_cache[name] = category_id
                logger.debug(f"Created category: {name}")
                return category_id
            logger.error(
                f"Failed to create category {name}: {response.status_code}"
            )
            return None

        except Exception as e:
            logger.error(f"Error with category {name}: {e!s}")
            return None

    async def get_or_create_tag(
        self, name: str, description: str = ""
    ) -> UUID | None:
        """
        Get or create a tag by name.

        Args:
            name: Tag name
            description: Tag description

        Returns:
            Tag UUID if successful, None otherwise
        """
        # Check cache first
        if name in self._tags_cache:
            return self._tags_cache[name]

        try:
            # Try to find existing tag
            response = await self.client.get(
                f"{self.base_url}/api/v1/detections/tags/",
                headers=self._get_auth_headers(),
                params={"search": name},
            )

            if response.status_code == 200:
                data = response.json()
                # Handle both list and paginated response formats
                tags = data.get("items", data) if isinstance(data, dict) else data
                for tag in tags:
                    if tag["name"] == name:
                        tag_id = UUID(tag["id"])
                        self._tags_cache[name] = tag_id
                        return tag_id

            # Create new tag if not found
            response = await self.client.post(
                f"{self.base_url}/api/v1/detections/tags/",
                headers=self._get_auth_headers(),
                json={"name": name, "description": description},
            )

            if response.status_code == 201:
                tag = response.json()
                tag_id = UUID(tag["id"])
                self._tags_cache[name] = tag_id
                logger.debug(f"Created tag: {name}")
                return tag_id
            logger.error(f"Failed to create tag {name}: {response.status_code}")
            return None

        except Exception as e:
            logger.error(f"Error with tag {name}: {e!s}")
            return None

    async def create_detection(
        self, detection_data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Create a single detection rule.

        Args:
            detection_data: Detection data to create

        Returns:
            Created detection data if successful, None otherwise
        """
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/detections/",
                headers=self._get_auth_headers(),
                json=detection_data,
            )

            if response.status_code == 201:
                return response.json()
            logger.error(
                f"Failed to create detection: {response.status_code} - {response.text}"
            )
            return None

        except Exception as e:
            logger.error(f"Error creating detection: {e!s}")
            return None

    async def batch_create_detections(
        self, detections: list[dict[str, Any]], batch_size: int = 50
    ) -> dict[str, int]:
        """
        Create multiple detection rules in batches.

        Args:
            detections: List of detection data to create
            batch_size: Number of detections per batch

        Returns:
            Dict with success/failure counts
        """
        results = {"successful": 0, "failed": 0, "errors": []}

        for i in range(0, len(detections), batch_size):
            batch = detections[i : i + batch_size]
            logger.info(
                f"Processing batch {i // batch_size + 1} ({len(batch)} detections)"
            )

            # Process batch concurrently
            tasks = [self.create_detection(detection) for detection in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, Exception):
                    results["failed"] += 1
                    results["errors"].append(str(result))
                elif result is not None:
                    results["successful"] += 1
                else:
                    results["failed"] += 1

            # Small delay between batches to avoid overwhelming the API
            if i + batch_size < len(detections):
                await asyncio.sleep(0.5)

        return results

    async def get_detections(self, limit: int = 100) -> dict[str, Any] | None:
        """
        Get all detections from the API.

        Args:
            limit: Maximum number of detections to fetch per page (max 100)

        Returns:
            Response data or None if request failed
        """
        try:
            # API uses per_page parameter, capped at 100
            per_page = min(limit, 100)
            response = await self.client.get(
                f"{self.base_url}/api/v1/detections/",
                params={"per_page": per_page},
                headers=self._get_auth_headers(),
            )

            if response.status_code == 200:
                return response.json()
            logger.error(
                f"Failed to get detections: {response.status_code} - {response.text}"
            )
            return None

        except Exception as e:
            logger.error(f"Error getting detections: {e!s}")
            return None

    async def delete_detection(self, detection_id: str) -> bool:
        """
        Delete a detection by ID.

        Args:
            detection_id: ID of detection to delete

        Returns:
            True if successful, False otherwise
        """
        try:
            response = await self.client.delete(
                f"{self.base_url}/api/v1/detections/{detection_id}",
                headers=self._get_auth_headers(),
            )

            if response.status_code == 204:
                return True
            logger.error(
                f"Failed to delete detection {detection_id}: {response.status_code} - {response.text}"
            )
            return False

        except Exception as e:
            logger.error(f"Error deleting detection {detection_id}: {e!s}")
            return False

    async def post(self, url: str, json: Any = None) -> dict[str, Any] | None:
        """
        Make a POST request to the API.

        Args:
            url: API endpoint URL (relative to base URL)
            json: JSON data to send

        Returns:
            Response data if successful, None otherwise
        """
        try:
            full_url = f"{self.base_url}{url}"
            response = await self.client.post(
                full_url, headers=self._get_auth_headers(), json=json
            )

            if response.status_code in [200, 201]:
                return response.json()
            logger.error(
                f"POST {url} failed: {response.status_code} - {response.text}"
            )
            return None

        except Exception as e:
            logger.error(f"Error in POST {url}: {e!s}")
            return None

    async def get(
        self, url: str, params: dict[str, Any] = None
    ) -> dict[str, Any] | None:
        """
        Make a GET request to the API.

        Args:
            url: API endpoint URL (relative to base URL)
            params: Query parameters

        Returns:
            Response data if successful, None otherwise
        """
        try:
            full_url = f"{self.base_url}{url}"
            response = await self.client.get(
                full_url, headers=self._get_auth_headers(), params=params
            )

            if response.status_code == 200:
                return response.json()
            logger.error(
                f"GET {url} failed: {response.status_code} - {response.text}"
            )
            return None

        except Exception as e:
            logger.error(f"Error in GET {url}: {e!s}")
            return None

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
