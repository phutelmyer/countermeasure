"""
API client for Countermeasure authentication and data submission.
"""

import asyncio
from typing import Dict, List, Optional, Any
from uuid import UUID
from urllib.parse import quote

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
        self.base_url = base_url.rstrip('/')
        self.email = email
        self.password = password
        self.access_token: Optional[str] = None
        self.client = httpx.AsyncClient(timeout=30.0)

        # Cache for API lookups
        self._severities_cache: Optional[Dict[str, UUID]] = None
        self._categories_cache: Dict[str, UUID] = {}
        self._tags_cache: Dict[str, UUID] = {}

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
                "remember_me": False
            }
            response = await self.client.post(
                f"{self.base_url}/api/v1/auth/login",
                json=login_data
            )

            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                logger.info("Successfully authenticated with Countermeasure API")
                return True
            else:
                logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers with authentication token."""
        if not self.access_token:
            raise Exception("Not authenticated - call login() first")

        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

    async def get_severities(self) -> Dict[str, UUID]:
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
                headers=self._get_auth_headers()
            )

            if response.status_code == 200:
                severities = response.json()
                self._severities_cache = {
                    sev["name"]: UUID(sev["id"]) for sev in severities
                }
                logger.debug(f"Cached {len(self._severities_cache)} severities")
                return self._severities_cache
            else:
                logger.error(f"Failed to fetch severities: {response.status_code}")
                return {}

        except Exception as e:
            logger.error(f"Error fetching severities: {str(e)}")
            return {}

    async def get_or_create_category(self, name: str, description: str = "") -> Optional[UUID]:
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
                params={"search": name}
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
                json={
                    "name": name,
                    "description": description
                }
            )

            if response.status_code == 201:
                category = response.json()
                category_id = UUID(category["id"])
                self._categories_cache[name] = category_id
                logger.debug(f"Created category: {name}")
                return category_id
            else:
                logger.error(f"Failed to create category {name}: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error with category {name}: {str(e)}")
            return None

    async def get_or_create_tag(self, name: str, description: str = "") -> Optional[UUID]:
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
                params={"search": name}
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
                json={
                    "name": name,
                    "description": description
                }
            )

            if response.status_code == 201:
                tag = response.json()
                tag_id = UUID(tag["id"])
                self._tags_cache[name] = tag_id
                logger.debug(f"Created tag: {name}")
                return tag_id
            else:
                logger.error(f"Failed to create tag {name}: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error with tag {name}: {str(e)}")
            return None

    async def create_detection(self, detection_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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
                json=detection_data
            )

            if response.status_code == 201:
                return response.json()
            else:
                logger.error(f"Failed to create detection: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"Error creating detection: {str(e)}")
            return None

    async def batch_create_detections(self, detections: List[Dict[str, Any]], batch_size: int = 50) -> Dict[str, int]:
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
            batch = detections[i:i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1} ({len(batch)} detections)")

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

    async def get_detections(self, limit: int = 1000) -> Optional[Dict[str, Any]]:
        """
        Get all detections from the API.

        Args:
            limit: Maximum number of detections to fetch

        Returns:
            Response data or None if request failed
        """
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/detections/",
                params={"limit": limit},
                headers=self._get_auth_headers()
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get detections: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"Error getting detections: {str(e)}")
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
                headers=self._get_auth_headers()
            )

            if response.status_code == 204:
                return True
            else:
                logger.error(f"Failed to delete detection {detection_id}: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error deleting detection {detection_id}: {str(e)}")
            return False

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()