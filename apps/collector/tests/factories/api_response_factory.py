"""
Factory for API response data.
"""

import factory
from faker import Faker
from typing import Dict, Any, List
import uuid

fake = Faker()


class ApiResponseFactory(factory.DictFactory):
    """Factory for creating API response dictionaries."""

    @classmethod
    def detection_response(cls, **kwargs) -> Dict[str, Any]:
        """Create a detection API response."""
        defaults = {
            "id": str(uuid.uuid4()),
            "name": fake.sentence(nb_words=3),
            "description": fake.text(max_nb_chars=200),
            "rule_content": "sample rule content",
            "rule_format": "sigma",
            "author": fake.name(),
            "severity_id": str(uuid.uuid4()),
            "visibility": "private",
            "confidence_score": fake.pyfloat(min_value=0.0, max_value=1.0),
            "performance_impact": fake.random_element(["low", "medium", "high"]),
            "status": fake.random_element(["draft", "testing", "active"]),
            "version": "1.0.0",
            "source_url": fake.url(),
            "platforms": ["Windows"],
            "data_sources": ["Process Creation"],
            "false_positives": [fake.sentence(nb_words=4)],
            "log_sources": ["product:windows | category:process_creation"],
            "created_at": fake.iso8601(),
            "updated_at": fake.iso8601(),
            "tenant_id": str(uuid.uuid4())
        }
        defaults.update(kwargs)
        return defaults

    @classmethod
    def detection_list_response(cls, count: int = 5) -> Dict[str, Any]:
        """Create a detection list API response."""
        return {
            "items": [cls.detection_response() for _ in range(count)],
            "total": count,
            "page": 1,
            "per_page": 50,
            "pages": 1
        }

    @classmethod
    def severity_response(cls, **kwargs) -> Dict[str, Any]:
        """Create a severity API response."""
        defaults = {
            "id": str(uuid.uuid4()),
            "name": fake.random_element(["Critical", "High", "Medium", "Low"]),
            "description": fake.sentence(nb_words=5),
            "color": fake.color(),
            "score": fake.random_int(min=1, max=100),
            "is_active": True,
            "created_at": fake.iso8601(),
            "updated_at": fake.iso8601(),
            "tenant_id": str(uuid.uuid4())
        }
        defaults.update(kwargs)
        return defaults

    @classmethod
    def category_response(cls, **kwargs) -> Dict[str, Any]:
        """Create a category API response."""
        defaults = {
            "id": str(uuid.uuid4()),
            "name": fake.random_element(["Malware", "APT", "Insider Threat"]),
            "description": fake.sentence(nb_words=5),
            "color": fake.color(),
            "icon": fake.random_element(["shield", "bug", "user"]),
            "is_active": True,
            "created_at": fake.iso8601(),
            "updated_at": fake.iso8601(),
            "tenant_id": str(uuid.uuid4())
        }
        defaults.update(kwargs)
        return defaults

    @classmethod
    def error_response(cls, status_code: int = 400, message: str = None) -> Dict[str, Any]:
        """Create an error API response."""
        return {
            "detail": message or fake.sentence(nb_words=5),
            "status_code": status_code,
            "timestamp": fake.iso8601()
        }

    @classmethod
    def auth_response(cls, **kwargs) -> Dict[str, Any]:
        """Create an authentication API response."""
        defaults = {
            "access_token": fake.sha256(),
            "refresh_token": fake.sha256(),
            "token_type": "bearer",
            "expires_in": 3600,
            "user": {
                "id": str(uuid.uuid4()),
                "email": fake.email(),
                "first_name": fake.first_name(),
                "last_name": fake.last_name(),
                "role": "viewer",
                "is_active": True
            }
        }
        defaults.update(kwargs)
        return defaults

    @classmethod
    def health_response(cls, **kwargs) -> Dict[str, Any]:
        """Create a health check API response."""
        defaults = {
            "status": "healthy",
            "timestamp": fake.iso8601(),
            "version": "1.0.0",
            "environment": "test",
            "database": "connected",
            "redis": "connected"
        }
        defaults.update(kwargs)
        return defaults

    @classmethod
    def batch_upload_response(cls, success_count: int = 5, error_count: int = 0) -> Dict[str, Any]:
        """Create a batch upload API response."""
        return {
            "success_count": success_count,
            "error_count": error_count,
            "total_processed": success_count + error_count,
            "errors": [
                {
                    "item_index": i,
                    "error": fake.sentence(nb_words=4),
                    "details": fake.text(max_nb_chars=100)
                }
                for i in range(error_count)
            ],
            "created_ids": [str(uuid.uuid4()) for _ in range(success_count)]
        }