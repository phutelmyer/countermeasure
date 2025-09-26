"""
Pytest configuration and fixtures for Countermeasure Collector tests.
"""

import asyncio
import tempfile
from collections.abc import AsyncGenerator, Generator
from pathlib import Path
from typing import Dict, Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import AsyncClient, Response
import aiohttp

from src.core.api_client import CountermeasureClient
from src.core.config import Settings


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_settings() -> Settings:
    """Create test settings."""
    return Settings(
        api_url="http://test-api:8000",
        default_email="test@example.com",
        default_password="TestPassword123!",
        environment="testing",
        log_level="DEBUG",
        redis_url="redis://localhost:6379/1",
        celery_broker_url="redis://localhost:6379/1",
        celery_result_backend="redis://localhost:6379/1",
    )


@pytest.fixture
def mock_api_client():
    """Create a mock API client."""
    client = AsyncMock(spec=CountermeasureClient)
    client.login.return_value = True
    client.logout.return_value = True
    client.get_detections.return_value = []
    client.create_detection.return_value = {"id": "test-id", "name": "Test Detection"}
    client.update_detection.return_value = {"id": "test-id", "name": "Updated Detection"}
    client.delete_detection.return_value = True
    client.health_check.return_value = {"status": "healthy"}
    return client


@pytest.fixture
def mock_http_response():
    """Create a mock HTTP response."""
    response = MagicMock(spec=Response)
    response.status_code = 200
    response.json.return_value = {"message": "success"}
    response.text = '{"message": "success"}'
    response.headers = {"content-type": "application/json"}
    return response


@pytest.fixture
def mock_aiohttp_session():
    """Create a mock aiohttp session."""
    session = AsyncMock(spec=aiohttp.ClientSession)

    # Mock response
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={"message": "success"})
    mock_response.text = AsyncMock(return_value='{"message": "success"}')
    mock_response.headers = {"content-type": "application/json"}

    # Context manager support
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=None)

    session.get.return_value = mock_response
    session.post.return_value = mock_response
    session.put.return_value = mock_response
    session.delete.return_value = mock_response

    return session


@pytest.fixture
def temp_git_repo():
    """Create a temporary git repository for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_path = Path(temp_dir) / "test-repo"
        repo_path.mkdir()

        # Create some test files
        rules_dir = repo_path / "rules"
        rules_dir.mkdir()

        # Create a sample SIGMA rule
        sigma_file = rules_dir / "test_rule.yml"
        sigma_file.write_text("""
title: Test SIGMA Rule
id: 12345678-1234-5678-9012-123456789012
description: A test rule
author: Test Author
date: 2024/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
        Image|endswith: '\\test.exe'
    condition: selection
falsepositives:
    - Test scenarios
level: medium
""")

        yield repo_path


@pytest.fixture
def sample_sigma_rules():
    """Sample SIGMA rules for testing."""
    return [
        {
            "title": "Test Rule 1",
            "id": "11111111-1111-1111-1111-111111111111",
            "description": "First test rule",
            "author": "Test Author",
            "date": "2024/01/01",
            "logsource": {
                "category": "process_creation",
                "product": "windows"
            },
            "detection": {
                "selection": {
                    "EventID": 1,
                    "Image|endswith": "\\test1.exe"
                },
                "condition": "selection"
            },
            "falsepositives": ["Test scenarios"],
            "level": "medium"
        },
        {
            "title": "Test Rule 2",
            "id": "22222222-2222-2222-2222-222222222222",
            "description": "Second test rule",
            "author": "Test Author",
            "date": "2024/01/01",
            "logsource": {
                "category": "network_connection",
                "product": "windows"
            },
            "detection": {
                "selection": {
                    "EventID": 3,
                    "DestinationPort": 4444
                },
                "condition": "selection"
            },
            "falsepositives": ["Legitimate connections"],
            "level": "high"
        }
    ]


@pytest.fixture
def sample_detection_data():
    """Sample detection data for API calls."""
    return {
        "name": "Test Detection",
        "description": "A test detection rule",
        "rule_content": "sample rule content",
        "rule_format": "sigma",
        "author": "Test Author",
        "severity_id": "00000000-0000-0000-0000-000000000001",
        "platforms": ["Windows"],
        "data_sources": ["Process Creation"],
        "false_positives": ["Test scenarios"],
        "log_sources": ["product:windows | category:process_creation"]
    }


@pytest.fixture
def mock_celery_app():
    """Create a mock Celery app."""
    app = MagicMock()
    app.send_task.return_value = MagicMock(id="test-task-id")
    return app


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    redis_mock = AsyncMock()
    redis_mock.get.return_value = None
    redis_mock.set.return_value = True
    redis_mock.delete.return_value = 1
    redis_mock.exists.return_value = False
    return redis_mock


@pytest.fixture
def test_fixture_files() -> Dict[str, Path]:
    """Paths to test fixture files."""
    fixtures_dir = Path(__file__).parent / "fixtures"
    fixtures_dir.mkdir(exist_ok=True)

    # Create sample files if they don't exist
    sigma_file = fixtures_dir / "sample_sigma.yml"
    if not sigma_file.exists():
        sigma_file.write_text("""
title: Sample SIGMA Rule
id: 12345678-1234-5678-9012-123456789012
description: A sample rule for testing
author: Test Author
date: 2024/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
        Image|endswith: '\\sample.exe'
    condition: selection
falsepositives:
    - Test scenarios
level: medium
""")

    return {
        "sigma_rule": sigma_file,
    }


@pytest.fixture
def mock_git_operations(monkeypatch):
    """Mock git operations."""
    def mock_clone(url, path, **kwargs):
        # Create a fake repo structure
        repo_path = Path(path)
        repo_path.mkdir(parents=True, exist_ok=True)
        rules_dir = repo_path / "rules"
        rules_dir.mkdir(exist_ok=True)

        # Create a sample rule file
        sample_rule = rules_dir / "test.yml"
        sample_rule.write_text("""
title: Mock SIGMA Rule
id: 99999999-9999-9999-9999-999999999999
description: Mock rule for testing
author: Mock Author
date: 2024/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
        Image|endswith: '\\mock.exe'
    condition: selection
falsepositives:
    - Mock scenarios
level: medium
""")

        return MagicMock()

    monkeypatch.setattr("git.Repo.clone_from", mock_clone)


@pytest.fixture
async def authenticated_api_client(mock_api_client):
    """Create an authenticated API client."""
    mock_api_client.is_authenticated = True
    mock_api_client.access_token = "mock-access-token"
    return mock_api_client