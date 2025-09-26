"""
Pytest configuration and fixtures for Countermeasure API tests.
"""

import asyncio
import os
import tempfile
from collections.abc import AsyncGenerator, Generator
from pathlib import Path
from typing import Dict, Any

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from src.main import app
from src.db.session import get_db
from src.db.models.base import Base
from tests.factories import (
    UserFactory, TenantFactory, DetectionFactory, SeverityFactory,
    CategoryFactory, TagFactory, ActorFactory, MitreTacticFactory, MitreTechniqueFactory
)


# Test database URL - Use SQLite for speed
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

# Set environment variable for JSON type detection
os.environ["DATABASE_URL"] = TEST_DATABASE_URL


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a database session for testing."""
    async_session_local = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )

    async with async_session_local() as session:
        # Setup factories to use this session
        UserFactory._meta.sqlalchemy_session = session
        TenantFactory._meta.sqlalchemy_session = session
        DetectionFactory._meta.sqlalchemy_session = session
        SeverityFactory._meta.sqlalchemy_session = session
        CategoryFactory._meta.sqlalchemy_session = session
        TagFactory._meta.sqlalchemy_session = session
        ActorFactory._meta.sqlalchemy_session = session

        yield session

        # Rollback any uncommitted changes
        await session.rollback()


@pytest.fixture
def client(db_session) -> TestClient:
    """Create a test client for the FastAPI app."""

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def async_client(db_session) -> AsyncGenerator[AsyncClient, None]:
    """Create an async test client for the FastAPI app."""

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    try:
        async with AsyncClient(app=app, base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def sample_correlation_id() -> str:
    """Sample correlation ID for testing."""
    return "test-correlation-id-12345"


@pytest.fixture
async def test_tenant(db_session: AsyncSession):
    """Create a test tenant."""
    tenant = TenantFactory()
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)
    return tenant


@pytest.fixture
async def test_user(db_session: AsyncSession, test_tenant):
    """Create a test user."""
    user = UserFactory(tenant=test_tenant)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def admin_user(db_session: AsyncSession, test_tenant):
    """Create an admin test user."""
    from tests.factories.user_factory import AdminUserFactory
    user = AdminUserFactory(tenant=test_tenant)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def test_severity(db_session: AsyncSession, test_tenant):
    """Create a test severity."""
    severity = SeverityFactory(tenant=test_tenant)
    db_session.add(severity)
    await db_session.commit()
    await db_session.refresh(severity)
    return severity


@pytest.fixture
async def test_detection(db_session: AsyncSession, test_tenant, test_severity):
    """Create a test detection."""
    detection = DetectionFactory(tenant=test_tenant, severity=test_severity)
    db_session.add(detection)
    await db_session.commit()
    await db_session.refresh(detection)
    return detection


@pytest.fixture
def sample_sigma_rule() -> str:
    """Sample SIGMA rule content for testing."""
    return """
title: Test SIGMA Rule
id: 12345678-1234-5678-9012-123456789012
description: A test rule for unit testing
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
"""


@pytest.fixture
def sample_yara_rule() -> str:
    """Sample YARA rule content for testing."""
    return """
rule TestRule
{
    meta:
        description = "Test YARA rule"
        author = "Test Author"
        date = "2024-01-01"

    strings:
        $test_string = "test" ascii
        $hex_pattern = { 48 65 6C 6C 6F }

    condition:
        any of them
}
"""


@pytest.fixture
def sample_jwt_token() -> str:
    """Sample JWT token for testing."""
    return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImFkbWluIjp0cnVlfQ.test"


@pytest.fixture
def test_file_fixtures() -> Dict[str, Path]:
    """Paths to test fixture files."""
    fixtures_dir = Path(__file__).parent / "fixtures"
    return {
        "sigma_rules": fixtures_dir / "sigma_rules.yaml",
        "yara_rules": fixtures_dir / "yara_rules.yar",
        "suricata_rules": fixtures_dir / "suricata_rules.rules",
        "mitre_data": fixtures_dir / "mitre_data.json",
    }


@pytest.fixture
def mock_redis(monkeypatch):
    """Mock Redis for testing."""
    class MockRedis:
        def __init__(self):
            self._data = {}

        async def get(self, key):
            return self._data.get(key)

        async def set(self, key, value, ex=None):
            self._data[key] = value

        async def delete(self, key):
            self._data.pop(key, None)

        async def exists(self, key):
            return key in self._data

    mock_redis = MockRedis()
    monkeypatch.setattr("src.core.cache.redis_client", mock_redis)
    return mock_redis