"""
Unit tests for threat actor management system.
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.security import create_access_token
from src.db.models.user import User
from src.db.models.tenant import Tenant
from src.db.models.threat_actor import ThreatActor, Campaign, MalwareFamily
from src.schemas.threat_actor import ThreatActorCreate, ThreatActorUpdate, ThreatActorSearchRequest
from src.services.threat_actor_service import ThreatActorService


class TestThreatActorModel:
    """Test threat actor model and business logic."""

    def test_calculate_confidence_score(self):
        """Test threat actor confidence score calculation."""
        threat_actor = ThreatActor(
            id=uuid4(),
            tenant_id=uuid4(),
            name="Test Actor",
            actor_type="group",
            attribution_confidence=0.8,
            description="Test description",
            first_observed=datetime.utcnow(),
            last_observed=datetime.utcnow(),
            origin_country="USA",
            mitre_attack_id="G0001",
            references=["http://example.com/ref1", "http://example.com/ref2"],
            is_validated=True
        )

        confidence = threat_actor.calculate_confidence_score()

        # Should be high confidence due to good data completeness and validation
        assert 0.8 <= confidence <= 1.0
        assert isinstance(confidence, float)

    def test_calculate_confidence_score_minimal_data(self):
        """Test confidence calculation with minimal data."""
        threat_actor = ThreatActor(
            id=uuid4(),
            tenant_id=uuid4(),
            name="Minimal Actor",
            actor_type="unknown",
            attribution_confidence=0.3
        )

        confidence = threat_actor.calculate_confidence_score()

        # Should be lower confidence due to missing data
        assert 0.0 <= confidence <= 0.5
        assert isinstance(confidence, float)


class TestThreatActorService:
    """Test threat actor service operations."""

    @pytest.fixture
    async def test_tenant(self, db: AsyncSession) -> Tenant:
        """Create a test tenant."""
        tenant = Tenant(
            name="Test Organization",
            slug="test-org-actors",
            description="Test tenant for threat actor tests"
        )
        db.add(tenant)
        await db.commit()
        return tenant

    @pytest.fixture
    async def test_user(self, db: AsyncSession, test_tenant: Tenant) -> User:
        """Create a test user."""
        from src.core.security import get_password_hash
        user = User(
            tenant_id=test_tenant.id,
            email="analyst@threatactors.test",
            password_hash=get_password_hash("testpassword123"),
            first_name="Threat",
            last_name="Analyst",
            role="analyst",
            is_active=True,
            is_verified=True
        )
        db.add(user)
        await db.commit()
        return user

    async def test_create_threat_actor(self, db: AsyncSession, test_tenant: Tenant, test_user: User):
        """Test creating a new threat actor."""
        actor_data = ThreatActorCreate(
            name="FIN99",
            actor_type="group",
            attribution_confidence=0.85,
            sophistication_level="high",
            threat_level="medium",
            motivations=["financial"],
            origin_country="RUS",
            description="Test financial threat group"
        )

        threat_actor = await ThreatActorService.create_threat_actor(
            db=db,
            threat_actor_data=actor_data,
            tenant_id=test_tenant.id,
            user_id=test_user.id
        )

        assert threat_actor.name == "FIN99"
        assert threat_actor.actor_type == "group"
        assert threat_actor.tenant_id == test_tenant.id
        assert threat_actor.created_by == test_user.id
        assert 0.0 <= threat_actor.confidence_score <= 1.0
        assert 0.0 <= threat_actor.quality_score <= 1.0

    async def test_create_duplicate_threat_actor(self, db: AsyncSession, test_tenant: Tenant, test_user: User):
        """Test creating duplicate threat actor should fail."""
        actor_data = ThreatActorCreate(
            name="Duplicate Actor",
            actor_type="group",
            description="First actor"
        )

        # Create first actor
        await ThreatActorService.create_threat_actor(
            db=db,
            threat_actor_data=actor_data,
            tenant_id=test_tenant.id,
            user_id=test_user.id
        )

        # Try to create duplicate
        with pytest.raises(Exception):  # Should raise ValidationError
            await ThreatActorService.create_threat_actor(
                db=db,
                threat_actor_data=actor_data,
                tenant_id=test_tenant.id,
                user_id=test_user.id
            )

    async def test_get_threat_actor(self, db: AsyncSession, test_tenant: Tenant, test_user: User):
        """Test retrieving a threat actor."""
        # Create actor first
        actor_data = ThreatActorCreate(
            name="Get Test Actor",
            actor_type="individual",
            description="Actor for get test"
        )

        created_actor = await ThreatActorService.create_threat_actor(
            db=db,
            threat_actor_data=actor_data,
            tenant_id=test_tenant.id,
            user_id=test_user.id
        )

        # Retrieve actor
        retrieved_actor = await ThreatActorService.get_threat_actor(
            db=db,
            threat_actor_id=created_actor.id,
            tenant_id=test_tenant.id
        )

        assert retrieved_actor.id == created_actor.id
        assert retrieved_actor.name == "Get Test Actor"

    async def test_get_nonexistent_threat_actor(self, db: AsyncSession, test_tenant: Tenant):
        """Test retrieving non-existent threat actor should fail."""
        with pytest.raises(Exception):  # Should raise NotFoundError
            await ThreatActorService.get_threat_actor(
                db=db,
                threat_actor_id=uuid4(),
                tenant_id=test_tenant.id
            )

    async def test_update_threat_actor(self, db: AsyncSession, test_tenant: Tenant, test_user: User):
        """Test updating a threat actor."""
        # Create actor first
        actor_data = ThreatActorCreate(
            name="Update Test Actor",
            actor_type="group",
            threat_level="low"
        )

        created_actor = await ThreatActorService.create_threat_actor(
            db=db,
            threat_actor_data=actor_data,
            tenant_id=test_tenant.id,
            user_id=test_user.id
        )

        # Update actor
        update_data = ThreatActorUpdate(
            threat_level="high",
            description="Updated description",
            is_validated=True
        )

        updated_actor = await ThreatActorService.update_threat_actor(
            db=db,
            threat_actor_id=created_actor.id,
            threat_actor_data=update_data,
            tenant_id=test_tenant.id,
            user_id=test_user.id
        )

        assert updated_actor.threat_level == "high"
        assert updated_actor.description == "Updated description"
        assert updated_actor.is_validated is True
        assert updated_actor.updated_by == test_user.id

    async def test_delete_threat_actor(self, db: AsyncSession, test_tenant: Tenant, test_user: User):
        """Test deleting a threat actor."""
        # Create actor first
        actor_data = ThreatActorCreate(
            name="Delete Test Actor",
            actor_type="cluster"
        )

        created_actor = await ThreatActorService.create_threat_actor(
            db=db,
            threat_actor_data=actor_data,
            tenant_id=test_tenant.id,
            user_id=test_user.id
        )

        # Delete actor
        await ThreatActorService.delete_threat_actor(
            db=db,
            threat_actor_id=created_actor.id,
            tenant_id=test_tenant.id,
            user_id=test_user.id
        )

        # Try to retrieve deleted actor
        with pytest.raises(Exception):  # Should raise NotFoundError
            await ThreatActorService.get_threat_actor(
                db=db,
                threat_actor_id=created_actor.id,
                tenant_id=test_tenant.id
            )

    async def test_search_threat_actors(self, db: AsyncSession, test_tenant: Tenant, test_user: User):
        """Test searching threat actors with filters."""
        # Create multiple actors
        actors_data = [
            ThreatActorCreate(
                name="Search Actor 1",
                actor_type="group",
                threat_level="high",
                origin_country="RUS"
            ),
            ThreatActorCreate(
                name="Search Actor 2",
                actor_type="individual",
                threat_level="medium",
                origin_country="CHN"
            ),
            ThreatActorCreate(
                name="Different Actor",
                actor_type="group",
                threat_level="low",
                origin_country="USA"
            )
        ]

        for actor_data in actors_data:
            await ThreatActorService.create_threat_actor(
                db=db,
                threat_actor_data=actor_data,
                tenant_id=test_tenant.id,
                user_id=test_user.id
            )

        # Search with query
        search_params = ThreatActorSearchRequest(query="Search Actor")
        results, total = await ThreatActorService.search_threat_actors(
            db=db,
            search_params=search_params,
            tenant_id=test_tenant.id
        )

        assert total == 2
        assert len(results) == 2
        assert all("Search Actor" in actor.name for actor in results)

        # Search by actor type
        search_params = ThreatActorSearchRequest(actor_types=["group"])
        results, total = await ThreatActorService.search_threat_actors(
            db=db,
            search_params=search_params,
            tenant_id=test_tenant.id
        )

        assert total == 2
        assert all(actor.actor_type == "group" for actor in results)

        # Search by threat level
        search_params = ThreatActorSearchRequest(threat_levels=["high"])
        results, total = await ThreatActorService.search_threat_actors(
            db=db,
            search_params=search_params,
            tenant_id=test_tenant.id
        )

        assert total == 1
        assert results[0].threat_level == "high"

    async def test_get_threat_actor_statistics(self, db: AsyncSession, test_tenant: Tenant, test_user: User):
        """Test getting threat actor statistics."""
        # Create actors with different attributes
        actors_data = [
            ThreatActorCreate(name="Stats Actor 1", actor_type="group", threat_level="high", is_validated=True),
            ThreatActorCreate(name="Stats Actor 2", actor_type="individual", threat_level="medium", is_validated=False),
            ThreatActorCreate(name="Stats Actor 3", actor_type="group", threat_level="high", is_validated=True)
        ]

        for actor_data in actors_data:
            await ThreatActorService.create_threat_actor(
                db=db,
                threat_actor_data=actor_data,
                tenant_id=test_tenant.id,
                user_id=test_user.id
            )

        stats = await ThreatActorService.get_threat_actor_statistics(
            db=db,
            tenant_id=test_tenant.id
        )

        assert stats["total_actors"] == 3
        assert stats["by_type"]["group"] == 2
        assert stats["by_type"]["individual"] == 1
        assert stats["by_threat_level"]["high"] == 2
        assert stats["by_threat_level"]["medium"] == 1
        assert stats["validation_stats"]["validated"] == 2
        assert stats["validation_stats"]["unvalidated"] == 1
        assert isinstance(stats["average_confidence"], float)


class TestThreatActorEndpoints:
    """Test threat actor API endpoints."""

    @pytest.fixture
    async def test_tenant(self, db: AsyncSession) -> Tenant:
        """Create a test tenant."""
        tenant = Tenant(
            name="Test API Organization",
            slug="test-api-org",
            description="Test tenant for API tests"
        )
        db.add(tenant)
        await db.commit()
        return tenant

    @pytest.fixture
    async def test_user(self, db: AsyncSession, test_tenant: Tenant) -> User:
        """Create a test user."""
        from src.core.security import get_password_hash
        user = User(
            tenant_id=test_tenant.id,
            email="api@threatactors.test",
            password_hash=get_password_hash("testpassword123"),
            first_name="API",
            last_name="Tester",
            role="analyst",
            is_active=True,
            is_verified=True
        )
        db.add(user)
        await db.commit()
        return user

    def test_create_threat_actor_endpoint(self, client: TestClient, test_user: User):
        """Test POST /threat-actors endpoint."""
        token = create_access_token(
            subject=str(test_user.id),
            additional_claims={
                "tenant_id": str(test_user.tenant_id),
                "role": test_user.role,
                "email": test_user.email
            }
        )

        actor_data = {
            "name": "API Test Actor",
            "actor_type": "group",
            "attribution_confidence": 0.75,
            "description": "Test actor created via API"
        }

        response = client.post(
            "/api/v1/threat-actors/",
            json=actor_data,
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "API Test Actor"
        assert data["actor_type"] == "group"
        assert "id" in data
        assert "confidence_score" in data

    def test_get_threat_actors_list(self, client: TestClient, test_user: User):
        """Test GET /threat-actors endpoint."""
        token = create_access_token(
            subject=str(test_user.id),
            additional_claims={
                "tenant_id": str(test_user.tenant_id),
                "role": test_user.role,
                "email": test_user.email
            }
        )

        response = client.get(
            "/api/v1/threat-actors/",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert isinstance(data["items"], list)

    def test_search_threat_actors_endpoint(self, client: TestClient, test_user: User):
        """Test POST /threat-actors/search endpoint."""
        token = create_access_token(
            subject=str(test_user.id),
            additional_claims={
                "tenant_id": str(test_user.tenant_id),
                "role": test_user.role,
                "email": test_user.email
            }
        )

        search_data = {
            "query": "test",
            "actor_types": ["group"],
            "threat_levels": ["high", "medium"]
        }

        response = client.post(
            "/api/v1/threat-actors/search",
            json=search_data,
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data

    def test_get_threat_actor_statistics_endpoint(self, client: TestClient, test_user: User):
        """Test GET /threat-actors/statistics/dashboard endpoint."""
        token = create_access_token(
            subject=str(test_user.id),
            additional_claims={
                "tenant_id": str(test_user.tenant_id),
                "role": test_user.role,
                "email": test_user.email
            }
        )

        response = client.get(
            "/api/v1/threat-actors/statistics/dashboard",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "total_actors" in data
        assert "by_type" in data
        assert "by_threat_level" in data
        assert "average_confidence" in data
        assert "validation_stats" in data

    def test_unauthorized_access(self, client: TestClient):
        """Test that endpoints require authentication."""
        response = client.get("/api/v1/threat-actors/")
        assert response.status_code == 401

        response = client.post("/api/v1/threat-actors/", json={"name": "test"})
        assert response.status_code == 401


class TestConfidenceAlgorithms:
    """Test confidence scoring algorithms."""

    def test_temporal_decay_calculation(self):
        """Test temporal decay factor calculation."""
        from src.core.confidence import ConfidenceAlgorithms

        # Recent observation should have high confidence
        recent_date = datetime.utcnow() - timedelta(days=30)
        decay_factor = ConfidenceAlgorithms.calculate_temporal_decay(recent_date)
        assert 0.8 <= decay_factor <= 1.0

        # Old observation should have lower confidence
        old_date = datetime.utcnow() - timedelta(days=730)  # 2 years
        decay_factor = ConfidenceAlgorithms.calculate_temporal_decay(old_date)
        assert 0.0 <= decay_factor <= 0.5

    def test_attribution_confidence_calculation(self):
        """Test attribution confidence calculation."""
        from src.core.confidence import ConfidenceAlgorithms

        # High attribution confidence
        confidence = ConfidenceAlgorithms.calculate_attribution_confidence(
            technical_indicators=15,
            behavioral_patterns=10,
            infrastructure_overlap=8,
            timeline_correlation=0.9,
            witness_reports=5
        )
        assert 0.8 <= confidence <= 1.0

        # Low attribution confidence
        confidence = ConfidenceAlgorithms.calculate_attribution_confidence(
            technical_indicators=1,
            behavioral_patterns=1,
            infrastructure_overlap=0,
            timeline_correlation=0.2,
            witness_reports=0
        )
        assert 0.0 <= confidence <= 0.3

    def test_composite_confidence_calculation(self):
        """Test composite confidence calculation."""
        from src.core.confidence import ConfidenceAlgorithms

        scores = [0.8, 0.6, 0.9, 0.7]
        weights = [0.4, 0.3, 0.2, 0.1]

        composite = ConfidenceAlgorithms.calculate_composite_confidence(scores, weights)
        assert 0.0 <= composite <= 1.0

        # Test equal weighting
        composite_equal = ConfidenceAlgorithms.calculate_composite_confidence(scores)
        assert 0.0 <= composite_equal <= 1.0

    def test_confidence_level_description(self):
        """Test confidence level descriptions."""
        from src.core.confidence import ConfidenceAlgorithms

        assert ConfidenceAlgorithms.get_confidence_level_description(0.95) == "Very High"
        assert ConfidenceAlgorithms.get_confidence_level_description(0.75) == "High"
        assert ConfidenceAlgorithms.get_confidence_level_description(0.55) == "Medium"
        assert ConfidenceAlgorithms.get_confidence_level_description(0.35) == "Low"
        assert ConfidenceAlgorithms.get_confidence_level_description(0.15) == "Very Low"