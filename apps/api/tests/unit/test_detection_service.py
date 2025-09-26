"""
Unit tests for DetectionService.
"""

import pytest
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from src.services.detection_service import DetectionService
from src.core.exceptions import (
    ResourceNotFoundError,
    ValidationError,
)
from src.schemas.detection import (
    DetectionCreate,
    DetectionUpdate,
    DetectionSearchRequest,
    CategoryCreate,
    TagCreate,
)
from tests.factories import (
    DetectionFactory,
    SeverityFactory,
    CategoryFactory,
    TagFactory,
    TenantFactory,
    UserFactory,
)


class TestDetectionService:
    """Test suite for DetectionService."""

    @pytest.mark.asyncio
    async def test_create_detection_success(
        self, db_session: AsyncSession, test_tenant, test_user, test_severity
    ):
        """Test successful detection creation."""
        detection_data = DetectionCreate(
            name="Test Detection",
            description="A test detection rule",
            rule_content="valid rule content",
            rule_format="sigma",
            severity_id=test_severity.id,
            author="Test Author",
            platforms=["Windows"],
            data_sources=["Process Creation"],
            false_positives=["Test scenarios"],
            log_sources=["sysmon"]
        )

        with patch("src.core.rule_confidence.validate_rule_format") as mock_validate:
            mock_validate.return_value = (True, [])
            with patch("src.core.rule_confidence.calculate_rule_content_quality") as mock_confidence:
                mock_confidence.return_value = 0.85

                detection = await DetectionService.create_detection(
                    db_session, detection_data, test_tenant.id, test_user.id
                )

                assert detection.name == "Test Detection"
                assert detection.description == "A test detection rule"
                assert detection.rule_content == "valid rule content"
                assert detection.rule_format == "sigma"
                assert detection.severity_id == test_severity.id
                assert detection.tenant_id == test_tenant.id
                assert detection.created_by == test_user.id
                assert detection.confidence_score == 0.85

    @pytest.mark.asyncio
    async def test_create_detection_invalid_rule(
        self, db_session: AsyncSession, test_tenant, test_user, test_severity
    ):
        """Test detection creation with invalid rule content."""
        detection_data = DetectionCreate(
            name="Invalid Detection",
            description="A detection with invalid rule",
            rule_content="invalid rule content",
            rule_format="sigma",
            severity_id=test_severity.id,
            author="Test Author"
        )

        with patch("src.core.rule_confidence.validate_rule_format") as mock_validate:
            mock_validate.return_value = (False, ["Syntax error in rule"])

            with pytest.raises(ValidationError, match="Detection validation failed"):
                await DetectionService.create_detection(
                    db_session, detection_data, test_tenant.id, test_user.id
                )

    @pytest.mark.asyncio
    async def test_create_detection_duplicate_name(
        self, db_session: AsyncSession, test_tenant, test_user, test_severity
    ):
        """Test detection creation with duplicate name."""
        # Create existing detection
        existing_detection = DetectionFactory(tenant=test_tenant, name="Duplicate Name")
        db_session.add(existing_detection)
        await db_session.commit()

        detection_data = DetectionCreate(
            name="Duplicate Name",
            description="Another detection",
            rule_content="valid rule content",
            rule_format="sigma",
            severity_id=test_severity.id,
            author="Test Author"
        )

        with patch("src.core.rule_confidence.validate_rule_format") as mock_validate:
            mock_validate.return_value = (True, [])

            with pytest.raises(ValidationError, match="Detection with name 'Duplicate Name' already exists"):
                await DetectionService.create_detection(
                    db_session, detection_data, test_tenant.id, test_user.id
                )

    @pytest.mark.asyncio
    async def test_create_detection_invalid_severity(
        self, db_session: AsyncSession, test_tenant, test_user
    ):
        """Test detection creation with invalid severity."""
        detection_data = DetectionCreate(
            name="Test Detection",
            description="A test detection",
            rule_content="valid rule content",
            rule_format="sigma",
            severity_id=uuid4(),  # Non-existent severity
            author="Test Author"
        )

        with patch("src.core.rule_confidence.validate_rule_format") as mock_validate:
            mock_validate.return_value = (True, [])

            with pytest.raises(ValidationError, match="Severity with ID .* not found"):
                await DetectionService.create_detection(
                    db_session, detection_data, test_tenant.id, test_user.id
                )

    @pytest.mark.asyncio
    async def test_get_detection_success(
        self, db_session: AsyncSession, test_detection
    ):
        """Test successful detection retrieval."""
        result = await DetectionService.get_detection(
            db_session, test_detection.id, test_detection.tenant_id
        )

        assert result.id == test_detection.id
        assert result.name == test_detection.name
        assert result.severity is not None

    @pytest.mark.asyncio
    async def test_get_detection_not_found(
        self, db_session: AsyncSession, test_tenant
    ):
        """Test detection retrieval with non-existent ID."""
        with pytest.raises(ResourceNotFoundError, match="Detection with ID .* not found"):
            await DetectionService.get_detection(
                db_session, uuid4(), test_tenant.id
            )

    @pytest.mark.asyncio
    async def test_get_detection_wrong_tenant(
        self, db_session: AsyncSession, test_detection
    ):
        """Test detection retrieval with wrong tenant."""
        wrong_tenant = TenantFactory()
        db_session.add(wrong_tenant)
        await db_session.commit()

        with pytest.raises(ResourceNotFoundError):
            await DetectionService.get_detection(
                db_session, test_detection.id, wrong_tenant.id
            )

    @pytest.mark.asyncio
    async def test_update_detection_success(
        self, db_session: AsyncSession, test_detection, test_user
    ):
        """Test successful detection update."""
        update_data = DetectionUpdate(
            name="Updated Detection",
            description="Updated description",
            status="active"
        )

        updated_detection = await DetectionService.update_detection(
            db_session, test_detection.id, update_data, test_detection.tenant_id, test_user.id
        )

        assert updated_detection.name == "Updated Detection"
        assert updated_detection.description == "Updated description"
        assert updated_detection.status == "active"
        assert updated_detection.updated_by == test_user.id

    @pytest.mark.asyncio
    async def test_update_detection_with_rule_content(
        self, db_session: AsyncSession, test_detection, test_user
    ):
        """Test detection update with rule content."""
        update_data = DetectionUpdate(
            rule_content="updated rule content",
            rule_format="sigma"
        )

        with patch("src.core.rule_confidence.validate_rule_format") as mock_validate:
            mock_validate.return_value = (True, [])
            with patch("src.core.rule_confidence.calculate_rule_content_quality") as mock_confidence:
                mock_confidence.return_value = 0.90

                updated_detection = await DetectionService.update_detection(
                    db_session, test_detection.id, update_data, test_detection.tenant_id, test_user.id
                )

                assert updated_detection.rule_content == "updated rule content"
                assert updated_detection.confidence_score == 0.90

    @pytest.mark.asyncio
    async def test_update_detection_invalid_rule_content(
        self, db_session: AsyncSession, test_detection, test_user
    ):
        """Test detection update with invalid rule content."""
        update_data = DetectionUpdate(
            rule_content="invalid rule content",
            rule_format="sigma"
        )

        with patch("src.core.rule_confidence.validate_rule_format") as mock_validate:
            mock_validate.return_value = (False, ["Invalid syntax"])

            with pytest.raises(ValidationError, match="Detection validation failed"):
                await DetectionService.update_detection(
                    db_session, test_detection.id, update_data, test_detection.tenant_id, test_user.id
                )

    @pytest.mark.asyncio
    async def test_delete_detection_success(
        self, db_session: AsyncSession, test_detection
    ):
        """Test successful detection deletion."""
        await DetectionService.delete_detection(
            db_session, test_detection.id, test_detection.tenant_id
        )

        # Verify deletion
        with pytest.raises(ResourceNotFoundError):
            await DetectionService.get_detection(
                db_session, test_detection.id, test_detection.tenant_id
            )

    @pytest.mark.asyncio
    async def test_delete_detection_not_found(
        self, db_session: AsyncSession, test_tenant
    ):
        """Test deletion of non-existent detection."""
        with pytest.raises(ResourceNotFoundError):
            await DetectionService.delete_detection(
                db_session, uuid4(), test_tenant.id
            )

    @pytest.mark.asyncio
    async def test_search_detections_no_filters(
        self, db_session: AsyncSession, test_tenant
    ):
        """Test detection search without filters."""
        # Create multiple detections
        detections = [
            DetectionFactory(tenant=test_tenant, name=f"Detection {i}")
            for i in range(5)
        ]
        db_session.add_all(detections)
        await db_session.commit()

        search_request = DetectionSearchRequest()
        results, total = await DetectionService.search_detections(
            db_session, search_request, test_tenant.id
        )

        assert len(results) == 5
        assert total == 5

    @pytest.mark.asyncio
    async def test_search_detections_name_filter(
        self, db_session: AsyncSession, test_tenant
    ):
        """Test detection search with name filter."""
        detections = [
            DetectionFactory(tenant=test_tenant, name="PowerShell Detection"),
            DetectionFactory(tenant=test_tenant, name="Network Detection"),
            DetectionFactory(tenant=test_tenant, name="File Detection"),
        ]
        db_session.add_all(detections)
        await db_session.commit()

        search_request = DetectionSearchRequest(name="PowerShell")
        results, total = await DetectionService.search_detections(
            db_session, search_request, test_tenant.id
        )

        assert len(results) == 1
        assert total == 1
        assert "PowerShell" in results[0].name

    @pytest.mark.asyncio
    async def test_search_detections_status_filter(
        self, db_session: AsyncSession, test_tenant
    ):
        """Test detection search with status filter."""
        detections = [
            DetectionFactory(tenant=test_tenant, status="active"),
            DetectionFactory(tenant=test_tenant, status="draft"),
            DetectionFactory(tenant=test_tenant, status="active"),
        ]
        db_session.add_all(detections)
        await db_session.commit()

        search_request = DetectionSearchRequest(status="active")
        results, total = await DetectionService.search_detections(
            db_session, search_request, test_tenant.id
        )

        assert len(results) == 2
        assert total == 2
        assert all(r.status == "active" for r in results)

    @pytest.mark.asyncio
    async def test_search_detections_confidence_filter(
        self, db_session: AsyncSession, test_tenant
    ):
        """Test detection search with confidence score filter."""
        detections = [
            DetectionFactory(tenant=test_tenant, confidence_score=0.9),
            DetectionFactory(tenant=test_tenant, confidence_score=0.5),
            DetectionFactory(tenant=test_tenant, confidence_score=0.8),
        ]
        db_session.add_all(detections)
        await db_session.commit()

        search_request = DetectionSearchRequest(confidence_min=0.7)
        results, total = await DetectionService.search_detections(
            db_session, search_request, test_tenant.id
        )

        assert len(results) == 2
        assert total == 2
        assert all(r.confidence_score >= 0.7 for r in results)

    @pytest.mark.asyncio
    async def test_search_detections_pagination(
        self, db_session: AsyncSession, test_tenant
    ):
        """Test detection search with pagination."""
        # Create 10 detections
        detections = [
            DetectionFactory(tenant=test_tenant, name=f"Detection {i:02d}")
            for i in range(10)
        ]
        db_session.add_all(detections)
        await db_session.commit()

        search_request = DetectionSearchRequest()
        results, total = await DetectionService.search_detections(
            db_session, search_request, test_tenant.id, page=1, per_page=3
        )

        assert len(results) == 3
        assert total == 10

        # Test second page
        results_page2, _ = await DetectionService.search_detections(
            db_session, search_request, test_tenant.id, page=2, per_page=3
        )

        assert len(results_page2) == 3
        # Verify different results
        page1_ids = {r.id for r in results}
        page2_ids = {r.id for r in results_page2}
        assert page1_ids.isdisjoint(page2_ids)

    @pytest.mark.asyncio
    async def test_validate_detection_content(self):
        """Test detection content validation."""
        with patch("src.core.rule_confidence.validate_rule_format") as mock_validate:
            mock_validate.return_value = (True, [])
            with patch("src.core.rule_confidence.calculate_rule_content_quality") as mock_confidence:
                mock_confidence.return_value = 0.85

                result = await DetectionService.validate_detection_content(
                    "valid rule content", "sigma"
                )

                assert result["is_valid"] is True
                assert result["syntax_errors"] == []
                assert result["confidence_score"] == 0.85

    @pytest.mark.asyncio
    async def test_validate_detection_content_invalid(self):
        """Test detection content validation with invalid content."""
        with patch("src.core.rule_confidence.validate_rule_format") as mock_validate:
            mock_validate.return_value = (False, ["Syntax error"])
            with patch("src.core.rule_confidence.calculate_rule_content_quality") as mock_confidence:
                mock_confidence.return_value = 0.2

                result = await DetectionService.validate_detection_content(
                    "invalid rule content", "sigma"
                )

                assert result["is_valid"] is False
                assert result["syntax_errors"] == ["Syntax error"]
                assert result["confidence_score"] == 0.2

    @pytest.mark.asyncio
    async def test_create_category_success(
        self, db_session: AsyncSession, test_tenant
    ):
        """Test successful category creation."""
        category_data = CategoryCreate(
            name="Test Category",
            description="A test category",
            color="#ff0000",
            icon="shield"
        )

        category = await DetectionService.create_category(
            db_session, category_data, test_tenant.id
        )

        assert category.name == "Test Category"
        assert category.description == "A test category"
        assert category.tenant_id == test_tenant.id
        assert category.level == 0
        assert category.path == "/test-category"

    @pytest.mark.asyncio
    async def test_create_category_with_parent(
        self, db_session: AsyncSession, test_tenant
    ):
        """Test category creation with parent."""
        # Create parent category
        parent_category = CategoryFactory(tenant=test_tenant, name="Parent", level=0, path="/parent")
        db_session.add(parent_category)
        await db_session.commit()

        category_data = CategoryCreate(
            name="Child Category",
            description="A child category",
            parent_id=parent_category.id,
            color="#00ff00",
            icon="shield"
        )

        category = await DetectionService.create_category(
            db_session, category_data, test_tenant.id
        )

        assert category.name == "Child Category"
        assert category.parent_id == parent_category.id
        assert category.level == 1
        assert category.path == "/parent/child-category"

    @pytest.mark.asyncio
    async def test_create_category_invalid_parent(
        self, db_session: AsyncSession, test_tenant
    ):
        """Test category creation with invalid parent."""
        category_data = CategoryCreate(
            name="Test Category",
            description="A test category",
            parent_id=uuid4(),  # Non-existent parent
            color="#ff0000",
            icon="shield"
        )

        with pytest.raises(ValidationError, match="Invalid parent category"):
            await DetectionService.create_category(
                db_session, category_data, test_tenant.id
            )

    @pytest.mark.asyncio
    async def test_create_tag_success(
        self, db_session: AsyncSession, test_tenant
    ):
        """Test successful tag creation."""
        tag_data = TagCreate(
            name="test-tag",
            description="A test tag",
            color="#0000ff"
        )

        tag = await DetectionService.create_tag(
            db_session, tag_data, test_tenant.id
        )

        assert tag.name == "test-tag"
        assert tag.description == "A test tag"
        assert tag.tenant_id == test_tenant.id

    @pytest.mark.asyncio
    async def test_create_tag_duplicate_name(
        self, db_session: AsyncSession, test_tenant
    ):
        """Test tag creation with duplicate name."""
        # Create existing tag
        existing_tag = TagFactory(tenant=test_tenant, name="duplicate-tag")
        db_session.add(existing_tag)
        await db_session.commit()

        tag_data = TagCreate(
            name="duplicate-tag",
            description="Another tag",
            color="#0000ff"
        )

        with pytest.raises(ValidationError, match="Tag with name 'duplicate-tag' already exists"):
            await DetectionService.create_tag(
                db_session, tag_data, test_tenant.id
            )