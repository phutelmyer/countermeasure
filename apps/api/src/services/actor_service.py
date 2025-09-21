"""
Business logic service for actor management.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.exceptions import ValidationError, ResourceNotFoundError
from src.core.logging import get_logger
from src.db.models import Actor, Campaign, Malware
from src.schemas.actor import (
    ActorCreate, ActorUpdate, ActorSearchRequest,
    CampaignCreate, CampaignUpdate,
    MalwareCreate, MalwareUpdate
)

logger = get_logger(__name__)


class ActorService:
    """Service for actor management and business logic."""

    @staticmethod
    async def create_actor(
        db: AsyncSession,
        actor_data: ActorCreate,
        tenant_id: UUID,
        user_id: UUID
    ) -> Actor:
        """
        Create a new actor.

        Args:
            db: Database session
            actor_data: Actor creation data
            tenant_id: Current tenant ID
            user_id: Current user ID

        Returns:
            Actor: Created actor

        Raises:
            ValidationError: If validation fails
        """
        # Check for duplicate names within tenant
        existing = await db.execute(
            select(Actor).where(
                and_(
                    Actor.tenant_id == tenant_id,
                    Actor.name == actor_data.name
                )
            )
        )
        if existing.scalar_one_or_none():
            raise ValidationError(f"Actor with name '{actor_data.name}' already exists")

        # Create actor
        actor_dict = actor_data.model_dump()
        actor = Actor(
            **actor_dict,
            tenant_id=tenant_id,
            created_by=user_id,
            updated_by=user_id
        )

        # Calculate confidence score
        actor.confidence_score = actor.calculate_confidence_score()

        db.add(actor)
        await db.commit()

        logger.info("actor_created", actor_id=str(actor.id), name=actor.name, tenant_id=str(tenant_id))
        return actor

    @staticmethod
    async def get_actor(
        db: AsyncSession,
        actor_id: UUID,
        tenant_id: UUID
    ) -> Actor:
        """
        Get actor by ID.

        Args:
            db: Database session
            actor_id: Actor ID
            tenant_id: Current tenant ID

        Returns:
            Actor: The actor

        Raises:
            ResourceNotFoundError: If actor not found
        """
        result = await db.execute(
            select(Actor)
            .options(
                selectinload(Actor.campaigns),
                selectinload(Actor.malware_families)
            )
            .where(
                and_(
                    Actor.id == actor_id,
                    Actor.tenant_id == tenant_id
                )
            )
        )
        actor = result.scalar_one_or_none()
        if not actor:
            raise ResourceNotFoundError(f"Actor with ID {actor_id} not found")

        return actor

    @staticmethod
    async def update_actor(
        db: AsyncSession,
        actor_id: UUID,
        actor_data: ActorUpdate,
        tenant_id: UUID,
        user_id: UUID
    ) -> Actor:
        """
        Update actor.

        Args:
            db: Database session
            actor_id: Actor ID
            actor_data: Actor update data
            tenant_id: Current tenant ID
            user_id: Current user ID

        Returns:
            Actor: Updated actor

        Raises:
            ResourceNotFoundError: If actor not found
            ValidationError: If validation fails
        """
        actor = await ActorService.get_actor(db, actor_id, tenant_id)

        # Check for name conflicts if name is being updated
        if actor_data.name and actor_data.name != actor.name:
            existing = await db.execute(
                select(Actor).where(
                    and_(
                        Actor.tenant_id == tenant_id,
                        Actor.name == actor_data.name,
                        Actor.id != actor_id
                    )
                )
            )
            if existing.scalar_one_or_none():
                raise ValidationError(f"Actor with name '{actor_data.name}' already exists")

        # Update fields
        update_data = actor_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(actor, field, value)

        actor.updated_by = user_id

        # Recalculate confidence score
        actor.confidence_score = actor.calculate_confidence_score()

        await db.commit()

        logger.info("actor_updated", actor_id=str(actor.id), name=actor.name, tenant_id=str(tenant_id))
        return actor

    @staticmethod
    async def delete_actor(
        db: AsyncSession,
        actor_id: UUID,
        tenant_id: UUID
    ) -> None:
        """
        Delete actor.

        Args:
            db: Database session
            actor_id: Actor ID
            tenant_id: Current tenant ID

        Raises:
            ResourceNotFoundError: If actor not found
        """
        actor = await ActorService.get_actor(db, actor_id, tenant_id)
        await db.delete(actor)
        await db.commit()

        logger.info("actor_deleted", actor_id=str(actor_id), name=actor.name, tenant_id=str(tenant_id))

    @staticmethod
    async def search_actors(
        db: AsyncSession,
        search_request: ActorSearchRequest,
        tenant_id: UUID,
        page: int = 1,
        per_page: int = 50
    ) -> tuple[List[Actor], int]:
        """
        Search actors with advanced filtering.

        Args:
            db: Database session
            search_request: Search criteria
            tenant_id: Current tenant ID
            page: Page number
            per_page: Items per page

        Returns:
            tuple[List[Actor], int]: (actors, total_count)
        """
        query = select(Actor).where(Actor.tenant_id == tenant_id)

        # Apply text search filters
        if search_request.query:
            search_term = f"%{search_request.query}%"
            query = query.where(
                or_(
                    Actor.name.ilike(search_term),
                    Actor.description.ilike(search_term),
                    Actor.summary.ilike(search_term)
                )
            )

        # Apply categorical filters
        if search_request.actor_types:
            query = query.where(Actor.actor_type.in_(search_request.actor_types))

        if search_request.threat_levels:
            query = query.where(Actor.threat_level.in_(search_request.threat_levels))

        if search_request.sophistication_levels:
            query = query.where(Actor.sophistication_level.in_(search_request.sophistication_levels))

        if search_request.statuses:
            query = query.where(Actor.status.in_(search_request.statuses))

        if search_request.origin_countries:
            query = query.where(Actor.origin_country.in_(search_request.origin_countries))

        if search_request.target_sectors:
            # Use overlap operator for array fields
            query = query.where(Actor.target_sectors.op("&&")(search_request.target_sectors))

        if search_request.motivations:
            query = query.where(Actor.motivations.op("&&")(search_request.motivations))

        # Apply confidence range filters
        if search_request.min_confidence is not None:
            query = query.where(Actor.confidence_score >= search_request.min_confidence)

        if search_request.max_confidence is not None:
            query = query.where(Actor.confidence_score <= search_request.max_confidence)

        # Apply validation filter
        if search_request.is_validated is not None:
            query = query.where(Actor.is_validated == search_request.is_validated)

        # Apply date filters
        if search_request.created_after:
            query = query.where(Actor.created_at >= search_request.created_after)

        if search_request.created_before:
            query = query.where(Actor.created_at <= search_request.created_before)

        if search_request.updated_after:
            query = query.where(Actor.updated_at >= search_request.updated_after)

        if search_request.updated_before:
            query = query.where(Actor.updated_at <= search_request.updated_before)

        # Apply tag filter
        if search_request.tags:
            query = query.where(Actor.tags.op("&&")(search_request.tags))

        # Get total count before pagination
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        # Apply pagination and ordering
        offset = (page - 1) * per_page
        query = query.order_by(Actor.confidence_score.desc(), Actor.updated_at.desc())
        query = query.offset(offset).limit(per_page)

        # Execute query
        result = await db.execute(query)
        actors = result.scalars().all()

        logger.info("actors_searched", total=total, returned=len(actors), tenant_id=str(tenant_id))
        return list(actors), total

    @staticmethod
    async def list_actors(
        db: AsyncSession,
        tenant_id: UUID,
        page: int = 1,
        per_page: int = 50,
        include_related: bool = False
    ) -> tuple[List[Actor], int]:
        """
        List actors with pagination.

        Args:
            db: Database session
            tenant_id: Current tenant ID
            page: Page number
            per_page: Items per page
            include_related: Whether to include related entities

        Returns:
            tuple[List[Actor], int]: (actors, total_count)
        """
        query = select(Actor).where(Actor.tenant_id == tenant_id)

        if include_related:
            query = query.options(
                selectinload(Actor.campaigns),
                selectinload(Actor.malware_families)
            )

        # Get total count
        count_query = select(func.count()).select_from(Actor).where(Actor.tenant_id == tenant_id)
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        # Apply pagination and ordering
        offset = (page - 1) * per_page
        query = query.order_by(Actor.confidence_score.desc(), Actor.updated_at.desc())
        query = query.offset(offset).limit(per_page)

        # Execute query
        result = await db.execute(query)
        actors = result.scalars().all()

        return list(actors), total