"""
Base factory configuration for all model factories.
"""

import factory
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.session import get_db


class BaseFactory(factory.alchemy.SQLAlchemyModelFactory):
    """Base factory with async session support."""

    class Meta:
        abstract = True
        sqlalchemy_session_persistence = "commit"

    @classmethod
    def _setup_next_sequence(cls):
        """Setup the next sequence number."""
        return 1

    @classmethod
    async def create_async(cls, **kwargs):
        """Create model instance asynchronously."""
        async for session in get_db():
            cls._meta.sqlalchemy_session = session
            instance = cls.create(**kwargs)
            await session.commit()
            await session.refresh(instance)
            return instance

    @classmethod
    async def create_batch_async(cls, size, **kwargs):
        """Create multiple model instances asynchronously."""
        async for session in get_db():
            cls._meta.sqlalchemy_session = session
            instances = cls.create_batch(size, **kwargs)
            await session.commit()
            for instance in instances:
                await session.refresh(instance)
            return instances