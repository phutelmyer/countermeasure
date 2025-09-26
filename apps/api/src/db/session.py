"""
Database session configuration and connection management.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from src.core.config import settings
from src.core.logging import get_logger


logger = get_logger(__name__)

# Create async engine
engine = create_async_engine(
    settings.get_database_url(async_driver=True),
    echo=settings.database_echo,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    poolclass=NullPool if settings.is_testing else None,
    future=True,
)

# Create session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency to get database session.

    Yields:
        AsyncSession: Database session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager for database session.

    Yields:
        AsyncSession: Database session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def run_migrations():
    """Run Alembic migrations to upgrade database schema."""
    import subprocess
    from pathlib import Path

    # Get the API directory (where alembic.ini is located)
    api_dir = Path(__file__).parent.parent.parent

    try:
        # Run alembic upgrade head
        result = subprocess.run(
            ["uv", "run", "alembic", "upgrade", "head"],
            cwd=api_dir,
            capture_output=True,
            text=True,
            check=True,
        )
        logger.info("database_migrations_completed", output=result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error(
            "database_migrations_failed", error=e.stderr, returncode=e.returncode
        )
        raise RuntimeError(f"Database migration failed: {e.stderr}")


async def create_all_tables():
    """Create all database tables using migrations (legacy wrapper)."""
    logger.warning("create_all_tables is deprecated, use run_migrations() instead")
    await run_migrations()


async def drop_all_tables():
    """Drop all database tables (for testing)."""
    from src.db.models.base import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    logger.info("database_tables_dropped")


async def close_db_connections():
    """Close all database connections."""
    await engine.dispose()
    logger.info("database_connections_closed")
