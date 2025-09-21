"""
Database initialization script.
Creates tables and default tenant for easy onboarding.
"""

import asyncio
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.logging import get_logger
from src.core.security import get_password_hash
from src.db.models.system import Tenant, User
from src.db.session import get_db_context, run_migrations

logger = get_logger(__name__)


async def create_default_tenant() -> Tenant:
    """
    Create default tenant for easy onboarding.

    Returns:
        Tenant: Created or existing default tenant
    """
    async with get_db_context() as db:
        # Check if default tenant already exists
        result = await db.execute(
            select(Tenant).where(Tenant.slug == settings.default_tenant_slug)
        )
        existing_tenant = result.scalar_one_or_none()

        if existing_tenant:
            logger.info("default_tenant_exists", tenant_id=str(existing_tenant.id))
            return existing_tenant

        # Create default tenant
        tenant = Tenant(
            name="Default Organization",
            slug=settings.default_tenant_slug,
            description="Default organization for easy onboarding",
            settings={
                "theme": "dark",
                "timezone": "UTC",
                "max_file_size_mb": 50,
                "welcome_message": "Welcome to Countermeasure - your threat detection confidence platform!"
            },
            max_users=1000,  # Higher limit for default tenant
            max_storage_gb=100,
            is_active=True
        )

        db.add(tenant)
        await db.commit()

        logger.info("default_tenant_created", tenant_id=str(tenant.id), slug=tenant.slug)
        return tenant


async def create_default_admin(tenant: Tenant) -> Optional[User]:
    """
    Create default admin user if none exists.

    Args:
        tenant: Default tenant

    Returns:
        User: Created admin user or None if admin already exists
    """
    async with get_db_context() as db:
        # Check if any admin users exist in the tenant
        result = await db.execute(
            select(User).where(
                User.tenant_id == tenant.id,
                User.role == "admin",
                User.is_active == True
            )
        )
        existing_admin = result.scalars().first()

        if existing_admin:
            logger.info("default_admin_exists", user_id=str(existing_admin.id))
            return None

        # Create default admin user
        admin_email = "admin@countermeasure.dev"
        admin_password = "CountermeasureAdmin123!"

        admin_user = User(
            tenant_id=tenant.id,
            email=admin_email,
            password_hash=get_password_hash(admin_password),
            first_name="Admin",
            last_name="User",
            role="admin",
            is_active=True,
            is_verified=True,  # Pre-verified for convenience
            settings={
                "theme": "dark",
                "notifications_enabled": True,
                "tutorial_completed": False
            }
        )

        db.add(admin_user)
        await db.commit()

        logger.info(
            "default_admin_created",
            user_id=str(admin_user.id),
            email=admin_email,
            tenant_id=str(tenant.id)
        )

        return admin_user


async def seed_demo_data(tenant: Tenant) -> None:
    """
    Seed some demo data for easier testing and onboarding.

    Args:
        tenant: Default tenant
    """
    async with get_db_context() as db:
        # Create demo analyst user
        demo_email = "analyst@countermeasure.dev"

        # Check if demo user already exists
        result = await db.execute(
            select(User).where(User.email == demo_email)
        )
        existing_user = result.scalar_one_or_none()

        if not existing_user:
            demo_user = User(
                tenant_id=tenant.id,
                email=demo_email,
                password_hash=get_password_hash("AnalystDemo123!"),
                first_name="Demo",
                last_name="Analyst",
                role="analyst",
                is_active=True,
                is_verified=True,
                settings={
                    "theme": "dark",
                    "notifications_enabled": True,
                    "tutorial_completed": True
                }
            )

            db.add(demo_user)
            await db.commit()

            logger.info(
                "demo_user_created",
                user_id=str(demo_user.id),
                email=demo_email,
                role="analyst"
            )


async def init_database() -> None:
    """
    Initialize database with tables and default data.
    """
    logger.info("database_initialization_started")

    try:
        # Run database migrations
        await run_migrations()
        logger.info("database_migrations_applied")

        # Create default tenant
        tenant = await create_default_tenant()

        # Create default admin user
        admin_user = await create_default_admin(tenant)

        # Seed demo data if in development
        if settings.is_development:
            await seed_demo_data(tenant)

            # Seed actor sample data
            from src.db.seed_data.seed_actors import seed_actors
            if admin_user:
                await seed_actors(tenant.id, admin_user.id)

        # Seed MITRE ATT&CK data (always seed regardless of environment)
        # TODO: Fix MITRE models foreign key constraints
        # from src.db.seed_data.seed_mitre_async import seed_mitre_data_async, get_mitre_stats_async
        # await seed_mitre_data_async()
        # mitre_stats = await get_mitre_stats_async()
        mitre_stats = {"tactics": 0, "techniques": 0, "parent_techniques": 0, "sub_techniques": 0, "severities": 0}

        logger.info(
            "database_initialization_completed",
            tenant_id=str(tenant.id),
            admin_created=admin_user is not None
        )

        # Print helpful information
        if admin_user:
            print("\n" + "="*60)
            print("🎉 COUNTERMEASURE DATABASE INITIALIZED SUCCESSFULLY!")
            print("="*60)
            print(f"📧 Admin Email: admin@countermeasure.dev")
            print(f"🔐 Admin Password: CountermeasureAdmin123!")
            print(f"🏢 Default Tenant: {tenant.name} ({tenant.slug})")
            print(f"🌐 API Base URL: http://localhost:8000")
            print(f"📚 API Docs: http://localhost:8000/docs")
            print("="*60)

            if settings.is_development:
                print("🧪 Demo analyst account also created:")
                print("📧 Demo Email: analyst@countermeasure.dev")
                print("🔐 Demo Password: AnalystDemo123!")
                print("\n🎯 Sample threat actor data seeded:")
                print("• FIN7, FIN8, FIN11 - Financial threat groups")
                print("• Scattered Spider - Modern social engineering group")
                print("• APT29 - Nation-state espionage group")
                print("• Sample campaigns and malware families included")

            print(f"\n⚠️ MITRE ATT&CK data seeding temporarily disabled:")
            print("• MITRE models need foreign key constraint fixes")
            print("• Will be re-enabled once constraints are resolved")
            print("="*60)

    except Exception as e:
        logger.error("database_initialization_failed", error=str(e))
        raise


async def main():
    """Main function for CLI usage."""
    await init_database()


if __name__ == "__main__":
    asyncio.run(main())