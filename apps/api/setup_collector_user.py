#!/usr/bin/env python3
"""
Setup script to create collector admin user and seed severity data.
"""

import asyncio
import sys
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from sqlalchemy import text
from src.db.session import engine, AsyncSessionLocal
from src.db.models import User, Tenant, Severity
from src.core.security import get_password_hash
from src.core.logging import get_logger

logger = get_logger(__name__)


async def setup_database():
    """Setup database with admin user and severities."""

    async with AsyncSessionLocal() as session:
        try:
            # Check if admin user already exists
            result = await session.execute(
                text("SELECT id FROM users WHERE email = 'collector@admin.com'")
            )
            existing_user = result.fetchone()

            if existing_user:
                print("✅ Collector admin user already exists")
            else:
                # Get or create default tenant
                result = await session.execute(text("SELECT id FROM tenants LIMIT 1"))
                tenant_row = result.fetchone()

                if not tenant_row:
                    # Create default tenant
                    await session.execute(text("""
                        INSERT INTO tenants (id, name, slug, settings, created_at, updated_at)
                        VALUES (gen_random_uuid(), 'Default Tenant', 'default', '{}', NOW(), NOW())
                    """))
                    result = await session.execute(text("SELECT id FROM tenants LIMIT 1"))
                    tenant_row = result.fetchone()

                tenant_id = tenant_row[0]

                # Create admin user
                hashed_password = get_password_hash("CollectorAdmin123")
                await session.execute(text("""
                    INSERT INTO users (id, tenant_id, email, password_hash, role, is_active, is_verified, is_superuser, mfa_enabled, settings, failed_login_attempts, metadata, created_at, updated_at)
                    VALUES (gen_random_uuid(), :tenant_id, 'collector@admin.com', :password_hash, 'admin', true, true, true, false, '{}', 0, '{}', NOW(), NOW())
                """), {
                    "tenant_id": str(tenant_id),
                    "password_hash": hashed_password
                })
                print("✅ Created collector admin user: collector@admin.com / CollectorAdmin123")

            # Check if severities exist
            result = await session.execute(text("SELECT COUNT(*) FROM severities"))
            severity_count = result.scalar()

            if severity_count > 0:
                print(f"✅ Severities already exist ({severity_count} found)")
            else:
                # Create severities
                severities = [
                    ("low", "Low severity", 1, "#28a745"),
                    ("medium", "Medium severity", 2, "#ffc107"),
                    ("high", "High severity", 3, "#fd7e14"),
                    ("critical", "Critical severity", 4, "#dc3545"),
                ]

                for name, description, level, color in severities:
                    await session.execute(text("""
                        INSERT INTO severities (id, name, description, level, color, created_at, updated_at)
                        VALUES (gen_random_uuid(), :name, :description, :level, :color, NOW(), NOW())
                    """), {
                        "name": name,
                        "description": description,
                        "level": level,
                        "color": color
                    })

                print("✅ Created severity levels: low, medium, high, critical")

            await session.commit()
            print("🎉 Database setup completed successfully!")

        except Exception as e:
            await session.rollback()
            print(f"❌ Database setup failed: {str(e)}")
            raise


async def test_auth():
    """Test the created user can authenticate."""
    import httpx

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://localhost:8000/api/v1/auth/login",
                json={
                    "email": "collector@admin.com",
                    "password": "CollectorAdmin123",
                    "remember_me": False
                }
            )

            if response.status_code == 200:
                data = response.json()
                print("✅ Authentication test successful!")
                print(f"   Access token: {data['access_token'][:50]}...")
                return True
            else:
                print(f"❌ Authentication test failed: {response.status_code} - {response.text}")
                return False
    except Exception as e:
        print(f"❌ Authentication test error: {str(e)}")
        return False


async def main():
    """Main setup function."""
    print("🚀 Setting up database for collector...")

    await setup_database()

    print("\n🔧 Testing authentication...")
    auth_success = await test_auth()

    if auth_success:
        print("\n✅ Setup completed! You can now run the collector with:")
        print("   collector@admin.com / CollectorAdmin123")
    else:
        print("\n❌ Setup completed with authentication issues")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())