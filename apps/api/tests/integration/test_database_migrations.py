"""
Integration tests for database migrations.

Tests Alembic migration scripts, schema consistency,
and data migration scenarios.
"""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine
from alembic.config import Config
from alembic import command
from alembic.script import ScriptDirectory
from alembic.runtime.environment import EnvironmentContext

from src.core.config import get_settings
from src.db.models.base import Base


class TestDatabaseMigrations:
    """Test database migration operations."""

    def test_migration_scripts_exist(self):
        """Test that migration scripts exist and are valid."""
        # Get the alembic directory
        alembic_dir = Path(__file__).parent.parent.parent / "alembic"
        versions_dir = alembic_dir / "versions"

        assert alembic_dir.exists(), "Alembic directory should exist"
        assert versions_dir.exists(), "Versions directory should exist"

        # Check that at least one migration exists
        migration_files = list(versions_dir.glob("*.py"))
        migration_files = [f for f in migration_files if not f.name.startswith("__")]
        assert len(migration_files) > 0, "At least one migration script should exist"

        # Verify migration files have proper naming
        for migration_file in migration_files:
            # Should match pattern: YYYYMMDD_HHMM_revision_description.py
            parts = migration_file.stem.split("_")
            assert len(parts) >= 4, f"Migration {migration_file.name} has invalid naming format"

    def test_alembic_config_valid(self):
        """Test that Alembic configuration is valid."""
        alembic_dir = Path(__file__).parent.parent.parent / "alembic"
        alembic_ini = alembic_dir.parent / "alembic.ini"

        assert alembic_ini.exists(), "alembic.ini should exist"

        # Load and validate config
        config = Config(str(alembic_ini))
        script_dir = ScriptDirectory.from_config(config)

        # Should be able to get current head
        heads = script_dir.get_heads()
        assert len(heads) > 0, "Should have at least one migration head"

    @pytest.mark.asyncio
    async def test_migration_up_and_down(self):
        """Test migrating up and down with real database."""
        settings = get_settings()

        # Create temporary database for testing
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
            test_db_url = f"sqlite:///{tmp_db.name}"

        try:
            # Create async engine for our test
            test_engine = create_async_engine(test_db_url)

            # Set up Alembic config
            alembic_dir = Path(__file__).parent.parent.parent / "alembic"
            alembic_ini = alembic_dir.parent / "alembic.ini"
            config = Config(str(alembic_ini))

            # Override database URL in config
            config.set_main_option("sqlalchemy.url", test_db_url.replace("sqlite:///", "sqlite:///"))

            # Test migration up
            command.upgrade(config, "head")

            # Verify tables were created
            sync_engine = create_engine(test_db_url)
            inspector = inspect(sync_engine)
            tables = inspector.get_table_names()

            # Should have core tables
            expected_tables = [
                "tenants",
                "users",
                "detections",
                "actors",
                "mitre_techniques",
                "detection_actors",
                "detection_mitre_techniques",
                "alembic_version"
            ]

            for expected_table in expected_tables:
                assert expected_table in tables, f"Table {expected_table} should exist after migration"

            # Test migration down (to previous version)
            script_dir = ScriptDirectory.from_config(config)
            heads = script_dir.get_heads()
            if len(heads) > 0:
                # Get all revisions
                revisions = list(script_dir.walk_revisions())
                if len(revisions) > 1:
                    # Downgrade to previous revision
                    previous_rev = revisions[1].revision
                    command.downgrade(config, previous_rev)

                    # Verify we can upgrade again
                    command.upgrade(config, "head")

            await test_engine.dispose()
            sync_engine.dispose()

        finally:
            # Clean up temp database
            if os.path.exists(tmp_db.name):
                os.unlink(tmp_db.name)

    @pytest.mark.asyncio
    async def test_schema_consistency_with_models(self):
        """Test that migration schema matches SQLAlchemy models."""
        settings = get_settings()

        # Create two temporary databases
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db1, \
             tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db2:

            migration_db_url = f"sqlite:///{tmp_db1.name}"
            model_db_url = f"sqlite:///{tmp_db2.name}"

        try:
            # Database 1: Create via migrations
            alembic_dir = Path(__file__).parent.parent.parent / "alembic"
            alembic_ini = alembic_dir.parent / "alembic.ini"
            config = Config(str(alembic_ini))
            config.set_main_option("sqlalchemy.url", migration_db_url.replace("sqlite:///", "sqlite:///"))
            command.upgrade(config, "head")

            # Database 2: Create via SQLAlchemy models
            model_engine = create_engine(model_db_url)
            Base.metadata.create_all(model_engine)

            # Compare schemas
            migration_inspector = inspect(create_engine(migration_db_url))
            model_inspector = inspect(model_engine)

            migration_tables = set(migration_inspector.get_table_names())
            model_tables = set(model_inspector.get_table_names())

            # Remove alembic_version table for comparison
            migration_tables.discard("alembic_version")

            assert migration_tables == model_tables, \
                f"Tables differ: Migration={migration_tables}, Models={model_tables}"

            # Compare table schemas for common tables
            for table_name in migration_tables & model_tables:
                migration_columns = {
                    col['name']: col for col in
                    migration_inspector.get_columns(table_name)
                }
                model_columns = {
                    col['name']: col for col in
                    model_inspector.get_columns(table_name)
                }

                # Check column names match
                migration_col_names = set(migration_columns.keys())
                model_col_names = set(model_columns.keys())

                assert migration_col_names == model_col_names, \
                    f"Columns differ for table {table_name}: Migration={migration_col_names}, Models={model_col_names}"

                # Check basic column properties
                for col_name in migration_col_names:
                    migration_col = migration_columns[col_name]
                    model_col = model_columns[col_name]

                    # Check nullable property
                    assert migration_col['nullable'] == model_col['nullable'], \
                        f"Nullable differs for {table_name}.{col_name}"

            model_engine.dispose()

        finally:
            # Clean up temp databases
            for db_file in [tmp_db1.name, tmp_db2.name]:
                if os.path.exists(db_file):
                    os.unlink(db_file)

    def test_migration_revision_order(self):
        """Test that migration revisions are in proper order."""
        alembic_dir = Path(__file__).parent.parent.parent / "alembic"
        alembic_ini = alembic_dir.parent / "alembic.ini"
        config = Config(str(alembic_ini))
        script_dir = ScriptDirectory.from_config(config)

        # Get all revisions in order
        revisions = list(script_dir.walk_revisions())

        assert len(revisions) > 0, "Should have at least one revision"

        # Check that revisions have proper down_revision links
        revision_map = {rev.revision: rev for rev in revisions}

        for revision in revisions:
            if revision.down_revision:
                assert revision.down_revision in revision_map, \
                    f"Revision {revision.revision} references unknown down_revision {revision.down_revision}"

    @pytest.mark.asyncio
    async def test_migration_with_existing_data(self):
        """Test migration behavior with existing data."""
        settings = get_settings()

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
            test_db_url = f"sqlite:///{tmp_db.name}"

        try:
            # Create database and run migrations
            alembic_dir = Path(__file__).parent.parent.parent / "alembic"
            alembic_ini = alembic_dir.parent / "alembic.ini"
            config = Config(str(alembic_ini))
            config.set_main_option("sqlalchemy.url", test_db_url.replace("sqlite:///", "sqlite:///"))

            command.upgrade(config, "head")

            # Insert some test data
            sync_engine = create_engine(test_db_url)
            with sync_engine.connect() as conn:
                # Insert a tenant
                tenant_result = conn.execute(
                    text("""
                        INSERT INTO tenants (name, domain, is_active, created_at, updated_at)
                        VALUES ('Test Tenant', 'test.com', 1, datetime('now'), datetime('now'))
                    """)
                )

                # Get the tenant ID (SQLite returns rowid)
                tenant_id = tenant_result.lastrowid or 1

                # Insert a user
                conn.execute(
                    text("""
                        INSERT INTO users (tenant_id, email, full_name, hashed_password,
                                         is_active, is_superuser, created_at, updated_at)
                        VALUES (:tenant_id, 'test@example.com', 'Test User', 'hashed_password',
                                1, 0, datetime('now'), datetime('now'))
                    """),
                    {"tenant_id": tenant_id}
                )

                conn.commit()

            # Verify data exists
            with sync_engine.connect() as conn:
                tenant_count = conn.execute(text("SELECT COUNT(*) FROM tenants")).scalar()
                user_count = conn.execute(text("SELECT COUNT(*) FROM users")).scalar()

                assert tenant_count == 1, "Should have one tenant"
                assert user_count == 1, "Should have one user"

            # Test that migrations don't break with existing data
            # (Re-running current migration should be safe)
            command.upgrade(config, "head")

            # Verify data is still there
            with sync_engine.connect() as conn:
                tenant_count = conn.execute(text("SELECT COUNT(*) FROM tenants")).scalar()
                user_count = conn.execute(text("SELECT COUNT(*) FROM users")).scalar()

                assert tenant_count == 1, "Tenant should still exist after migration"
                assert user_count == 1, "User should still exist after migration"

            sync_engine.dispose()

        finally:
            # Clean up temp database
            if os.path.exists(tmp_db.name):
                os.unlink(tmp_db.name)

    def test_migration_performance(self):
        """Test that migrations complete in reasonable time."""
        import time

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
            test_db_url = f"sqlite:///{tmp_db.name}"

        try:
            alembic_dir = Path(__file__).parent.parent.parent / "alembic"
            alembic_ini = alembic_dir.parent / "alembic.ini"
            config = Config(str(alembic_ini))
            config.set_main_option("sqlalchemy.url", test_db_url.replace("sqlite:///", "sqlite:///"))

            # Time the migration
            start_time = time.time()
            command.upgrade(config, "head")
            end_time = time.time()

            migration_time = end_time - start_time

            # Migration should complete in under 30 seconds for a fresh database
            assert migration_time < 30, f"Migration took too long: {migration_time} seconds"

        finally:
            if os.path.exists(tmp_db.name):
                os.unlink(tmp_db.name)