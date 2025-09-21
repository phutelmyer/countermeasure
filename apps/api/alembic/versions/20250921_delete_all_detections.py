"""delete all detections data

Revision ID: delete_all_detections
Revises: 9fb3edc4b794
Create Date: 2025-09-21 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'delete_all_detections'
down_revision: str | None = '9fb3edc4b794'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Delete all detection records."""
    op.execute("DELETE FROM detections")


def downgrade() -> None:
    """Downgrade database schema."""
    # No downgrade needed - we're just deleting data
    pass