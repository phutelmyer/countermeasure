"""fix_existing_detection_data_arrays_and_source_urls

Revision ID: 9fb3edc4b794
Revises: 9a81bfabb414
Create Date: 2025-09-21 09:05:51.288529

"""
from collections.abc import Sequence
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '9fb3edc4b794'
down_revision: str | None = '9a81bfabb414'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Fix existing detection data - convert string arrays to proper arrays."""

    # Fix platforms: convert "{Windows}" to ["Windows"]
    op.execute("""
        UPDATE detections
        SET platforms = CASE
            WHEN platforms::text LIKE '{%}' THEN
                ARRAY[TRIM(BOTH '{}' FROM platforms::text)]::text[]
            ELSE platforms
        END
        WHERE platforms IS NOT NULL AND platforms::text LIKE '{%}'
    """)

    # Fix data_sources: convert "{\"Image Load\"}" to ["Image Load"]
    op.execute("""
        UPDATE detections
        SET data_sources = CASE
            WHEN data_sources::text LIKE '{%}' THEN
                ARRAY[TRIM(BOTH '{}\"' FROM data_sources::text)]::text[]
            ELSE data_sources
        END
        WHERE data_sources IS NOT NULL AND data_sources::text LIKE '{%}'
    """)

    # Fix false_positives: convert "{\"Other DLLs with the same Imphash\"}" to ["Other DLLs with the same Imphash"]
    op.execute("""
        UPDATE detections
        SET false_positives = CASE
            WHEN false_positives::text LIKE '{%}' THEN
                ARRAY[TRIM(BOTH '{}\"' FROM false_positives::text)]::text[]
            ELSE false_positives
        END
        WHERE false_positives IS NOT NULL AND false_positives::text LIKE '{%}'
    """)

    # For source_url, we can't easily reconstruct them from existing data
    # so we'll leave them as null and they'll be fixed on next import


def downgrade() -> None:
    """Downgrade database schema."""
    # No downgrade needed - the data is being corrected, not schema changed
    pass
