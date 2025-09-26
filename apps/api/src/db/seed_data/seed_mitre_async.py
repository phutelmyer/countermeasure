"""
Async version of MITRE ATT&CK data seeding.
"""

from sqlalchemy import select

from src.core.logging import get_logger
from src.db.models import MitreTactic, MitreTechnique, Severity
from src.db.session import get_db_context

from .mitre_data import MITRE_TACTICS, MITRE_TECHNIQUES, SEVERITY_LEVELS


logger = get_logger(__name__)


async def seed_severities_async() -> None:
    """Seed severity levels asynchronously."""
    logger.info("Seeding severity levels...")

    async with get_db_context() as db:
        for severity_data in SEVERITY_LEVELS:
            try:
                # Check if severity already exists
                result = await db.execute(
                    select(Severity).where(Severity.name == severity_data["name"])
                )
                existing = result.scalar_one_or_none()

                if not existing:
                    severity = Severity(**severity_data)
                    db.add(severity)
                    logger.info("severity_added", name=severity_data["name"])
                else:
                    logger.info("severity_exists", name=severity_data["name"])

            except Exception as e:
                logger.warning(
                    "severity_add_failed", name=severity_data["name"], error=str(e)
                )
                await db.rollback()
                continue

        try:
            await db.commit()
            logger.info("severities_seeded_successfully")
        except Exception as e:
            logger.error("severities_commit_failed", error=str(e))
            await db.rollback()


async def seed_mitre_tactics_async() -> None:
    """Seed MITRE ATT&CK tactics asynchronously."""
    logger.info("Seeding MITRE ATT&CK tactics...")

    async with get_db_context() as db:
        for tactic_data in MITRE_TACTICS:
            try:
                # Check if tactic already exists
                result = await db.execute(
                    select(MitreTactic).where(
                        MitreTactic.tactic_id == tactic_data["tactic_id"]
                    )
                )
                existing = result.scalar_one_or_none()

                if not existing:
                    tactic = MitreTactic(**tactic_data)
                    db.add(tactic)
                    logger.info(
                        "tactic_added",
                        tactic_id=tactic_data["tactic_id"],
                        name=tactic_data["name"],
                    )
                else:
                    logger.info("tactic_exists", tactic_id=tactic_data["tactic_id"])

            except Exception as e:
                logger.warning(
                    "tactic_add_failed",
                    tactic_id=tactic_data["tactic_id"],
                    error=str(e),
                )
                await db.rollback()
                continue

        try:
            await db.commit()
            logger.info("tactics_seeded_successfully")
        except Exception as e:
            logger.error("tactics_commit_failed", error=str(e))
            await db.rollback()


async def seed_mitre_techniques_async() -> None:
    """Seed MITRE ATT&CK techniques asynchronously."""
    logger.info("Seeding MITRE ATT&CK techniques...")

    # First, seed parent techniques (those without parent_technique_id)
    parent_techniques = [
        t for t in MITRE_TECHNIQUES if t["parent_technique_id"] is None
    ]
    sub_techniques = [
        t for t in MITRE_TECHNIQUES if t["parent_technique_id"] is not None
    ]

    async with get_db_context() as db:
        # Seed parent techniques first
        for technique_data in parent_techniques:
            try:
                # Check if technique already exists
                result = await db.execute(
                    select(MitreTechnique).where(
                        MitreTechnique.technique_id == technique_data["technique_id"]
                    )
                )
                existing = result.scalar_one_or_none()

                if not existing:
                    technique = MitreTechnique(**technique_data)
                    db.add(technique)
                    logger.info(
                        "technique_added",
                        technique_id=technique_data["technique_id"],
                        name=technique_data["name"],
                    )
                else:
                    logger.info(
                        "technique_exists", technique_id=technique_data["technique_id"]
                    )

            except Exception as e:
                logger.warning(
                    "technique_add_failed",
                    technique_id=technique_data["technique_id"],
                    error=str(e),
                )
                await db.rollback()
                continue

        try:
            await db.commit()
            logger.info("parent_techniques_seeded_successfully")
        except Exception as e:
            logger.error("parent_techniques_commit_failed", error=str(e))
            await db.rollback()
            return

        # Then seed sub-techniques
        for technique_data in sub_techniques:
            try:
                # Check if technique already exists
                result = await db.execute(
                    select(MitreTechnique).where(
                        MitreTechnique.technique_id == technique_data["technique_id"]
                    )
                )
                existing = result.scalar_one_or_none()

                if not existing:
                    technique = MitreTechnique(**technique_data)
                    db.add(technique)
                    logger.info(
                        "sub_technique_added",
                        technique_id=technique_data["technique_id"],
                        name=technique_data["name"],
                    )
                else:
                    logger.info(
                        "sub_technique_exists",
                        technique_id=technique_data["technique_id"],
                    )

            except Exception as e:
                logger.warning(
                    "sub_technique_add_failed",
                    technique_id=technique_data["technique_id"],
                    error=str(e),
                )
                await db.rollback()
                continue

        try:
            await db.commit()
            logger.info("sub_techniques_seeded_successfully")
        except Exception as e:
            logger.error("sub_techniques_commit_failed", error=str(e))
            await db.rollback()


async def seed_mitre_data_async() -> None:
    """Seed all MITRE ATT&CK data asynchronously."""
    logger.info("mitre_seeding_started")

    try:
        # Seed in order of dependencies
        await seed_severities_async()
        await seed_mitre_tactics_async()
        await seed_mitre_techniques_async()

        logger.info("mitre_seeding_completed_successfully")

    except Exception as e:
        logger.error("mitre_seeding_failed", error=str(e))
        raise


async def get_mitre_stats_async() -> dict:
    """Get statistics about MITRE data in the database asynchronously."""
    async with get_db_context() as db:
        tactics_result = await db.execute(select(MitreTactic))
        tactics_count = len(tactics_result.scalars().all())

        techniques_result = await db.execute(select(MitreTechnique))
        techniques_count = len(techniques_result.scalars().all())

        parent_techniques_result = await db.execute(
            select(MitreTechnique).where(MitreTechnique.parent_technique_id.is_(None))
        )
        parent_techniques_count = len(parent_techniques_result.scalars().all())

        sub_techniques_result = await db.execute(
            select(MitreTechnique).where(MitreTechnique.parent_technique_id.isnot(None))
        )
        sub_techniques_count = len(sub_techniques_result.scalars().all())

        severities_result = await db.execute(select(Severity))
        severities_count = len(severities_result.scalars().all())

        return {
            "tactics": tactics_count,
            "techniques": techniques_count,
            "parent_techniques": parent_techniques_count,
            "sub_techniques": sub_techniques_count,
            "severities": severities_count,
        }
