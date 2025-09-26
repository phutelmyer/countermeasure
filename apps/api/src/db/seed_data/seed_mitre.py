"""
Seed MITRE ATT&CK data into the database.
"""

import logging

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .mitre_data import MITRE_TACTICS, MITRE_TECHNIQUES, SEVERITY_LEVELS
from ..models import MitreTactic, MitreTechnique, Severity


logger = logging.getLogger(__name__)


def seed_severities(db: Session) -> None:
    """Seed severity levels."""
    logger.info("Seeding severity levels...")

    for severity_data in SEVERITY_LEVELS:
        try:
            # Check if severity already exists
            existing = (
                db.query(Severity)
                .filter(Severity.name == severity_data["name"])
                .first()
            )

            if not existing:
                severity = Severity(**severity_data)
                db.add(severity)
                logger.info(f"Added severity: {severity_data['name']}")
            else:
                logger.info(f"Severity already exists: {severity_data['name']}")

        except IntegrityError as e:
            logger.warning(f"Failed to add severity {severity_data['name']}: {e}")
            db.rollback()
            continue

    try:
        db.commit()
        logger.info("Successfully seeded severity levels")
    except Exception as e:
        logger.error(f"Failed to commit severity levels: {e}")
        db.rollback()


def seed_mitre_tactics(db: Session) -> None:
    """Seed MITRE ATT&CK tactics."""
    logger.info("Seeding MITRE ATT&CK tactics...")

    for tactic_data in MITRE_TACTICS:
        try:
            # Check if tactic already exists
            existing = (
                db.query(MitreTactic)
                .filter(MitreTactic.tactic_id == tactic_data["tactic_id"])
                .first()
            )

            if not existing:
                tactic = MitreTactic(**tactic_data)
                db.add(tactic)
                logger.info(
                    f"Added tactic: {tactic_data['tactic_id']} - {tactic_data['name']}"
                )
            else:
                logger.info(f"Tactic already exists: {tactic_data['tactic_id']}")

        except IntegrityError as e:
            logger.warning(f"Failed to add tactic {tactic_data['tactic_id']}: {e}")
            db.rollback()
            continue

    try:
        db.commit()
        logger.info("Successfully seeded MITRE tactics")
    except Exception as e:
        logger.error(f"Failed to commit MITRE tactics: {e}")
        db.rollback()


def seed_mitre_techniques(db: Session) -> None:
    """Seed MITRE ATT&CK techniques."""
    logger.info("Seeding MITRE ATT&CK techniques...")

    # First, seed parent techniques (those without parent_technique_id)
    parent_techniques = [
        t for t in MITRE_TECHNIQUES if t["parent_technique_id"] is None
    ]
    sub_techniques = [
        t for t in MITRE_TECHNIQUES if t["parent_technique_id"] is not None
    ]

    # Seed parent techniques first
    for technique_data in parent_techniques:
        try:
            # Check if technique already exists
            existing = (
                db.query(MitreTechnique)
                .filter(MitreTechnique.technique_id == technique_data["technique_id"])
                .first()
            )

            if not existing:
                technique = MitreTechnique(**technique_data)
                db.add(technique)
                logger.info(
                    f"Added technique: {technique_data['technique_id']} - {technique_data['name']}"
                )
            else:
                logger.info(
                    f"Technique already exists: {technique_data['technique_id']}"
                )

        except IntegrityError as e:
            logger.warning(
                f"Failed to add technique {technique_data['technique_id']}: {e}"
            )
            db.rollback()
            continue

    try:
        db.commit()
        logger.info("Successfully seeded parent techniques")
    except Exception as e:
        logger.error(f"Failed to commit parent techniques: {e}")
        db.rollback()
        return

    # Then seed sub-techniques
    for technique_data in sub_techniques:
        try:
            # Check if technique already exists
            existing = (
                db.query(MitreTechnique)
                .filter(MitreTechnique.technique_id == technique_data["technique_id"])
                .first()
            )

            if not existing:
                technique = MitreTechnique(**technique_data)
                db.add(technique)
                logger.info(
                    f"Added sub-technique: {technique_data['technique_id']} - {technique_data['name']}"
                )
            else:
                logger.info(
                    f"Sub-technique already exists: {technique_data['technique_id']}"
                )

        except IntegrityError as e:
            logger.warning(
                f"Failed to add sub-technique {technique_data['technique_id']}: {e}"
            )
            db.rollback()
            continue

    try:
        db.commit()
        logger.info("Successfully seeded MITRE sub-techniques")
    except Exception as e:
        logger.error(f"Failed to commit MITRE sub-techniques: {e}")
        db.rollback()


def seed_mitre_data(db: Session) -> None:
    """Seed all MITRE ATT&CK data."""
    logger.info("Starting MITRE ATT&CK data seeding...")

    try:
        # Seed in order of dependencies
        seed_severities(db)
        seed_mitre_tactics(db)
        seed_mitre_techniques(db)

        logger.info("MITRE ATT&CK data seeding completed successfully")

    except Exception as e:
        logger.error(f"MITRE ATT&CK data seeding failed: {e}")
        db.rollback()
        raise


def get_mitre_stats(db: Session) -> dict:
    """Get statistics about MITRE data in the database."""
    tactics_count = db.query(MitreTactic).count()
    techniques_count = db.query(MitreTechnique).count()
    parent_techniques_count = (
        db.query(MitreTechnique)
        .filter(MitreTechnique.parent_technique_id.is_(None))
        .count()
    )
    sub_techniques_count = (
        db.query(MitreTechnique)
        .filter(MitreTechnique.parent_technique_id.isnot(None))
        .count()
    )
    severities_count = db.query(Severity).count()

    return {
        "tactics": tactics_count,
        "techniques": techniques_count,
        "parent_techniques": parent_techniques_count,
        "sub_techniques": sub_techniques_count,
        "severities": severities_count,
    }


if __name__ == "__main__":
    from ..session import SessionLocal

    db = SessionLocal()
    try:
        seed_mitre_data(db)
        stats = get_mitre_stats(db)
        print(f"MITRE ATT&CK seeding completed. Stats: {stats}")
    finally:
        db.close()
