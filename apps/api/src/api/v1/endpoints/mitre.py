"""
MITRE ATT&CK framework API endpoints.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from sqlalchemy.orm import selectinload

from src.db.session import get_db
from src.db.models.framework.mitre import MitreTactic, MitreTechnique
from src.db.models.intel.actor import Actor
from src.schemas.framework.mitre import (
    MitreTacticCreate, MitreTacticUpdate, MitreTacticResponse,
    MitreTechniqueCreate, MitreTechniqueUpdate, MitreTechniqueResponse,
    MitreActorGroupCreate, MitreActorGroupResponse
)
from src.api.v1.dependencies.auth import get_current_user
from src.db.models.system import User
from src.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter()


# MITRE Tactics Endpoints
@router.post("/tactics", response_model=MitreTacticResponse, status_code=status.HTTP_201_CREATED)
async def create_tactic(
    tactic: MitreTacticCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new MITRE tactic."""

    # Check if tactic already exists
    existing = await db.execute(
        select(MitreTactic).where(MitreTactic.tactic_id == tactic.tactic_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Tactic with ID {tactic.tactic_id} already exists"
        )

    db_tactic = MitreTactic(**tactic.dict())
    db.add(db_tactic)
    await db.commit()
    await db.refresh(db_tactic)

    logger.info(f"Created MITRE tactic: {tactic.tactic_id} - {tactic.name}")
    return db_tactic


@router.get("/tactics", response_model=List[MitreTacticResponse])
async def list_tactics(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all MITRE tactics."""

    result = await db.execute(
        select(MitreTactic)
        .offset(skip)
        .limit(limit)
        .order_by(MitreTactic.tactic_id)
    )
    tactics = result.scalars().all()
    return tactics


@router.get("/tactics/{tactic_id}", response_model=MitreTacticResponse)
async def get_tactic(
    tactic_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific MITRE tactic by ID."""

    result = await db.execute(
        select(MitreTactic).where(MitreTactic.tactic_id == tactic_id)
    )
    tactic = result.scalar_one_or_none()

    if not tactic:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tactic {tactic_id} not found"
        )

    return tactic


@router.put("/tactics/{tactic_id}", response_model=MitreTacticResponse)
async def update_tactic(
    tactic_id: str,
    tactic_update: MitreTacticUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a MITRE tactic."""

    result = await db.execute(
        select(MitreTactic).where(MitreTactic.tactic_id == tactic_id)
    )
    tactic = result.scalar_one_or_none()

    if not tactic:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tactic {tactic_id} not found"
        )

    # Update fields
    for field, value in tactic_update.dict(exclude_unset=True).items():
        setattr(tactic, field, value)

    await db.commit()
    await db.refresh(tactic)

    logger.info(f"Updated MITRE tactic: {tactic_id}")
    return tactic


# MITRE Techniques Endpoints
@router.post("/techniques", response_model=MitreTechniqueResponse, status_code=status.HTTP_201_CREATED)
async def create_technique(
    technique: MitreTechniqueCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new MITRE technique."""

    # Check if technique already exists
    existing = await db.execute(
        select(MitreTechnique).where(MitreTechnique.technique_id == technique.technique_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Technique with ID {technique.technique_id} already exists"
        )

    db_technique = MitreTechnique(**technique.dict())
    db.add(db_technique)
    await db.commit()
    await db.refresh(db_technique)

    logger.info(f"Created MITRE technique: {technique.technique_id} - {technique.name}")
    return db_technique


@router.get("/techniques", response_model=List[MitreTechniqueResponse])
async def list_techniques(
    skip: int = 0,
    limit: int = 100,
    tactic_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List MITRE techniques, optionally filtered by tactic."""

    query = select(MitreTechnique)

    if tactic_id:
        query = query.where(MitreTechnique.tactic_id == tactic_id)

    query = query.offset(skip).limit(limit).order_by(MitreTechnique.technique_id)

    result = await db.execute(query)
    techniques = result.scalars().all()
    return techniques


@router.get("/techniques/{technique_id}", response_model=MitreTechniqueResponse)
async def get_technique(
    technique_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific MITRE technique by ID."""

    result = await db.execute(
        select(MitreTechnique).where(MitreTechnique.technique_id == technique_id)
    )
    technique = result.scalar_one_or_none()

    if not technique:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique {technique_id} not found"
        )

    return technique


@router.put("/techniques/{technique_id}", response_model=MitreTechniqueResponse)
async def update_technique(
    technique_id: str,
    technique_update: MitreTechniqueUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a MITRE technique."""

    result = await db.execute(
        select(MitreTechnique).where(MitreTechnique.technique_id == technique_id)
    )
    technique = result.scalar_one_or_none()

    if not technique:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique {technique_id} not found"
        )

    # Update fields
    for field, value in technique_update.dict(exclude_unset=True).items():
        setattr(technique, field, value)

    await db.commit()
    await db.refresh(technique)

    logger.info(f"Updated MITRE technique: {technique_id}")
    return technique


# Actor Groups (MITRE Groups) Endpoints
@router.post("/groups", response_model=MitreActorGroupResponse, status_code=status.HTTP_201_CREATED)
async def create_actor_group(
    group: MitreActorGroupCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new MITRE actor group."""

    # Check if actor already exists by name or MITRE ID
    existing = await db.execute(
        select(Actor).where(
            (Actor.name == group.name) |
            (Actor.mitre_attack_id == group.mitre_attack_id)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Actor group with name '{group.name}' or MITRE ID '{group.mitre_attack_id}' already exists"
        )

    # Create actor from MITRE group data
    actor_data = {
        "name": group.name,
        "description": group.description,
        "aliases": group.aliases,
        "mitre_attack_id": group.mitre_attack_id,
        "stix_uuid": group.stix_uuid,
        "references": group.references,
        "tenant_id": current_user.tenant_id,
        "created_by_id": current_user.id
    }

    db_actor = Actor(**actor_data)
    db.add(db_actor)
    await db.commit()
    await db.refresh(db_actor)

    logger.info(f"Created MITRE actor group: {group.mitre_attack_id} - {group.name}")
    return db_actor


@router.get("/groups", response_model=List[MitreActorGroupResponse])
async def list_actor_groups(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all MITRE actor groups."""

    result = await db.execute(
        select(Actor)
        .where(Actor.mitre_attack_id.isnot(None))
        .where(Actor.tenant_id == current_user.tenant_id)
        .offset(skip)
        .limit(limit)
        .order_by(Actor.mitre_attack_id)
    )
    actors = result.scalars().all()
    return actors


@router.get("/groups/{mitre_id}", response_model=MitreActorGroupResponse)
async def get_actor_group(
    mitre_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific MITRE actor group by MITRE ATT&CK ID."""

    result = await db.execute(
        select(Actor)
        .where(Actor.mitre_attack_id == mitre_id)
        .where(Actor.tenant_id == current_user.tenant_id)
    )
    actor = result.scalar_one_or_none()

    if not actor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MITRE actor group {mitre_id} not found"
        )

    return actor


# Bulk Operations
@router.post("/tactics/bulk", status_code=status.HTTP_201_CREATED)
async def bulk_create_tactics(
    tactics: List[MitreTacticCreate],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Bulk create MITRE tactics."""

    created_count = 0
    updated_count = 0

    for tactic_data in tactics:
        # Check if tactic exists
        existing = await db.execute(
            select(MitreTactic).where(MitreTactic.tactic_id == tactic_data.tactic_id)
        )
        existing_tactic = existing.scalar_one_or_none()

        if existing_tactic:
            # Update existing tactic
            for field, value in tactic_data.dict().items():
                setattr(existing_tactic, field, value)
            updated_count += 1
        else:
            # Create new tactic
            db_tactic = MitreTactic(**tactic_data.dict())
            db.add(db_tactic)
            created_count += 1

    await db.commit()

    logger.info(f"Bulk tactics operation: {created_count} created, {updated_count} updated")
    return {
        "message": f"Processed {len(tactics)} tactics",
        "created": created_count,
        "updated": updated_count
    }


@router.post("/techniques/bulk", status_code=status.HTTP_201_CREATED)
async def bulk_create_techniques(
    techniques: List[MitreTechniqueCreate],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Bulk create MITRE techniques."""

    created_count = 0
    updated_count = 0

    for technique_data in techniques:
        # Check if technique exists
        existing = await db.execute(
            select(MitreTechnique).where(MitreTechnique.technique_id == technique_data.technique_id)
        )
        existing_technique = existing.scalar_one_or_none()

        if existing_technique:
            # Update existing technique
            for field, value in technique_data.dict().items():
                setattr(existing_technique, field, value)
            updated_count += 1
        else:
            # Create new technique
            db_technique = MitreTechnique(**technique_data.dict())
            db.add(db_technique)
            created_count += 1

    await db.commit()

    logger.info(f"Bulk techniques operation: {created_count} created, {updated_count} updated")
    return {
        "message": f"Processed {len(techniques)} techniques",
        "created": created_count,
        "updated": updated_count
    }


@router.post("/groups/bulk", status_code=status.HTTP_201_CREATED)
async def bulk_create_groups(
    groups: List[MitreActorGroupCreate],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Bulk create MITRE actor groups."""

    created_count = 0
    updated_count = 0

    for group_data in groups:
        # Check if actor exists
        existing = await db.execute(
            select(Actor).where(
                (Actor.mitre_attack_id == group_data.mitre_attack_id) &
                (Actor.tenant_id == current_user.tenant_id)
            )
        )
        existing_actor = existing.scalar_one_or_none()

        if existing_actor:
            # Update existing actor
            actor_fields = {
                "name": group_data.name,
                "description": group_data.description,
                "aliases": group_data.aliases,
                "stix_uuid": group_data.stix_uuid,
                "references": group_data.references
            }
            for field, value in actor_fields.items():
                setattr(existing_actor, field, value)
            updated_count += 1
        else:
            # Create new actor
            actor_data = {
                "name": group_data.name,
                "description": group_data.description,
                "aliases": group_data.aliases,
                "mitre_attack_id": group_data.mitre_attack_id,
                "stix_uuid": group_data.stix_uuid,
                "references": group_data.references,
                "tenant_id": current_user.tenant_id,
                "created_by_id": current_user.id
            }
            db_actor = Actor(**actor_data)
            db.add(db_actor)
            created_count += 1

    await db.commit()

    logger.info(f"Bulk groups operation: {created_count} created, {updated_count} updated")
    return {
        "message": f"Processed {len(groups)} groups",
        "created": created_count,
        "updated": updated_count
    }


# Unified Import Endpoint
@router.post("/import", status_code=status.HTTP_201_CREATED)
async def import_mitre_data(
    data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Unified MITRE data import endpoint that handles dependencies properly.

    Imports tactics first, then techniques, then groups to avoid foreign key violations.

    Expected data format:
    {
        "tactics": [list of MitreTacticCreate objects],
        "techniques": [list of MitreTechniqueCreate objects],
        "groups": [list of MitreActorGroupCreate objects]
    }
    """

    total_created = 0
    total_updated = 0
    results = {
        "tactics": {"created": 0, "updated": 0},
        "techniques": {"created": 0, "updated": 0},
        "groups": {"created": 0, "updated": 0}
    }

    try:
        # Step 1: Import tactics first (no dependencies)
        if "tactics" in data and data["tactics"]:
            logger.info(f"Importing {len(data['tactics'])} tactics...")

            for tactic_data in data["tactics"]:
                # Validate tactic data
                tactic = MitreTacticCreate(**tactic_data)

                # Check if tactic exists
                existing = await db.execute(
                    select(MitreTactic).where(MitreTactic.tactic_id == tactic.tactic_id)
                )
                existing_tactic = existing.scalar_one_or_none()

                if existing_tactic:
                    # Update existing tactic
                    for field, value in tactic.dict().items():
                        setattr(existing_tactic, field, value)
                    results["tactics"]["updated"] += 1
                    total_updated += 1
                else:
                    # Create new tactic
                    db_tactic = MitreTactic(**tactic.dict())
                    db.add(db_tactic)
                    results["tactics"]["created"] += 1
                    total_created += 1

            await db.commit()
            logger.info(f"Tactics imported: {results['tactics']['created']} created, {results['tactics']['updated']} updated")

        # Step 2: Import techniques (depends on tactics)
        if "techniques" in data and data["techniques"]:
            logger.info(f"Importing {len(data['techniques'])} techniques...")

            for technique_data in data["techniques"]:
                # Validate technique data
                technique = MitreTechniqueCreate(**technique_data)

                # Check if technique exists
                existing = await db.execute(
                    select(MitreTechnique).where(MitreTechnique.technique_id == technique.technique_id)
                )
                existing_technique = existing.scalar_one_or_none()

                if existing_technique:
                    # Update existing technique
                    for field, value in technique.dict().items():
                        setattr(existing_technique, field, value)
                    results["techniques"]["updated"] += 1
                    total_updated += 1
                else:
                    # Create new technique
                    db_technique = MitreTechnique(**technique.dict())
                    db.add(db_technique)
                    results["techniques"]["created"] += 1
                    total_created += 1

            await db.commit()
            logger.info(f"Techniques imported: {results['techniques']['created']} created, {results['techniques']['updated']} updated")

        # Step 3: Import groups (no dependencies on tactics/techniques)
        if "groups" in data and data["groups"]:
            logger.info(f"Importing {len(data['groups'])} groups...")

            for group_data in data["groups"]:
                # Validate group data
                group = MitreActorGroupCreate(**group_data)

                # Check if actor exists
                existing = await db.execute(
                    select(Actor).where(
                        (Actor.mitre_attack_id == group.mitre_attack_id) &
                        (Actor.tenant_id == current_user.tenant_id)
                    )
                )
                existing_actor = existing.scalar_one_or_none()

                if existing_actor:
                    # Update existing actor
                    actor_fields = {
                        "name": group.name,
                        "description": group.description,
                        "aliases": group.aliases,
                        "stix_uuid": group.stix_uuid,
                        "references": group.references
                    }
                    for field, value in actor_fields.items():
                        setattr(existing_actor, field, value)
                    results["groups"]["updated"] += 1
                    total_updated += 1
                else:
                    # Create new actor
                    actor_data = {
                        "name": group.name,
                        "description": group.description,
                        "aliases": group.aliases,
                        "mitre_attack_id": group.mitre_attack_id,
                        "stix_uuid": group.stix_uuid,
                        "references": group.references,
                        "actor_type": "group",
                        "tenant_id": current_user.tenant_id,
                        "created_by": current_user.id
                    }
                    db_actor = Actor(**actor_data)
                    db.add(db_actor)
                    results["groups"]["created"] += 1
                    total_created += 1

            await db.commit()
            logger.info(f"Groups imported: {results['groups']['created']} created, {results['groups']['updated']} updated")

        logger.info(f"MITRE import completed: {total_created} total created, {total_updated} total updated")

        return {
            "message": f"MITRE data import completed successfully",
            "total_created": total_created,
            "total_updated": total_updated,
            "details": results
        }

    except Exception as e:
        logger.error(f"MITRE import failed: {str(e)}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Import failed: {str(e)}"
        )


# Utility endpoints
@router.delete("/tactics/clear", status_code=status.HTTP_204_NO_CONTENT)
async def clear_all_tactics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Clear all MITRE tactics. Use with caution."""

    await db.execute(delete(MitreTactic))
    await db.commit()

    logger.warning("All MITRE tactics have been cleared")


@router.delete("/techniques/clear", status_code=status.HTTP_204_NO_CONTENT)
async def clear_all_techniques(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Clear all MITRE techniques. Use with caution."""

    await db.execute(delete(MitreTechnique))
    await db.commit()

    logger.warning("All MITRE techniques have been cleared")