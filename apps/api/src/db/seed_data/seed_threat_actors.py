"""
Seed threat actor sample data into the database.
"""

import asyncio
from uuid import UUID

from sqlalchemy import select

from src.core.logging import get_logger
from src.db.models import Tenant
from src.db.models.threat_actor import Campaign, Malware, ThreatActor
from src.db.seed_data.threat_actors import (
    get_sample_campaigns,
    get_sample_malware_families,
    threat_actor_samples,
)
from src.db.session import get_db_context


logger = get_logger(__name__)


async def seed_threat_actors(tenant_id: UUID, user_id: UUID) -> None:
    """
    Seed threat actor sample data for a tenant.

    Args:
        tenant_id: Target tenant ID
        user_id: User ID for audit tracking
    """
    async with get_db_context() as db:
        logger.info("seeding_threat_actors_started", tenant_id=str(tenant_id))

        # Track created actors for linking campaigns and malware
        created_actors: dict[str, ThreatActor] = {}

        # Create threat actors
        for actor_data in threat_actor_samples:
            # Check if actor already exists
            existing = await db.execute(
                select(ThreatActor).where(
                    ThreatActor.tenant_id == tenant_id,
                    ThreatActor.name == actor_data["name"],
                )
            )
            if existing.scalar_one_or_none():
                logger.info(
                    "threat_actor_exists",
                    name=actor_data["name"],
                    tenant_id=str(tenant_id),
                )
                continue

            # Create threat actor
            threat_actor = ThreatActor(
                **{k: v for k, v in actor_data.items()}, tenant_id=tenant_id
            )

            # Calculate confidence and quality scores
            threat_actor.confidence_score = threat_actor.calculate_confidence_score()
            threat_actor.quality_score = await _calculate_quality_score(threat_actor)

            db.add(threat_actor)
            await db.flush()  # Get ID without committing

            created_actors[actor_data["name"]] = threat_actor

            logger.info(
                "threat_actor_seeded",
                name=threat_actor.name,
                actor_type=threat_actor.actor_type,
                confidence_score=threat_actor.confidence_score,
                tenant_id=str(tenant_id),
            )

        # Create campaigns
        for campaign_data in get_sample_campaigns():
            threat_actor_name = campaign_data.pop("threat_actor_name", None)
            threat_actor = (
                created_actors.get(threat_actor_name) if threat_actor_name else None
            )

            # Check if campaign already exists
            existing = await db.execute(
                select(Campaign).where(
                    Campaign.tenant_id == tenant_id,
                    Campaign.name == campaign_data["name"],
                )
            )
            if existing.scalar_one_or_none():
                logger.info(
                    "campaign_exists",
                    name=campaign_data["name"],
                    tenant_id=str(tenant_id),
                )
                continue

            campaign = Campaign(
                **campaign_data,
                tenant_id=tenant_id,
                threat_actor_id=threat_actor.id if threat_actor else None,
            )

            # Calculate confidence score based on attribution and completeness
            campaign.confidence_score = _calculate_campaign_confidence(campaign)

            db.add(campaign)

            logger.info(
                "campaign_seeded",
                name=campaign.name,
                threat_actor=threat_actor_name,
                confidence_score=campaign.confidence_score,
                tenant_id=str(tenant_id),
            )

        # Create malware families
        for malware_data in get_sample_malware_families():
            threat_actor_name = malware_data.pop("threat_actor_name", None)
            threat_actor = (
                created_actors.get(threat_actor_name) if threat_actor_name else None
            )

            # Check if malware family already exists
            existing = await db.execute(
                select(Malware).where(
                    Malware.tenant_id == tenant_id, Malware.name == malware_data["name"]
                )
            )
            if existing.scalar_one_or_none():
                logger.info(
                    "malware_family_exists",
                    name=malware_data["name"],
                    tenant_id=str(tenant_id),
                )
                continue

            malware_family = Malware(
                **malware_data,
                tenant_id=tenant_id,
                threat_actor_id=threat_actor.id if threat_actor else None,
            )

            # Calculate confidence score
            malware_family.confidence_score = _calculate_malware_confidence(
                malware_family
            )

            db.add(malware_family)

            logger.info(
                "malware_family_seeded",
                name=malware_family.name,
                family_type=malware_family.family_type,
                threat_actor=threat_actor_name,
                confidence_score=malware_family.confidence_score,
                tenant_id=str(tenant_id),
            )

        # Commit all changes
        await db.commit()

        logger.info(
            "seeding_threat_actors_completed",
            tenant_id=str(tenant_id),
            actors_count=len(created_actors),
            campaigns_count=len(get_sample_campaigns()),
            malware_count=len(get_sample_malware_families()),
        )


async def seed_default_tenant_threat_actors() -> None:
    """
    Seed threat actors for the default tenant using default admin user.
    """
    async with get_db_context() as db:
        # Find default tenant and admin user
        from src.core.config import settings

        tenant_result = await db.execute(
            select(Tenant).where(Tenant.slug == settings.default_tenant_slug)
        )
        tenant = tenant_result.scalar_one_or_none()

        if not tenant:
            logger.error("default_tenant_not_found", slug=settings.default_tenant_slug)
            return

        # Find an admin user in the tenant
        from src.db.models import User

        user_result = await db.execute(
            select(User).where(
                User.tenant_id == tenant.id,
                User.role == "admin",
                User.is_active == True,
            )
        )
        admin_user = user_result.scalar_one_or_none()

        if not admin_user:
            logger.error("default_admin_not_found", tenant_id=str(tenant.id))
            return

        # Seed threat actors
        await seed_threat_actors(tenant.id, admin_user.id)


async def _calculate_quality_score(threat_actor: ThreatActor) -> float:
    """Calculate data quality score for threat actor."""
    score_factors = []

    # Essential fields (40% weight)
    essential_fields = [
        threat_actor.name,
        threat_actor.actor_type,
        threat_actor.description,
    ]
    essential_completeness = sum(1 for field in essential_fields if field) / len(
        essential_fields
    )
    score_factors.append(essential_completeness * 0.4)

    # Attribution data (30% weight)
    attribution_fields = [
        threat_actor.primary_attribution,
        threat_actor.origin_country,
        threat_actor.attribution_rationale,
    ]
    attribution_completeness = sum(1 for field in attribution_fields if field) / len(
        attribution_fields
    )
    score_factors.append(attribution_completeness * 0.3)

    # Intelligence enrichment (20% weight)
    intel_fields = [
        threat_actor.references,
        threat_actor.mitre_attack_id,
        threat_actor.first_observed,
        threat_actor.last_observed,
    ]
    intel_completeness = sum(1 for field in intel_fields if field) / len(intel_fields)
    score_factors.append(intel_completeness * 0.2)

    # Validation status (10% weight)
    validation_score = 1.0 if threat_actor.is_validated else 0.0
    score_factors.append(validation_score * 0.1)

    return min(1.0, sum(score_factors))


def _calculate_campaign_confidence(campaign: Campaign) -> float:
    """Calculate confidence score for campaign."""
    factors = []

    # Attribution confidence (40% weight)
    factors.append(campaign.attribution_confidence * 0.4)

    # Data completeness (35% weight)
    completeness_fields = [
        campaign.description,
        campaign.start_date,
        campaign.end_date,
        campaign.objectives,
        campaign.target_sectors,
    ]
    completeness = sum(1 for field in completeness_fields if field) / len(
        completeness_fields
    )
    factors.append(completeness * 0.35)

    # References quality (15% weight)
    ref_score = (
        min(1.0, len(campaign.references or []) / 2.0) if campaign.references else 0.0
    )
    factors.append(ref_score * 0.15)

    # TTPs documentation (10% weight)
    ttps_score = (
        min(1.0, len(campaign.tactics_techniques or []) / 5.0)
        if campaign.tactics_techniques
        else 0.0
    )
    factors.append(ttps_score * 0.1)

    return min(1.0, sum(factors))


def _calculate_malware_confidence(malware: Malware) -> float:
    """Calculate confidence score for malware family."""
    factors = []

    # Attribution confidence (40% weight)
    factors.append(malware.attribution_confidence * 0.4)

    # Technical documentation (30% weight)
    tech_fields = [malware.description, malware.capabilities, malware.platforms]
    tech_completeness = sum(1 for field in tech_fields if field) / len(tech_fields)
    factors.append(tech_completeness * 0.3)

    # Timeline data (20% weight)
    timeline_fields = [malware.first_seen, malware.last_seen]
    timeline_completeness = sum(1 for field in timeline_fields if field) / len(
        timeline_fields
    )
    factors.append(timeline_completeness * 0.2)

    # References (10% weight)
    ref_score = (
        min(1.0, len(malware.references or []) / 2.0) if malware.references else 0.0
    )
    factors.append(ref_score * 0.1)

    return min(1.0, sum(factors))


async def main():
    """Main function for CLI usage."""
    await seed_default_tenant_threat_actors()


if __name__ == "__main__":
    asyncio.run(main())
