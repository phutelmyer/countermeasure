"""
Seed actor sample data into the database.
"""

import asyncio
from uuid import UUID

from sqlalchemy import select

from src.core.logging import get_logger
from src.db.models.intel import Actor, Campaign, Malware
from src.db.seed_data.actors import (
    actor_samples,
    get_sample_campaigns,
    get_sample_malware_families,
)
from src.db.session import get_db_context


logger = get_logger(__name__)


async def seed_actors(tenant_id: UUID, user_id: UUID) -> None:
    """
    Seed actor sample data for a tenant.

    Args:
        tenant_id: Target tenant ID
        user_id: User ID for creating records
    """
    async with get_db_context() as db:
        try:
            # Check if actors already exist
            result = await db.execute(select(Actor).where(Actor.tenant_id == tenant_id))
            existing_actors = result.scalars().all()

            if existing_actors:
                logger.info(
                    "actors_already_seeded",
                    count=len(existing_actors),
                    tenant_id=str(tenant_id),
                )
                return

            # Create sample actors
            created_actors = []
            for actor_data in actor_samples:
                # Prepare actor data
                actor_dict = actor_data.copy()
                actor_dict.update(
                    {
                        "tenant_id": tenant_id,
                        "created_by": user_id,
                        "updated_by": user_id,
                    }
                )

                # Create actor
                actor = Actor(**actor_dict)

                # Calculate confidence score
                actor.confidence_score = actor.calculate_confidence_score()

                db.add(actor)
                created_actors.append(actor)

            # Commit actors first
            await db.commit()

            # Now create campaigns and malware families
            actor_lookup = {actor.name: actor for actor in created_actors}

            # Create sample campaigns
            campaign_data = get_sample_campaigns()
            for campaign_info in campaign_data:
                actor_name = campaign_info.pop("actor_name")
                if actor_name in actor_lookup:
                    campaign_info.update(
                        {
                            "actor_id": actor_lookup[actor_name].id,
                            "tenant_id": tenant_id,
                            # TODO: Add created_by/updated_by fields to Campaign model
                            # "created_by": user_id,
                            # "updated_by": user_id
                        }
                    )
                    campaign = Campaign(**campaign_info)
                    db.add(campaign)

            # Create sample malware families
            malware_data = get_sample_malware_families()
            for malware_info in malware_data:
                actor_name = malware_info.pop("actor_name")
                if actor_name in actor_lookup:
                    malware_info.update(
                        {
                            "actor_id": actor_lookup[actor_name].id,
                            "tenant_id": tenant_id,
                            # TODO: Add created_by/updated_by fields to Malware model
                            # "created_by": user_id,
                            # "updated_by": user_id
                        }
                    )
                    malware = Malware(**malware_info)
                    db.add(malware)

            await db.commit()

            logger.info(
                "actors_seeded_successfully",
                actors_count=len(created_actors),
                tenant_id=str(tenant_id),
            )

        except Exception as e:
            logger.error(
                "actors_seeding_failed", error=str(e), tenant_id=str(tenant_id)
            )
            await db.rollback()
            raise


async def main():
    """Main function for testing."""
    # This would need a real tenant and user ID


if __name__ == "__main__":
    asyncio.run(main())
