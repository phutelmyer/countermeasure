"""
Enrichment tasks for Celery.
"""

import asyncio
from typing import Any, Dict, List

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.api_client import CountermeasureClient
from src.core.config import settings
from src.core.logging import get_logger
from src.db.session import async_session_maker
from src.schedulers.celery_app import app


logger = get_logger(__name__)


@app.task
def enrich_detections(
    tenant_id: str = None,
    detection_ids: List[str] = None,
    enrich_types: List[str] = None
):
    """
    Celery task to enrich existing detection rules with additional metadata.

    Args:
        tenant_id: Specific tenant to enrich (optional)
        detection_ids: Specific detection IDs to enrich (optional)
        enrich_types: Types of enrichment to perform (optional)
    """
    logger.info("Starting detection enrichment task")

    # Use asyncio to run the async enrichment function
    result = asyncio.run(_enrich_detections_async(tenant_id, detection_ids, enrich_types))
    return result


async def _enrich_detections_async(
    tenant_id: str = None,
    detection_ids: List[str] = None,
    enrich_types: List[str] = None
) -> Dict[str, Any]:
    """
    Async implementation of detection enrichment.
    """
    try:
        async with async_session_maker() as db:
            # Import here to avoid circular imports
            from src.db.models import Detection, MitreTechnique, Actor

            enriched_count = 0
            failed_count = 0

            # Build query for detections to enrich
            query = select(Detection)

            if tenant_id:
                query = query.where(Detection.tenant_id == tenant_id)

            if detection_ids:
                query = query.where(Detection.id.in_(detection_ids))

            # Limit to prevent overwhelming the system
            query = query.limit(1000)

            result = await db.execute(query)
            detections = result.scalars().all()

            logger.info(f"Found {len(detections)} detections to enrich")

            for detection in detections:
                try:
                    updated = False

                    # Enrich MITRE mappings
                    if not enrich_types or "mitre" in enrich_types:
                        updated |= await _enrich_mitre_mappings(db, detection)

                    # Enrich confidence scores
                    if not enrich_types or "confidence" in enrich_types:
                        updated |= await _enrich_confidence_score(db, detection)

                    # Enrich threat actor associations
                    if not enrich_types or "actors" in enrich_types:
                        updated |= await _enrich_actor_associations(db, detection)

                    # Update metadata fields
                    if not enrich_types or "metadata" in enrich_types:
                        updated |= await _enrich_metadata_fields(db, detection)

                    if updated:
                        enriched_count += 1
                        await db.commit()

                except Exception as e:
                    logger.error(f"Failed to enrich detection {detection.id}: {e}")
                    failed_count += 1
                    await db.rollback()

            logger.info(f"Enrichment complete: {enriched_count} updated, {failed_count} failed")

            return {
                "status": "completed",
                "enriched_count": enriched_count,
                "failed_count": failed_count,
                "total_processed": len(detections)
            }

    except Exception as e:
        logger.error(f"Detection enrichment task failed: {e}")
        return {
            "status": "failed",
            "error": str(e)
        }


async def _enrich_mitre_mappings(db: AsyncSession, detection) -> bool:
    """Enrich detection with MITRE ATT&CK technique mappings."""
    try:
        # Simple keyword-based MITRE mapping
        rule_content = detection.rule_content or ""
        name = detection.name or ""
        description = detection.description or ""

        # Combine text for analysis
        text_content = f"{name} {description} {rule_content}".lower()

        # Import here to avoid circular imports
        from src.db.models import MitreTechnique

        # Get MITRE techniques
        result = await db.execute(select(MitreTechnique))
        techniques = result.scalars().all()

        matched_techniques = []

        # Simple keyword matching for common techniques
        technique_keywords = {
            "T1059": ["command", "script", "powershell", "cmd", "bash"],
            "T1055": ["inject", "process injection", "dll"],
            "T1003": ["credential", "password", "hash", "dump"],
            "T1082": ["system information", "discovery", "enumerate"],
            "T1083": ["file discovery", "directory", "listing"],
            "T1057": ["process discovery", "tasklist", "ps"],
            "T1018": ["network", "discovery", "ping", "arp"],
            "T1071": ["http", "https", "web", "application layer"],
            "T1090": ["proxy", "connection", "proxy"],
            "T1105": ["download", "upload", "transfer", "ingress"],
        }

        for technique_id, keywords in technique_keywords.items():
            if any(keyword in text_content for keyword in keywords):
                # Find the technique in our database
                for technique in techniques:
                    if technique.technique_id == technique_id:
                        matched_techniques.append(technique.technique_id)
                        break

        # Update detection if we found new techniques
        if matched_techniques and not detection.mitre_technique_ids:
            detection.mitre_technique_ids = matched_techniques
            logger.debug(f"Added MITRE techniques {matched_techniques} to detection {detection.id}")
            return True

    except Exception as e:
        logger.warning(f"Failed to enrich MITRE mappings for {detection.id}: {e}")

    return False


async def _enrich_confidence_score(db: AsyncSession, detection) -> bool:
    """Enrich detection confidence score based on various factors."""
    try:
        # Calculate confidence based on rule characteristics
        score = 0.5  # Base score

        # Factors that increase confidence
        if detection.author and detection.author != "unknown":
            score += 0.1

        if detection.mitre_technique_ids:
            score += 0.1

        if detection.platforms and len(detection.platforms) > 0:
            score += 0.1

        if detection.data_sources and len(detection.data_sources) > 0:
            score += 0.1

        if detection.false_positives and len(detection.false_positives) > 0:
            score += 0.1  # Having documented false positives is good

        # Rule content quality indicators
        rule_content = detection.rule_content or ""
        if "selection:" in rule_content and "condition:" in rule_content:
            score += 0.1

        # Cap at 1.0
        score = min(score, 1.0)

        # Only update if significantly different
        if abs((detection.confidence_score or 0.5) - score) > 0.05:
            detection.confidence_score = score
            logger.debug(f"Updated confidence score for {detection.id}: {score:.2f}")
            return True

    except Exception as e:
        logger.warning(f"Failed to enrich confidence score for {detection.id}: {e}")

    return False


async def _enrich_actor_associations(db: AsyncSession, detection) -> bool:
    """Enrich detection with threat actor associations."""
    try:
        # Import here to avoid circular imports
        from src.db.models import Actor

        # Get all actors
        result = await db.execute(select(Actor))
        actors = result.scalars().all()

        # Simple keyword-based actor matching
        text_content = f"{detection.name or ''} {detection.description or ''}".lower()

        matched_actors = []

        for actor in actors:
            # Check if actor name or aliases appear in detection
            if actor.name and actor.name.lower() in text_content:
                matched_actors.append(actor.id)

            # Check aliases if available
            if hasattr(actor, 'aliases') and actor.aliases:
                for alias in actor.aliases:
                    if alias.lower() in text_content:
                        matched_actors.append(actor.id)
                        break

        # Update detection if we found associations
        if matched_actors:
            # Convert to strings for storage
            detection.threat_actor_ids = [str(actor_id) for actor_id in matched_actors]
            logger.debug(f"Added actor associations {matched_actors} to detection {detection.id}")
            return True

    except Exception as e:
        logger.warning(f"Failed to enrich actor associations for {detection.id}: {e}")

    return False


async def _enrich_metadata_fields(db: AsyncSession, detection) -> bool:
    """Enrich detection metadata fields."""
    try:
        updated = False

        # Ensure platforms are properly set
        if not detection.platforms:
            rule_content = detection.rule_content or ""
            name = detection.name or ""

            platforms = []
            if any(term in rule_content.lower() or term in name.lower()
                   for term in ['windows', 'sysmon', 'eventlog', 'winlog']):
                platforms.append('Windows')
            if any(term in rule_content.lower() or term in name.lower()
                   for term in ['linux', 'unix', 'syslog', 'bash']):
                platforms.append('Linux')
            if any(term in rule_content.lower() or term in name.lower()
                   for term in ['macos', 'darwin', 'osx']):
                platforms.append('macOS')

            if platforms:
                detection.platforms = platforms
                updated = True

        # Ensure data sources are properly set
        if not detection.data_sources:
            rule_content = detection.rule_content or ""

            data_sources = []
            if 'process_creation' in rule_content.lower():
                data_sources.append('Process Creation')
            if 'network' in rule_content.lower():
                data_sources.append('Network Connection')
            if 'file' in rule_content.lower():
                data_sources.append('File Monitoring')
            if 'registry' in rule_content.lower():
                data_sources.append('Windows Registry')

            if data_sources:
                detection.data_sources = data_sources
                updated = True

        return updated

    except Exception as e:
        logger.warning(f"Failed to enrich metadata for {detection.id}: {e}")

    return False


@app.task
def enrich_actors(
    tenant_id: str = None,
    actor_ids: List[str] = None,
    enrich_types: List[str] = None
):
    """
    Celery task to enrich threat actor data with external intelligence.

    Args:
        tenant_id: Specific tenant to enrich (optional)
        actor_ids: Specific actor IDs to enrich (optional)
        enrich_types: Types of enrichment to perform (optional)
    """
    logger.info("Starting actor enrichment task")

    # Use asyncio to run the async enrichment function
    result = asyncio.run(_enrich_actors_async(tenant_id, actor_ids, enrich_types))
    return result


async def _enrich_actors_async(
    tenant_id: str = None,
    actor_ids: List[str] = None,
    enrich_types: List[str] = None
) -> Dict[str, Any]:
    """
    Async implementation of actor enrichment.
    """
    try:
        async with async_session_maker() as db:
            # Import here to avoid circular imports
            from src.db.models import Actor, Detection

            enriched_count = 0
            failed_count = 0

            # Build query for actors to enrich
            query = select(Actor)

            if tenant_id:
                query = query.where(Actor.tenant_id == tenant_id)

            if actor_ids:
                query = query.where(Actor.id.in_(actor_ids))

            # Limit to prevent overwhelming the system
            query = query.limit(100)

            result = await db.execute(query)
            actors = result.scalars().all()

            logger.info(f"Found {len(actors)} actors to enrich")

            for actor in actors:
                try:
                    updated = False

                    # Enrich attribution confidence
                    if not enrich_types or "confidence" in enrich_types:
                        updated |= await _enrich_actor_confidence(db, actor)

                    # Enrich associated detections count
                    if not enrich_types or "detections" in enrich_types:
                        updated |= await _enrich_actor_detection_associations(db, actor)

                    # Enrich metadata fields
                    if not enrich_types or "metadata" in enrich_types:
                        updated |= await _enrich_actor_metadata(db, actor)

                    # Enrich campaign associations
                    if not enrich_types or "campaigns" in enrich_types:
                        updated |= await _enrich_actor_campaigns(db, actor)

                    if updated:
                        enriched_count += 1
                        await db.commit()

                except Exception as e:
                    logger.error(f"Failed to enrich actor {actor.id}: {e}")
                    failed_count += 1
                    await db.rollback()

            logger.info(f"Actor enrichment complete: {enriched_count} updated, {failed_count} failed")

            return {
                "status": "completed",
                "enriched_count": enriched_count,
                "failed_count": failed_count,
                "total_processed": len(actors)
            }

    except Exception as e:
        logger.error(f"Actor enrichment task failed: {e}")
        return {
            "status": "failed",
            "error": str(e)
        }


async def _enrich_actor_confidence(db: AsyncSession, actor) -> bool:
    """Enrich actor attribution confidence score."""
    try:
        # Calculate confidence based on available data
        score = 0.3  # Base score for having an entry

        # Factors that increase confidence
        if actor.aliases and len(actor.aliases) > 1:
            score += 0.1

        if hasattr(actor, 'description') and actor.description:
            score += 0.1

        if hasattr(actor, 'country') and actor.country:
            score += 0.1

        if hasattr(actor, 'first_seen') and actor.first_seen:
            score += 0.1

        if hasattr(actor, 'motivation') and actor.motivation:
            score += 0.1

        # Attribution quality indicators
        if hasattr(actor, 'sophistication') and actor.sophistication:
            if actor.sophistication in ['expert', 'advanced']:
                score += 0.15
            elif actor.sophistication in ['intermediate']:
                score += 0.1

        # Cap at 1.0
        score = min(score, 1.0)

        # Only update if significantly different
        current_score = getattr(actor, 'attribution_confidence', 0.3)
        if abs(current_score - score) > 0.05:
            actor.attribution_confidence = score
            logger.debug(f"Updated attribution confidence for {actor.id}: {score:.2f}")
            return True

    except Exception as e:
        logger.warning(f"Failed to enrich actor confidence for {actor.id}: {e}")

    return False


async def _enrich_actor_detection_associations(db: AsyncSession, actor) -> bool:
    """Enrich actor with associated detection counts."""
    try:
        # Import here to avoid circular imports
        from src.db.models import Detection

        # Count detections associated with this actor
        result = await db.execute(
            select(Detection).where(
                Detection.threat_actor_ids.contains([str(actor.id)])
            )
        )
        associated_detections = result.scalars().all()

        detection_count = len(associated_detections)

        # Update if different
        current_count = getattr(actor, 'associated_detections_count', 0)
        if current_count != detection_count:
            actor.associated_detections_count = detection_count
            logger.debug(f"Updated detection count for {actor.id}: {detection_count}")
            return True

    except Exception as e:
        logger.warning(f"Failed to enrich actor detection associations for {actor.id}: {e}")

    return False


async def _enrich_actor_metadata(db: AsyncSession, actor) -> bool:
    """Enrich actor metadata fields."""
    try:
        updated = False

        # Standardize country codes
        if hasattr(actor, 'country') and actor.country:
            country_mappings = {
                'russia': 'RU',
                'china': 'CN',
                'north korea': 'KP',
                'iran': 'IR',
                'united states': 'US',
                'usa': 'US',
            }

            country_lower = actor.country.lower()
            if country_lower in country_mappings and actor.country != country_mappings[country_lower]:
                actor.country = country_mappings[country_lower]
                updated = True

        # Normalize motivation fields
        if hasattr(actor, 'motivation') and actor.motivation:
            motivation_mappings = {
                'financial': 'Financial',
                'espionage': 'Espionage',
                'hacktivism': 'Hacktivism',
                'nation-state': 'Nation-State',
                'cyber-crime': 'Cybercrime',
            }

            motivation_lower = actor.motivation.lower()
            if motivation_lower in motivation_mappings and actor.motivation != motivation_mappings[motivation_lower]:
                actor.motivation = motivation_mappings[motivation_lower]
                updated = True

        return updated

    except Exception as e:
        logger.warning(f"Failed to enrich actor metadata for {actor.id}: {e}")

    return False


async def _enrich_actor_campaigns(db: AsyncSession, actor) -> bool:
    """Enrich actor with campaign associations."""
    try:
        # For now, this is a placeholder for future campaign functionality
        # In a real implementation, this would:
        # - Look up campaigns associated with this actor
        # - Update campaign relationships
        # - Calculate campaign timeline overlaps
        # - Identify common TTPs across campaigns

        # Check if actor has campaign data to update
        if hasattr(actor, 'campaigns') and not actor.campaigns:
            # Simple example: extract potential campaign names from description
            if hasattr(actor, 'description') and actor.description:
                description = actor.description.lower()

                # Look for common campaign naming patterns
                campaign_keywords = ['operation', 'campaign', 'apt', 'group']

                # This is very simplified - in reality you'd use more sophisticated NLP
                # and integrate with threat intelligence feeds
                if any(keyword in description for keyword in campaign_keywords):
                    # Mark that this actor might have campaign associations
                    # that need manual review
                    if not hasattr(actor, 'needs_campaign_review'):
                        actor.needs_campaign_review = True
                        logger.debug(f"Marked actor {actor.id} for campaign review")
                        return True

    except Exception as e:
        logger.warning(f"Failed to enrich actor campaigns for {actor.id}: {e}")

    return False
