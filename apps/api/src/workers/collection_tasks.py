"""
Collection tasks for the worker system.
"""

import asyncio
import traceback
from typing import Any, Dict, Optional

from celery import current_task
from celery.exceptions import Retry

from src.workers.task_queue import celery_app
from src.core.logging import get_logger

logger = get_logger(__name__)


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_kwargs={"max_retries": 3, "countdown": 60})
def run_collector(
    self,
    collector_type: str,
    config: Dict[str, Any],
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute a collector task asynchronously.

    Args:
        collector_type: Type of collector to run (e.g., 'sigma', 'splunk', 'mitre')
        config: Configuration dictionary for the collector
        tenant_id: Optional tenant ID for multi-tenant isolation
        user_id: Optional user ID who initiated the task

    Returns:
        Dictionary with task results
    """

    task_id = current_task.request.id
    logger.info(f"Starting collection task {task_id} - type: {collector_type}")

    try:
        # Update task state
        current_task.update_state(
            state="PROGRESS",
            meta={"step": "initializing", "progress": 0}
        )

        # Dynamic collector import and execution
        result = asyncio.run(
            execute_collector_async(collector_type, config, task_id, tenant_id, user_id)
        )

        logger.info(f"Collection task {task_id} completed successfully")
        return {
            "task_id": task_id,
            "collector_type": collector_type,
            "status": "completed",
            "result": result,
            "tenant_id": tenant_id,
            "user_id": user_id,
        }

    except Exception as exc:
        logger.error(f"Collection task {task_id} failed: {exc}")
        logger.error(traceback.format_exc())

        # Update task state with error
        current_task.update_state(
            state="FAILURE",
            meta={
                "error": str(exc),
                "traceback": traceback.format_exc(),
                "collector_type": collector_type,
            }
        )

        # Re-raise for Celery retry mechanism
        raise exc


async def execute_collector_async(
    collector_type: str,
    config: Dict[str, Any],
    task_id: str,
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute collector asynchronously with proper error handling."""

    # Update progress
    if current_task:
        current_task.update_state(
            state="PROGRESS",
            meta={"step": "loading_collector", "progress": 10}
        )

    # Dynamic collector loading
    collector_class = await load_collector_class(collector_type)
    if not collector_class:
        raise ValueError(f"Unknown collector type: {collector_type}")

    # Add tenant context to config
    if tenant_id:
        config["tenant_id"] = tenant_id
    if user_id:
        config["user_id"] = user_id
    if task_id:
        config["task_id"] = task_id

    # Initialize and run collector
    collector = collector_class(config)

    try:
        # Execute collector pipeline
        if current_task:
            current_task.update_state(
                state="PROGRESS",
                meta={"step": "running_collector", "progress": 20}
            )

        result = await collector.run()

        if current_task:
            current_task.update_state(
                state="PROGRESS",
                meta={"step": "completed", "progress": 100}
            )

        return {
            "total_processed": result.total_processed,
            "successful": result.successful,
            "failed": result.failed,
            "errors": result.errors,
            "execution_time": result.execution_time,
        }

    finally:
        # Always cleanup
        await collector.cleanup()


async def load_collector_class(collector_type: str):
    """Dynamically load collector class based on type."""

    collector_map = {
        "sigma": ("src.collectors.detection.sigma", "SigmaCollector"),
        # Add new collectors here:
        # "splunk": ("src.collectors.siem.splunk", "SplunkCollector"),
        # "mitre": ("src.collectors.framework.mitre", "MitreCollector"),
        # "custom": ("src.collectors.custom.custom", "CustomCollector"),
    }

    if collector_type not in collector_map:
        return None

    module_path, class_name = collector_map[collector_type]

    try:
        # Dynamic import
        import importlib
        module = importlib.import_module(module_path)
        collector_class = getattr(module, class_name)
        return collector_class

    except (ImportError, AttributeError) as e:
        logger.error(f"Failed to load collector {collector_type}: {e}")
        return None


@celery_app.task(bind=True)
def schedule_recurring_collection(
    self,
    collector_type: str,
    config: Dict[str, Any],
    cron_schedule: str,
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Schedule a recurring collection task.

    Args:
        collector_type: Type of collector to run
        config: Configuration dictionary
        cron_schedule: Cron-style schedule string
        tenant_id: Optional tenant ID
        user_id: Optional user ID

    Returns:
        Dictionary with scheduling result
    """

    task_id = current_task.request.id
    logger.info(f"Scheduling recurring collection task {task_id} - type: {collector_type}")

    try:
        # Add to Celery beat scheduler
        from celery.beat import crontab
        from django_celery_beat.models import PeriodicTask, CrontabSchedule
        import json

        # Parse cron schedule
        minute, hour, day_of_month, month, day_of_week = cron_schedule.split()

        # Create or get crontab schedule
        schedule, created = CrontabSchedule.objects.get_or_create(
            minute=minute,
            hour=hour,
            day_of_week=day_of_week,
            day_of_month=day_of_month,
            month_of_year=month,
        )

        # Create periodic task
        periodic_task = PeriodicTask.objects.create(
            crontab=schedule,
            name=f"{collector_type}_recurring_{task_id}",
            task="src.workers.collection_tasks.run_collector",
            args=json.dumps([collector_type, config, tenant_id, user_id]),
        )

        logger.info(f"Created recurring task: {periodic_task.name}")

        return {
            "task_id": task_id,
            "periodic_task_id": periodic_task.id,
            "schedule": cron_schedule,
            "status": "scheduled",
        }

    except Exception as exc:
        logger.error(f"Failed to schedule recurring task: {exc}")
        raise exc