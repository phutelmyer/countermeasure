"""
Task queue system using Celery with Redis backend.
"""

import os
from typing import Any, Dict, List, Optional
from celery import Celery
from pydantic import BaseModel
from enum import Enum

from src.core.config import get_settings

settings = get_settings()


class TaskStatus(str, Enum):
    PENDING = "pending"
    STARTED = "started"
    SUCCESS = "success"
    FAILURE = "failure"
    RETRY = "retry"
    REVOKED = "revoked"


class TaskPriority(int, Enum):
    LOW = 0
    NORMAL = 5
    HIGH = 10
    CRITICAL = 15


class CollectionTask(BaseModel):
    """Task definition for collection jobs."""

    task_id: str
    collector_type: str
    config: Dict[str, Any]
    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    priority: TaskPriority = TaskPriority.NORMAL
    max_retries: int = 3
    retry_delay: int = 60  # seconds
    scheduled_at: Optional[str] = None  # ISO format datetime


# Initialize Celery app
def create_celery_app() -> Celery:
    """Create and configure Celery application."""

    # Redis URL from settings
    broker_url = settings.redis_url
    result_backend = settings.redis_url

    app = Celery(
        "countermeasure_workers",
        broker=broker_url,
        backend=result_backend,
        include=[
            "src.workers.collection_tasks",
            "src.workers.processing_tasks",
            "src.workers.maintenance_tasks",
        ]
    )

    app.conf.update(
        # Task settings
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        result_expires=3600,  # 1 hour
        timezone="UTC",
        enable_utc=True,

        # Worker settings
        worker_prefetch_multiplier=1,  # Don't prefetch tasks
        task_acks_late=True,  # Acknowledge after completion
        worker_max_tasks_per_child=1000,  # Restart workers periodically

        # Routing
        task_routes={
            "src.workers.collection_tasks.*": {"queue": "collection"},
            "src.workers.processing_tasks.*": {"queue": "processing"},
            "src.workers.maintenance_tasks.*": {"queue": "maintenance"},
        },

        # Priority queues
        task_queue_max_priority=15,
        task_default_priority=5,

        # Retry settings
        task_default_retry_delay=60,
        task_max_retries=3,

        # Monitoring
        worker_send_task_events=True,
        task_send_sent_event=True,
    )

    return app


# Global celery instance
celery_app = create_celery_app()


class TaskManager:
    """High-level interface for managing tasks."""

    def __init__(self):
        self.app = celery_app

    def submit_collection_task(
        self,
        collector_type: str,
        config: Dict[str, Any],
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        schedule_at: Optional[str] = None,
    ) -> str:
        """Submit a collection task to the queue."""

        from src.workers.collection_tasks import run_collector

        task_args = [collector_type, config, tenant_id, user_id]
        task_kwargs = {}

        # Schedule task
        if schedule_at:
            result = run_collector.apply_async(
                args=task_args,
                kwargs=task_kwargs,
                eta=schedule_at,
                priority=priority.value,
            )
        else:
            result = run_collector.apply_async(
                args=task_args,
                kwargs=task_kwargs,
                priority=priority.value,
            )

        return result.id

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get the status of a task."""
        result = self.app.AsyncResult(task_id)

        return {
            "task_id": task_id,
            "status": result.status,
            "result": result.result if result.successful() else None,
            "error": str(result.result) if result.failed() else None,
            "traceback": result.traceback if result.failed() else None,
        }

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a task."""
        try:
            self.app.control.revoke(task_id, terminate=True)
            return True
        except Exception:
            return False

    def list_active_tasks(self) -> List[Dict[str, Any]]:
        """List all active tasks."""
        inspect = self.app.control.inspect()
        active_tasks = inspect.active()

        if not active_tasks:
            return []

        # Flatten tasks from all workers
        all_tasks = []
        for worker, tasks in active_tasks.items():
            for task in tasks:
                task["worker"] = worker
                all_tasks.append(task)

        return all_tasks

    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        inspect = self.app.control.inspect()

        return {
            "active": inspect.active(),
            "scheduled": inspect.scheduled(),
            "reserved": inspect.reserved(),
            "stats": inspect.stats(),
        }


# Global task manager instance
task_manager = TaskManager()