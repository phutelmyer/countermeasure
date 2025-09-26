"""
Celery application configuration for collector service.
"""

from celery import Celery
from celery.schedules import crontab

from src.core.config import BaseConfig, ConfigManager


# Load configuration
config_manager = ConfigManager(BaseConfig)
config = config_manager.load_config()

# Create Celery app
app = Celery("countermeasure_collector")

# Configuration
app.conf.update(
    broker_url=config.redis_broker_url,
    result_backend=config.redis_result_backend,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
    include=[
        "src.tasks.collect",
        "src.tasks.enrich",
        "src.tasks.validate",
    ],
)

# Beat Schedule
app.conf.beat_schedule = {
    "collect-sigma-rules": {
        "task": "src.tasks.collect.collect_sigma_rules",
        "schedule": crontab(hour=2, minute=0),  # Daily at 2 AM
        "kwargs": {
            "api_url": config.api_url,
            "limit": 100,  # Limit for scheduled collection
            "dry_run": False,
        },
    },
    "collect-sigma-github-updates": {
        "task": "src.tasks.collect.collect_sigma_rules",
        "schedule": crontab(minute=0),  # Every hour
        "kwargs": {
            "api_url": config.api_url,
            "limit": 50,  # Smaller limit for frequent updates
            "dry_run": False,
        },
    },
    "validate-detections": {
        "task": "src.tasks.validate.validate_all_rules",
        "schedule": crontab(hour=4, minute=0),  # Daily at 4 AM
    },
    "enrich-detections": {
        "task": "src.tasks.enrich.enrich_detections",
        "schedule": crontab(hour="*/6"),  # Every 6 hours
    },
}

# Use default beat scheduler (file-based)
# app.conf.beat_scheduler = 'celery.beat:PersistentScheduler'  # This is the default
