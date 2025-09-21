"""
Celery application configuration for collector service.
"""

from celery import Celery
from celery.schedules import crontab

# Create Celery app
app = Celery('countermeasure_collector')

# Configuration
app.conf.update(
    broker_url='redis://localhost:6379/0',
    result_backend='redis://localhost:6379/1',
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
    include=[
        'src.tasks.collect',
        'src.tasks.enrich',
        'src.tasks.validate',
    ]
)

# Beat Schedule
app.conf.beat_schedule = {
    'collect-sigma-rules': {
        'task': 'src.tasks.collect.collect_sigma_rules',
        'schedule': crontab(hour=2, minute=0),  # Daily at 2 AM
        'kwargs': {
            'api_url': 'http://localhost:8000',
            'limit': 100,  # Limit for scheduled collection
            'dry_run': False
        }
    },
    'collect-sigma-github-updates': {
        'task': 'src.tasks.collect.collect_sigma_rules',
        'schedule': crontab(minute=0),  # Every hour
        'kwargs': {
            'api_url': 'http://localhost:8000',
            'limit': 50,  # Smaller limit for frequent updates
            'dry_run': False
        }
    },
    'validate-detections': {
        'task': 'src.tasks.validate.validate_all_rules',
        'schedule': crontab(hour=4, minute=0),  # Daily at 4 AM
    },
    'enrich-detections': {
        'task': 'src.tasks.enrich.enrich_detections',
        'schedule': crontab(hour='*/6'),  # Every 6 hours
    },
}

app.conf.beat_scheduler = 'django_celery_beat.schedulers:DatabaseScheduler'