"""
Collection tasks for Celery.
"""

import os
from typing import Dict, Any

from src.schedulers.celery_app import app
from src.collectors.detection.sigma import SigmaCollector
from src.core.logging import get_logger

logger = get_logger(__name__)


@app.task(bind=True, retry_delay=60, max_retries=3)
def collect_sigma_rules(self, api_url: str, email: str = None, password: str = None, **kwargs):
    """
    Celery task to collect SIGMA rules.

    Args:
        api_url: Countermeasure API base URL
        email: Admin email (will use env var if not provided)
        password: Admin password (will use env var if not provided)
        **kwargs: Additional configuration options
    """
    try:
        # Get credentials from environment if not provided
        email = email or os.getenv('COUNTERMEASURE_EMAIL')
        password = password or os.getenv('COUNTERMEASURE_PASSWORD')

        if not email or not password:
            raise ValueError("Email and password must be provided or set in environment variables")

        # Build configuration
        config = {
            'api_url': api_url,
            'email': email,
            'password': password,
            'repo_url': kwargs.get('repo_url', 'https://github.com/SigmaHQ/sigma.git'),
            'categories': kwargs.get('categories', []),
            'limit': kwargs.get('limit'),
            'batch_size': kwargs.get('batch_size', 50),
            'dry_run': kwargs.get('dry_run', False)
        }

        logger.info(f"Starting SIGMA collection task with config: {config}")

        # Create and run collector
        collector = SigmaCollector(config)
        result = await collector.run()

        # Log results
        logger.info(
            f"SIGMA collection completed: {result.successful} successful, "
            f"{result.failed} failed, {result.execution_time:.2f}s"
        )

        return {
            'status': 'success',
            'total_processed': result.total_processed,
            'successful': result.successful,
            'failed': result.failed,
            'execution_time': result.execution_time,
            'errors': result.errors[:10]  # Limit error list for task result
        }

    except Exception as e:
        logger.error(f"SIGMA collection task failed: {str(e)}")
        # Retry task if within retry limits
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying task (attempt {self.request.retries + 1}/{self.max_retries})")
            raise self.retry(countdown=60 * (self.request.retries + 1))

        return {
            'status': 'failed',
            'error': str(e),
            'retries': self.request.retries
        }


@app.task
def collect_custom_rules(config: Dict[str, Any]):
    """
    Celery task to collect custom detection rules from various sources.

    Args:
        config: Configuration dictionary for custom collection
    """
    logger.info(f"Starting custom rule collection with config: {config}")

    # TODO: Implement custom rule collection logic
    # This could include:
    # - Local file system scanning
    # - Custom GitHub repositories
    # - MISP feeds
    # - Custom APIs

    return {
        'status': 'not_implemented',
        'message': 'Custom rule collection not yet implemented'
    }