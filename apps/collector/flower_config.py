"""
Flower configuration for Countermeasure Collector monitoring.
"""

import os
from src.core.config import BaseConfig, ConfigManager

# Load configuration
config_manager = ConfigManager(BaseConfig)
config = config_manager.load_config()

# Flower configuration
# These can be overridden by command line arguments or environment variables

# Basic settings
port = int(os.environ.get('FLOWER_PORT', 5555))
address = os.environ.get('FLOWER_ADDRESS', '0.0.0.0')
broker_url = config.redis_broker_url
result_backend = config.redis_result_backend

# Authentication (basic auth for demo - use proper auth in production)
basic_auth = os.environ.get('FLOWER_BASIC_AUTH', 'admin:countermeasure123')

# UI settings
max_tasks = 10000
db = os.path.join(os.path.dirname(__file__), 'flower.db')

# URL prefix for reverse proxy support
url_prefix = os.environ.get('FLOWER_URL_PREFIX', '')

# Celery inspect timeout
inspect_timeout = 3000

# Task monitoring
persistent = True
enable_events = True

# Logging
logging_level = 'INFO'

# Security headers
xheaders = True

# Custom columns for task list
task_columns = [
    'name',
    'uuid',
    'state',
    'args',
    'kwargs',
    'result',
    'received',
    'started',
    'timestamp',
    'runtime',
    'worker',
    'retries',
]

# Auto-refresh interval (seconds)
auto_refresh = True
auto_refresh_interval = 30

# Flower configuration dictionary
flower_config = {
    'port': port,
    'address': address,
    'broker_url': broker_url,
    'result_backend': result_backend,
    'basic_auth': basic_auth,
    'max_tasks': max_tasks,
    'db': db,
    'url_prefix': url_prefix,
    'inspect_timeout': inspect_timeout,
    'persistent': persistent,
    'enable_events': enable_events,
    'logging': logging_level,
    'xheaders': xheaders,
    'auto_refresh': auto_refresh,
    'task_columns': task_columns,
}

# Custom task names for better display
task_names = {
    'src.tasks.collect.collect_sigma_rules': 'SIGMA Collection',
    'src.tasks.enrich.enrich_detections': 'Detection Enrichment',
    'src.tasks.enrich.enrich_actors': 'Actor Enrichment',
    'src.tasks.validate.validate_all_rules': 'Rule Validation',
    'src.tasks.validate.validate_sigma_rule': 'SIGMA Rule Validation',
}

# Task color coding based on status
task_colors = {
    'SUCCESS': '#5cb85c',
    'FAILURE': '#d9534f',
    'PENDING': '#f0ad4e',
    'RECEIVED': '#5bc0de',
    'STARTED': '#5bc0de',
    'RETRY': '#f0ad4e',
    'REVOKED': '#d9534f',
}

# Environment-specific overrides
if config.environment == 'production':
    # Production settings
    basic_auth = os.environ.get('FLOWER_BASIC_AUTH', 'admin:SecurePassword123!')
    logging_level = 'WARNING'
    auto_refresh_interval = 60

elif config.environment == 'development':
    # Development settings
    auto_refresh_interval = 15
    max_tasks = 1000

# Export configuration for use by startup scripts
def get_flower_command_args():
    """Get Flower command line arguments."""
    args = [
        f"--port={flower_config['port']}",
        f"--address={flower_config['address']}",
        f"--broker={flower_config['broker_url']}",
        f"--basic-auth={flower_config['basic_auth']}",
        f"--max-tasks={flower_config['max_tasks']}",
        f"--db={flower_config['db']}",
        f"--inspect-timeout={flower_config['inspect_timeout']}",
        "--persistent=True",
        "--enable-events",
        f"--logging={flower_config['logging']}",
        "--xheaders",
    ]

    if flower_config['url_prefix']:
        args.append(f"--url-prefix={flower_config['url_prefix']}")

    return args