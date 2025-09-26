# Countermeasure Collector Services

This document describes how to run and manage the Countermeasure Collector services, including Celery workers, beat scheduler, and Flower monitoring UI.

## Quick Start

### Start All Services
```bash
./collector start
```

### Check Status
```bash
./collector status
```

### Access Flower UI
Open http://localhost:5555 in your browser (default credentials: admin/countermeasure123)

### Stop All Services
```bash
./collector stop
```

## Available Services

### 1. Celery Worker
Processes background tasks for collection, enrichment, and validation.

```bash
# Start worker only
./collector worker

# Start in background
./collector worker --background
```

### 2. Celery Beat Scheduler
Manages scheduled tasks (automatic SIGMA collection, enrichment, validation).

```bash
# Start beat scheduler only
./collector beat

# Start in background
./collector beat --background
```

### 3. Flower Monitoring UI
Web-based monitoring and management interface for Celery tasks.

```bash
# Start Flower only
./collector flower

# Start in background
./collector flower --background
```

Features:
- Real-time task monitoring
- Worker status and statistics
- Task history and results
- Task retry and revoke capabilities
- Queue monitoring
- System metrics

## Scheduled Tasks

The following tasks are automatically scheduled:

| Task | Schedule | Description |
|------|----------|-------------|
| SIGMA Collection | Daily at 2 AM | Full SIGMA rule collection (100 rules) |
| SIGMA Updates | Every hour | Incremental SIGMA updates (50 rules) |
| Rule Validation | Daily at 4 AM | Validate all detection rules |
| Detection Enrichment | Every 6 hours | Enrich detection metadata |

## Manual Task Execution

### SIGMA Collection
```bash
# Collect 100 SIGMA rules
./collector collect --limit 100

# Collect with incremental updates
./collector collect --incremental --limit 50

# Dry run (no API submission)
./collector collect --dry-run --limit 10
```

### Enrichment Tasks
```bash
# Run detection enrichment
./collector enrich

# Or use Celery directly for specific parameters
uv run celery -A src.schedulers.celery_app:app call src.tasks.enrich.enrich_detections --kwargs='{"tenant_id": "specific-tenant"}'
```

### Validation Tasks
```bash
# Run validation on all rules
./collector validate

# Or use Celery directly
uv run celery -A src.schedulers.celery_app:app call src.tasks.validate.validate_all_rules
```

## Collection History

View collection history and statistics:

```bash
# List recent collection runs
./collector history list

# Show detailed run information
./collector history show <run_id>

# Show collection statistics
./collector history stats

# Show stats for last 7 days
./collector history stats --days 7

# Clean up old history (keep last 30 days)
./collector history cleanup --keep-days 30
```

## Configuration

### Environment Variables

Create a `.env` file in the collector directory:

```env
# Redis Configuration
REDIS_BROKER_URL=redis://localhost:6379/0
REDIS_RESULT_BACKEND=redis://localhost:6379/0

# API Configuration
API_URL=http://localhost:8000
DEFAULT_EMAIL=admin@countermeasure.dev
DEFAULT_PASSWORD=CountermeasureAdmin123!

# Flower Configuration
FLOWER_PORT=5555
FLOWER_ADDRESS=0.0.0.0
FLOWER_BASIC_AUTH=admin:countermeasure123

# Logging
LOG_LEVEL=INFO
```

### Flower Authentication

For production, set a secure password:

```bash
export FLOWER_BASIC_AUTH="admin:SecurePassword123!"
```

Or configure OAuth/LDAP authentication in `flower_config.py`.

## Monitoring and Troubleshooting

### Check Service Status
```bash
./collector status
```

### View Recent Logs
```bash
./collector logs
```

### Common Issues

1. **Redis Connection Failed**
   - Ensure Redis is running: `redis-server`
   - Check connection: `redis-cli ping`

2. **Tasks Stuck in PENDING**
   - Check worker status in Flower
   - Restart worker: `./collector stop && ./collector worker`

3. **Permission Errors**
   - Check file permissions: `chmod +x collector`
   - Ensure PID directory is writable: `mkdir -p .pids`

4. **API Connection Issues**
   - Verify API is running: `curl http://localhost:8000/health`
   - Check credentials in `.env`

### Performance Tuning

For high-volume processing, adjust worker settings in `start_services.py`:

```python
# Increase worker concurrency
"--concurrency=8",

# Adjust prefetch multiplier
worker_prefetch_multiplier=2,

# Increase task limits
task_time_limit=60 * 60,  # 60 minutes
```

## Integration with Main Application

The collector integrates with the main Countermeasure API:

1. **Authentication**: Uses API credentials for secure access
2. **Multi-tenancy**: Supports tenant-specific operations
3. **Audit Logging**: All operations are logged for compliance
4. **Rate Limiting**: Respects API rate limits

## Production Deployment

### Docker Deployment

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY . .

RUN pip install uv && uv sync

# Start services
CMD ["./collector", "start", "--background"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: collector-worker
spec:
  replicas: 3
  selector:
    matchLabels:
      app: collector-worker
  template:
    metadata:
      labels:
        app: collector-worker
    spec:
      containers:
      - name: worker
        image: countermeasure/collector
        command: ["./collector", "worker", "--background"]
        env:
        - name: REDIS_BROKER_URL
          value: "redis://redis-service:6379/0"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: collector-flower
spec:
  replicas: 1
  selector:
    matchLabels:
      app: collector-flower
  template:
    metadata:
      labels:
        app: collector-flower
    spec:
      containers:
      - name: flower
        image: countermeasure/collector
        command: ["./collector", "flower", "--background"]
        ports:
        - containerPort: 5555
```

### Monitoring

Use Prometheus metrics from Flower:
- Worker health and performance
- Task success/failure rates
- Queue lengths and processing times
- System resource usage

## Security Considerations

1. **Authentication**: Change default Flower credentials
2. **Network Access**: Restrict Flower UI access to admin networks
3. **API Keys**: Use secure API credentials
4. **Redis Security**: Enable Redis AUTH and encryption
5. **Log Rotation**: Configure log rotation to prevent disk filling

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review logs: `./collector logs`
3. Check service status: `./collector status`
4. View task history in Flower UI
5. Consult the main application documentation