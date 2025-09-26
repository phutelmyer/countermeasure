# Countermeasure Platform Troubleshooting Guide

## Overview

This guide helps diagnose and resolve common issues with the Countermeasure platform. It covers API, collector, database, and infrastructure problems with step-by-step solutions.

## Quick Diagnostics

### Health Check Commands

```bash
# Check API health
curl -f http://localhost:8000/health

# Check database connectivity
pg_isready -h localhost -U countermeasure

# Check Redis connectivity (if used)
redis-cli -h localhost ping

# Check service status
systemctl status countermeasure-api
systemctl status postgresql
systemctl status redis
```

### Log Locations

```bash
# API logs (development)
tail -f apps/api/logs/api.log

# API logs (production Docker)
docker logs -f countermeasure-api

# API logs (systemd)
journalctl -u countermeasure-api -f

# Database logs
tail -f /var/log/postgresql/postgresql-15-main.log

# Nginx logs
tail -f /var/log/nginx/error.log
tail -f /var/log/nginx/access.log
```

## API Issues

### 1. API Server Won't Start

#### Symptoms
- `uvicorn` command fails to start
- "Address already in use" error
- Application crashes on startup

#### Diagnostic Steps
```bash
# Check if port is in use
lsof -i :8000
netstat -tulpn | grep :8000

# Check for orphaned processes
ps aux | grep uvicorn
ps aux | grep python

# Check configuration
cd apps/api
uv run python -c "from src.core.config import settings; print(settings.dict())"
```

#### Solutions

**Port Already in Use:**
```bash
# Kill existing processes
sudo kill -9 $(lsof -t -i:8000)

# Or use different port
uv run uvicorn src.main:app --port 8001
```

**Configuration Errors:**
```bash
# Validate environment file
cd apps/api
cat .env

# Check database URL format
echo $DATABASE_URL

# Test database connection
uv run python -c "
from sqlalchemy import create_engine
from src.core.config import settings
engine = create_engine(settings.database_url.replace('+asyncpg', ''))
conn = engine.connect()
print('Database connection successful')
conn.close()
"
```

**Missing Dependencies:**
```bash
# Reinstall dependencies
cd apps/api
uv sync --all-extras --dev

# Check Python version
python --version  # Should be 3.12+
```

### 2. Database Connection Errors

#### Symptoms
- "Connection refused" errors
- "Authentication failed" errors
- Timeout errors

#### Diagnostic Steps
```bash
# Check PostgreSQL service
sudo systemctl status postgresql

# Test direct connection
psql -h localhost -U countermeasure -d countermeasure

# Check database logs
sudo tail -f /var/log/postgresql/postgresql-15-main.log

# Verify configuration
cat apps/api/.env | grep DATABASE
```

#### Solutions

**Service Not Running:**
```bash
# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Check status
sudo systemctl status postgresql
```

**Authentication Issues:**
```bash
# Reset password
sudo -u postgres psql
ALTER USER countermeasure PASSWORD 'newpassword';
\q

# Update environment file
sed -i 's/old_password/newpassword/g' apps/api/.env
```

**Connection Configuration:**
```bash
# Check pg_hba.conf
sudo nano /etc/postgresql/15/main/pg_hba.conf

# Add or modify line for local connections:
# local   all             countermeasure                          md5
# host    all             countermeasure  127.0.0.1/32           md5

# Restart PostgreSQL
sudo systemctl restart postgresql
```

### 3. Authentication Problems

#### Symptoms
- "Invalid credentials" errors
- Token verification failures
- 401 Unauthorized responses

#### Diagnostic Steps
```bash
# Test admin login
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=admin@countermeasure.dev&password=CountermeasureAdmin123!"

# Check user exists in database
cd apps/api
uv run python -c "
from src.db.session import SessionLocal
from src.db.models import User
from sqlalchemy import select

with SessionLocal() as db:
    result = db.execute(select(User).where(User.email == 'admin@countermeasure.dev'))
    user = result.scalar_one_or_none()
    if user:
        print(f'User found: {user.email}, Active: {user.is_active}')
    else:
        print('Admin user not found')
"

# Verify JWT secret
echo $SECRET_KEY
```

#### Solutions

**Admin User Missing:**
```bash
# Reinitialize database
cd apps/api
uv run python -m src.db.init_db
```

**Wrong Secret Key:**
```bash
# Generate new secret key
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Update .env file
echo "SECRET_KEY=your_new_secret_key" >> apps/api/.env
```

**Token Verification Errors:**
```bash
# Check token manually
uv run python -c "
from src.core.security import verify_token
token = 'your_token_here'
try:
    payload = verify_token(token)
    print('Token valid:', payload)
except Exception as e:
    print('Token invalid:', e)
"
```

### 4. Performance Issues

#### Symptoms
- Slow API responses
- High CPU/memory usage
- Database query timeouts

#### Diagnostic Steps
```bash
# Monitor system resources
htop
iotop
free -h
df -h

# Check API response times
curl -w "@curl-format.txt" -o /dev/null -s "http://localhost:8000/health"

# Create curl-format.txt:
echo '     time_namelookup:  %{time_namelookup}\n
        time_connect:  %{time_connect}\n
     time_appconnect:  %{time_appconnect}\n
    time_pretransfer:  %{time_pretransfer}\n
       time_redirect:  %{time_redirect}\n
  time_starttransfer:  %{time_starttransfer}\n
                     ----------\n
          time_total:  %{time_total}\n' > curl-format.txt

# Monitor database queries
sudo -u postgres psql -c "
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements
ORDER BY total_time DESC
LIMIT 10;
"
```

#### Solutions

**Database Optimization:**
```sql
-- Connect to database
\c countermeasure

-- Analyze tables
ANALYZE;

-- Check for missing indexes
SELECT schemaname, tablename, attname, n_distinct, correlation
FROM pg_stats
WHERE schemaname = 'public'
ORDER BY n_distinct DESC;

-- Add common indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_detections_tenant_status
ON detections(tenant_id, status);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_detections_platforms_gin
ON detections USING GIN(platforms);

-- Vacuum tables
VACUUM ANALYZE detections;
VACUUM ANALYZE actors;
```

**API Optimization:**
```bash
# Increase worker count
uv run uvicorn src.main:app --workers 4

# Add connection pooling
# Update DATABASE_POOL_SIZE in .env
echo "DATABASE_POOL_SIZE=20" >> apps/api/.env
echo "DATABASE_MAX_OVERFLOW=30" >> apps/api/.env
```

**System Optimization:**
```bash
# Increase file descriptor limits
echo "fs.file-max = 65536" | sudo tee -a /etc/sysctl.conf
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Reload settings
sudo sysctl -p
```

## Collector Issues

### 1. Collection Jobs Failing

#### Symptoms
- SIGMA rules not importing
- Celery task failures
- API submission errors

#### Diagnostic Steps
```bash
# Check collector logs
cd apps/collector
tail -f logs/collector.log

# Test API connectivity
curl -f http://localhost:8000/health

# Check Celery worker status
celery -A src.schedulers.celery_app inspect active

# Test manual collection
uv run python -m src.collectors.detection.sigma --limit 10 --dry-run
```

#### Solutions

**API Connection Issues:**
```bash
# Test authentication
cd apps/collector
uv run python -c "
import asyncio
from src.core.api_client import CountermeasureClient

async def test():
    client = CountermeasureClient(
        'http://localhost:8000',
        'admin@countermeasure.dev',
        'CountermeasureAdmin123!'
    )
    success = await client.login()
    print(f'Login successful: {success}')
    await client.close()

asyncio.run(test())
"
```

**Git Repository Issues:**
```bash
# Clear cache and retry
rm -rf /tmp/sigma_repo
cd apps/collector
uv run python -m src.collectors.detection.sigma --limit 10
```

**Permission Issues:**
```bash
# Check file permissions
ls -la /tmp/sigma_repo

# Fix permissions
chmod -R 755 /tmp/sigma_repo
```

### 2. Celery Worker Problems

#### Symptoms
- Workers not starting
- Tasks stuck in pending
- Redis connection errors

#### Diagnostic Steps
```bash
# Check Redis connection
redis-cli ping

# Check Celery configuration
cd apps/collector
uv run python -c "
from src.schedulers.celery_app import app
print('Broker URL:', app.conf.broker_url)
print('Result backend:', app.conf.result_backend)
"

# List active workers
celery -A src.schedulers.celery_app inspect active

# Check task queues
celery -A src.schedulers.celery_app inspect reserved
```

#### Solutions

**Redis Not Running:**
```bash
# Start Redis
sudo systemctl start redis
sudo systemctl enable redis

# Or with Docker
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

**Worker Start Issues:**
```bash
# Kill existing workers
pkill -f celery

# Start worker with debug
cd apps/collector
celery -A src.schedulers.celery_app worker --loglevel=debug

# Start beat scheduler
celery -A src.schedulers.celery_app beat --loglevel=info
```

**Task Routing Issues:**
```bash
# Purge all tasks
celery -A src.schedulers.celery_app purge

# Restart workers
pkill -f celery
celery -A src.schedulers.celery_app worker --loglevel=info &
```

## Database Issues

### 1. Migration Problems

#### Symptoms
- Migration failures
- Schema inconsistencies
- Duplicate key errors

#### Diagnostic Steps
```bash
# Check migration status
cd apps/api
uv run alembic current

# Show migration history
uv run alembic history --verbose

# Check database schema
psql -h localhost -U countermeasure -d countermeasure -c "\dt"
```

#### Solutions

**Migration Conflicts:**
```bash
# Show current revision
uv run alembic current

# Check for conflicts
uv run alembic check

# Manual resolution if needed
uv run alembic stamp head
uv run alembic upgrade head
```

**Schema Inconsistencies:**
```bash
# Drop and recreate (development only!)
cd apps/api
psql -h localhost -U countermeasure -c "DROP DATABASE countermeasure;"
psql -h localhost -U countermeasure -c "CREATE DATABASE countermeasure;"

# Recreate schema
uv run alembic upgrade head
uv run python -m src.db.init_db
```

### 2. Performance Issues

#### Symptoms
- Slow queries
- High CPU usage
- Connection timeouts

#### Diagnostic Steps
```bash
# Check active connections
psql -h localhost -U countermeasure -d countermeasure -c "
SELECT count(*) as active_connections
FROM pg_stat_activity
WHERE state = 'active';
"

# Find slow queries
psql -h localhost -U countermeasure -d countermeasure -c "
SELECT query, query_start, now() - query_start as duration
FROM pg_stat_activity
WHERE state = 'active'
  AND now() - query_start > interval '1 minute';
"

# Check table sizes
psql -h localhost -U countermeasure -d countermeasure -c "
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"
```

#### Solutions

**Connection Pool Tuning:**
```bash
# Edit postgresql.conf
sudo nano /etc/postgresql/15/main/postgresql.conf

# Increase connection limits
max_connections = 200
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB

# Restart PostgreSQL
sudo systemctl restart postgresql
```

**Query Optimization:**
```sql
-- Enable pg_stat_statements
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Find expensive queries
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements
ORDER BY total_time DESC
LIMIT 10;

-- Add missing indexes
EXPLAIN ANALYZE SELECT * FROM detections WHERE tenant_id = 'some-id';
```

## Network and Infrastructure Issues

### 1. Load Balancer Problems

#### Symptoms
- 502/503 errors
- Health check failures
- Uneven traffic distribution

#### Diagnostic Steps
```bash
# Check upstream health
curl -f http://api1:8000/health
curl -f http://api2:8000/health

# Check nginx configuration
nginx -t

# Monitor nginx logs
tail -f /var/log/nginx/error.log
```

#### Solutions

**Nginx Configuration:**
```nginx
upstream api_backend {
    least_conn;
    server api1:8000 max_fails=3 fail_timeout=30s;
    server api2:8000 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

server {
    location / {
        proxy_pass http://api_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    location /health {
        proxy_pass http://api_backend;
        access_log off;
    }
}
```

### 2. SSL/TLS Issues

#### Symptoms
- Certificate errors
- Handshake failures
- Mixed content warnings

#### Diagnostic Steps
```bash
# Check certificate validity
openssl x509 -in /etc/nginx/ssl/cert.pem -text -noout

# Test SSL configuration
openssl s_client -connect countermeasure.com:443

# Check certificate chain
ssl-cert-check -c /etc/nginx/ssl/cert.pem
```

#### Solutions

**Certificate Renewal:**
```bash
# With Let's Encrypt
certbot renew --nginx

# Manual certificate update
# Replace files in /etc/nginx/ssl/
# Restart nginx
sudo systemctl restart nginx
```

## Monitoring and Alerting Issues

### 1. Metrics Collection Problems

#### Symptoms
- Missing metrics in Prometheus
- Grafana dashboards empty
- Alert rules not firing

#### Diagnostic Steps
```bash
# Check metrics endpoint
curl http://localhost:8000/metrics

# Verify Prometheus configuration
cat /etc/prometheus/prometheus.yml

# Check Prometheus targets
curl http://localhost:9090/api/v1/targets
```

#### Solutions

**Prometheus Configuration:**
```yaml
scrape_configs:
  - job_name: 'countermeasure-api'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s
    scrape_timeout: 10s
```

### 2. Log Aggregation Issues

#### Symptoms
- Logs not appearing in aggregation system
- Incorrect log format
- High log volume

#### Solutions

**Structured Logging:**
```bash
# Verify log format
cd apps/api
uv run python -c "
from src.core.logging import get_logger
logger = get_logger('test')
logger.info('Test message', extra={'user_id': '123'})
"
```

**Log Rotation:**
```bash
# Configure logrotate
cat > /etc/logrotate.d/countermeasure << 'EOF'
/var/log/countermeasure/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
```

## Recovery Procedures

### 1. Database Recovery

```bash
# Stop API services
sudo systemctl stop countermeasure-api

# Restore from backup
gunzip -c /backups/countermeasure_20240922.sql.gz | \
  psql -h localhost -U countermeasure countermeasure

# Run migrations if needed
cd apps/api
uv run alembic upgrade head

# Restart services
sudo systemctl start countermeasure-api
```

### 2. Complete System Recovery

```bash
# 1. Restore from backup
# 2. Recreate environment
cd countermeasure
git pull origin main

# 3. Rebuild containers
docker-compose down
docker-compose pull
docker-compose up -d

# 4. Verify health
curl -f http://localhost:8000/health
```

## Emergency Contacts and Escalation

### Severity Levels

1. **Critical**: System down, data loss
2. **High**: Major functionality broken
3. **Medium**: Performance degradation
4. **Low**: Minor issues, cosmetic problems

### Response Times

- **Critical**: Immediate (< 15 minutes)
- **High**: 1 hour
- **Medium**: 4 hours
- **Low**: Next business day

### Escalation Path

1. Platform team (first response)
2. Engineering lead
3. CTO/Technical director
4. External vendor support (if applicable)

## Useful Scripts

### System Health Check Script

```bash
#!/bin/bash
# health_check.sh

echo "=== Countermeasure Health Check ==="
echo "Date: $(date)"
echo

# API Health
echo "1. API Health:"
if curl -s -f http://localhost:8000/health > /dev/null; then
    echo "   ✅ API is healthy"
else
    echo "   ❌ API is not responding"
fi

# Database Health
echo "2. Database Health:"
if pg_isready -h localhost -U countermeasure > /dev/null 2>&1; then
    echo "   ✅ Database is healthy"
else
    echo "   ❌ Database is not responding"
fi

# Redis Health (if used)
echo "3. Redis Health:"
if redis-cli ping > /dev/null 2>&1; then
    echo "   ✅ Redis is healthy"
else
    echo "   ❌ Redis is not responding"
fi

# Disk Space
echo "4. Disk Space:"
df -h | grep -E "/$|/var|/tmp" | while read line; do
    usage=$(echo $line | awk '{print $5}' | sed 's/%//')
    if [ $usage -gt 80 ]; then
        echo "   ❌ High disk usage: $line"
    else
        echo "   ✅ Disk usage OK: $line"
    fi
done

echo
echo "=== End Health Check ==="
```

### Log Analysis Script

```bash
#!/bin/bash
# analyze_logs.sh

echo "=== Recent Errors ==="
tail -n 100 /var/log/countermeasure/api.log | grep -i error

echo
echo "=== Top API Endpoints ==="
tail -n 1000 /var/log/nginx/access.log | \
awk '{print $7}' | sort | uniq -c | sort -nr | head -10

echo
echo "=== Response Time Analysis ==="
tail -n 1000 /var/log/nginx/access.log | \
awk '{print $10}' | sort -n | \
awk '{times[NR]=$1} END {
    print "50th percentile:", times[int(NR*0.5)]
    print "90th percentile:", times[int(NR*0.9)]
    print "95th percentile:", times[int(NR*0.95)]
}'
```

This troubleshooting guide provides comprehensive diagnostic procedures and solutions for common issues in the Countermeasure platform.