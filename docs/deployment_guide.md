# Countermeasure Platform Deployment Guide

## Overview

This guide covers deploying the Countermeasure platform for development, staging, and production environments. The platform consists of an API service, collector service, and supporting infrastructure.

## Architecture Overview

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│   Load Balancer │───▶│  API Servers │───▶│   Database      │
│   (Nginx/ALB)   │    │ (Multiple)   │    │ (PostgreSQL)    │
└─────────────────┘    └──────────────┘    └─────────────────┘
                              │
                       ┌──────────────┐    ┌─────────────────┐
                       │  Collectors  │───▶│  Redis Cache    │
                       │ (Background) │    │  (Optional)     │
                       └──────────────┘    └─────────────────┘
```

## Prerequisites

### System Requirements

#### Minimum Requirements (Development)
- **CPU**: 2 cores
- **RAM**: 4GB
- **Storage**: 10GB
- **OS**: Ubuntu 20.04+, CentOS 8+, or macOS 12+

#### Production Requirements
- **CPU**: 4+ cores
- **RAM**: 8GB+
- **Storage**: 50GB+ SSD
- **OS**: Ubuntu 20.04+, CentOS 8+
- **Network**: Load balancer, SSL certificate

### Software Dependencies

- **Python**: 3.12+
- **uv**: Python package manager
- **PostgreSQL**: 13+
- **Redis**: 6+ (optional, for caching)
- **Git**: For source code management

## Environment Setup

### 1. Development Environment

#### Quick Start with Docker

```bash
# Clone repository
git clone https://github.com/countermeasure/countermeasure.git
cd countermeasure

# Start development services
docker-compose -f apps/api/docker-compose.yml up -d

# Initialize database
cd apps/api
uv run python -m src.db.init_db

# Start API server
uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Manual Development Setup

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Set up API service
cd apps/api
cp .env.example .env
# Edit .env with your settings
uv sync --all-extras --dev

# Set up Collector service
cd ../collector
cp .env.example .env
# Edit .env with your settings
uv sync --all-extras --dev

# Start PostgreSQL (via Docker or native)
docker run --name countermeasure-postgres \
  -e POSTGRES_DB=countermeasure \
  -e POSTGRES_USER=countermeasure \
  -e POSTGRES_PASSWORD=secretpassword \
  -p 5432:5432 -d postgres:15

# Initialize database
cd ../api
uv run python -m src.db.init_db

# Run database migrations
uv run alembic upgrade head

# Start services
uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Production Environment

#### Docker Deployment

**docker-compose.prod.yml:**
```yaml
version: '3.8'

services:
  api:
    build:
      context: apps/api
      target: production
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://countermeasure:${DB_PASSWORD}@postgres:5432/countermeasure
      - SECRET_KEY=${SECRET_KEY}
      - ENVIRONMENT=production
      - SENTRY_DSN=${SENTRY_DSN}
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  collector:
    build:
      context: apps/collector
      target: production
    environment:
      - API_URL=http://api:8000
      - REDIS_URL=redis://redis:6379/0
      - CELERY_BROKER_URL=redis://redis:6379/1
    depends_on:
      - api
      - redis
    restart: unless-stopped

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=countermeasure
      - POSTGRES_USER=countermeasure
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U countermeasure"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - api
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
```

#### Kubernetes Deployment

**kubernetes/namespace.yaml:**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: countermeasure
```

**kubernetes/configmap.yaml:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: countermeasure-config
  namespace: countermeasure
data:
  ENVIRONMENT: "production"
  LOG_LEVEL: "INFO"
  DATABASE_HOST: "postgres"
  DATABASE_NAME: "countermeasure"
  REDIS_URL: "redis://redis:6379/0"
```

**kubernetes/secret.yaml:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: countermeasure-secrets
  namespace: countermeasure
type: Opaque
data:
  SECRET_KEY: <base64-encoded-secret>
  DATABASE_PASSWORD: <base64-encoded-password>
  SENTRY_DSN: <base64-encoded-dsn>
```

**kubernetes/api-deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: countermeasure-api
  namespace: countermeasure
spec:
  replicas: 3
  selector:
    matchLabels:
      app: countermeasure-api
  template:
    metadata:
      labels:
        app: countermeasure-api
    spec:
      containers:
      - name: api
        image: countermeasure/api:latest
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: countermeasure-config
        - secretRef:
            name: countermeasure-secrets
        livenessProbe:
          httpGet:
            path: /live
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 15
          periodSeconds: 10
        resources:
          requests:
            cpu: 100m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
```

### 3. Environment Configuration

#### API Configuration (.env)

```bash
# Application
APP_NAME="Countermeasure API"
APP_VERSION="0.1.0"
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=INFO

# API Server
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
API_RELOAD=false

# Database
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/countermeasure
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=30
DATABASE_ECHO=false

# Security
SECRET_KEY=your-super-secret-key-256-bits-long
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# CORS
ALLOWED_ORIGINS=["https://app.countermeasure.com"]
ALLOWED_METHODS=["GET","POST","PUT","DELETE"]
ALLOWED_HEADERS=["*"]

# Monitoring
PROMETHEUS_METRICS=true
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project
SENTRY_ENVIRONMENT=production
SENTRY_TRACES_SAMPLE_RATE=0.1

# External Services
MITRE_API_URL=https://attack.mitre.org/api/v1
GITHUB_TOKEN=your-github-token

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=100
RATE_LIMIT_BURST=20

# File Upload
MAX_FILE_SIZE_MB=100
ALLOWED_FILE_TYPES=[".yml",".yaml",".json",".txt"]
```

#### Collector Configuration (.env)

```bash
# API Connection
API_URL=http://localhost:8000
DEFAULT_EMAIL=admin@countermeasure.dev
DEFAULT_PASSWORD=CountermeasureAdmin123!

# Celery Configuration
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/1
CELERY_TASK_SERIALIZER=json
CELERY_RESULT_SERIALIZER=json

# SIGMA Collection
SIGMA_REPO_URL=https://github.com/SigmaHQ/sigma.git
SIGMA_CATEGORIES=["process_creation","network_connection","file_event"]
DEFAULT_BATCH_SIZE=50
DEFAULT_LIMIT=1000

# Logging
LOG_LEVEL=INFO
```

## Database Setup

### 1. PostgreSQL Installation

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### CentOS/RHEL
```bash
sudo dnf install postgresql postgresql-server
sudo postgresql-setup --initdb
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### 2. Database Configuration

```bash
# Create database and user
sudo -u postgres psql

CREATE DATABASE countermeasure;
CREATE USER countermeasure WITH PASSWORD 'secretpassword';
GRANT ALL PRIVILEGES ON DATABASE countermeasure TO countermeasure;
ALTER USER countermeasure CREATEDB;
\q
```

### 3. Database Migrations

```bash
cd apps/api

# Run migrations
uv run alembic upgrade head

# Initialize with seed data
uv run python -m src.db.init_db
```

## SSL/TLS Configuration

### Nginx Configuration

**nginx.conf:**
```nginx
events {
    worker_connections 1024;
}

http {
    upstream api_backend {
        server api:8000;
    }

    server {
        listen 80;
        server_name countermeasure.com www.countermeasure.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name countermeasure.com www.countermeasure.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;

        location / {
            proxy_pass http://api_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /health {
            proxy_pass http://api_backend/health;
            access_log off;
        }

        location /metrics {
            proxy_pass http://api_backend/metrics;
            allow 10.0.0.0/8;
            deny all;
        }
    }
}
```

## Monitoring Setup

### 1. Prometheus Configuration

**prometheus.yml:**
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'countermeasure-api'
    static_configs:
      - targets: ['api:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
```

### 2. Grafana Dashboard

Import the Countermeasure dashboard JSON from `monitoring/grafana/dashboard.json`.

### 3. Alerting Rules

**alerts.yml:**
```yaml
groups:
  - name: countermeasure
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status_code="500"}[5m]) > 0.1
        labels:
          severity: critical
        annotations:
          summary: High error rate detected

      - alert: DatabaseConnectionFailed
        expr: up{job="postgres"} == 0
        labels:
          severity: critical
        annotations:
          summary: Database connection failed
```

## Backup and Recovery

### 1. Database Backup

```bash
# Create backup script
cat > backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="countermeasure_${DATE}.sql.gz"

pg_dump -h localhost -U countermeasure countermeasure | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"

# Keep only last 7 days of backups
find ${BACKUP_DIR} -name "countermeasure_*.sql.gz" -mtime +7 -delete
EOF

chmod +x backup.sh

# Schedule with cron
echo "0 2 * * * /path/to/backup.sh" | crontab -
```

### 2. Database Recovery

```bash
# Restore from backup
gunzip -c /backups/countermeasure_20240922_020000.sql.gz | psql -h localhost -U countermeasure countermeasure
```

## Security Considerations

### 1. Network Security

- Use HTTPS/TLS for all communications
- Implement proper firewall rules
- Use VPC/private networks in cloud deployments
- Restrict database access to application servers only

### 2. Application Security

- Set strong `SECRET_KEY` (256+ bits)
- Use environment variables for secrets
- Enable Sentry for error tracking
- Implement rate limiting
- Regular security updates

### 3. Database Security

- Use strong database passwords
- Enable SSL for database connections
- Regular backups with encryption
- Database user with minimal privileges

## Performance Optimization

### 1. Database Optimization

```sql
-- Create indexes for common queries
CREATE INDEX CONCURRENTLY idx_detections_tenant_status
ON detections(tenant_id, status);

CREATE INDEX CONCURRENTLY idx_detections_platforms_gin
ON detections USING GIN(platforms);

-- Analyze tables
ANALYZE;
```

### 2. Application Optimization

- Use connection pooling
- Implement Redis caching
- Enable compression
- Optimize database queries
- Use async/await properly

### 3. Infrastructure Optimization

- Use CDN for static assets
- Implement horizontal scaling
- Use load balancers
- Monitor resource usage

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   ```bash
   # Check PostgreSQL status
   sudo systemctl status postgresql

   # Check connection
   psql -h localhost -U countermeasure -d countermeasure
   ```

2. **Migration Errors**
   ```bash
   # Check migration status
   uv run alembic current

   # Show migration history
   uv run alembic history

   # Rollback if needed
   uv run alembic downgrade -1
   ```

3. **High Memory Usage**
   ```bash
   # Check process memory
   ps aux | grep uvicorn

   # Monitor in real-time
   htop
   ```

4. **API Response Slow**
   ```bash
   # Check database queries
   tail -f /var/log/postgresql/postgresql.log

   # Monitor API logs
   docker logs -f countermeasure-api
   ```

### Logs Locations

- **API Logs**: `/var/log/countermeasure/api.log`
- **Database Logs**: `/var/log/postgresql/postgresql.log`
- **Nginx Logs**: `/var/log/nginx/access.log`
- **System Logs**: `journalctl -u countermeasure-api`

### Health Checks

```bash
# API Health
curl http://localhost:8000/health

# Database Health
pg_isready -h localhost -U countermeasure

# Redis Health (if used)
redis-cli ping
```

## Scaling

### Horizontal Scaling

1. **API Servers**: Deploy multiple API instances behind load balancer
2. **Database**: Use read replicas for read-heavy workloads
3. **Caching**: Implement Redis cluster for high availability
4. **Background Jobs**: Scale Celery workers

### Vertical Scaling

1. **CPU**: Increase CPU cores for API servers
2. **Memory**: Add RAM for database and caching
3. **Storage**: Use SSDs for database storage
4. **Network**: Increase bandwidth for high traffic

## Maintenance

### Regular Tasks

1. **Database Maintenance**
   ```bash
   # Vacuum and analyze
   vacuumdb -h localhost -U countermeasure --analyze countermeasure

   # Reindex
   reindexdb -h localhost -U countermeasure countermeasure
   ```

2. **Log Rotation**
   ```bash
   # Configure logrotate
   cat > /etc/logrotate.d/countermeasure << 'EOF'
   /var/log/countermeasure/*.log {
       daily
       rotate 30
       compress
       delaycompress
       missingok
       notifempty
       create 644 countermeasure countermeasure
   }
   EOF
   ```

3. **Security Updates**
   ```bash
   # Update dependencies
   uv sync --upgrade

   # Check for vulnerabilities
   uv run safety check

   # Update system packages
   sudo apt update && sudo apt upgrade
   ```

This deployment guide provides comprehensive instructions for deploying the Countermeasure platform in various environments with proper security, monitoring, and maintenance considerations.