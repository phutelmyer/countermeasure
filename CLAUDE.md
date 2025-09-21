# Countermeasure Platform - Claude Development Guide

## Overview

Countermeasure is a threat detection confidence platform that ingests, enriches, and manages security detection rules. The platform consists of an API backend and collectors that import detection rules from various sources.

## Architecture

### Current Foundation (Implemented ✅)

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│   Collectors    │───▶│  API Server  │───▶│   Database      │
│  (SIGMA, etc.)  │    │ (FastAPI)    │    │ (PostgreSQL)    │
│                 │    │              │    │                 │
│ • SIGMA Parser  │    │ • JWT Auth   │    │ • Migrations    │
│ • Data Enricher │    │ • RBAC       │    │ • Multi-tenant  │
│ • Validator     │    │ • OpenAPI    │    │ • JSONB Fields  │
└─────────────────┘    └──────────────┘    └─────────────────┘
```

**What's Working Now:**
- **Authentication**: JWT tokens, user management, role-based access
- **Data Collection**: SIGMA rule import from GitHub repository
- **Data Processing**: Rule parsing, metadata extraction, validation
- **Database**: PostgreSQL with Alembic migrations, multi-tenant design
- **API**: FastAPI with automatic OpenAPI documentation
- **Scripts**: Enterprise import utilities with batch processing

### Enterprise Vision (Planned 📋)

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│ Advanced        │───▶│ AI-Enhanced  │───▶│ Enterprise      │
│ Collectors      │    │ API Platform │    │ Storage         │
│                 │    │              │    │                 │
│ • SIEM Connectors│   │ • AI Analysis│    │ • Redis Cache   │
│ • Threat Intel  │    │ • Coverage   │    │ • Search Engine │
│ • Validation    │    │   Scoring    │    │ • File Storage  │
│ • Real-time     │    │ • Risk Assess│    │ • Data Lake     │
└─────────────────┘    └──────────────┘    └─────────────────┘
```

## Quick Start

### 1. Start the API Server

```bash
cd apps/api
uv run uvicorn src.main:app --host 0.0.0.0 --port 8000
```

**API Endpoints:**
- API Docs: http://localhost:8000/docs
- Health Check: http://localhost:8000/health

### 2. Initialize Database

```bash
cd apps/api
uv run python -m src.db.init_db
```

**Default Credentials:**
- Email: `admin@countermeasure.dev`
- Password: `CountermeasureAdmin123!`

### 3. Run SIGMA Collector

**Using the Enterprise Script (Recommended):**
```bash
python scripts/import_sigma_rules.py --limit 100
```

**Or use the collector directly:**
```bash
cd apps/collector
uv run python -m src.collectors.detection.sigma --limit 100
```

## Project Structure

### API (`apps/api/`)
```
src/
├── api/           # API route handlers
├── core/          # Configuration, logging, security
├── db/            # Database models, sessions, migrations
│   ├── models/    # SQLAlchemy models
│   └── seed_data/ # Sample data
└── schemas/       # Pydantic schemas
```

### Collector (`apps/collector/`)
```
src/
├── collectors/    # Data collection modules
│   ├── base.py    # Base collector class
│   └── detection/ # Detection rule collectors
├── core/          # API client, configuration
└── schemas/       # Data schemas
```

### Scripts (`scripts/`)
```
scripts/
├── README.md              # Scripts documentation
└── import_sigma_rules.py  # Enterprise SIGMA import utility
```

## Database Management

### Migrations
```bash
cd apps/api

# Create migration
uv run alembic revision --autogenerate -m "description"

# Apply migrations
uv run alembic upgrade head

# Check current version
uv run alembic current
```

### Reset Database
```bash
cd apps/collector
uv run python reset_and_import.py
```

## SIGMA Rule Collection

### Configuration
```python
config = {
    "api_url": "http://localhost:8000",
    "email": "admin@countermeasure.dev",
    "password": "CountermeasureAdmin123!",
    "repo_url": "https://github.com/SigmaHQ/sigma.git",
    "limit": 100,
    "batch_size": 50
}
```

### Manual Collection
```bash
cd apps/collector

# Collect 100 SIGMA rules
uv run python -m src.collectors.detection.sigma \
    --api-url "http://localhost:8000" \
    --email "admin@countermeasure.dev" \
    --password "CountermeasureAdmin123!" \
    --limit 100

# Test parser
uv run python test_parser.py
```

## Structured Metadata

The platform extracts structured metadata from SIGMA rules:

### Platforms
Extracted from:
- `logsource.product` (windows, linux, macos)
- Rule tags (windows, linux, macos)
- File path hints (`/windows/`, `/linux/`, `/macos/`)

### Data Sources
Mapped from `logsource.category`:
- `process_creation` → "Process Creation"
- `network_connection` → "Network Connection"
- `file_event` → "File Monitoring"
- `registry_event` → "Windows Registry"
- `image_load` → "Image Load"
- `dns` → "DNS"
- Plus 10+ more mappings

### False Positives
Direct extraction from `falsepositives` field in SIGMA rules.

### Log Sources
Formatted string: `product:windows | category:image_load | service:sysmon`

## Detections Table Recommendations

### Current Schema Issues
Based on analysis, here are recommended improvements:

#### 1. Add Missing Indexes
```sql
-- Performance indexes
CREATE INDEX idx_detections_name ON detections(name);
CREATE INDEX idx_detections_severity_id ON detections(severity_id);
CREATE INDEX idx_detections_status ON detections(status);
CREATE INDEX idx_detections_created_at ON detections(created_at);
CREATE INDEX idx_detections_platforms ON detections USING GIN(platforms);
CREATE INDEX idx_detections_data_sources ON detections USING GIN(data_sources);

-- Search indexes
CREATE INDEX idx_detections_name_trgm ON detections USING gin(name gin_trgm_ops);
CREATE INDEX idx_detections_description_trgm ON detections USING gin(description gin_trgm_ops);
```

#### 2. Optimize Array Storage
Current implementation stores arrays correctly. Consider:
- Using PostgreSQL native arrays (already implemented ✅)
- Adding GIN indexes for array searches (recommended above)

#### 3. Add Constraints
```sql
-- Ensure valid status values
ALTER TABLE detections ADD CONSTRAINT check_status
CHECK (status IN ('active', 'draft', 'testing', 'deprecated'));

-- Ensure valid visibility values
ALTER TABLE detections ADD CONSTRAINT check_visibility
CHECK (visibility IN ('public', 'private', 'community'));

-- Ensure confidence score is valid
ALTER TABLE detections ADD CONSTRAINT check_confidence_score
CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0);
```

#### 4. Performance Optimizations
```sql
-- Partition by creation date for large datasets
CREATE TABLE detections_y2024m01 PARTITION OF detections
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- Add statistics targets for better query planning
ALTER TABLE detections ALTER COLUMN platforms SET STATISTICS 1000;
ALTER TABLE detections ALTER COLUMN data_sources SET STATISTICS 1000;
```

#### 5. Enhanced Metadata Schema
Consider adding these fields for better detection management:

```python
# Additional recommended fields
detection_type: str = Field(..., description="Type: signature, behavioral, ml")
threat_types: List[str] = Field([], description="Malware, APT, Insider, etc.")
kill_chain_phases: List[str] = Field([], description="MITRE kill chain phases")
data_retention_days: int = Field(90, description="How long to keep alerts")
tuning_notes: str = Field("", description="Analyst tuning notes")
last_tested: datetime = Field(None, description="Last validation test")
test_results: dict = Field({}, description="Validation test results")
```

## Testing Commands

### Run All Tests
```bash
# API tests
cd apps/api
uv run pytest tests/ -v

# Collector tests
cd apps/collector
uv run pytest tests/ -v
```

### Test Specific Components
```bash
# Test SIGMA parser
cd apps/collector
uv run python test_parser.py

# Test API authentication
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -d "email=admin@countermeasure.dev&password=CountermeasureAdmin123!"

# Test detection creation
curl -H "Authorization: Bearer <token>" \
  "http://localhost:8000/api/v1/detections/"
```

## Troubleshooting

### Common Issues

#### 1. Authentication Failures
```bash
# Check if API is running
curl http://localhost:8000/health

# Verify credentials
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -d "email=admin@countermeasure.dev&password=CountermeasureAdmin123!"
```

#### 2. Database Connection Issues
```bash
# Check database initialization
cd apps/api
uv run python -m src.db.init_db

# Check migrations
uv run alembic current
uv run alembic upgrade head
```

#### 3. Empty Structured Metadata
The recent fix ensures arrays are properly formatted:
- ✅ Fixed: `"platforms": "{Windows}"` → `"platforms": ["Windows"]`
- ✅ Confirmed: Parser extracts metadata correctly
- ✅ Verified: Database stores arrays properly

#### 4. Collection Failures
```bash
# Check API server logs
cd apps/api
uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 --log-level debug

# Test collector connectivity
cd apps/collector
uv run python -c "
import asyncio
from src.core.api_client import CountermeasureClient
async def test():
    client = CountermeasureClient('http://localhost:8000', 'admin@countermeasure.dev', 'CountermeasureAdmin123!')
    success = await client.login()
    print(f'Login successful: {success}')
    await client.close()
asyncio.run(test())
"
```

## Development Workflow

### 1. Adding New Collectors
```python
# Create new collector in src/collectors/
class NewCollector(BaseCollector):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

    async def fetch_raw_data(self) -> List[Any]:
        # Implement data fetching
        pass

    async def parse_raw_data(self, raw_data: List[Any]) -> List[DetectionCreate]:
        # Implement data parsing
        pass
```

### 2. Database Schema Changes
```bash
# 1. Update models in src/db/models/
# 2. Create migration
cd apps/api
uv run alembic revision --autogenerate -m "add new field"

# 3. Apply migration
uv run alembic upgrade head

# 4. Update schemas in src/schemas/
```

### 3. API Endpoint Development
```python
# Add new endpoints in src/api/
@router.post("/new-endpoint")
async def new_endpoint(
    data: RequestSchema,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Implementation
    pass
```

## Environment Variables

Create `.env` files for configuration:

### `apps/api/.env`
```env
DATABASE_URL=postgresql://user:pass@localhost/countermeasure
SECRET_KEY=your-secret-key
ENVIRONMENT=development
LOG_LEVEL=INFO
```

### `apps/collector/.env`
```env
API_URL=http://localhost:8000
DEFAULT_EMAIL=admin@countermeasure.dev
DEFAULT_PASSWORD=CountermeasureAdmin123!
LOG_LEVEL=INFO
```

## Deployment Notes

### Docker Support
```dockerfile
# API Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install uv && uv sync
CMD ["uv", "run", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Production Checklist
- [ ] Use production database (not SQLite)
- [ ] Set secure SECRET_KEY
- [ ] Enable SSL/TLS
- [ ] Configure proper logging
- [ ] Set up monitoring
- [ ] Use environment-specific configs
- [ ] Enable rate limiting
- [ ] Set up backup strategy

## Recent Fixes & Improvements

### JSON Serialization Fix (2024-09-21)
- ✅ Fixed structured metadata arrays stored as strings
- ✅ Added proper API client methods for reset script
- ✅ Enhanced SIGMA parser with better data source mappings
- ✅ Created comprehensive reset and import script

### Migration to Database Migrations
- ✅ Replaced `create_all_tables()` with Alembic migrations
- ✅ Added proper migration workflow
- ✅ Fixed Alembic configuration issues

This guide should help you understand and work with the Countermeasure platform effectively!