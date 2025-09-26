# Countermeasure API Documentation

## Overview

The Countermeasure API is a enterprise-grade threat detection confidence platform that provides comprehensive endpoints for managing security detection rules, threat actors, and MITRE ATT&CK framework data.

## Base URL

- **Development**: `http://localhost:8000`
- **Production**: `https://api.countermeasure.com` (TBD)

## Authentication

The API uses JWT (JSON Web Token) based authentication with bearer tokens.

### Authentication Flow

1. **Login**: `POST /api/v1/auth/login`
2. **Use access token**: Include in `Authorization: Bearer <token>` header
3. **Refresh token**: `POST /api/v1/auth/refresh` when access token expires

### Token Lifecycle

- **Access Token**: 15 minutes (configurable)
- **Refresh Token**: 7 days (configurable)

## API Endpoints

### Authentication Endpoints

#### POST /api/v1/auth/login
Authenticate user with email and password.

**Request Body:**
```json
{
  "email": "admin@countermeasure.dev",
  "password": "CountermeasureAdmin123!"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 900,
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "admin@countermeasure.dev",
    "full_name": "Admin User",
    "role": "admin",
    "is_active": true
  }
}
```

#### POST /api/v1/auth/signup
Register a new user account.

**Request Body:**
```json
{
  "email": "newuser@example.com",
  "password": "SecurePassword123!",
  "full_name": "New User"
}
```

#### POST /api/v1/auth/refresh
Refresh access token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### GET /api/v1/auth/me
Get current authenticated user information.

**Headers:** `Authorization: Bearer <access_token>`

**Response:**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "admin@countermeasure.dev",
  "full_name": "Admin User",
  "role": "admin",
  "is_active": true,
  "tenant_id": "tenant-123"
}
```

#### POST /api/v1/auth/logout
Logout user (client-side token removal).

#### POST /api/v1/auth/password/change
Change password for authenticated user.

#### POST /api/v1/auth/password/reset
Request password reset email.

#### POST /api/v1/auth/password/reset/confirm
Confirm password reset with token.

### Detection Endpoints

#### GET /api/v1/detections/
List detections with filtering and pagination.

**Query Parameters:**
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 50, max: 100)
- `search`: Search in name and description
- `category_ids`: Filter by category IDs (comma-separated)
- `tag_ids`: Filter by tag IDs (comma-separated)
- `severity_ids`: Filter by severity IDs (comma-separated)
- `status`: Filter by status (`active`, `draft`, `testing`, `deprecated`)
- `platforms`: Filter by platforms (comma-separated)
- `data_sources`: Filter by data sources (comma-separated)

**Response:**
```json
{
  "items": [
    {
      "id": "det-123",
      "name": "Suspicious PowerShell Execution",
      "description": "Detects suspicious PowerShell execution patterns",
      "content": "title: Suspicious PowerShell...",
      "format": "sigma",
      "status": "active",
      "platforms": ["windows"],
      "data_sources": ["Process Creation"],
      "confidence_score": 0.85,
      "severity": {
        "id": "sev-high",
        "name": "High",
        "level": 3
      },
      "category": {
        "id": "cat-malware",
        "name": "Malware"
      },
      "created_at": "2024-09-22T10:00:00Z",
      "updated_at": "2024-09-22T10:00:00Z"
    }
  ],
  "total": 150,
  "page": 1,
  "per_page": 50,
  "total_pages": 3
}
```

#### POST /api/v1/detections/
Create a new detection.

**Request Body:**
```json
{
  "name": "New Detection Rule",
  "description": "Description of the detection rule",
  "content": "detection: rule content here",
  "format": "sigma",
  "status": "draft",
  "platforms": ["windows", "linux"],
  "data_sources": ["Process Creation"],
  "category_id": "cat-malware",
  "severity_id": "sev-medium",
  "tag_ids": ["tag-apt", "tag-persistence"]
}
```

#### GET /api/v1/detections/{detection_id}
Get specific detection by ID.

#### PUT /api/v1/detections/{detection_id}
Update existing detection.

#### DELETE /api/v1/detections/{detection_id}
Delete detection.

### Actor Endpoints

#### GET /api/v1/actors/
List threat actors with filtering.

**Query Parameters:**
- `page`, `per_page`: Pagination
- `search`: Search in name and aliases
- `country`: Filter by country
- `motivation`: Filter by motivation
- `sophistication`: Filter by sophistication level

**Response:**
```json
{
  "items": [
    {
      "id": "actor-123",
      "name": "APT29",
      "aliases": ["Cozy Bear", "The Dukes"],
      "description": "Russian state-sponsored threat group",
      "country": "Russia",
      "motivation": "espionage",
      "sophistication": "expert",
      "first_seen": "2008-01-01",
      "last_activity": "2024-09-01",
      "mitre_id": "G0016",
      "stix_uuid": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"
    }
  ],
  "total": 75,
  "page": 1,
  "per_page": 50
}
```

#### POST /api/v1/actors/
Create new threat actor.

#### GET /api/v1/actors/{actor_id}
Get specific actor details.

#### PUT /api/v1/actors/{actor_id}
Update actor information.

#### DELETE /api/v1/actors/{actor_id}
Delete actor.

### MITRE ATT&CK Endpoints

#### GET /api/v1/mitre/tactics/
List MITRE ATT&CK tactics.

**Response:**
```json
{
  "items": [
    {
      "id": "tactic-123",
      "mitre_id": "TA0001",
      "name": "Initial Access",
      "description": "The adversary is trying to get into your network",
      "stix_uuid": "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
      "url": "https://attack.mitre.org/tactics/TA0001/"
    }
  ]
}
```

#### GET /api/v1/mitre/techniques/
List MITRE ATT&CK techniques.

**Query Parameters:**
- `tactic_id`: Filter by tactic
- `search`: Search in name and description

#### GET /api/v1/mitre/techniques/{technique_id}
Get specific technique details with sub-techniques.

### Tenant Management Endpoints

#### GET /api/v1/tenants/
List tenants (admin only).

#### POST /api/v1/tenants/
Create new tenant (admin only).

#### GET /api/v1/tenants/{tenant_id}
Get tenant details.

#### PUT /api/v1/tenants/{tenant_id}
Update tenant.

### User Management Endpoints

#### GET /api/v1/users/
List users in current tenant.

#### POST /api/v1/users/
Create new user (admin/manager only).

#### GET /api/v1/users/{user_id}
Get user details.

#### PUT /api/v1/users/{user_id}
Update user.

#### DELETE /api/v1/users/{user_id}
Delete user (admin only).

### Monitoring Endpoints

#### GET /health
Comprehensive health check with database and Redis status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1632150000,
  "version": "0.1.0",
  "environment": "development",
  "checks": {
    "database": {
      "status": "healthy",
      "response_time": 15.2
    },
    "redis": {
      "status": "healthy",
      "response_time": 2.1
    }
  }
}
```

#### GET /health/dashboard
HTML dashboard for system monitoring.

#### GET /metrics
Prometheus metrics endpoint.

## Error Handling

The API uses standard HTTP status codes and returns consistent error responses:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "field": "email",
      "issue": "Invalid email format"
    }
  }
}
```

### Common Status Codes

- **200**: Success
- **201**: Created
- **400**: Bad Request
- **401**: Unauthorized
- **403**: Forbidden
- **404**: Not Found
- **409**: Conflict
- **422**: Validation Error
- **500**: Internal Server Error

## Rate Limiting

API requests are rate-limited to prevent abuse:

- **Default**: 60 requests per minute per IP
- **Burst**: 10 additional requests
- **Headers**: Rate limit status included in response headers

## Pagination

List endpoints support pagination:

```json
{
  "items": [...],
  "total": 150,
  "page": 1,
  "per_page": 50,
  "total_pages": 3
}
```

## Data Formats

### Detection Formats

Supported detection rule formats:

- **SIGMA**: YAML-based detection rules
- **YARA**: Pattern matching rules
- **Suricata**: Network intrusion detection rules
- **Custom JSON**: Platform-specific JSON format

### Date Formats

All dates use ISO 8601 format: `2024-09-22T10:00:00Z`

## Security

### Authentication

- JWT tokens with configurable expiration
- Refresh token rotation
- Secure password hashing (bcrypt)

### Authorization

Role-based access control (RBAC):

- **Admin**: Full system access
- **Manager**: Tenant management and user creation
- **Analyst**: Detection management and analysis
- **Viewer**: Read-only access

### Data Protection

- Multi-tenant isolation
- Input validation and sanitization
- SQL injection prevention
- CORS protection
- Security headers

## Examples

### Create Detection with cURL

```bash
# Login
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=admin@countermeasure.dev&password=CountermeasureAdmin123!"

# Create detection
curl -X POST "http://localhost:8000/api/v1/detections/" \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Detection",
    "description": "Test detection rule",
    "content": "title: Test\ndetection:\n  condition: selection",
    "format": "sigma",
    "status": "draft"
  }'
```

### Search Detections

```bash
curl "http://localhost:8000/api/v1/detections/?search=powershell&platforms=windows&status=active" \
  -H "Authorization: Bearer <access_token>"
```

## SDK and Client Libraries

- **Python**: Official Python SDK (planned)
- **JavaScript**: Official JavaScript/TypeScript SDK (planned)
- **OpenAPI**: Full OpenAPI 3.0 specification available at `/docs`

## Support

- **Documentation**: [CLAUDE.md](../CLAUDE.md)
- **API Reference**: `/docs` (development mode)
- **Health Dashboard**: `/health/dashboard`