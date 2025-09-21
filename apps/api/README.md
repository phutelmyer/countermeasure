# Countermeasure API

Enterprise Threat Detection Platform API Service

## Overview

The Countermeasure API provides a comprehensive threat detection and response platform for enterprise security operations.

## Requirements

- Python 3.12+
- PostgreSQL
- Redis

## Development Setup

1. Install dependencies:
   ```bash
   uv sync
   ```

2. Run the application:
   ```bash
   uv run uvicorn src.main:app --reload
   ```

## Testing

Run tests with:
```bash
uv run pytest
```