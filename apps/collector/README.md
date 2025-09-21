# Countermeasure Collector

Data collection service for the Countermeasure threat intelligence platform.

## Features

- SIGMA rule collection from public repositories
- Automated detection rule ingestion
- Celery-based task scheduling
- API integration with authentication

## Usage

```bash
# Run SIGMA collection
countermeasure-collector collect sigma

# Start Celery worker
countermeasure-collector worker

# Start Celery beat scheduler
countermeasure-collector beat
```