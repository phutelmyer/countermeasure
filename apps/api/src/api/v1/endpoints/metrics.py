"""
Metrics and observability endpoints.
"""

import json
import time
from typing import Any

from fastapi import APIRouter, Depends, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.session import get_db
from src.middleware.metrics import get_metrics, get_metrics_content_type


router = APIRouter()


@router.get(
    "/metrics",
    summary="Prometheus Metrics",
    description="Prometheus metrics endpoint for monitoring",
    include_in_schema=False,  # Don't include in OpenAPI docs
)
async def prometheus_metrics() -> Response:
    """
    Prometheus metrics endpoint.

    Returns:
        Response: Prometheus metrics in text format
    """
    metrics_data = get_metrics()
    return Response(
        content=metrics_data,
        media_type=get_metrics_content_type(),
    )


@router.get(
    "/health",
    summary="Health Check",
    description="Comprehensive health check including database connectivity",
)
async def health_check(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """
    Comprehensive health check endpoint.

    Args:
        db: Database session

    Returns:
        Dict: Health status information
    """
    health_info = {
        "status": "healthy",
        "timestamp": int(time.time()),
        "version": "0.1.0",
        "environment": settings.environment,
        "checks": {
            "database": {"status": "unknown", "response_time": None},
            "redis": {"status": "unknown", "response_time": None},
        },
    }

    # Database health check
    try:
        start_time = time.time()
        await db.execute(text("SELECT 1"))
        db_response_time = time.time() - start_time

        health_info["checks"]["database"] = {
            "status": "healthy",
            "response_time": round(db_response_time * 1000, 2),  # ms
        }

    except Exception as e:
        health_info["status"] = "unhealthy"
        health_info["checks"]["database"] = {
            "status": "unhealthy",
            "error": str(e),
            "response_time": None,
        }

    # Redis health check (if configured)
    if hasattr(settings, "redis_url") and settings.redis_url:
        try:
            import redis.asyncio as redis

            start_time = time.time()
            redis_client = redis.from_url(settings.redis_url)
            await redis_client.ping()
            redis_response_time = time.time() - start_time
            await redis_client.close()

            health_info["checks"]["redis"] = {
                "status": "healthy",
                "response_time": round(redis_response_time * 1000, 2),  # ms
            }

        except Exception as e:
            health_info["status"] = "unhealthy"
            health_info["checks"]["redis"] = {
                "status": "unhealthy",
                "error": str(e),
                "response_time": None,
            }
    else:
        health_info["checks"]["redis"] = {
            "status": "not_configured",
            "response_time": None,
        }

    return health_info


@router.get(
    "/health/dashboard",
    summary="Health Dashboard",
    description="HTML dashboard for system health monitoring",
    include_in_schema=False,
)
async def health_dashboard() -> Response:
    """
    HTML health monitoring dashboard.

    Returns:
        Response: HTML dashboard
    """
    dashboard_html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Countermeasure Health Dashboard</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
                color: #333;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                padding: 30px;
            }
            .header {
                border-bottom: 2px solid #e0e0e0;
                padding-bottom: 20px;
                margin-bottom: 30px;
            }
            .header h1 {
                margin: 0;
                color: #2c3e50;
                font-size: 2.5rem;
            }
            .header .subtitle {
                color: #7f8c8d;
                font-size: 1.1rem;
                margin-top: 10px;
            }
            .status-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .status-card {
                background: #f8f9fa;
                border-radius: 8px;
                padding: 20px;
                border-left: 4px solid #28a745;
                transition: transform 0.2s;
            }
            .status-card:hover {
                transform: translateY(-2px);
            }
            .status-card.unhealthy {
                border-left-color: #dc3545;
                background: #fdf2f2;
            }
            .status-card.warning {
                border-left-color: #ffc107;
                background: #fffbf0;
            }
            .status-title {
                font-size: 1.2rem;
                font-weight: 600;
                margin-bottom: 10px;
                color: #2c3e50;
            }
            .status-value {
                font-size: 2rem;
                font-weight: 700;
                margin-bottom: 5px;
            }
            .status-value.healthy { color: #28a745; }
            .status-value.unhealthy { color: #dc3545; }
            .status-value.warning { color: #ffc107; }
            .status-details {
                color: #6c757d;
                font-size: 0.9rem;
            }
            .metrics-section {
                margin-top: 30px;
                padding-top: 20px;
                border-top: 2px solid #e0e0e0;
            }
            .refresh-button {
                background: #007bff;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 1rem;
                margin-bottom: 20px;
                transition: background-color 0.2s;
            }
            .refresh-button:hover {
                background: #0056b3;
            }
            .timestamp {
                text-align: right;
                color: #6c757d;
                font-size: 0.9rem;
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Countermeasure Health Dashboard</h1>
                <div class="subtitle">Enterprise Threat Detection Platform Monitoring</div>
            </div>

            <button class="refresh-button" onclick="loadHealthData()">🔄 Refresh Status</button>

            <div id="health-content">
                <div class="status-grid">
                    <div class="status-card">
                        <div class="status-title">System Status</div>
                        <div class="status-value" id="system-status">Loading...</div>
                        <div class="status-details" id="system-details">Checking system health...</div>
                    </div>
                    <div class="status-card">
                        <div class="status-title">Database</div>
                        <div class="status-value" id="db-status">Loading...</div>
                        <div class="status-details" id="db-details">Checking database connectivity...</div>
                    </div>
                    <div class="status-card">
                        <div class="status-title">Redis Cache</div>
                        <div class="status-value" id="redis-status">Loading...</div>
                        <div class="status-details" id="redis-details">Checking Redis connectivity...</div>
                    </div>
                </div>
            </div>

            <div class="metrics-section">
                <h3>📊 Quick Actions</h3>
                <p>
                    <a href="/docs" target="_blank">📋 API Documentation</a> |
                    <a href="/metrics" target="_blank">📈 Prometheus Metrics</a> |
                    <a href="/health" target="_blank">🔍 Health JSON</a>
                </p>
            </div>

            <div class="timestamp" id="last-updated">
                Last updated: Loading...
            </div>
        </div>

        <script>
            async function loadHealthData() {
                try {
                    const response = await fetch('/health');
                    const data = await response.json();

                    // Update system status
                    const systemStatusEl = document.getElementById('system-status');
                    const systemDetailsEl = document.getElementById('system-details');
                    const systemCard = systemStatusEl.closest('.status-card');

                    systemStatusEl.textContent = data.status.toUpperCase();
                    systemStatusEl.className = 'status-value ' + data.status;
                    systemDetailsEl.textContent = `Environment: ${data.environment} | Version: ${data.version}`;
                    systemCard.className = 'status-card ' + (data.status === 'healthy' ? '' : 'unhealthy');

                    // Update database status
                    const dbStatusEl = document.getElementById('db-status');
                    const dbDetailsEl = document.getElementById('db-details');
                    const dbCard = dbStatusEl.closest('.status-card');

                    const dbStatus = data.checks.database.status;
                    dbStatusEl.textContent = dbStatus.toUpperCase();
                    dbStatusEl.className = 'status-value ' + dbStatus;

                    if (dbStatus === 'healthy') {
                        dbDetailsEl.textContent = `Response time: ${data.checks.database.response_time}ms`;
                        dbCard.className = 'status-card';
                    } else {
                        dbDetailsEl.textContent = data.checks.database.error || 'Database connection failed';
                        dbCard.className = 'status-card unhealthy';
                    }

                    // Update Redis status
                    const redisStatusEl = document.getElementById('redis-status');
                    const redisDetailsEl = document.getElementById('redis-details');
                    const redisCard = redisStatusEl.closest('.status-card');

                    const redisStatus = data.checks.redis.status;
                    redisStatusEl.textContent = redisStatus.toUpperCase().replace('_', ' ');
                    redisStatusEl.className = 'status-value ' + (redisStatus === 'healthy' ? 'healthy' : redisStatus === 'not_configured' ? 'warning' : 'unhealthy');

                    if (redisStatus === 'healthy') {
                        redisDetailsEl.textContent = `Response time: ${data.checks.redis.response_time}ms`;
                        redisCard.className = 'status-card';
                    } else if (redisStatus === 'not_configured') {
                        redisDetailsEl.textContent = 'Redis not configured (optional)';
                        redisCard.className = 'status-card warning';
                    } else {
                        redisDetailsEl.textContent = data.checks.redis.error || 'Redis connection failed';
                        redisCard.className = 'status-card unhealthy';
                    }

                    // Update timestamp
                    document.getElementById('last-updated').textContent =
                        'Last updated: ' + new Date().toLocaleString();

                } catch (error) {
                    console.error('Failed to load health data:', error);
                    document.getElementById('system-status').textContent = 'ERROR';
                    document.getElementById('system-status').className = 'status-value unhealthy';
                    document.getElementById('system-details').textContent = 'Failed to load health data';
                }
            }

            // Load data on page load
            loadHealthData();

            // Auto-refresh every 30 seconds
            setInterval(loadHealthData, 30000);
        </script>
    </body>
    </html>
    '''

    return Response(
        content=dashboard_html,
        media_type="text/html",
    )