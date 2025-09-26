#!/bin/bash

# Countermeasure Process Manager
# Provides clean startup/shutdown with PID file tracking
# Usage: ./process_manager.sh {start|stop|restart|status|cleanup}

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
API_DIR="$PROJECT_ROOT/apps/api"
COLLECTOR_DIR="$PROJECT_ROOT/apps/collector"
PID_DIR="$PROJECT_ROOT/.pids"
LOG_DIR="$PROJECT_ROOT/.logs"

# PID files
API_PID_FILE="$PID_DIR/api.pid"
COLLECTOR_PID_FILE="$PID_DIR/collector.pid"
REDIS_PID_FILE="$PID_DIR/redis.pid"
CELERY_PID_FILE="$PID_DIR/celery.pid"

# Log files
API_LOG_FILE="$LOG_DIR/api.log"
COLLECTOR_LOG_FILE="$LOG_DIR/collector.log"
CELERY_LOG_FILE="$LOG_DIR/celery.log"

# Create directories
mkdir -p "$PID_DIR" "$LOG_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if process is running by PID
is_running() {
    local pid_file="$1"
    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            return 0  # Process is running
        else
            rm -f "$pid_file"  # Clean up stale PID file
            return 1
        fi
    fi
    return 1
}

# Kill orphaned processes by name
cleanup_orphaned() {
    local process_name="$1"
    log_info "Cleaning up orphaned $process_name processes..."

    # Get PIDs of processes matching the name
    local pids=$(pgrep -f "$process_name" || true)

    if [[ -n "$pids" ]]; then
        log_warning "Found orphaned $process_name processes: $pids"
        echo "$pids" | xargs kill -TERM 2>/dev/null || true
        sleep 2
        # Force kill if still running
        echo "$pids" | xargs kill -KILL 2>/dev/null || true
        log_success "Cleaned up orphaned $process_name processes"
    else
        log_info "No orphaned $process_name processes found"
    fi
}

# Start API server
start_api() {
    if is_running "$API_PID_FILE"; then
        log_warning "API server is already running (PID: $(cat $API_PID_FILE))"
        return 0
    fi

    log_info "Starting API server..."

    # Navigate to API directory
    cd "$API_DIR"

    # Sync dependencies
    log_info "Syncing API dependencies..."
    uv sync

    # Run migrations
    log_info "Running database migrations..."
    uv run alembic upgrade head

    # Start server in background and capture PID
    log_info "Starting uvicorn server..."
    nohup uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 > "$API_LOG_FILE" 2>&1 &
    local api_pid=$!
    echo "$api_pid" > "$API_PID_FILE"

    # Wait a moment and check if it started successfully
    sleep 3
    if is_running "$API_PID_FILE"; then
        log_success "API server started successfully (PID: $api_pid)"
        log_info "API available at: http://localhost:8000"
        log_info "API docs at: http://localhost:8000/docs"
        log_info "Logs: $API_LOG_FILE"
    else
        log_error "Failed to start API server"
        return 1
    fi
}

# Stop API server
stop_api() {
    if is_running "$API_PID_FILE"; then
        local pid=$(cat "$API_PID_FILE")
        log_info "Stopping API server (PID: $pid)..."
        kill -TERM "$pid"

        # Wait for graceful shutdown
        local count=0
        while is_running "$API_PID_FILE" && [[ $count -lt 10 ]]; do
            sleep 1
            ((count++))
        done

        if is_running "$API_PID_FILE"; then
            log_warning "Forcing API server shutdown..."
            kill -KILL "$pid" 2>/dev/null || true
        fi

        rm -f "$API_PID_FILE"
        log_success "API server stopped"
    else
        log_info "API server is not running"
    fi
}

# Start Celery worker
start_celery() {
    if is_running "$CELERY_PID_FILE"; then
        log_warning "Celery worker is already running (PID: $(cat $CELERY_PID_FILE))"
        return 0
    fi

    log_info "Starting Celery worker..."

    cd "$COLLECTOR_DIR"

    # Start Celery worker in background
    nohup uv run celery -A src.core.celery worker --loglevel=info > "$CELERY_LOG_FILE" 2>&1 &
    local celery_pid=$!
    echo "$celery_pid" > "$CELERY_PID_FILE"

    sleep 2
    if is_running "$CELERY_PID_FILE"; then
        log_success "Celery worker started successfully (PID: $celery_pid)"
        log_info "Logs: $CELERY_LOG_FILE"
    else
        log_error "Failed to start Celery worker"
        return 1
    fi
}

# Stop Celery worker
stop_celery() {
    if is_running "$CELERY_PID_FILE"; then
        local pid=$(cat "$CELERY_PID_FILE")
        log_info "Stopping Celery worker (PID: $pid)..."
        kill -TERM "$pid"

        # Wait for graceful shutdown
        local count=0
        while is_running "$CELERY_PID_FILE" && [[ $count -lt 15 ]]; do
            sleep 1
            ((count++))
        done

        if is_running "$CELERY_PID_FILE"; then
            log_warning "Forcing Celery worker shutdown..."
            kill -KILL "$pid" 2>/dev/null || true
        fi

        rm -f "$CELERY_PID_FILE"
        log_success "Celery worker stopped"
    else
        log_info "Celery worker is not running"
    fi
}

# Show status of all services
show_status() {
    echo
    log_info "=== Countermeasure Platform Status ==="
    echo

    # API Status
    if is_running "$API_PID_FILE"; then
        log_success "API Server: RUNNING (PID: $(cat $API_PID_FILE))"
        echo "  - URL: http://localhost:8000"
        echo "  - Docs: http://localhost:8000/docs"
        echo "  - Logs: $API_LOG_FILE"
    else
        log_error "API Server: STOPPED"
    fi

    # Celery Status
    if is_running "$CELERY_PID_FILE"; then
        log_success "Celery Worker: RUNNING (PID: $(cat $CELERY_PID_FILE))"
        echo "  - Logs: $CELERY_LOG_FILE"
    else
        log_error "Celery Worker: STOPPED"
    fi

    echo

    # Check for orphaned processes
    local orphaned_uvicorn=$(pgrep -f uvicorn | wc -l | tr -d ' ')
    local orphaned_celery=$(pgrep -f "celery.*worker" | wc -l | tr -d ' ')

    if [[ "$orphaned_uvicorn" -gt 0 ]] || [[ "$orphaned_celery" -gt 0 ]]; then
        log_warning "Orphaned Processes Found:"
        [[ "$orphaned_uvicorn" -gt 0 ]] && echo "  - uvicorn: $orphaned_uvicorn processes"
        [[ "$orphaned_celery" -gt 0 ]] && echo "  - celery: $orphaned_celery processes"
        echo "  Run: $0 cleanup"
    else
        log_info "No orphaned processes found"
    fi
}

# Cleanup all orphaned processes
cleanup_all() {
    log_info "=== Cleaning up orphaned processes ==="
    cleanup_orphaned "uvicorn"
    cleanup_orphaned "celery.*worker"

    # Remove stale PID files
    find "$PID_DIR" -name "*.pid" -type f | while read -r pid_file; do
        if ! is_running "$pid_file"; then
            rm -f "$pid_file"
            log_info "Removed stale PID file: $(basename "$pid_file")"
        fi
    done

    log_success "Cleanup complete"
}

# Main command handling
case "${1:-}" in
    start)
        log_info "=== Starting Countermeasure Platform ==="
        cleanup_all
        start_api
        start_celery
        echo
        show_status
        ;;
    stop)
        log_info "=== Stopping Countermeasure Platform ==="
        stop_celery
        stop_api
        log_success "Platform stopped"
        ;;
    restart)
        log_info "=== Restarting Countermeasure Platform ==="
        stop_celery
        stop_api
        sleep 2
        cleanup_all
        start_api
        start_celery
        echo
        show_status
        ;;
    status)
        show_status
        ;;
    cleanup)
        cleanup_all
        ;;
    api-only)
        log_info "=== Starting API Only ==="
        cleanup_orphaned "uvicorn"
        start_api
        ;;
    stop-api)
        stop_api
        ;;
    logs)
        log_info "=== Recent Logs ==="
        echo
        if [[ -f "$API_LOG_FILE" ]]; then
            echo "=== API Logs (last 20 lines) ==="
            tail -20 "$API_LOG_FILE"
            echo
        fi
        if [[ -f "$CELERY_LOG_FILE" ]]; then
            echo "=== Celery Logs (last 20 lines) ==="
            tail -20 "$CELERY_LOG_FILE"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|cleanup|api-only|stop-api|logs}"
        echo
        echo "Commands:"
        echo "  start     - Start all services (API + Celery)"
        echo "  stop      - Stop all services"
        echo "  restart   - Restart all services"
        echo "  status    - Show status of all services"
        echo "  cleanup   - Kill orphaned processes and clean PID files"
        echo "  api-only  - Start only the API server"
        echo "  stop-api  - Stop only the API server"
        echo "  logs      - Show recent logs from all services"
        echo
        exit 1
        ;;
esac