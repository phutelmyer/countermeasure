#!/usr/bin/env python3
"""
Startup script for Countermeasure Collector services.
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

from flower_config import get_flower_command_args
from src.core.config import BaseConfig, ConfigManager


class ServiceManager:
    """Manager for collector services."""

    def __init__(self):
        self.config_manager = ConfigManager(BaseConfig)
        self.config = self.config_manager.load_config()
        self.pids_dir = Path(".pids")
        self.pids_dir.mkdir(exist_ok=True)

    def get_pid_file(self, service: str) -> Path:
        """Get PID file path for a service."""
        return self.pids_dir / f"{service}.pid"

    def is_service_running(self, service: str) -> bool:
        """Check if a service is running."""
        pid_file = self.get_pid_file(service)
        if not pid_file.exists():
            return False

        try:
            with open(pid_file, 'r') as f:
                pid = int(f.read().strip())

            # Check if process is still running
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            # Process not running or invalid PID
            pid_file.unlink(missing_ok=True)
            return False

    def start_celery_worker(self, queues: Optional[List[str]] = None) -> subprocess.Popen:
        """Start Celery worker."""
        service_name = "celery-worker"

        if self.is_service_running(service_name):
            print(f"❌ Celery worker is already running")
            return None

        cmd = [
            "celery",
            "-A", "src.schedulers.celery_app:app",
            "worker",
            "--loglevel=info",
            "--pool=solo" if sys.platform == "win32" else "--pool=prefork",
            "--concurrency=4",
        ]

        if queues:
            cmd.extend(["--queues", ",".join(queues)])

        print(f"🚀 Starting Celery worker...")
        print(f"Command: {' '.join(cmd)}")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )

        # Save PID
        with open(self.get_pid_file(service_name), 'w') as f:
            f.write(str(process.pid))

        print(f"✅ Celery worker started (PID: {process.pid})")
        return process

    def start_celery_beat(self) -> subprocess.Popen:
        """Start Celery beat scheduler."""
        service_name = "celery-beat"

        if self.is_service_running(service_name):
            print(f"❌ Celery beat is already running")
            return None

        cmd = [
            "celery",
            "-A", "src.schedulers.celery_app:app",
            "beat",
            "--loglevel=info",
            "--schedule=celerybeat-schedule",
            "--pidfile=.pids/celerybeat.pid",
        ]

        print(f"📅 Starting Celery beat scheduler...")
        print(f"Command: {' '.join(cmd)}")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )

        # Save PID
        with open(self.get_pid_file(service_name), 'w') as f:
            f.write(str(process.pid))

        print(f"✅ Celery beat started (PID: {process.pid})")
        return process

    def start_flower(self) -> subprocess.Popen:
        """Start Flower monitoring."""
        service_name = "flower"

        if self.is_service_running(service_name):
            print(f"❌ Flower is already running")
            return None

        flower_args = get_flower_command_args()
        cmd = ["celery", "-A", "src.schedulers.celery_app:app", "flower"] + flower_args

        print(f"🌸 Starting Flower monitoring UI...")
        print(f"Command: {' '.join(cmd)}")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )

        # Save PID
        with open(self.get_pid_file(service_name), 'w') as f:
            f.write(str(process.pid))

        print(f"✅ Flower started (PID: {process.pid})")
        print(f"📊 Flower UI available at: http://localhost:5555")
        return process

    def stop_service(self, service: str) -> bool:
        """Stop a service."""
        if not self.is_service_running(service):
            print(f"❌ {service} is not running")
            return False

        pid_file = self.get_pid_file(service)
        try:
            with open(pid_file, 'r') as f:
                pid = int(f.read().strip())

            os.kill(pid, 15)  # SIGTERM
            time.sleep(2)

            # Check if still running
            try:
                os.kill(pid, 0)
                print(f"⚠️ {service} (PID: {pid}) didn't stop gracefully, sending SIGKILL")
                os.kill(pid, 9)  # SIGKILL
            except OSError:
                pass

            pid_file.unlink(missing_ok=True)
            print(f"✅ {service} stopped")
            return True

        except (OSError, ValueError) as e:
            print(f"❌ Failed to stop {service}: {e}")
            pid_file.unlink(missing_ok=True)
            return False

    def stop_all_services(self):
        """Stop all collector services."""
        services = ["flower", "celery-beat", "celery-worker"]
        for service in services:
            self.stop_service(service)

    def status(self):
        """Show status of all services."""
        services = {
            "celery-worker": "Celery Worker",
            "celery-beat": "Celery Beat Scheduler",
            "flower": "Flower Monitoring UI"
        }

        print("🔍 Countermeasure Collector Services Status")
        print("=" * 50)

        for service, description in services.items():
            running = self.is_service_running(service)
            status_icon = "✅" if running else "❌"
            status_text = "Running" if running else "Stopped"

            if running:
                pid_file = self.get_pid_file(service)
                with open(pid_file, 'r') as f:
                    pid = f.read().strip()
                print(f"{status_icon} {description}: {status_text} (PID: {pid})")
            else:
                print(f"{status_icon} {description}: {status_text}")

        # Show configuration info
        print(f"\n⚙️ Configuration:")
        print(f"   Redis Broker: {self.config.redis_broker_url}")
        print(f"   Environment: {self.config.environment}")
        print(f"   Log Level: {self.config.log_level}")

        # Show useful URLs
        if self.is_service_running("flower"):
            print(f"\n🌐 Access Points:")
            print(f"   Flower UI: http://localhost:5555")

    def start_all(self, background: bool = False):
        """Start all collector services."""
        print("🚀 Starting Countermeasure Collector Services")
        print("=" * 50)

        processes = []

        # Start services in order
        worker_process = self.start_celery_worker()
        if worker_process:
            processes.append(("celery-worker", worker_process))

        time.sleep(2)  # Give worker time to start

        beat_process = self.start_celery_beat()
        if beat_process:
            processes.append(("celery-beat", beat_process))

        time.sleep(2)  # Give beat time to start

        flower_process = self.start_flower()
        if flower_process:
            processes.append(("flower", flower_process))

        if not background and processes:
            print(f"\n🎯 All services started! Press Ctrl+C to stop all services.")
            print(f"📊 Monitor at: http://localhost:5555")

            try:
                # Wait for processes
                for name, process in processes:
                    process.wait()
            except KeyboardInterrupt:
                print(f"\n🛑 Stopping all services...")
                self.stop_all_services()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Countermeasure Collector Service Manager")
    parser.add_argument(
        "command",
        choices=["start", "stop", "restart", "status", "start-worker", "start-beat", "start-flower"],
        help="Service command"
    )
    parser.add_argument(
        "--background", "-b",
        action="store_true",
        help="Run in background (don't wait for processes)"
    )
    parser.add_argument(
        "--queues",
        nargs="+",
        help="Queues for worker to process"
    )

    args = parser.parse_args()

    service_manager = ServiceManager()

    try:
        if args.command == "start":
            service_manager.start_all(background=args.background)
        elif args.command == "stop":
            service_manager.stop_all_services()
        elif args.command == "restart":
            service_manager.stop_all_services()
            time.sleep(3)
            service_manager.start_all(background=args.background)
        elif args.command == "status":
            service_manager.status()
        elif args.command == "start-worker":
            worker_process = service_manager.start_celery_worker(queues=args.queues)
            if worker_process and not args.background:
                try:
                    worker_process.wait()
                except KeyboardInterrupt:
                    service_manager.stop_service("celery-worker")
        elif args.command == "start-beat":
            beat_process = service_manager.start_celery_beat()
            if beat_process and not args.background:
                try:
                    beat_process.wait()
                except KeyboardInterrupt:
                    service_manager.stop_service("celery-beat")
        elif args.command == "start-flower":
            flower_process = service_manager.start_flower()
            if flower_process and not args.background:
                try:
                    flower_process.wait()
                except KeyboardInterrupt:
                    service_manager.stop_service("flower")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()