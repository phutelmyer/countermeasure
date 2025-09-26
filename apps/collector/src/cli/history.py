#!/usr/bin/env python3
"""
Collection history CLI utility.
"""

import argparse
from datetime import datetime
from typing import List

from src.models.collection_history import collection_history, CollectionRun


def format_duration(seconds: float) -> str:
    """Format duration in a human-readable way."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"


def format_datetime(dt: datetime) -> str:
    """Format datetime in a readable way."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def print_run_summary(run: CollectionRun, detailed: bool = False) -> None:
    """Print a summary of a collection run."""
    status_icon = {
        "completed": "✅",
        "completed_with_errors": "⚠️",
        "failed": "❌",
        "running": "⏳",
        "cancelled": "🚫"
    }.get(run.status, "❓")

    duration_str = format_duration(run.duration_seconds())
    success_rate = f"{run.success_rate():.1f}%" if run.total_processed > 0 else "N/A"

    print(f"{status_icon} {run.id[:8]} | {run.collector_type.upper()} | {format_datetime(run.start_time)}")
    print(f"   📊 {run.successful}/{run.total_processed} successful ({success_rate}) | ⏱️ {duration_str}")

    if run.duplicates_removed > 0:
        print(f"   🔄 {run.duplicates_removed} duplicates removed")

    if run.errors and not detailed:
        print(f"   🚨 {len(run.errors)} errors")

    if detailed:
        if run.configuration:
            print(f"   ⚙️ Config: {run.configuration}")

        if run.errors:
            print(f"   🚨 Errors:")
            for error in run.errors[:3]:
                print(f"      - {error}")
            if len(run.errors) > 3:
                print(f"      ... and {len(run.errors) - 3} more")

        if run.warnings:
            print(f"   ⚠️ Warnings:")
            for warning in run.warnings[:3]:
                print(f"      - {warning}")
            if len(run.warnings) > 3:
                print(f"      ... and {len(run.warnings) - 3} more")

        if run.metrics:
            print(f"   📈 Metrics: {run.metrics}")

    print()


def cmd_list(args) -> None:
    """List recent collection runs."""
    runs = collection_history.get_recent_runs(
        limit=args.limit,
        collector_type=args.type,
        tenant_id=args.tenant
    )

    if not runs:
        print("No collection runs found.")
        return

    print(f"Recent Collection Runs (showing {len(runs)} of {len(collection_history.runs)} total):")
    print("=" * 80)

    for run in runs:
        print_run_summary(run, detailed=args.detailed)


def cmd_show(args) -> None:
    """Show details of a specific collection run."""
    run = collection_history.get_run(args.run_id)

    if not run:
        print(f"Collection run '{args.run_id}' not found.")
        return

    print(f"Collection Run Details: {run.id}")
    print("=" * 50)
    print_run_summary(run, detailed=True)


def cmd_stats(args) -> None:
    """Show collection statistics."""
    stats = collection_history.get_stats(
        collector_type=args.type,
        tenant_id=args.tenant,
        days=args.days
    )

    print(f"Collection Statistics (last {args.days} days)")
    print("=" * 50)
    print(f"📊 Total Runs: {stats.total_runs}")
    print(f"✅ Successful: {stats.successful_runs}")
    print(f"❌ Failed: {stats.failed_runs}")
    print(f"📈 Success Rate: {(stats.successful_runs / stats.total_runs * 100):.1f}%" if stats.total_runs > 0 else "N/A")
    print(f"🔢 Total Detections: {stats.total_detections_collected}")
    print(f"🔄 Duplicates Removed: {stats.total_duplicates_removed}")
    print(f"⏱️ Avg Duration: {format_duration(stats.avg_duration_seconds)}")
    print(f"📅 Last Run: {format_datetime(stats.last_run_time) if stats.last_run_time else 'Never'}")

    if stats.common_errors:
        print(f"\n🚨 Common Errors:")
        for error_info in stats.common_errors:
            print(f"   {error_info['count']}x {error_info['error']}")

    print()


def cmd_cleanup(args) -> None:
    """Clean up old collection runs."""
    removed_count = collection_history.cleanup_old_runs(keep_days=args.keep_days)
    print(f"🧹 Cleaned up {removed_count} old collection runs (keeping last {args.keep_days} days)")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="Collection History Management")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # List command
    list_parser = subparsers.add_parser("list", help="List recent collection runs")
    list_parser.add_argument("--limit", type=int, default=20, help="Number of runs to show")
    list_parser.add_argument("--type", help="Filter by collector type")
    list_parser.add_argument("--tenant", help="Filter by tenant ID")
    list_parser.add_argument("--detailed", action="store_true", help="Show detailed information")

    # Show command
    show_parser = subparsers.add_parser("show", help="Show details of a specific run")
    show_parser.add_argument("run_id", help="Collection run ID")

    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show collection statistics")
    stats_parser.add_argument("--type", help="Filter by collector type")
    stats_parser.add_argument("--tenant", help="Filter by tenant ID")
    stats_parser.add_argument("--days", type=int, default=30, help="Number of days to include")

    # Cleanup command
    cleanup_parser = subparsers.add_parser("cleanup", help="Clean up old collection runs")
    cleanup_parser.add_argument("--keep-days", type=int, default=90, help="Number of days to keep")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == "list":
            cmd_list(args)
        elif args.command == "show":
            cmd_show(args)
        elif args.command == "stats":
            cmd_stats(args)
        elif args.command == "cleanup":
            cmd_cleanup(args)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()