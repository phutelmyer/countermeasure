"""
Main entry point for the collector service.
"""

import asyncio
import sys
from pathlib import Path

import click


# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from src.collectors.detection.sigma import SigmaCollector
from src.config.settings import settings
from src.core.logging import get_logger


logger = get_logger(__name__)


@click.group()
def cli():
    """Countermeasure Collector Service."""


@cli.command()
@click.option(
    "--api-url",
    default=settings.API_URL,
    help="Countermeasure API base URL",
    show_default=True,
)
@click.option(
    "--email", default=settings.API_EMAIL, help="Admin email for authentication"
)
@click.option(
    "--password",
    default=settings.API_PASSWORD,
    help="Admin password for authentication",
)
@click.option(
    "--repo-url",
    default=settings.SIGMA_REPO_URL,
    help="SIGMA repository URL",
    show_default=True,
)
@click.option(
    "--categories",
    multiple=True,
    help="Filter by rule categories (can be specified multiple times)",
)
@click.option(
    "--limit",
    type=int,
    default=settings.SIGMA_DEFAULT_LIMIT,
    help="Maximum number of rules to import",
    show_default=True,
)
@click.option(
    "--batch-size",
    type=int,
    default=settings.DEFAULT_BATCH_SIZE,
    help="Batch size for API submissions",
    show_default=True,
)
@click.option("--dry-run", is_flag=True, help="Preview rules without importing to API")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def collect_sigma(
    api_url: str,
    email: str,
    password: str,
    repo_url: str,
    categories: tuple,
    limit: int,
    batch_size: int,
    dry_run: bool,
    verbose: bool,
):
    """
    Collect SIGMA rules from SigmaHQ repository and import them into Countermeasure.

    This tool clones the SIGMA repository, parses the detection rules,
    enriches them with categories and tags, and imports them via the API.

    Examples:

        # Import first 10 rules in dry-run mode
        python main.py collect-sigma --email admin@example.com --password mypass --limit 10 --dry-run

        # Import only Windows process creation rules
        python main.py collect-sigma --email admin@example.com --password mypass --categories windows --categories process

        # Import from custom API endpoint
        python main.py collect-sigma --api-url https://my-countermeasure.com --email admin@example.com --password mypass
    """
    # Validate required parameters
    if not email or not password:
        click.echo("❌ Email and password are required", err=True)
        return 1

    # Configure logging
    import logging

    if verbose:
        logging.basicConfig(level=logging.DEBUG, format=settings.LOG_FORMAT)
    else:
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
        )

    # Build configuration
    config = {
        "api_url": api_url,
        "email": email,
        "password": password,
        "repo_url": repo_url,
        "categories": list(categories),
        "limit": limit,
        "batch_size": batch_size,
        "dry_run": dry_run,
    }

    async def run_collector():
        """Run the SIGMA collector asynchronously."""
        collector = SigmaCollector(config)

        try:
            click.echo("🚀 Starting SIGMA rule collection...")

            if dry_run:
                click.echo("🔍 Running in DRY-RUN mode - no rules will be imported")

            if categories:
                click.echo(f"📂 Filtering by categories: {', '.join(categories)}")

            if limit:
                click.echo(f"📊 Limiting to {limit} rules")

            # Run collection
            result = await collector.run()

            # Print detailed summary
            collector.print_summary(result)

            if result.successful > 0:
                if dry_run:
                    click.echo(
                        f"\n✅ Dry run completed successfully! {result.successful} rules would be imported."
                    )
                else:
                    click.echo(
                        f"\n✅ Successfully imported {result.successful} SIGMA rules!"
                    )
                return 0
            click.echo("\n❌ No rules were imported. Check logs for errors.")
            return 1

        except Exception as e:
            click.echo(f"\n💥 Collection failed: {e!s}", err=True)
            if verbose:
                import traceback

                traceback.print_exc()
            return 1

    # Run the async collector
    exit_code = asyncio.run(run_collector())
    sys.exit(exit_code)


@cli.command()
@click.option(
    "--api-url",
    default=settings.API_URL,
    help="Countermeasure API base URL",
    show_default=True,
)
@click.option(
    "--email", default=settings.API_EMAIL, help="Admin email for authentication"
)
@click.option(
    "--password",
    default=settings.API_PASSWORD,
    help="Admin password for authentication",
)
def test_connection(api_url: str, email: str, password: str):
    """Test connection to Countermeasure API."""
    if not email or not password:
        click.echo("❌ Email and password are required", err=True)
        return 1

    async def test():
        from src.core.api_client import CountermeasureClient

        client = CountermeasureClient(api_url, email, password)
        try:
            click.echo("🔌 Testing connection to Countermeasure API...")

            if await client.login():
                click.echo("✅ Authentication successful!")

                # Test fetching severities
                severities = await client.get_severities()
                click.echo(f"📊 Found {len(severities)} severity levels")

                return 0
            click.echo("❌ Authentication failed!")
            return 1

        except Exception as e:
            click.echo(f"💥 Connection failed: {e!s}", err=True)
            return 1
        finally:
            await client.close()

    exit_code = asyncio.run(test())
    sys.exit(exit_code)


@cli.command()
def worker():
    """Start Celery worker."""
    click.echo("🔧 Starting Celery worker...")
    import subprocess

    subprocess.run(
        ["celery", "-A", "src.schedulers.celery_app", "worker", "--loglevel=info"], check=False
    )


@cli.command()
def beat():
    """Start Celery beat scheduler."""
    click.echo("⏰ Starting Celery beat scheduler...")
    import subprocess

    subprocess.run(
        ["celery", "-A", "src.schedulers.celery_app", "beat", "--loglevel=info"], check=False
    )


@cli.command()
def flower():
    """Start Flower monitoring."""
    click.echo("🌸 Starting Flower monitoring...")
    import subprocess

    subprocess.run(["celery", "-A", "src.schedulers.celery_app", "flower"], check=False)


if __name__ == "__main__":
    cli()
