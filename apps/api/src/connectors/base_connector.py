"""
Enhanced base connector with plugin support and better lifecycle management.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable
from enum import Enum

from src.core.logging import get_logger
from src.connectors.registry import ConnectorMetadata

logger = get_logger(__name__)


class ConnectorState(str, Enum):
    """States of connector execution."""
    IDLE = "idle"
    AUTHENTICATING = "authenticating"
    FETCHING = "fetching"
    PARSING = "parsing"
    ENRICHING = "enriching"
    SUBMITTING = "submitting"
    CLEANING_UP = "cleaning_up"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ConnectorResult:
    """Enhanced result format for connectors."""
    total_processed: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    duplicates_removed: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    state: ConnectorState = ConnectorState.IDLE
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_processed == 0:
            return 0.0
        return (self.successful / self.total_processed) * 100


class ProgressCallback:
    """Callback interface for progress updates."""

    def __init__(self, callback_func: Optional[Callable] = None):
        self.callback_func = callback_func

    def update(self, state: ConnectorState, progress: int = 0, message: str = ""):
        """Update progress with state, percentage, and message."""
        if self.callback_func:
            self.callback_func({
                "state": state.value,
                "progress": max(0, min(100, progress)),
                "message": message,
                "timestamp": time.time()
            })


class EnhancedConnector(ABC):
    """
    Enhanced base connector with better lifecycle management and plugin support.

    This is the evolution of AbstractCollector with:
    - Better state management
    - Progress callbacks
    - Plugin hooks
    - Enhanced error handling
    - Metrics collection
    """

    def __init__(
        self,
        config: Dict[str, Any],
        progress_callback: Optional[ProgressCallback] = None,
        metadata: Optional[ConnectorMetadata] = None
    ):
        """
        Initialize connector.

        Args:
            config: Configuration dictionary
            progress_callback: Optional callback for progress updates
            metadata: Connector metadata
        """
        self.config = config
        self.logger = logger
        self.progress = progress_callback or ProgressCallback()
        self.metadata = metadata

        # State management
        self.state = ConnectorState.IDLE
        self._start_time = 0.0

        # Plugin hooks
        self._before_hooks: List[Callable] = []
        self._after_hooks: List[Callable] = []
        self._error_hooks: List[Callable] = []

        # Metrics
        self.metrics = {
            "fetch_time": 0.0,
            "parse_time": 0.0,
            "enrich_time": 0.0,
            "submit_time": 0.0,
            "cleanup_time": 0.0,
        }

    # Plugin hook system
    def add_before_hook(self, hook: Callable) -> None:
        """Add a hook to run before connector execution."""
        self._before_hooks.append(hook)

    def add_after_hook(self, hook: Callable) -> None:
        """Add a hook to run after connector execution."""
        self._after_hooks.append(hook)

    def add_error_hook(self, hook: Callable) -> None:
        """Add a hook to run on errors."""
        self._error_hooks.append(hook)

    async def _run_hooks(self, hooks: List[Callable], *args, **kwargs) -> None:
        """Run a list of hooks."""
        for hook in hooks:
            try:
                if asyncio.iscoroutinefunction(hook):
                    await hook(self, *args, **kwargs)
                else:
                    hook(self, *args, **kwargs)
            except Exception as e:
                self.logger.warning(f"Hook failed: {e}")

    def _update_state(self, state: ConnectorState, progress: int = 0, message: str = ""):
        """Update connector state and notify progress."""
        self.state = state
        self.progress.update(state, progress, message)

    # Abstract methods (same as before but with enhanced typing)
    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with external services."""
        pass

    @abstractmethod
    async def fetch(self) -> Any:
        """Fetch raw data from source."""
        pass

    @abstractmethod
    async def parse(self, raw_data: Any) -> Any:
        """Parse raw data into structured format."""
        pass

    @abstractmethod
    async def enrich(self, parsed_data: Any) -> Any:
        """Enrich data with additional metadata."""
        pass

    @abstractmethod
    async def submit(self, enriched_data: Any) -> ConnectorResult:
        """Submit data to destination."""
        pass

    async def cleanup(self) -> None:
        """Cleanup resources. Override in subclasses."""
        pass

    # Enhanced run method with hooks and metrics
    async def run(self) -> ConnectorResult:
        """Execute the complete connector pipeline with enhanced features."""

        self._start_time = time.time()
        result = ConnectorResult()

        try:
            self._update_state(ConnectorState.IDLE, 0, "Starting connector")

            # Run before hooks
            await self._run_hooks(self._before_hooks)

            # Step 1: Authenticate
            self._update_state(ConnectorState.AUTHENTICATING, 10, "Authenticating")
            if not await self.authenticate():
                result.state = ConnectorState.FAILED
                result.errors.append("Authentication failed")
                result.execution_time = time.time() - self._start_time
                return result

            # Step 2: Fetch
            self._update_state(ConnectorState.FETCHING, 20, "Fetching data")
            fetch_start = time.time()
            raw_data = await self.fetch()
            self.metrics["fetch_time"] = time.time() - fetch_start

            # Step 3: Parse
            self._update_state(ConnectorState.PARSING, 40, "Parsing data")
            parse_start = time.time()
            parsed_data = await self.parse(raw_data)
            self.metrics["parse_time"] = time.time() - parse_start

            # Step 4: Enrich
            self._update_state(ConnectorState.ENRICHING, 60, "Enriching data")
            enrich_start = time.time()
            enriched_data = await self.enrich(parsed_data)
            self.metrics["enrich_time"] = time.time() - enrich_start

            # Step 5: Submit
            self._update_state(ConnectorState.SUBMITTING, 80, "Submitting data")
            submit_start = time.time()
            result = await self.submit(enriched_data)
            self.metrics["submit_time"] = time.time() - submit_start

            # Success
            result.state = ConnectorState.COMPLETED
            result.execution_time = time.time() - self._start_time
            result.metadata = {
                "connector_type": self.metadata.name if self.metadata else "unknown",
                "version": self.metadata.version if self.metadata else "unknown",
                "metrics": self.metrics,
                "config_hash": hash(str(sorted(self.config.items()))),
            }

            self._update_state(ConnectorState.COMPLETED, 100, "Completed successfully")

            # Run after hooks
            await self._run_hooks(self._after_hooks, result)

            self.logger.info(
                f"Connector completed: {result.successful} successful, "
                f"{result.failed} failed, {result.execution_time:.2f}s"
            )

            return result

        except Exception as e:
            # Handle errors
            self.state = ConnectorState.FAILED
            result.state = ConnectorState.FAILED
            result.errors.append(str(e))
            result.execution_time = time.time() - self._start_time

            self.logger.error(f"Connector failed: {e}", exc_info=True)

            # Run error hooks
            await self._run_hooks(self._error_hooks, e, result)

            self._update_state(ConnectorState.FAILED, 0, f"Failed: {str(e)}")

            return result

        finally:
            # Always cleanup
            try:
                self._update_state(ConnectorState.CLEANING_UP, 95, "Cleaning up")
                cleanup_start = time.time()
                await self.cleanup()
                self.metrics["cleanup_time"] = time.time() - cleanup_start
            except Exception as e:
                self.logger.warning(f"Cleanup failed: {e}")

    # Utility methods
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value with fallback."""
        return self.config.get(key, default)

    def get_required_config(self, key: str) -> Any:
        """Get required configuration value, raise if missing."""
        if key not in self.config:
            raise ValueError(f"Missing required configuration: {key}")
        return self.config[key]

    def validate_config(self) -> List[str]:
        """Validate configuration using metadata."""
        if not self.metadata:
            return []

        errors = []

        # Check required config
        for required_key in self.metadata.required_config:
            if required_key not in self.config:
                errors.append(f"Missing required config: {required_key}")

        return errors