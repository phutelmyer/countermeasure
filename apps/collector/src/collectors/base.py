"""
Abstract base collector for all data collection operations.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CollectionResult:
    """Standard result format for all collectors."""
    total_processed: int
    successful: int
    failed: int
    errors: List[str]
    execution_time: float


class AbstractCollector(ABC):
    """
    Abstract base class for all collectors.

    Provides a standard pipeline for data collection:
    1. authenticate() - Authenticate with external services
    2. fetch() - Fetch raw data from source
    3. parse() - Parse raw data into structured format
    4. enrich() - Enrich data with additional metadata
    5. submit() - Submit processed data to Countermeasure API
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize collector with configuration.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = logger

    @abstractmethod
    async def authenticate(self) -> bool:
        """
        Authenticate with external services or APIs.

        Returns:
            True if authentication successful, False otherwise
        """
        pass

    @abstractmethod
    async def fetch(self) -> Any:
        """
        Fetch raw data from the source.

        Returns:
            Raw data from the source
        """
        pass

    @abstractmethod
    async def parse(self, raw_data: Any) -> Any:
        """
        Parse raw data into structured format.

        Args:
            raw_data: Raw data from fetch()

        Returns:
            Parsed structured data
        """
        pass

    @abstractmethod
    async def enrich(self, parsed_data: Any) -> Any:
        """
        Enrich parsed data with additional metadata.

        Args:
            parsed_data: Parsed data from parse()

        Returns:
            Enriched data ready for submission
        """
        pass

    @abstractmethod
    async def submit(self, enriched_data: Any) -> CollectionResult:
        """
        Submit enriched data to Countermeasure API.

        Args:
            enriched_data: Enriched data from enrich()

        Returns:
            Collection result with statistics
        """
        pass

    async def cleanup(self):
        """
        Cleanup resources after collection.
        Override in subclasses if cleanup is needed.
        """
        pass

    async def run(self) -> CollectionResult:
        """
        Execute the complete collection pipeline.

        Returns:
            Collection result with execution statistics
        """
        start_time = time.time()

        try:
            self.logger.info(f"Starting collection pipeline for {self.__class__.__name__}")

            # Step 1: Authenticate
            if not await self.authenticate():
                return CollectionResult(
                    total_processed=0,
                    successful=0,
                    failed=0,
                    errors=["Authentication failed"],
                    execution_time=time.time() - start_time
                )

            # Step 2: Fetch raw data
            self.logger.info("Fetching raw data from source...")
            raw_data = await self.fetch()

            # Step 3: Parse data
            self.logger.info("Parsing raw data...")
            parsed_data = await self.parse(raw_data)

            # Step 4: Enrich data
            self.logger.info("Enriching parsed data...")
            enriched_data = await self.enrich(parsed_data)

            # Step 5: Submit data
            self.logger.info("Submitting enriched data...")
            result = await self.submit(enriched_data)

            # Set execution time
            result.execution_time = time.time() - start_time

            self.logger.info(
                f"Collection completed: {result.successful} successful, "
                f"{result.failed} failed, {result.execution_time:.2f}s"
            )

            return result

        except Exception as e:
            self.logger.error(f"Collection pipeline failed: {str(e)}", exc_info=True)
            return CollectionResult(
                total_processed=0,
                successful=0,
                failed=0,
                errors=[str(e)],
                execution_time=time.time() - start_time
            )