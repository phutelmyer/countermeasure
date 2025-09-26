"""
Connector registry and plugin management system.
"""

import inspect
import importlib
import pkgutil
from typing import Dict, List, Type, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from src.core.logging import get_logger
from src.collectors.base import AbstractCollector

logger = get_logger(__name__)


class ConnectorType(str, Enum):
    """Types of connectors supported."""
    DETECTION = "detection"           # Detection rule sources (SIGMA, YARA, etc.)
    SIEM = "siem"                    # SIEM platforms (Splunk, Elastic, etc.)
    THREAT_INTEL = "threat_intel"    # Threat intelligence feeds
    FRAMEWORK = "framework"          # Security frameworks (MITRE, NIST, etc.)
    CUSTOM = "custom"                # Custom integrations


@dataclass
class ConnectorMetadata:
    """Metadata about a connector."""
    name: str
    display_name: str
    description: str
    version: str
    connector_type: ConnectorType
    author: str
    supported_formats: List[str]
    required_config: List[str]
    optional_config: List[str] = None
    documentation_url: str = None
    homepage_url: str = None
    tags: List[str] = None

    def __post_init__(self):
        if self.optional_config is None:
            self.optional_config = []
        if self.tags is None:
            self.tags = []


class ConnectorRegistry:
    """Registry for managing connectors and plugins."""

    def __init__(self):
        self._connectors: Dict[str, Type[AbstractCollector]] = {}
        self._metadata: Dict[str, ConnectorMetadata] = {}
        self._loaded = False

    def register_connector(
        self,
        name: str,
        connector_class: Type[AbstractCollector],
        metadata: ConnectorMetadata
    ) -> None:
        """Register a connector with the registry."""

        if not issubclass(connector_class, AbstractCollector):
            raise ValueError(f"Connector {name} must inherit from AbstractCollector")

        if name in self._connectors:
            logger.warning(f"Connector {name} is already registered, overwriting")

        self._connectors[name] = connector_class
        self._metadata[name] = metadata

        logger.info(f"Registered connector: {name} v{metadata.version}")

    def get_connector(self, name: str) -> Optional[Type[AbstractCollector]]:
        """Get a connector class by name."""
        return self._connectors.get(name)

    def get_metadata(self, name: str) -> Optional[ConnectorMetadata]:
        """Get connector metadata by name."""
        return self._metadata.get(name)

    def list_connectors(self, connector_type: ConnectorType = None) -> List[str]:
        """List all registered connectors, optionally filtered by type."""
        if connector_type is None:
            return list(self._connectors.keys())

        return [
            name for name, metadata in self._metadata.items()
            if metadata.connector_type == connector_type
        ]

    def get_all_metadata(self) -> Dict[str, ConnectorMetadata]:
        """Get metadata for all connectors."""
        return self._metadata.copy()

    def validate_config(self, name: str, config: Dict[str, Any]) -> List[str]:
        """Validate configuration for a connector."""
        metadata = self.get_metadata(name)
        if not metadata:
            return [f"Unknown connector: {name}"]

        errors = []

        # Check required config
        for required_key in metadata.required_config:
            if required_key not in config:
                errors.append(f"Missing required config key: {required_key}")

        # Check for unknown config keys (optional validation)
        all_keys = set(metadata.required_config + metadata.optional_config)
        for config_key in config:
            if config_key not in all_keys and config_key not in [
                "tenant_id", "user_id", "task_id"  # System keys
            ]:
                logger.warning(f"Unknown config key for {name}: {config_key}")

        return errors

    def auto_discover_connectors(self, search_paths: List[str] = None) -> int:
        """Auto-discover connectors in specified paths."""

        if search_paths is None:
            # Default search paths
            search_paths = [
                "src.connectors.detection",
                "src.connectors.siem",
                "src.connectors.threat_intel",
                "src.connectors.framework",
                "src.connectors.custom",
                # Legacy path
                "src.collectors.detection",
            ]

        discovered_count = 0

        for search_path in search_paths:
            try:
                discovered_count += self._discover_in_path(search_path)
            except ImportError as e:
                logger.debug(f"Could not discover connectors in {search_path}: {e}")

        logger.info(f"Auto-discovered {discovered_count} connectors")
        return discovered_count

    def _discover_in_path(self, module_path: str) -> int:
        """Discover connectors in a specific module path."""
        discovered_count = 0

        try:
            # Import the module
            module = importlib.import_module(module_path)

            # Walk through the package
            if hasattr(module, "__path__"):
                for importer, modname, ispkg in pkgutil.walk_packages(
                    module.__path__,
                    module_path + "."
                ):
                    try:
                        submodule = importlib.import_module(modname)
                        discovered_count += self._scan_module_for_connectors(submodule)
                    except ImportError as e:
                        logger.debug(f"Could not import {modname}: {e}")
            else:
                # Single module
                discovered_count += self._scan_module_for_connectors(module)

        except ImportError as e:
            logger.debug(f"Could not import {module_path}: {e}")

        return discovered_count

    def _scan_module_for_connectors(self, module) -> int:
        """Scan a module for connector classes."""
        discovered_count = 0

        for name, obj in inspect.getmembers(module, inspect.isclass):
            # Skip abstract classes and non-collectors
            if (
                obj is AbstractCollector or
                inspect.isabstract(obj) or
                not issubclass(obj, AbstractCollector)
            ):
                continue

            # Check if connector has metadata
            if hasattr(obj, '__connector_metadata__'):
                metadata = obj.__connector_metadata__
                connector_name = metadata.name

                self.register_connector(connector_name, obj, metadata)
                discovered_count += 1
            else:
                # Auto-generate basic metadata for legacy connectors
                connector_name = name.lower().replace('collector', '')
                metadata = ConnectorMetadata(
                    name=connector_name,
                    display_name=name,
                    description=f"Auto-discovered connector: {name}",
                    version="1.0.0",
                    connector_type=ConnectorType.CUSTOM,
                    author="Unknown",
                    supported_formats=[],
                    required_config=["api_url", "email", "password"],
                )

                self.register_connector(connector_name, obj, metadata)
                discovered_count += 1
                logger.warning(
                    f"Auto-registered legacy connector {connector_name} - "
                    f"consider adding __connector_metadata__"
                )

        return discovered_count

    def load_all_connectors(self) -> None:
        """Load all available connectors."""
        if self._loaded:
            return

        # Auto-discover connectors
        self.auto_discover_connectors()
        self._loaded = True

        logger.info(f"Loaded {len(self._connectors)} connectors")


# Decorator for registering connectors
def connector(
    name: str,
    display_name: str,
    description: str,
    version: str,
    connector_type: ConnectorType,
    author: str,
    supported_formats: List[str] = None,
    required_config: List[str] = None,
    optional_config: List[str] = None,
    documentation_url: str = None,
    homepage_url: str = None,
    tags: List[str] = None,
):
    """
    Decorator to register a connector with metadata.

    Usage:
        @connector(
            name="sigma",
            display_name="SIGMA Rules",
            description="Collect SIGMA detection rules from repositories",
            version="2.0.0",
            connector_type=ConnectorType.DETECTION,
            author="Countermeasure Team",
            supported_formats=["yaml", "yml"],
            required_config=["api_url", "email", "password", "repo_url"],
            optional_config=["categories", "limit", "batch_size"],
            tags=["detection", "rules", "sigma"]
        )
        class SigmaCollector(AbstractCollector):
            ...
    """

    def decorator(cls: Type[AbstractCollector]) -> Type[AbstractCollector]:
        # Create metadata
        metadata = ConnectorMetadata(
            name=name,
            display_name=display_name,
            description=description,
            version=version,
            connector_type=connector_type,
            author=author,
            supported_formats=supported_formats or [],
            required_config=required_config or [],
            optional_config=optional_config or [],
            documentation_url=documentation_url,
            homepage_url=homepage_url,
            tags=tags or [],
        )

        # Attach metadata to class
        cls.__connector_metadata__ = metadata

        return cls

    return decorator


# Global registry instance
connector_registry = ConnectorRegistry()