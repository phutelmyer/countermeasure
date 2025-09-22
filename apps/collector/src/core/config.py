"""
Enterprise-grade configuration management for collectors.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Union
from dataclasses import dataclass, field
from pydantic import BaseModel, ValidationError, validator
import logging

logger = logging.getLogger(__name__)


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""
    pass


class BaseConfig(BaseModel):
    """Base configuration schema with common validation."""

    # API Configuration
    api_url: str = "http://localhost:8000"
    email: str = "admin@countermeasure.dev"
    password: str = ""

    # Timeouts and rate limiting
    request_timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0

    # Logging
    log_level: str = "INFO"

    @validator('api_url')
    def validate_api_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('api_url must start with http:// or https://')
        return v

    @validator('log_level')
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'log_level must be one of {valid_levels}')
        return v.upper()

    @validator('password')
    def validate_password(cls, v):
        if not v:
            env_password = os.getenv('COUNTERMEASURE_PASSWORD')
            if env_password:
                return env_password
            raise ValueError('password must be provided via config or COUNTERMEASURE_PASSWORD env var')
        return v


class MitreConfig(BaseConfig):
    """Configuration schema for MITRE ATT&CK collector."""

    mitre_stix_url: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    # MITRE-specific settings
    enable_tactics: bool = True
    enable_techniques: bool = True
    enable_groups: bool = True
    batch_size: int = 50

    @validator('mitre_stix_url')
    def validate_mitre_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('mitre_stix_url must be a valid URL')
        return v


class SigmaConfig(BaseConfig):
    """Configuration schema for SIGMA collector."""

    repo_url: str = "https://github.com/SigmaHQ/sigma.git"
    branch: str = "master"
    limit: Optional[int] = None
    batch_size: int = 50

    # SIGMA-specific settings
    include_test_rules: bool = False
    min_confidence: str = "medium"

    @validator('min_confidence')
    def validate_confidence(cls, v):
        valid_levels = ['low', 'medium', 'high']
        if v.lower() not in valid_levels:
            raise ValueError(f'min_confidence must be one of {valid_levels}')
        return v.lower()


class ConfigManager:
    """Enterprise configuration manager with validation, environment support, and secure loading."""

    def __init__(self, config_schema: type = BaseConfig):
        """
        Initialize config manager.

        Args:
            config_schema: Pydantic model class for validation
        """
        self.config_schema = config_schema
        self._config: Optional[BaseConfig] = None

    def load_config(
        self,
        config_file: Optional[Union[str, Path]] = None,
        env_prefix: str = "COUNTERMEASURE_",
        **override_kwargs
    ) -> BaseConfig:
        """
        Load and validate configuration from multiple sources with priority order:
        1. Keyword arguments (highest priority)
        2. Environment variables
        3. Configuration file
        4. Default values (lowest priority)

        Args:
            config_file: Path to JSON configuration file
            env_prefix: Prefix for environment variables
            **override_kwargs: Direct configuration overrides

        Returns:
            Validated configuration object

        Raises:
            ConfigValidationError: If configuration is invalid
        """
        try:
            # Start with empty config dict
            config_data = {}

            # 1. Load from configuration file (if provided)
            if config_file:
                config_data.update(self._load_from_file(config_file))

            # 2. Load from environment variables
            config_data.update(self._load_from_env(env_prefix))

            # 3. Apply direct overrides
            config_data.update(override_kwargs)

            # 4. Validate and create config object
            self._config = self.config_schema(**config_data)

            logger.info(f"Configuration loaded successfully")
            logger.debug(f"Using API URL: {self._config.api_url}")

            return self._config

        except ValidationError as e:
            error_msg = f"Configuration validation failed: {e}"
            logger.error(error_msg)
            raise ConfigValidationError(error_msg) from e
        except Exception as e:
            error_msg = f"Failed to load configuration: {e}"
            logger.error(error_msg)
            raise ConfigValidationError(error_msg) from e

    def _load_from_file(self, config_file: Union[str, Path]) -> Dict[str, Any]:
        """
        Load configuration from JSON file with proper error handling.

        Args:
            config_file: Path to configuration file

        Returns:
            Configuration dictionary

        Raises:
            ConfigValidationError: If file cannot be loaded or parsed
        """
        config_path = Path(config_file)

        if not config_path.exists():
            raise ConfigValidationError(f"Configuration file not found: {config_path}")

        if not config_path.is_file():
            raise ConfigValidationError(f"Configuration path is not a file: {config_path}")

        # Check file permissions
        if not os.access(config_path, os.R_OK):
            raise ConfigValidationError(f"Cannot read configuration file: {config_path}")

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)

            if not isinstance(config_data, dict):
                raise ConfigValidationError("Configuration file must contain a JSON object")

            logger.info(f"Loaded configuration from file: {config_path}")
            return config_data

        except json.JSONDecodeError as e:
            raise ConfigValidationError(f"Invalid JSON in configuration file {config_path}: {e}")
        except Exception as e:
            raise ConfigValidationError(f"Error reading configuration file {config_path}: {e}")

    def _load_from_env(self, prefix: str) -> Dict[str, Any]:
        """
        Load configuration from environment variables.

        Args:
            prefix: Environment variable prefix

        Returns:
            Configuration dictionary from environment
        """
        config_data = {}

        # Map environment variables to config keys
        env_mappings = {
            f"{prefix}API_URL": "api_url",
            f"{prefix}EMAIL": "email",
            f"{prefix}PASSWORD": "password",
            f"{prefix}REQUEST_TIMEOUT": "request_timeout",
            f"{prefix}MAX_RETRIES": "max_retries",
            f"{prefix}RETRY_DELAY": "retry_delay",
            f"{prefix}LOG_LEVEL": "log_level",
            # MITRE-specific
            f"{prefix}MITRE_STIX_URL": "mitre_stix_url",
            f"{prefix}ENABLE_TACTICS": "enable_tactics",
            f"{prefix}ENABLE_TECHNIQUES": "enable_techniques",
            f"{prefix}ENABLE_GROUPS": "enable_groups",
            f"{prefix}BATCH_SIZE": "batch_size",
            # SIGMA-specific
            f"{prefix}REPO_URL": "repo_url",
            f"{prefix}BRANCH": "branch",
            f"{prefix}LIMIT": "limit",
            f"{prefix}INCLUDE_TEST_RULES": "include_test_rules",
            f"{prefix}MIN_CONFIDENCE": "min_confidence",
        }

        for env_var, config_key in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert string values to appropriate types
                config_data[config_key] = self._convert_env_value(value, config_key)

        if config_data:
            logger.info(f"Loaded {len(config_data)} configuration values from environment")

        return config_data

    def _convert_env_value(self, value: str, key: str) -> Any:
        """Convert environment variable string to appropriate type."""

        # Boolean conversions
        if key in ['enable_tactics', 'enable_techniques', 'enable_groups', 'include_test_rules']:
            return value.lower() in ('true', '1', 'yes', 'on')

        # Integer conversions
        if key in ['request_timeout', 'max_retries', 'batch_size', 'limit']:
            try:
                return int(value)
            except ValueError:
                logger.warning(f"Invalid integer value for {key}: {value}")
                return value

        # Float conversions
        if key in ['retry_delay']:
            try:
                return float(value)
            except ValueError:
                logger.warning(f"Invalid float value for {key}: {value}")
                return value

        # String values (default)
        return value

    @property
    def config(self) -> Optional[BaseConfig]:
        """Get the loaded configuration."""
        return self._config

    def get_config_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary."""
        if self._config is None:
            raise ConfigValidationError("No configuration loaded")
        return self._config.dict()


def load_mitre_config(config_file: Optional[str] = None, **kwargs) -> MitreConfig:
    """
    Convenience function to load MITRE collector configuration.

    Args:
        config_file: Optional path to configuration file
        **kwargs: Direct configuration overrides

    Returns:
        Validated MITRE configuration
    """
    manager = ConfigManager(MitreConfig)
    return manager.load_config(config_file, **kwargs)


def load_sigma_config(config_file: Optional[str] = None, **kwargs) -> SigmaConfig:
    """
    Convenience function to load SIGMA collector configuration.

    Args:
        config_file: Optional path to configuration file
        **kwargs: Direct configuration overrides

    Returns:
        Validated SIGMA configuration
    """
    manager = ConfigManager(SigmaConfig)
    return manager.load_config(config_file, **kwargs)