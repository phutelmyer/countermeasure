"""
Enterprise-grade configuration management for collectors.
"""

import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError, field_validator, validator
from pydantic_settings import BaseSettings, SettingsConfigDict


logger = logging.getLogger(__name__)


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""



class BaseConfig(BaseSettings):
    """Base configuration schema with common validation."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        case_sensitive=False,
        extra="forbid",
    )

    # API Configuration
    api_url: str = "http://localhost:8000"
    api_timeout_seconds: int = 30
    api_retries: int = 3

    # Authentication
    default_email: str = "admin@countermeasure.dev"
    default_password: str = ""

    # Collector Configuration
    collector_name: str = "countermeasure-collector"
    collector_version: str = "1.0.0"
    batch_size: int = 50
    max_workers: int = 4
    collection_timeout_minutes: int = 30

    # Environment
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"
    log_format: str = "structured"

    # Redis/Celery Configuration
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str | None = None
    celery_broker_url: str | None = None
    celery_result_backend: str | None = None

    @field_validator("api_url")
    @classmethod
    def validate_api_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("api_url must start with http:// or https://")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        return v.upper()

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        valid_envs = ["development", "staging", "production"]
        if v.lower() not in valid_envs:
            raise ValueError(f"environment must be one of {valid_envs}")
        return v.lower()

    def get_redis_url(self, db: int | None = None) -> str:
        """Get Redis URL for the specified database."""
        db_num = db if db is not None else self.redis_db
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{db_num}"
        return f"redis://{self.redis_host}:{self.redis_port}/{db_num}"

    @property
    def redis_broker_url(self) -> str:
        """Get Redis broker URL for Celery."""
        return self.get_redis_url(0)

    @property
    def redis_result_backend(self) -> str:
        """Get Redis result backend URL for Celery."""
        return self.get_redis_url(1)


class MitreConfig(BaseConfig):
    """Configuration schema for MITRE ATT&CK collector."""

    mitre_stix_url: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    # MITRE-specific settings
    enable_tactics: bool = True
    enable_techniques: bool = True
    enable_groups: bool = True
    batch_size: int = 50

    @validator("mitre_stix_url")
    def validate_mitre_url(cls, v):
        if not v.startswith(("http://", "https://")):
            raise ValueError("mitre_stix_url must be a valid URL")
        return v


class SigmaConfig(BaseConfig):
    """Configuration schema for SIGMA collector."""

    # SIGMA Repository Configuration
    sigma_repo_url: str = "https://github.com/SigmaHQ/sigma.git"
    sigma_repo_branch: str = "master"
    sigma_rules_directory: str = "rules"
    sigma_categories: list[str] = [
        "process_creation",
        "network_connection",
        "file_event",
        "registry_event",
        "image_load",
        "dns",
    ]

    # Collection Configuration
    collection_limit: int | None = None
    dry_run: bool = False

    # Git Configuration
    git_clone_depth: int = 1
    git_timeout_seconds: int = 300
    temp_dir_prefix: str = "countermeasure_sigma_"

    # Data Processing
    validate_sigma_rules: bool = True
    skip_invalid_rules: bool = True
    extract_metadata: bool = True
    enrich_with_mitre: bool = True

    @field_validator("sigma_categories")
    @classmethod
    def validate_categories(cls, v: list[str]) -> list[str]:
        valid_categories = [
            "process_creation",
            "network_connection",
            "file_event",
            "registry_event",
            "image_load",
            "dns",
            "command_line",
            "authentication",
            "privilege_escalation",
            "lateral_movement",
        ]
        for category in v:
            if category not in valid_categories:
                raise ValueError(f"Invalid category: {category}. Valid: {valid_categories}")
        return v


class Settings(BaseConfig):
    """Main collector settings combining all configs."""

    # API Configuration
    api_url: str = "http://localhost:8000"
    default_email: str = "admin@countermeasure.dev"
    default_password: str = "CountermeasureAdmin123!"

    # Basic Configuration
    environment: str = "development"
    log_level: str = "INFO"
    debug: bool = False

    # Redis Configuration
    redis_url: str = "redis://localhost:6379/0"

    # Celery Configuration
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"
    celery_timezone: str = "UTC"


class ConfigManager:
    """Enterprise configuration manager with validation, environment support, and secure loading."""

    def __init__(self, config_schema: type = BaseConfig):
        """
        Initialize config manager.

        Args:
            config_schema: Pydantic model class for validation
        """
        self.config_schema = config_schema
        self._config: BaseConfig | None = None

    def load_config(
        self,
        config_file: str | Path | None = None,
        env_prefix: str = "COUNTERMEASURE_",
        **override_kwargs,
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

            logger.info("Configuration loaded successfully")
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

    def _load_from_file(self, config_file: str | Path) -> dict[str, Any]:
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
            raise ConfigValidationError(
                f"Configuration path is not a file: {config_path}"
            )

        # Check file permissions
        if not os.access(config_path, os.R_OK):
            raise ConfigValidationError(
                f"Cannot read configuration file: {config_path}"
            )

        try:
            with open(config_path, encoding="utf-8") as f:
                config_data = json.load(f)

            if not isinstance(config_data, dict):
                raise ConfigValidationError(
                    "Configuration file must contain a JSON object"
                )

            logger.info(f"Loaded configuration from file: {config_path}")
            return config_data

        except json.JSONDecodeError as e:
            raise ConfigValidationError(
                f"Invalid JSON in configuration file {config_path}: {e}"
            )
        except Exception as e:
            raise ConfigValidationError(
                f"Error reading configuration file {config_path}: {e}"
            )

    def _load_from_env(self, prefix: str) -> dict[str, Any]:
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
            logger.info(
                f"Loaded {len(config_data)} configuration values from environment"
            )

        return config_data

    def _convert_env_value(self, value: str, key: str) -> Any:
        """Convert environment variable string to appropriate type."""

        # Boolean conversions
        if key in [
            "enable_tactics",
            "enable_techniques",
            "enable_groups",
            "include_test_rules",
        ]:
            return value.lower() in ("true", "1", "yes", "on")

        # Integer conversions
        if key in ["request_timeout", "max_retries", "batch_size", "limit"]:
            try:
                return int(value)
            except ValueError:
                logger.warning(f"Invalid integer value for {key}: {value}")
                return value

        # Float conversions
        if key in ["retry_delay"]:
            try:
                return float(value)
            except ValueError:
                logger.warning(f"Invalid float value for {key}: {value}")
                return value

        # String values (default)
        return value

    @property
    def config(self) -> BaseConfig | None:
        """Get the loaded configuration."""
        return self._config

    def get_config_dict(self) -> dict[str, Any]:
        """Get configuration as dictionary."""
        if self._config is None:
            raise ConfigValidationError("No configuration loaded")
        return self._config.dict()


# Global configuration instances
_sigma_config: SigmaConfig | None = None
_mitre_config: MitreConfig | None = None


def get_sigma_config() -> SigmaConfig:
    """Get the global SIGMA configuration instance."""
    global _sigma_config
    if _sigma_config is None:
        _sigma_config = SigmaConfig()
    return _sigma_config


def get_mitre_config() -> MitreConfig:
    """Get the global MITRE configuration instance."""
    global _mitre_config
    if _mitre_config is None:
        _mitre_config = MitreConfig()
    return _mitre_config


def load_sigma_config(**kwargs) -> SigmaConfig:
    """
    Load and cache SIGMA collector configuration.

    Args:
        **kwargs: Direct configuration overrides

    Returns:
        Validated SIGMA configuration
    """
    global _sigma_config
    _sigma_config = SigmaConfig(**kwargs)
    return _sigma_config


def load_mitre_config(**kwargs) -> MitreConfig:
    """
    Load and cache MITRE collector configuration.

    Args:
        **kwargs: Direct configuration overrides

    Returns:
        Validated MITRE configuration
    """
    global _mitre_config
    _mitre_config = MitreConfig(**kwargs)
    return _mitre_config
