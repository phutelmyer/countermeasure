"""
Unit tests for collector configuration management.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

from src.core.config import (
    Settings,
    BaseConfig,
    MitreConfig,
    SigmaConfig,
    ConfigManager,
    ConfigValidationError
)


class TestSettings:
    """Test suite for Settings configuration."""

    def test_default_settings(self):
        """Test default configuration values."""
        settings = Settings()

        assert settings.api_url == "http://localhost:8000"
        assert settings.default_email == "admin@countermeasure.dev"
        assert settings.environment == "development"
        assert settings.log_level == "INFO"
        assert settings.debug is False

    def test_settings_with_overrides(self):
        """Test settings with environment variable overrides."""
        with patch.dict('os.environ', {
            'API_URL': 'http://production:8000',
            'ENVIRONMENT': 'production',
            'LOG_LEVEL': 'ERROR',
            'DEBUG': 'true'
        }):
            settings = Settings()

            assert settings.api_url == "http://production:8000"
            assert settings.environment == "production"
            assert settings.log_level == "ERROR"
            assert settings.debug is True

    def test_redis_configuration(self):
        """Test Redis configuration."""
        settings = Settings()

        assert settings.redis_url == "redis://localhost:6379/0"
        assert settings.celery_broker_url == "redis://localhost:6379/0"
        assert settings.celery_result_backend == "redis://localhost:6379/0"

    def test_settings_validation(self):
        """Test settings validation."""
        # Test with valid settings
        settings = Settings(
            api_url="http://valid-url:8000",
            environment="production",
            log_level="DEBUG"
        )

        assert settings.api_url == "http://valid-url:8000"
        assert settings.environment == "production"
        assert settings.log_level == "DEBUG"


class TestMitreConfig:
    """Test suite for MITRE configuration."""

    def test_default_mitre_config(self):
        """Test default MITRE configuration."""
        config = MitreConfig()

        assert "attack.mitre.org" in config.mitre_stix_url
        assert config.mitre_cache_ttl == 3600
        assert config.mitre_batch_size == 100

    def test_mitre_config_validation(self):
        """Test MITRE configuration validation."""
        # Test with valid URL
        config = MitreConfig(
            mitre_stix_url="https://custom-mitre-source.com/stix.json"
        )
        assert config.mitre_stix_url == "https://custom-mitre-source.com/stix.json"

    def test_mitre_config_invalid_url(self):
        """Test MITRE configuration with invalid URL."""
        with pytest.raises(ValueError, match="Invalid MITRE STIX URL"):
            MitreConfig(mitre_stix_url="invalid-url")

    def test_mitre_config_batch_size_validation(self):
        """Test MITRE batch size validation."""
        # Valid batch size
        config = MitreConfig(mitre_batch_size=50)
        assert config.mitre_batch_size == 50

        # Invalid batch size (too small)
        with pytest.raises(ValueError, match="Batch size must be between"):
            MitreConfig(mitre_batch_size=0)

        # Invalid batch size (too large)
        with pytest.raises(ValueError, match="Batch size must be between"):
            MitreConfig(mitre_batch_size=1001)


class TestSigmaConfig:
    """Test suite for SIGMA configuration."""

    def test_default_sigma_config(self):
        """Test default SIGMA configuration."""
        config = SigmaConfig()

        assert config.sigma_repo_url == "https://github.com/SigmaHQ/sigma.git"
        assert config.sigma_cache_dir == "/tmp/sigma_cache"
        assert config.sigma_update_interval == 86400
        assert config.sigma_batch_size == 50

    def test_sigma_config_validation(self):
        """Test SIGMA configuration validation."""
        config = SigmaConfig(
            sigma_repo_url="https://github.com/custom/sigma.git",
            sigma_batch_size=25,
            sigma_categories=["process_creation", "network_connection"]
        )

        assert config.sigma_repo_url == "https://github.com/custom/sigma.git"
        assert config.sigma_batch_size == 25
        assert "process_creation" in config.sigma_categories

    def test_sigma_invalid_categories(self):
        """Test SIGMA configuration with invalid categories."""
        with pytest.raises(ValueError, match="Invalid category"):
            SigmaConfig(sigma_categories=["invalid_category"])

    def test_sigma_valid_categories(self):
        """Test SIGMA configuration with all valid categories."""
        valid_categories = [
            "process_creation",
            "network_connection",
            "file_event",
            "registry_event",
            "image_load",
            "dns"
        ]

        config = SigmaConfig(sigma_categories=valid_categories)
        assert config.sigma_categories == valid_categories

    def test_sigma_batch_size_validation(self):
        """Test SIGMA batch size validation."""
        # Valid batch size
        config = SigmaConfig(sigma_batch_size=25)
        assert config.sigma_batch_size == 25

        # Invalid batch size (too small)
        with pytest.raises(ValueError, match="Batch size must be between"):
            SigmaConfig(sigma_batch_size=0)

        # Invalid batch size (too large)
        with pytest.raises(ValueError, match="Batch size must be between"):
            SigmaConfig(sigma_batch_size=501)


class TestConfigManager:
    """Test suite for ConfigManager."""

    def test_config_manager_initialization(self):
        """Test ConfigManager initialization."""
        manager = ConfigManager(Settings)

        assert manager.config_schema == Settings
        assert manager._config is None

    def test_load_config_from_environment(self):
        """Test loading configuration from environment variables."""
        manager = ConfigManager(Settings)

        with patch.dict('os.environ', {
            'API_URL': 'http://env-test:8000',
            'LOG_LEVEL': 'DEBUG'
        }):
            config = manager.load_config()

            assert config.api_url == "http://env-test:8000"
            assert config.log_level == "DEBUG"

    def test_load_config_from_file(self):
        """Test loading configuration from file."""
        config_content = """
api_url: http://file-test:8000
environment: testing
log_level: WARNING
debug: true
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            config_file = f.name

        try:
            manager = ConfigManager(Settings)
            config = manager.load_config(config_file=config_file)

            assert config.api_url == "http://file-test:8000"
            assert config.environment == "testing"
            assert config.log_level == "WARNING"
            assert config.debug is True
        finally:
            Path(config_file).unlink()

    def test_load_config_file_not_found(self):
        """Test loading configuration when file doesn't exist."""
        manager = ConfigManager(Settings)

        with pytest.raises(ConfigValidationError, match="Config file not found"):
            manager.load_config(config_file="/nonexistent/config.yaml")

    def test_load_config_invalid_yaml(self):
        """Test loading configuration with invalid YAML."""
        invalid_yaml = "invalid: yaml: content: here:"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_yaml)
            config_file = f.name

        try:
            manager = ConfigManager(Settings)

            with pytest.raises(ConfigValidationError, match="Invalid YAML format"):
                manager.load_config(config_file=config_file)
        finally:
            Path(config_file).unlink()

    def test_load_config_validation_error(self):
        """Test configuration validation error handling."""
        # Create a config that will fail validation
        config_content = """
api_url: invalid-url-format
sigma_batch_size: -1
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            config_file = f.name

        try:
            manager = ConfigManager(SigmaConfig)

            with pytest.raises(ConfigValidationError, match="Configuration validation failed"):
                manager.load_config(config_file=config_file)
        finally:
            Path(config_file).unlink()

    def test_get_config_before_load(self):
        """Test getting configuration before it's loaded."""
        manager = ConfigManager(Settings)

        with pytest.raises(ConfigValidationError, match="Configuration not loaded"):
            manager.get_config()

    def test_get_config_after_load(self):
        """Test getting configuration after it's loaded."""
        manager = ConfigManager(Settings)

        # Load config first
        config = manager.load_config()

        # Now get_config should return the same instance
        retrieved_config = manager.get_config()

        assert retrieved_config is config
        assert isinstance(retrieved_config, Settings)

    def test_reload_config(self):
        """Test reloading configuration."""
        manager = ConfigManager(Settings)

        # Load initial config
        initial_config = manager.load_config()

        # Reload with different environment
        with patch.dict('os.environ', {'LOG_LEVEL': 'ERROR'}):
            reloaded_config = manager.load_config()

            assert reloaded_config is not initial_config
            assert reloaded_config.log_level == "ERROR"

    def test_validate_environment_values(self):
        """Test environment value validation."""
        manager = ConfigManager(Settings)

        # Test with invalid environment
        with patch.dict('os.environ', {'ENVIRONMENT': 'invalid_env'}):
            with pytest.raises(ConfigValidationError):
                manager.load_config()

        # Test with valid environment
        with patch.dict('os.environ', {'ENVIRONMENT': 'production'}):
            config = manager.load_config()
            assert config.environment == "production"

    def test_config_schema_flexibility(self):
        """Test using different config schemas."""
        # Test with MitreConfig
        mitre_manager = ConfigManager(MitreConfig)
        mitre_config = mitre_manager.load_config()
        assert isinstance(mitre_config, MitreConfig)

        # Test with SigmaConfig
        sigma_manager = ConfigManager(SigmaConfig)
        sigma_config = sigma_manager.load_config()
        assert isinstance(sigma_config, SigmaConfig)

    def test_config_precedence(self):
        """Test configuration precedence (env > file > defaults)."""
        config_content = """
api_url: http://file:8000
log_level: INFO
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            config_file = f.name

        try:
            # Environment should override file
            with patch.dict('os.environ', {'LOG_LEVEL': 'ERROR'}):
                manager = ConfigManager(Settings)
                config = manager.load_config(config_file=config_file)

                # File value
                assert config.api_url == "http://file:8000"
                # Environment override
                assert config.log_level == "ERROR"
                # Default value
                assert config.debug is False
        finally:
            Path(config_file).unlink()

    def test_config_with_custom_env_prefix(self):
        """Test configuration with custom environment prefix."""
        with patch.dict('os.environ', {
            'CUSTOM_API_URL': 'http://custom:8000',
            'CUSTOM_LOG_LEVEL': 'DEBUG'
        }):
            manager = ConfigManager(Settings)
            config = manager.load_config(env_prefix="CUSTOM_")

            assert config.api_url == "http://custom:8000"
            assert config.log_level == "DEBUG"