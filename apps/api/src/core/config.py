"""
Core configuration management for Countermeasure API.
Handles environment variables, secrets, and application settings.
"""


from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with validation and type safety."""

    # Application Information
    app_name: str = Field(default="Countermeasure API", env="APP_NAME")
    app_version: str = Field(default="0.1.0", env="APP_VERSION")
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    # API Configuration
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_workers: int = Field(default=1, env="API_WORKERS")
    api_reload: bool = Field(default=False, env="API_RELOAD")

    # Database Configuration
    database_url: str = Field(
        default="postgresql+asyncpg://countermeasure:secretpassword@localhost:5432/countermeasure",
        env="DATABASE_URL",
    )
    database_pool_size: int = Field(default=10, env="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(default=20, env="DATABASE_MAX_OVERFLOW")
    database_echo: bool = Field(default=False, env="DATABASE_ECHO")

    # Redis Configuration
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    redis_cache_ttl: int = Field(default=3600, env="REDIS_CACHE_TTL")  # 1 hour

    # Security Configuration
    secret_key: str = Field(
        default="your-super-secret-key-change-this-in-production", env="SECRET_KEY"
    )
    access_token_expire_minutes: int = Field(
        default=15, env="ACCESS_TOKEN_EXPIRE_MINUTES"
    )
    refresh_token_expire_days: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    algorithm: str = Field(default="HS256", env="ALGORITHM")

    # CORS Configuration
    allowed_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080"],
        env="ALLOWED_ORIGINS",
    )
    allowed_methods: list[str] = Field(default=["*"], env="ALLOWED_METHODS")
    allowed_headers: list[str] = Field(default=["*"], env="ALLOWED_HEADERS")

    # Rate Limiting
    rate_limit_requests_per_minute: int = Field(
        default=60, env="RATE_LIMIT_REQUESTS_PER_MINUTE"
    )
    rate_limit_burst: int = Field(default=10, env="RATE_LIMIT_BURST")

    # External Services
    claude_api_key: str | None = Field(default=None, env="CLAUDE_API_KEY")
    mitre_api_url: str = Field(
        default="https://attack.mitre.org/api/v1", env="MITRE_API_URL"
    )
    github_token: str | None = Field(default=None, env="GITHUB_TOKEN")

    # Monitoring
    prometheus_metrics: bool = Field(default=True, env="PROMETHEUS_METRICS")
    jaeger_endpoint: str | None = Field(default=None, env="JAEGER_ENDPOINT")
    sentry_dsn: str | None = Field(default=None, env="SENTRY_DSN")
    sentry_environment: str | None = Field(default=None, env="SENTRY_ENVIRONMENT")
    sentry_traces_sample_rate: float = Field(default=0.1, env="SENTRY_TRACES_SAMPLE_RATE")

    # Feature Flags
    enable_ai_mapping: bool = Field(default=True, env="ENABLE_AI_MAPPING")
    enable_real_time_updates: bool = Field(default=True, env="ENABLE_REAL_TIME_UPDATES")
    enable_advanced_analytics: bool = Field(
        default=True, env="ENABLE_ADVANCED_ANALYTICS"
    )

    # File Upload Configuration
    max_file_size_mb: int = Field(default=50, env="MAX_FILE_SIZE_MB")
    allowed_file_types: list[str] = Field(
        default=[".yml", ".yaml", ".json", ".txt", ".xml"], env="ALLOWED_FILE_TYPES"
    )

    # Tenant Configuration
    default_tenant_slug: str = Field(default="default", env="DEFAULT_TENANT_SLUG")
    max_tenants_per_instance: int = Field(default=100, env="MAX_TENANTS_PER_INSTANCE")

    @validator("environment")
    def validate_environment(cls, v: str) -> str:
        """Validate environment setting."""
        allowed_environments = ["development", "staging", "production", "testing"]
        if v not in allowed_environments:
            raise ValueError(f"Environment must be one of: {allowed_environments}")
        return v

    @validator("log_level")
    def validate_log_level(cls, v: str) -> str:
        """Validate log level setting."""
        allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed_levels:
            raise ValueError(f"Log level must be one of: {allowed_levels}")
        return v.upper()

    @validator("database_url")
    def validate_database_url(cls, v: str) -> str:
        """Validate database URL format."""
        if not v.startswith(
            ("postgresql://", "postgresql+psycopg2://", "postgresql+asyncpg://")
        ):
            raise ValueError("Database URL must start with postgresql://")
        return v

    @validator("redis_url")
    def validate_redis_url(cls, v: str) -> str:
        """Validate Redis URL format."""
        if not v.startswith("redis://"):
            raise ValueError("Redis URL must start with redis://")
        return v

    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == "development"

    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == "production"

    @property
    def is_testing(self) -> bool:
        """Check if running in testing mode."""
        return self.environment == "testing"

    def get_database_url(self, async_driver: bool = False) -> str:
        """Get database URL with optional async driver."""
        if async_driver and not self.database_url.startswith("postgresql+asyncpg://"):
            return self.database_url.replace("postgresql://", "postgresql+asyncpg://")
        return self.database_url

    class Config:
        """Pydantic configuration."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Dependency to get settings instance."""
    return settings
