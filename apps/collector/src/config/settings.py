"""
Configuration settings for the collector service.
"""

import os


class Settings:
    """Application settings."""

    # API Configuration
    API_URL: str = os.getenv("COUNTERMEASURE_API_URL", "http://localhost:8000")
    API_EMAIL: str | None = os.getenv("COUNTERMEASURE_EMAIL")
    API_PASSWORD: str | None = os.getenv("COUNTERMEASURE_PASSWORD")

    # Redis Configuration
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    REDIS_BROKER_DB: int = int(os.getenv("REDIS_BROKER_DB", "0"))
    REDIS_RESULT_DB: int = int(os.getenv("REDIS_RESULT_DB", "1"))

    # Celery Configuration
    CELERY_BROKER_URL: str = f"{REDIS_URL}/{REDIS_BROKER_DB}"
    CELERY_RESULT_BACKEND: str = f"{REDIS_URL}/{REDIS_RESULT_DB}"

    # Collection Configuration
    DEFAULT_BATCH_SIZE: int = int(os.getenv("DEFAULT_BATCH_SIZE", "50"))
    DEFAULT_TIMEOUT: int = int(os.getenv("DEFAULT_TIMEOUT", "300"))
    MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))

    # SIGMA Configuration
    SIGMA_REPO_URL: str = os.getenv(
        "SIGMA_REPO_URL", "https://github.com/SigmaHQ/sigma.git"
    )
    SIGMA_DEFAULT_LIMIT: int = int(os.getenv("SIGMA_DEFAULT_LIMIT", "100"))

    # Logging Configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = os.getenv(
        "LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-here")

    @classmethod
    def validate(cls) -> bool:
        """
        Validate required settings.

        Returns:
            True if all required settings are present, False otherwise
        """
        required_settings = [
            cls.API_EMAIL,
            cls.API_PASSWORD,
        ]

        missing = [setting for setting in required_settings if not setting]
        if missing:
            print(f"Missing required environment variables: {missing}")
            return False

        return True


settings = Settings()
