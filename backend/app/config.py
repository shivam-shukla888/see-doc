import os
from typing import List
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_DEV_SECRET: str = "seedoc-dev-insecure-jwt-secret-key-must-change-in-prod-0987654321"


class Settings(BaseSettings):
    PROJECT_NAME: str = "Seedoc"
    ENVIRONMENT: str = "development"
    API_V1_STR: str = "/api/v1"

    # Security & JWT Configuration
    # In production, SECRET_KEY must be provided via environment variable and be >= 32 chars
    SECRET_KEY: str = INSECURE_DEV_SECRET
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database Configuration (Port 5433 to avoid host port conflict)
    # Default runtime user: seedoc_app (non-superuser for RLS enforcement)
    DATABASE_URL: str = "postgresql+psycopg://seedoc_app:seedoc_dev_password@localhost:5433/seedoc"
    ADMIN_DATABASE_URL: str = "postgresql+psycopg://seedoc:seedoc_dev_password@localhost:5433/seedoc"

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        """
        Fails safely if running in production without a properly configured strong secret.
        Never prints or exposes the secret in the exception message.
        """
        if self.ENVIRONMENT.lower() == "production":
            if not self.SECRET_KEY or self.SECRET_KEY == INSECURE_DEV_SECRET:
                raise ValueError(
                    "Insecure configuration: SECRET_KEY must be set to a strong secret in production. "
                    "Default development fallback secret is not permitted."
                )
            if len(self.SECRET_KEY) < 32:
                raise ValueError(
                    "Insecure configuration: Production SECRET_KEY must be at least 32 characters long."
                )
        return self


settings = Settings()
