"""Configuration management using pydantic-settings for environment variables."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )
    
    # Application settings
    app_name: str = Field(default="Jira Intelligence Agent", description="Application name")
    debug: bool = Field(default=False, description="Debug mode")
    log_level: str = Field(default="INFO", description="Logging level")
    
    # Database settings
    database_url: str = Field(default="sqlite:///./app.db", description="Database URL")
    
    # Security settings
    secret_key: str = Field(default="your-secret-key-change-in-production", description="JWT secret key")
    session_timeout_minutes: int = Field(default=30, description="Session timeout in minutes")
    
    # Server settings
    host: str = Field(default="127.0.0.1", description="Server host")
    port: int = Field(default=8000, description="Server port")
    
    # OpenTelemetry settings
    otel_exporter_otlp_endpoint: Optional[str] = Field(default=None, description="OTLP endpoint for traces")
    
    # Configuration file paths
    config_dir: str = Field(default="config", description="Configuration directory")
    llm_config_file: str = Field(default="config/config.json", description="LLM configuration file")
    header_config_file: str = Field(default="config/header.json", description="Header configuration file")
    payload_config_file: str = Field(default="config/payload.json", description="Payload configuration file")
    prompts_config_file: str = Field(default="config/prompts.json", description="Prompts configuration file")


# Global settings instance
settings = Settings()