"""
Application configuration management using pydantic-settings.

This module provides centralized configuration management with
environment variable support and validation.
"""

import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings with environment variable support.
    
    All settings can be overridden via environment variables
    with the APP_ prefix (e.g., APP_DATABASE_URL).
    """
    
    # Application settings
    app_name: str = Field(default="AI Jira Confluence Agent", description="Application name")
    debug: bool = Field(default=False, description="Enable debug mode")
    environment: str = Field(default="development", description="Environment (development/production)")
    
    # Database settings
    database_url: str = Field(
        default="sqlite:///./app.db",
        description="Database connection URL"
    )
    
    # Security settings
    secret_key: str = Field(
        default="your-secret-key-change-in-production",
        description="Secret key for JWT token signing"
    )
    
    # Session settings
    session_timeout_minutes: int = Field(
        default=30,
        description="Session timeout in minutes (15, 20, or 30)"
    )
    
    # Logging settings
    log_level: str = Field(default="INFO", description="Logging level")
    json_logs: bool = Field(default=True, description="Enable JSON logging")
    
    # External service settings
    jira_timeout_seconds: int = Field(default=30, description="Jira API timeout")
    confluence_timeout_seconds: int = Field(default=30, description="Confluence API timeout")
    llm_timeout_seconds: int = Field(default=60, description="LLM API timeout")
    
    # Retry settings
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    retry_base_delay: float = Field(default=1.0, description="Base delay for retries")
    
    # Cache settings
    tool_cache_ttl_seconds: int = Field(default=21600, description="Tool cache TTL (6 hours)")
    
    # Background job settings
    huey_immediate: bool = Field(default=False, description="Execute Huey jobs immediately")
    
    # OpenTelemetry settings
    otel_exporter_otlp_endpoint: Optional[str] = Field(
        default=None,
        description="OTLP endpoint for trace export"
    )
    
    class Config:
        """Pydantic configuration."""
        env_prefix = "APP_"
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()


def get_database_url() -> str:
    """
    Get database URL with proper formatting.
    
    Returns:
        Formatted database URL
    """
    return settings.database_url


def is_development() -> bool:
    """
    Check if running in development mode.
    
    Returns:
        True if in development mode
    """
    return settings.environment.lower() == "development"


def is_production() -> bool:
    """
    Check if running in production mode.
    
    Returns:
        True if in production mode
    """
    return settings.environment.lower() == "production"