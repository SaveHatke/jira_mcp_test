"""
Configuration models for user-specific integrations.

This module defines models for storing user configurations for
LLM, Confluence, and other external service integrations.
"""

from typing import Optional
from datetime import datetime
from sqlalchemy import String, Text, Boolean, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel


class LLMConfig(BaseModel):
    """
    User-specific LLM configuration model.
    
    Stores encrypted cookies and configuration for Company LLM integration.
    Each user maintains their own LLM configuration with complete isolation.
    """
    
    __tablename__ = 'llm_configs'
    
    # Foreign key to user
    user_id: Mapped[int] = mapped_column(
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        unique=True,  # One config per user
        index=True,
        comment="Reference to the user who owns this configuration"
    )
    
    # Encrypted configuration data
    encrypted_cookie: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="AES-256 encrypted cookie value for LLM authentication"
    )
    
    # Configuration metadata
    tested_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When this configuration was last successfully tested"
    )
    
    test_success: Mapped[Optional[bool]] = mapped_column(
        Boolean,
        nullable=True,
        comment="Result of the last configuration test"
    )
    
    test_error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Error message from last failed test (if any)"
    )
    
    # LLM user validation
    llm_user_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="User ID returned by LLM service for validation"
    )
    
    llm_username: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Username returned by LLM service for validation"
    )
    
    # Relationship
    user: Mapped["User"] = relationship(
        "User",
        back_populates="llm_config",
        lazy="select"
    )
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_llm_config_user_id', 'user_id'),
        Index('idx_llm_config_tested_at', 'tested_at'),
    )
    
    def __repr__(self) -> str:
        """String representation of the LLM config."""
        return f"<LLMConfig(id={self.id}, user_id={self.user_id}, tested_at={self.tested_at})>"
    
    @property
    def is_tested(self) -> bool:
        """Check if configuration has been successfully tested."""
        return self.tested_at is not None and self.test_success is True
    
    @property
    def needs_testing(self) -> bool:
        """Check if configuration needs to be tested."""
        return self.tested_at is None or self.test_success is not True
    
    def mark_test_success(self, llm_user_id: str = None, llm_username: str = None) -> None:
        """Mark configuration test as successful."""
        self.tested_at = datetime.utcnow()
        self.test_success = True
        self.test_error_message = None
        if llm_user_id:
            self.llm_user_id = llm_user_id
        if llm_username:
            self.llm_username = llm_username
    
    def mark_test_failure(self, error_message: str) -> None:
        """Mark configuration test as failed."""
        self.tested_at = datetime.utcnow()
        self.test_success = False
        self.test_error_message = error_message


class ConfluenceConfig(BaseModel):
    """
    User-specific Confluence configuration model.
    
    Stores encrypted PAT tokens and configuration for Confluence MCP integration.
    Each user maintains their own Confluence configuration with complete isolation.
    """
    
    __tablename__ = 'confluence_configs'
    
    # Foreign key to user
    user_id: Mapped[int] = mapped_column(
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        unique=True,  # One config per user
        index=True,
        comment="Reference to the user who owns this configuration"
    )
    
    # Confluence connection details
    url: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="Confluence base URL"
    )
    
    encrypted_pat: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="AES-256 encrypted Confluence Personal Access Token"
    )
    
    # SSL configuration
    verify_ssl: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether to verify SSL certificates"
    )
    
    ssl_cert_path: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        comment="Path to custom SSL certificate file"
    )
    
    # Configuration metadata
    tested_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When this configuration was last successfully tested"
    )
    
    test_success: Mapped[Optional[bool]] = mapped_column(
        Boolean,
        nullable=True,
        comment="Result of the last configuration test"
    )
    
    test_error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Error message from last failed test (if any)"
    )
    
    # Confluence user validation
    confluence_user_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="User ID returned by Confluence for validation"
    )
    
    confluence_username: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Username returned by Confluence for validation"
    )
    
    # Relationship
    user: Mapped["User"] = relationship(
        "User",
        back_populates="confluence_config",
        lazy="select"
    )
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_confluence_config_user_id', 'user_id'),
        Index('idx_confluence_config_tested_at', 'tested_at'),
    )
    
    def __repr__(self) -> str:
        """String representation of the Confluence config."""
        return f"<ConfluenceConfig(id={self.id}, user_id={self.user_id}, url='{self.url}')>"
    
    @property
    def is_tested(self) -> bool:
        """Check if configuration has been successfully tested."""
        return self.tested_at is not None and self.test_success is True
    
    @property
    def needs_testing(self) -> bool:
        """Check if configuration needs to be tested."""
        return self.tested_at is None or self.test_success is not True
    
    @property
    def masked_url(self) -> str:
        """Get masked URL for display purposes."""
        if not self.url:
            return ""
        
        # Show protocol and domain, mask path if present
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        if parsed.path and parsed.path != '/':
            return f"{parsed.scheme}://{parsed.netloc}/***"
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def mark_test_success(self, confluence_user_id: str = None, confluence_username: str = None) -> None:
        """Mark configuration test as successful."""
        self.tested_at = datetime.utcnow()
        self.test_success = True
        self.test_error_message = None
        if confluence_user_id:
            self.confluence_user_id = confluence_user_id
        if confluence_username:
            self.confluence_username = confluence_username
    
    def mark_test_failure(self, error_message: str) -> None:
        """Mark configuration test as failed."""
        self.tested_at = datetime.utcnow()
        self.test_success = False
        self.test_error_message = error_message


class ToolCache(BaseModel):
    """
    Tool cache model for storing MCP tool lists per user.
    
    Caches tool lists from Jira and Confluence MCP servers with TTL
    and refresh timestamps for efficient tool discovery.
    """
    
    __tablename__ = 'tool_cache'
    
    # Foreign key to user
    user_id: Mapped[int] = mapped_column(
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Reference to the user who owns this cache entry"
    )
    
    # Cache identification
    source: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Source of the tools (jira, confluence)"
    )
    
    # Cached data
    tool_data: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="JSON serialized tool list data"
    )
    
    # Cache metadata
    refreshed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="When this cache entry was last refreshed"
    )
    
    ttl_seconds: Mapped[int] = mapped_column(
        default=21600,  # 6 hours
        nullable=False,
        comment="Time-to-live for this cache entry in seconds"
    )
    
    # Tool metadata
    tool_count: Mapped[Optional[int]] = mapped_column(
        nullable=True,
        comment="Number of tools in the cached data"
    )
    
    # Relationship
    user: Mapped["User"] = relationship(
        "User",
        back_populates="tool_cache_entries",
        lazy="select"
    )
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_tool_cache_user_source', 'user_id', 'source'),
        Index('idx_tool_cache_refreshed_at', 'refreshed_at'),
    )
    
    def __repr__(self) -> str:
        """String representation of the tool cache."""
        return f"<ToolCache(id={self.id}, user_id={self.user_id}, source='{self.source}')>"
    
    @property
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        from datetime import datetime, timezone, timedelta
        expiry_time = self.refreshed_at + timedelta(seconds=self.ttl_seconds)
        return datetime.now(timezone.utc) > expiry_time
    
    @property
    def expires_at(self) -> datetime:
        """Get expiration time for this cache entry."""
        from datetime import timedelta
        return self.refreshed_at + timedelta(seconds=self.ttl_seconds)
    
    def refresh_data(self, tool_data: str, tool_count: int = None) -> None:
        """Refresh cached tool data."""
        self.tool_data = tool_data
        self.refreshed_at = datetime.utcnow()
        if tool_count is not None:
            self.tool_count = tool_count


class BackgroundJob(BaseModel):
    """
    Background job model for tracking Huey job execution.
    
    Tracks background jobs with user isolation, status updates,
    and result storage for job monitoring and debugging.
    """
    
    __tablename__ = 'background_jobs'
    
    # Foreign key to user
    user_id: Mapped[int] = mapped_column(
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Reference to the user who owns this job"
    )
    
    # Job identification
    job_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Type of background job (tool_refresh, ai_generation, etc.)"
    )
    
    job_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        unique=True,
        index=True,
        comment="Unique job ID from Huey"
    )
    
    # Job data
    payload: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="JSON serialized job parameters"
    )
    
    # Job status
    status: Mapped[str] = mapped_column(
        String(20),
        default='pending',
        nullable=False,
        comment="Job status (pending, running, completed, failed)"
    )
    
    result: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="JSON serialized job result or error message"
    )
    
    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When job execution started"
    )
    
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When job execution completed"
    )
    
    # Retry information
    retry_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
        comment="Number of retry attempts"
    )
    
    max_retries: Mapped[int] = mapped_column(
        default=5,
        nullable=False,
        comment="Maximum number of retry attempts"
    )
    
    # Relationship
    user: Mapped["User"] = relationship(
        "User",
        back_populates="background_jobs",
        lazy="select"
    )
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_background_job_user_id', 'user_id'),
        Index('idx_background_job_status', 'status'),
        Index('idx_background_job_type', 'job_type'),
        Index('idx_background_job_created_at', 'created_at'),
    )
    
    def __repr__(self) -> str:
        """String representation of the background job."""
        return f"<BackgroundJob(id={self.id}, user_id={self.user_id}, type='{self.job_type}', status='{self.status}')>"
    
    @property
    def is_running(self) -> bool:
        """Check if job is currently running."""
        return self.status in ['pending', 'running']
    
    @property
    def is_completed(self) -> bool:
        """Check if job has completed (successfully or with failure)."""
        return self.status in ['completed', 'failed']
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Get job duration in seconds if completed."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    def mark_started(self) -> None:
        """Mark job as started."""
        self.status = 'running'
        self.started_at = datetime.utcnow()
    
    def mark_completed(self, result: str = None) -> None:
        """Mark job as completed successfully."""
        self.status = 'completed'
        self.completed_at = datetime.utcnow()
        if result:
            self.result = result
    
    def mark_failed(self, error_message: str) -> None:
        """Mark job as failed."""
        self.status = 'failed'
        self.completed_at = datetime.utcnow()
        self.result = error_message
    
    def increment_retry(self) -> bool:
        """Increment retry count and return True if more retries allowed."""
        self.retry_count += 1
        return self.retry_count < self.max_retries