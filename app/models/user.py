"""
User model with authentication and profile information.

This module defines the User model with proper relationships,
encryption for sensitive data, and user management functionality.
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Text, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel


class User(BaseModel):
    """
    User model representing registered users in the system.
    
    Each user registers with their Jira PAT token and maintains
    their own isolated configurations and data.
    """
    
    __tablename__ = 'users'
    
    # User identification (from Jira registration)
    employee_id: Mapped[str] = mapped_column(
        String(50), 
        unique=True, 
        nullable=False,
        index=True,
        comment="Employee ID from Jira (used as username)"
    )
    
    name: Mapped[str] = mapped_column(
        String(100), 
        nullable=False,
        comment="Full name from Jira user profile"
    )
    
    email: Mapped[str] = mapped_column(
        String(255), 
        unique=True, 
        nullable=False,
        index=True,
        comment="Email address from Jira user profile"
    )
    
    display_name: Mapped[str] = mapped_column(
        String(100), 
        nullable=False,
        comment="Display name from Jira user profile"
    )
    
    # Authentication
    hashed_password: Mapped[str] = mapped_column(
        String(255), 
        nullable=False,
        comment="Bcrypt hashed password"
    )
    
    # Jira integration (encrypted)
    encrypted_jira_pat: Mapped[str] = mapped_column(
        Text, 
        nullable=False,
        comment="AES-256 encrypted Jira Personal Access Token"
    )
    
    jira_url: Mapped[str] = mapped_column(
        String(500), 
        nullable=False,
        comment="Base Jira URL extracted from user profile"
    )
    
    # Profile information
    avatar_url: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        comment="Avatar URL from Jira (48x48)"
    )
    
    # Account status
    active: Mapped[bool] = mapped_column(
        Boolean, 
        default=True, 
        nullable=False,
        comment="Whether the user account is active"
    )
    
    # Relationships
    sessions: Mapped[List["UserSession"]] = relationship(
        "UserSession",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select"
    )
    
    llm_config: Mapped[Optional["LLMConfig"]] = relationship(
        "LLMConfig",
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
        lazy="select"
    )
    
    confluence_config: Mapped[Optional["ConfluenceConfig"]] = relationship(
        "ConfluenceConfig",
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
        lazy="select"
    )
    
    tool_cache_entries: Mapped[List["ToolCache"]] = relationship(
        "ToolCache",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select"
    )
    
    background_jobs: Mapped[List["BackgroundJob"]] = relationship(
        "BackgroundJob",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select"
    )
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_user_employee_id', 'employee_id'),
        Index('idx_user_email', 'email'),
        Index('idx_user_active', 'active'),
    )
    
    def __repr__(self) -> str:
        """String representation of the user."""
        return f"<User(id={self.id}, employee_id='{self.employee_id}', email='{self.email}')>"
    
    def to_dict(self, exclude_fields: list[str] = None) -> dict:
        """
        Convert user to dictionary, excluding sensitive fields by default.
        
        Args:
            exclude_fields: Additional fields to exclude
            
        Returns:
            Dictionary representation without sensitive data
        """
        default_exclude = ['hashed_password', 'encrypted_jira_pat']
        if exclude_fields:
            default_exclude.extend(exclude_fields)
        
        return super().to_dict(exclude_fields=default_exclude)
    
    @property
    def is_active(self) -> bool:
        """Check if user account is active."""
        return self.active
    
    @property
    def has_llm_config(self) -> bool:
        """Check if user has LLM configuration."""
        return self.llm_config is not None
    
    @property
    def has_confluence_config(self) -> bool:
        """Check if user has Confluence configuration."""
        return self.confluence_config is not None
    
    def get_masked_email(self) -> str:
        """Get masked email for display purposes."""
        if not self.email:
            return ""
        
        parts = self.email.split('@')
        if len(parts) != 2:
            return self.email
        
        username, domain = parts
        if len(username) <= 2:
            masked_username = '*' * len(username)
        else:
            masked_username = username[0] + '*' * (len(username) - 2) + username[-1]
        
        return f"{masked_username}@{domain}"


class UserSession(BaseModel):
    """
    User session model for JWT token management.
    
    Tracks active user sessions with expiration times and
    provides session management capabilities.
    """
    
    __tablename__ = 'user_sessions'
    
    # Foreign key to user
    user_id: Mapped[int] = mapped_column(
        nullable=False,
        index=True,
        comment="Reference to the user who owns this session"
    )
    
    # Session data
    token_hash: Mapped[str] = mapped_column(
        String(255), 
        nullable=False,
        unique=True,
        index=True,
        comment="SHA-256 hash of the JWT token"
    )
    
    expires_at: Mapped[datetime] = mapped_column(
        nullable=False,
        index=True,
        comment="When this session expires"
    )
    
    # Optional session metadata
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        comment="User agent string from the client"
    )
    
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),  # IPv6 max length
        nullable=True,
        comment="Client IP address"
    )
    
    # Relationship
    user: Mapped["User"] = relationship(
        "User",
        back_populates="sessions",
        lazy="select"
    )
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_session_user_id', 'user_id'),
        Index('idx_session_token_hash', 'token_hash'),
        Index('idx_session_expires_at', 'expires_at'),
    )
    
    def __repr__(self) -> str:
        """String representation of the session."""
        return f"<UserSession(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})>"
    
    @property
    def is_expired(self) -> bool:
        """Check if session is expired."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc) > self.expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if session is valid (not expired and user is active)."""
        return not self.is_expired and self.user and self.user.is_active