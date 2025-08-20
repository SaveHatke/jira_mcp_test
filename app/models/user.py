"""
User model for authentication and profile management.

This module defines the User SQLAlchemy model with all required fields
for user registration, authentication, and Jira integration.
"""

from typing import Optional, List
from sqlalchemy import String, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.utils.encryption import encrypt_sensitive_data, decrypt_sensitive_data


class User(BaseModel):
    """
    User model for storing user account information and Jira credentials.
    
    Stores user registration data from Jira PAT validation including
    encrypted PAT tokens and profile information.
    """
    
    __tablename__ = 'users'
    
    # User identification fields
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
    
    # Authentication fields
    hashed_password: Mapped[str] = mapped_column(
        String(255), 
        nullable=False,
        comment="Bcrypt hashed password"
    )
    
    # Jira integration fields
    encrypted_jira_pat: Mapped[str] = mapped_column(
        Text, 
        nullable=False,
        comment="AES-256 encrypted Jira Personal Access Token"
    )
    
    jira_url: Mapped[str] = mapped_column(
        String(500), 
        nullable=False,
        comment="Base Jira URL extracted from /myself API response"
    )
    
    avatar_url: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        comment="Avatar URL from Jira user profile (48x48)"
    )
    
    # Status fields
    active: Mapped[bool] = mapped_column(
        Boolean, 
        default=True, 
        nullable=False,
        comment="User account active status"
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
    
    def get_jira_pat(self) -> str:
        """
        Decrypt and return the Jira PAT.
        
        Returns:
            Decrypted Jira Personal Access Token
            
        Raises:
            SecurityError: If decryption fails
        """
        return decrypt_sensitive_data(self.encrypted_jira_pat)
    
    def set_jira_pat(self, pat: str) -> None:
        """
        Encrypt and store the Jira PAT.
        
        Args:
            pat: Jira Personal Access Token to encrypt and store
            
        Raises:
            SecurityError: If encryption fails
        """
        self.encrypted_jira_pat = encrypt_sensitive_data(pat)
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert user to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive fields
            
        Returns:
            Dictionary representation of user
        """
        exclude_fields = ['hashed_password', 'encrypted_jira_pat']
        if not include_sensitive:
            exclude_fields.extend(['sessions', 'llm_config', 'confluence_config'])
        
        return super().to_dict(exclude_fields=exclude_fields)
    
    def is_configuration_complete(self) -> bool:
        """
        Check if user has completed all required configurations.
        
        Returns:
            True if all configurations are complete and tested
        """
        # Check if LLM config exists and is tested
        if not self.llm_config or not self.llm_config.tested_at:
            return False
        
        # Jira config is always available from registration
        # Confluence config is optional but if present should be tested
        if self.confluence_config and not self.confluence_config.tested_at:
            return False
        
        return True
    
    def __repr__(self) -> str:
        """String representation of the user."""
        return f"<User(id={self.id}, employee_id='{self.employee_id}', email='{self.email}')>"