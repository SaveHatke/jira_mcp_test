"""
Configuration models for user-specific integrations.

This module defines SQLAlchemy models for storing user-specific
configurations for LLM and Confluence integrations.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.utils.encryption import encrypt_sensitive_data, decrypt_sensitive_data


class LLMConfig(BaseModel):
    """
    LLM configuration model for user-specific Custom LLM configurations.
    
    Stores encrypted cookie values and test status for Custom LLM integration
    with simple save/overwrite functionality.
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
    
    # Encrypted cookie/token data
    encrypted_cookie: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="AES-256 encrypted cookie value for Custom LLM authentication"
    )
    
    # Test status
    tested_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when configuration was last successfully tested"
    )
    
    # Test metadata
    test_user_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="User ID returned from successful test (for validation)"
    )
    
    test_username: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Username returned from successful test (for validation)"
    )
    
    # Relationship to user
    user: Mapped["User"] = relationship(
        "User", 
        back_populates="llm_config",
        lazy="select"
    )
    
    def get_cookie(self) -> str:
        """
        Decrypt and return the cookie value.
        
        Returns:
            Decrypted cookie value
            
        Raises:
            SecurityError: If decryption fails
        """
        return decrypt_sensitive_data(self.encrypted_cookie)
    
    def set_cookie(self, cookie: str) -> None:
        """
        Encrypt and store the cookie value.
        
        Args:
            cookie: Cookie value to encrypt and store
            
        Raises:
            SecurityError: If encryption fails
        """
        self.encrypted_cookie = encrypt_sensitive_data(cookie)
    
    def mark_tested(self, user_id: str, username: str) -> None:
        """
        Mark configuration as successfully tested.
        
        Args:
            user_id: User ID from test response
            username: Username from test response
        """
        self.tested_at = datetime.utcnow()
        self.test_user_id = user_id
        self.test_username = username
    
    def is_tested(self) -> bool:
        """
        Check if configuration has been successfully tested.
        
        Returns:
            True if configuration has been tested, False otherwise
        """
        return self.tested_at is not None
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert configuration to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive fields
            
        Returns:
            Dictionary representation of configuration
        """
        exclude_fields = ['encrypted_cookie'] if not include_sensitive else []
        result = super().to_dict(exclude_fields=exclude_fields)
        
        # Add computed fields
        result['is_tested'] = self.is_tested()
        if include_sensitive:
            result['cookie'] = self.get_cookie()
        
        return result
    
    def __repr__(self) -> str:
        """String representation of the configuration."""
        return f"<LLMConfig(id={self.id}, user_id={self.user_id}, tested={self.is_tested()})>"


class ConfluenceConfig(BaseModel):
    """
    Confluence configuration model for user-specific Confluence configurations.
    
    Stores encrypted PAT tokens and connection settings for Confluence MCP integration
    with SSL verification options.
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
    
    # Confluence connection settings
    url: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="Confluence base URL (≥150 characters)"
    )
    
    encrypted_pat: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="AES-256 encrypted Confluence Personal Access Token (≤20 chars)"
    )
    
    # SSL settings
    verify_ssl: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether to verify SSL certificates"
    )
    
    ssl_cert_path: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        comment="Path to SSL certificate file (when verify_ssl is True)"
    )
    
    # Test status
    tested_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when configuration was last successfully tested"
    )
    
    # Test metadata
    test_username: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Username returned from successful test (for employee ID validation)"
    )
    
    test_user_key: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="User key returned from successful test"
    )
    
    # Relationship to user
    user: Mapped["User"] = relationship(
        "User", 
        back_populates="confluence_config",
        lazy="select"
    )
    
    def get_pat(self) -> str:
        """
        Decrypt and return the PAT.
        
        Returns:
            Decrypted Confluence Personal Access Token
            
        Raises:
            SecurityError: If decryption fails
        """
        return decrypt_sensitive_data(self.encrypted_pat)
    
    def set_pat(self, pat: str) -> None:
        """
        Encrypt and store the PAT.
        
        Args:
            pat: Confluence Personal Access Token to encrypt and store
            
        Raises:
            SecurityError: If encryption fails
        """
        self.encrypted_pat = encrypt_sensitive_data(pat)
    
    def mark_tested(self, username: str, user_key: str) -> None:
        """
        Mark configuration as successfully tested.
        
        Args:
            username: Username from test response
            user_key: User key from test response
        """
        self.tested_at = datetime.utcnow()
        self.test_username = username
        self.test_user_key = user_key
    
    def is_tested(self) -> bool:
        """
        Check if configuration has been successfully tested.
        
        Returns:
            True if configuration has been tested, False otherwise
        """
        return self.tested_at is not None
    
    def validate_url_length(self) -> bool:
        """
        Validate that URL meets minimum length requirement.
        
        Returns:
            True if URL is ≥150 characters, False otherwise
        """
        return len(self.url) >= 150
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert configuration to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive fields
            
        Returns:
            Dictionary representation of configuration
        """
        exclude_fields = ['encrypted_pat'] if not include_sensitive else []
        result = super().to_dict(exclude_fields=exclude_fields)
        
        # Add computed fields
        result['is_tested'] = self.is_tested()
        result['url_length_valid'] = self.validate_url_length()
        if include_sensitive:
            result['pat'] = self.get_pat()
        
        return result
    
    def __repr__(self) -> str:
        """String representation of the configuration."""
        return f"<ConfluenceConfig(id={self.id}, user_id={self.user_id}, url='{self.url[:50]}...', tested={self.is_tested()})>"