"""
User session model for JWT token management.

This module defines the UserSession SQLAlchemy model for managing
user authentication sessions with expiration times.
"""

from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import String, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.utils.encryption import hash_token


class UserSession(BaseModel):
    """
    User session model for JWT token management with expiration times.
    
    Stores session tokens with expiration times and user references
    for secure session management and automatic cleanup.
    """
    
    __tablename__ = 'user_sessions'
    
    # Foreign key to user
    user_id: Mapped[int] = mapped_column(
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Reference to the user who owns this session"
    )
    
    # Session token (hashed for security)
    token_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        comment="SHA-256 hash of the JWT token"
    )
    
    # Session expiration
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Session expiration timestamp"
    )
    
    # Optional session metadata
    user_agent: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="User agent string from session creation"
    )
    
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),  # IPv6 max length
        nullable=True,
        comment="IP address from session creation"
    )
    
    # Relationship to user
    user: Mapped["User"] = relationship(
        "User", 
        back_populates="sessions",
        lazy="select"
    )
    
    @classmethod
    def create_session(
        cls,
        user_id: int,
        token: str,
        timeout_minutes: int = 30,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> "UserSession":
        """
        Create a new user session.
        
        Args:
            user_id: ID of the user
            token: JWT token to hash and store
            timeout_minutes: Session timeout in minutes
            user_agent: Optional user agent string
            ip_address: Optional IP address
            
        Returns:
            New UserSession instance
        """
        expires_at = datetime.utcnow() + timedelta(minutes=timeout_minutes)
        token_hash = hash_token(token)
        
        return cls(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address
        )
    
    def is_expired(self) -> bool:
        """
        Check if the session has expired.
        
        Returns:
            True if session is expired, False otherwise
        """
        return datetime.utcnow() > self.expires_at
    
    def extend_session(self, timeout_minutes: int = 30) -> None:
        """
        Extend the session expiration time.
        
        Args:
            timeout_minutes: Additional minutes to extend the session
        """
        self.expires_at = datetime.utcnow() + timedelta(minutes=timeout_minutes)
    
    def time_until_expiry(self) -> timedelta:
        """
        Get time remaining until session expires.
        
        Returns:
            Timedelta until expiration (negative if already expired)
        """
        return self.expires_at - datetime.utcnow()
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert session to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive fields
            
        Returns:
            Dictionary representation of session
        """
        exclude_fields = ['token_hash'] if not include_sensitive else []
        result = super().to_dict(exclude_fields=exclude_fields)
        
        # Add computed fields
        result['is_expired'] = self.is_expired()
        result['time_until_expiry_seconds'] = int(self.time_until_expiry().total_seconds())
        
        return result
    
    def __repr__(self) -> str:
        """String representation of the session."""
        return f"<UserSession(id={self.id}, user_id={self.user_id}, expires_at='{self.expires_at}')>"