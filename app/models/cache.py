"""
Tool cache model for storing MCP tool lists per user.

This module defines the ToolCache SQLAlchemy model for caching
MCP tool lists with TTL and refresh timestamps.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import json
from sqlalchemy import String, Text, Integer, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel


class ToolCache(BaseModel):
    """
    Tool cache model for storing MCP tool lists per user with TTL and refresh timestamps.
    
    Caches tool lists from Jira and Confluence MCP servers with automatic
    expiration and refresh capabilities for performance optimization.
    """
    
    __tablename__ = 'tool_cache'
    
    # Foreign key to user
    user_id: Mapped[int] = mapped_column(
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Reference to the user who owns this cache entry"
    )
    
    # Cache source identification
    source: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Source of the tools (jira, confluence)"
    )
    
    # Cached tool data
    tool_data: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="JSON serialized tool list data"
    )
    
    # Cache metadata
    refreshed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        comment="Timestamp when cache was last refreshed"
    )
    
    ttl_seconds: Mapped[int] = mapped_column(
        Integer,
        default=21600,  # 6 hours
        nullable=False,
        comment="Time-to-live in seconds (default 6 hours)"
    )
    
    # Cache statistics
    hit_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="Number of times this cache entry has been accessed"
    )
    
    last_accessed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when cache was last accessed"
    )
    
    # Relationship to user
    user: Mapped["User"] = relationship(
        "User", 
        back_populates="tool_cache_entries",
        lazy="select"
    )
    
    def get_tool_data(self) -> Dict[str, Any]:
        """
        Deserialize and return the cached tool data.
        
        Returns:
            Dictionary containing the cached tool data
            
        Raises:
            ValueError: If tool data cannot be deserialized
        """
        try:
            return json.loads(self.tool_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to deserialize tool data: {e}")
    
    def set_tool_data(self, data: Dict[str, Any]) -> None:
        """
        Serialize and store the tool data.
        
        Args:
            data: Dictionary containing tool data to cache
            
        Raises:
            ValueError: If data cannot be serialized
        """
        try:
            self.tool_data = json.dumps(data, ensure_ascii=False)
            self.refreshed_at = datetime.utcnow()
        except (TypeError, ValueError) as e:
            raise ValueError(f"Failed to serialize tool data: {e}")
    
    def is_expired(self) -> bool:
        """
        Check if the cache entry has expired.
        
        Returns:
            True if cache is expired, False otherwise
        """
        expiry_time = self.refreshed_at + timedelta(seconds=self.ttl_seconds)
        return datetime.utcnow() > expiry_time
    
    def time_until_expiry(self) -> timedelta:
        """
        Get time remaining until cache expires.
        
        Returns:
            Timedelta until expiration (negative if already expired)
        """
        expiry_time = self.refreshed_at + timedelta(seconds=self.ttl_seconds)
        return expiry_time - datetime.utcnow()
    
    def refresh_cache(self, data: Dict[str, Any]) -> None:
        """
        Refresh the cache with new data.
        
        Args:
            data: New tool data to cache
        """
        self.set_tool_data(data)
        self.refreshed_at = datetime.utcnow()
    
    def record_access(self) -> None:
        """
        Record that this cache entry was accessed.
        
        Updates hit count and last accessed timestamp.
        """
        self.hit_count += 1
        self.last_accessed_at = datetime.utcnow()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        return {
            'hit_count': self.hit_count,
            'last_accessed_at': self.last_accessed_at.isoformat() if self.last_accessed_at else None,
            'refreshed_at': self.refreshed_at.isoformat(),
            'is_expired': self.is_expired(),
            'time_until_expiry_seconds': int(self.time_until_expiry().total_seconds()),
            'ttl_seconds': self.ttl_seconds,
            'source': self.source
        }
    
    @classmethod
    def create_cache_entry(
        cls,
        user_id: int,
        source: str,
        tool_data: Dict[str, Any],
        ttl_seconds: int = 21600
    ) -> "ToolCache":
        """
        Create a new cache entry.
        
        Args:
            user_id: ID of the user
            source: Source of the tools (jira, confluence)
            tool_data: Tool data to cache
            ttl_seconds: Time-to-live in seconds
            
        Returns:
            New ToolCache instance
        """
        cache_entry = cls(
            user_id=user_id,
            source=source,
            ttl_seconds=ttl_seconds
        )
        cache_entry.set_tool_data(tool_data)
        return cache_entry
    
    def to_dict(self, include_data: bool = False) -> dict:
        """
        Convert cache entry to dictionary representation.
        
        Args:
            include_data: Whether to include the cached tool data
            
        Returns:
            Dictionary representation of cache entry
        """
        exclude_fields = [] if include_data else ['tool_data']
        result = super().to_dict(exclude_fields=exclude_fields)
        
        # Add computed fields
        result.update(self.get_cache_stats())
        
        if include_data:
            try:
                result['parsed_tool_data'] = self.get_tool_data()
            except ValueError:
                result['parsed_tool_data'] = None
        
        return result
    
    def __repr__(self) -> str:
        """String representation of the cache entry."""
        return f"<ToolCache(id={self.id}, user_id={self.user_id}, source='{self.source}', expired={self.is_expired()})>"