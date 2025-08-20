"""
Base SQLAlchemy model with common fields and functionality.

This module provides the base model class that all other models inherit from,
implementing common patterns and ensuring consistency across the data layer.
"""

from datetime import datetime
from typing import Any, Dict
from sqlalchemy import DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Mapped, mapped_column

# Create the base class for all models
Base = declarative_base()


class BaseModel(Base):
    """
    Abstract base model with common fields and functionality.
    
    Provides standard fields (id, created_at, updated_at) and common
    methods that all models should have.
    """
    
    __abstract__ = True
    
    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )
    
    def to_dict(self, exclude_fields: list[str] = None) -> Dict[str, Any]:
        """
        Convert model instance to dictionary.
        
        Args:
            exclude_fields: List of field names to exclude from output
            
        Returns:
            Dictionary representation of the model
        """
        exclude_fields = exclude_fields or []
        
        result = {}
        for column in self.__table__.columns:
            field_name = column.name
            if field_name not in exclude_fields:
                value = getattr(self, field_name)
                
                # Convert datetime objects to ISO format
                if isinstance(value, datetime):
                    value = value.isoformat()
                
                result[field_name] = value
        
        return result
    
    def update_from_dict(self, data: Dict[str, Any], exclude_fields: list[str] = None) -> None:
        """
        Update model instance from dictionary.
        
        Args:
            data: Dictionary with field values to update
            exclude_fields: List of field names to exclude from update
        """
        exclude_fields = exclude_fields or ['id', 'created_at']
        
        for key, value in data.items():
            if key not in exclude_fields and hasattr(self, key):
                setattr(self, key, value)
    
    def __repr__(self) -> str:
        """String representation of the model."""
        return f"<{self.__class__.__name__}(id={self.id})>"