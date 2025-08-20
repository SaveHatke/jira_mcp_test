"""
Models package for the AI Jira Confluence Agent.

This package contains all SQLAlchemy models for the application,
providing data persistence and relationship management.
"""

from app.models.base import Base, BaseModel
from app.models.user import User
from app.models.session import UserSession
from app.models.config import LLMConfig, ConfluenceConfig
from app.models.cache import ToolCache
from app.models.job import BackgroundJob

# Export all models for easy importing
__all__ = [
    'Base',
    'BaseModel',
    'User',
    'UserSession', 
    'LLMConfig',
    'ConfluenceConfig',
    'ToolCache',
    'BackgroundJob'
]