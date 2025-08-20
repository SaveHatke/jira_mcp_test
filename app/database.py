"""Database configuration and setup using SQLAlchemy with SQLite."""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.config import settings

# Create SQLite engine with proper configuration
engine = create_engine(
    settings.database_url,
    connect_args={
        "check_same_thread": False,  # Allow SQLite to be used with multiple threads
        "timeout": 20  # Connection timeout in seconds
    },
    poolclass=StaticPool,  # Use static pool for SQLite
    echo=settings.debug  # Log SQL queries in debug mode
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create declarative base for models
Base = declarative_base()


def get_db():
    """Dependency to get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create all database tables."""
    Base.metadata.create_all(bind=engine)


def drop_tables():
    """Drop all database tables (for testing)."""
    Base.metadata.drop_all(bind=engine)