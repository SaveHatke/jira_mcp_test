"""
Database connection and session management.

This module provides database connectivity, session management,
and connection pooling for the SQLAlchemy ORM.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
import structlog

from app.config import settings
from app.models import Base

logger = structlog.get_logger(__name__)

# Global engine and session factory
engine = None
async_session_factory = None


def create_database_engine():
    """
    Create and configure the database engine.
    
    Returns:
        Configured SQLAlchemy async engine
    """
    global engine
    
    if engine is not None:
        return engine
    
    # Convert SQLite URL to async format
    database_url = settings.database_url
    if database_url.startswith("sqlite:///"):
        database_url = database_url.replace("sqlite:///", "sqlite+aiosqlite:///")
    elif database_url.startswith("sqlite://"):
        database_url = database_url.replace("sqlite://", "sqlite+aiosqlite://")
    
    # Engine configuration
    engine_kwargs = {
        "echo": settings.debug,  # Log SQL queries in debug mode
        "future": True,  # Use SQLAlchemy 2.0 style
    }
    
    # SQLite-specific configuration
    if "sqlite" in database_url:
        engine_kwargs.update({
            "poolclass": StaticPool,
            "connect_args": {
                "check_same_thread": False,
                "timeout": 30,
            }
        })
    
    engine = create_async_engine(database_url, **engine_kwargs)
    
    logger.info(
        "Database engine created",
        database_url=database_url.split("://")[0] + "://***",  # Hide credentials
        debug_mode=settings.debug
    )
    
    return engine


def create_session_factory():
    """
    Create and configure the session factory.
    
    Returns:
        Configured SQLAlchemy async session factory
    """
    global async_session_factory
    
    if async_session_factory is not None:
        return async_session_factory
    
    # Ensure engine exists
    if engine is None:
        create_database_engine()
    
    async_session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=True,
        autocommit=False
    )
    
    logger.info("Database session factory created")
    
    return async_session_factory


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session with automatic cleanup.
    
    This is the primary way to get database sessions throughout
    the application. It ensures proper session lifecycle management.
    
    Yields:
        AsyncSession: Database session
        
    Example:
        async with get_session() as session:
            user = await session.get(User, user_id)
    """
    # Ensure session factory exists
    if async_session_factory is None:
        create_session_factory()
    
    async with async_session_factory() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error("Database session error, rolling back", error=str(e))
            raise
        finally:
            await session.close()


async def init_database():
    """
    Initialize database by creating all tables.
    
    This should be called during application startup to ensure
    all tables exist before the application starts serving requests.
    """
    # Ensure engine exists
    if engine is None:
        create_database_engine()
    
    try:
        # Create all tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database tables created successfully")
        
    except Exception as e:
        logger.error("Failed to initialize database", error=str(e))
        raise


async def close_database():
    """
    Close database connections and cleanup resources.
    
    This should be called during application shutdown to ensure
    proper cleanup of database connections.
    """
    global engine, async_session_factory
    
    if engine is not None:
        await engine.dispose()
        engine = None
        logger.info("Database engine disposed")
    
    async_session_factory = None
    logger.info("Database session factory cleared")


async def check_database_health() -> bool:
    """
    Check database connectivity and health.
    
    Returns:
        True if database is healthy, False otherwise
    """
    try:
        async with get_session() as session:
            # Simple query to test connectivity
            from sqlalchemy import text
            result = await session.execute(text("SELECT 1"))
            return result.scalar() == 1
    except Exception as e:
        logger.error("Database health check failed", error=str(e))
        return False


class DatabaseManager:
    """
    Database manager for handling database lifecycle operations.
    
    Provides methods for initializing, managing, and monitoring
    database connections in an enterprise environment.
    """
    
    def __init__(self):
        """Initialize database manager."""
        self._initialized = False
    
    async def initialize(self) -> None:
        """
        Initialize database connections and create tables.
        
        Raises:
            Exception: If database initialization fails
        """
        if self._initialized:
            logger.warning("Database already initialized")
            return
        
        try:
            # Create engine and session factory
            create_database_engine()
            create_session_factory()
            
            # Initialize database schema
            await init_database()
            
            # Verify connectivity
            if not await check_database_health():
                raise Exception("Database health check failed after initialization")
            
            self._initialized = True
            logger.info("Database manager initialized successfully")
            
        except Exception as e:
            logger.error("Database initialization failed", error=str(e))
            raise
    
    async def shutdown(self) -> None:
        """
        Shutdown database connections and cleanup resources.
        """
        if not self._initialized:
            logger.warning("Database not initialized, nothing to shutdown")
            return
        
        try:
            await close_database()
            self._initialized = False
            logger.info("Database manager shutdown completed")
            
        except Exception as e:
            logger.error("Database shutdown failed", error=str(e))
            raise
    
    async def health_check(self) -> dict:
        """
        Perform comprehensive database health check.
        
        Returns:
            Dictionary with health check results
        """
        health_status = {
            "initialized": self._initialized,
            "engine_created": engine is not None,
            "session_factory_created": async_session_factory is not None,
            "connectivity": False,
            "error": None
        }
        
        try:
            if self._initialized:
                health_status["connectivity"] = await check_database_health()
        except Exception as e:
            health_status["error"] = str(e)
        
        return health_status
    
    @property
    def is_initialized(self) -> bool:
        """Check if database manager is initialized."""
        return self._initialized


# Global database manager instance
db_manager = DatabaseManager()


# Dependency for FastAPI
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for getting database sessions.
    
    This function can be used as a dependency in FastAPI route handlers
    to automatically inject database sessions.
    
    Yields:
        AsyncSession: Database session
        
    Example:
        @app.get("/users/{user_id}")
        async def get_user(user_id: int, session: AsyncSession = Depends(get_db_session)):
            return await session.get(User, user_id)
    """
    async with get_session() as session:
        yield session