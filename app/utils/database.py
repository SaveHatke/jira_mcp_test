"""
Database utilities for initialization and management.

This module provides utilities for database initialization, health checks,
and maintenance operations.
"""

import asyncio
from typing import Dict, Any, Optional
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.database import get_session, init_database, check_database_health, db_manager
from app.models import User, UserSession, LLMConfig, ConfluenceConfig, ToolCache, BackgroundJob
from app.utils.logging import get_logger

logger = get_logger(__name__)


async def initialize_database() -> Dict[str, Any]:
    """
    Initialize the database and perform health checks.
    
    Returns:
        Dictionary with initialization results
    """
    result = {
        "success": False,
        "tables_created": False,
        "health_check": False,
        "error": None
    }
    
    try:
        # Initialize database manager
        await db_manager.initialize()
        result["tables_created"] = True
        
        # Perform health check
        health_status = await check_database_health()
        result["health_check"] = health_status
        
        if health_status:
            result["success"] = True
            logger.info("Database initialization completed successfully")
        else:
            result["error"] = "Health check failed"
            logger.error("Database health check failed after initialization")
        
    except Exception as e:
        result["error"] = str(e)
        logger.error("Database initialization failed", error=str(e))
    
    return result


async def get_database_stats() -> Dict[str, Any]:
    """
    Get database statistics and table counts.
    
    Returns:
        Dictionary with database statistics
    """
    stats = {
        "users": 0,
        "sessions": 0,
        "llm_configs": 0,
        "confluence_configs": 0,
        "tool_cache_entries": 0,
        "background_jobs": 0,
        "error": None
    }
    
    try:
        async with get_session() as session:
            # Count users
            result = await session.execute(text("SELECT COUNT(*) FROM users"))
            stats["users"] = result.scalar()
            
            # Count sessions
            result = await session.execute(text("SELECT COUNT(*) FROM user_sessions"))
            stats["sessions"] = result.scalar()
            
            # Count LLM configs
            result = await session.execute(text("SELECT COUNT(*) FROM llm_configs"))
            stats["llm_configs"] = result.scalar()
            
            # Count Confluence configs
            result = await session.execute(text("SELECT COUNT(*) FROM confluence_configs"))
            stats["confluence_configs"] = result.scalar()
            
            # Count tool cache entries
            result = await session.execute(text("SELECT COUNT(*) FROM tool_cache"))
            stats["tool_cache_entries"] = result.scalar()
            
            # Count background jobs
            result = await session.execute(text("SELECT COUNT(*) FROM background_jobs"))
            stats["background_jobs"] = result.scalar()
            
    except Exception as e:
        stats["error"] = str(e)
        logger.error("Failed to get database statistics", error=str(e))
    
    return stats


async def cleanup_expired_sessions() -> Dict[str, Any]:
    """
    Clean up expired user sessions.
    
    Returns:
        Dictionary with cleanup results
    """
    result = {
        "success": False,
        "expired_sessions_removed": 0,
        "error": None
    }
    
    try:
        async with get_session() as session:
            # Find and delete expired sessions
            expired_sessions = await session.execute(
                text("DELETE FROM user_sessions WHERE expires_at < datetime('now') RETURNING id")
            )
            
            deleted_count = len(expired_sessions.fetchall())
            await session.commit()
            
            result["expired_sessions_removed"] = deleted_count
            result["success"] = True
            
            logger.info("Expired sessions cleanup completed", 
                       expired_sessions_removed=deleted_count)
            
    except Exception as e:
        result["error"] = str(e)
        logger.error("Failed to cleanup expired sessions", error=str(e))
    
    return result


async def cleanup_old_cache_entries(max_age_hours: int = 24) -> Dict[str, Any]:
    """
    Clean up old cache entries that haven't been accessed recently.
    
    Args:
        max_age_hours: Maximum age in hours for cache entries
        
    Returns:
        Dictionary with cleanup results
    """
    result = {
        "success": False,
        "old_entries_removed": 0,
        "error": None
    }
    
    try:
        async with get_session() as session:
            # Find and delete old cache entries
            old_entries = await session.execute(
                text("""
                    DELETE FROM tool_cache 
                    WHERE last_accessed_at < datetime('now', '-{} hours')
                    OR (last_accessed_at IS NULL AND created_at < datetime('now', '-{} hours'))
                    RETURNING id
                """.format(max_age_hours, max_age_hours))
            )
            
            deleted_count = len(old_entries.fetchall())
            await session.commit()
            
            result["old_entries_removed"] = deleted_count
            result["success"] = True
            
            logger.info("Old cache entries cleanup completed", 
                       old_entries_removed=deleted_count,
                       max_age_hours=max_age_hours)
            
    except Exception as e:
        result["error"] = str(e)
        logger.error("Failed to cleanup old cache entries", error=str(e))
    
    return result


async def cleanup_completed_jobs(max_age_days: int = 7) -> Dict[str, Any]:
    """
    Clean up completed background jobs older than specified days.
    
    Args:
        max_age_days: Maximum age in days for completed jobs
        
    Returns:
        Dictionary with cleanup results
    """
    result = {
        "success": False,
        "completed_jobs_removed": 0,
        "error": None
    }
    
    try:
        async with get_session() as session:
            # Find and delete old completed jobs
            old_jobs = await session.execute(
                text("""
                    DELETE FROM background_jobs 
                    WHERE status IN ('completed', 'failed', 'cancelled')
                    AND completed_at < datetime('now', '-{} days')
                    RETURNING id
                """.format(max_age_days))
            )
            
            deleted_count = len(old_jobs.fetchall())
            await session.commit()
            
            result["completed_jobs_removed"] = deleted_count
            result["success"] = True
            
            logger.info("Completed jobs cleanup completed", 
                       completed_jobs_removed=deleted_count,
                       max_age_days=max_age_days)
            
    except Exception as e:
        result["error"] = str(e)
        logger.error("Failed to cleanup completed jobs", error=str(e))
    
    return result


async def perform_database_maintenance() -> Dict[str, Any]:
    """
    Perform comprehensive database maintenance.
    
    Returns:
        Dictionary with maintenance results
    """
    maintenance_result = {
        "success": False,
        "operations": {},
        "error": None
    }
    
    try:
        # Cleanup expired sessions
        session_cleanup = await cleanup_expired_sessions()
        maintenance_result["operations"]["session_cleanup"] = session_cleanup
        
        # Cleanup old cache entries
        cache_cleanup = await cleanup_old_cache_entries()
        maintenance_result["operations"]["cache_cleanup"] = cache_cleanup
        
        # Cleanup completed jobs
        job_cleanup = await cleanup_completed_jobs()
        maintenance_result["operations"]["job_cleanup"] = job_cleanup
        
        # Check if all operations succeeded
        all_success = all(
            op.get("success", False) 
            for op in maintenance_result["operations"].values()
        )
        
        maintenance_result["success"] = all_success
        
        if all_success:
            logger.info("Database maintenance completed successfully")
        else:
            logger.warning("Some database maintenance operations failed")
        
    except Exception as e:
        maintenance_result["error"] = str(e)
        logger.error("Database maintenance failed", error=str(e))
    
    return maintenance_result


async def verify_database_integrity() -> Dict[str, Any]:
    """
    Verify database integrity and constraints.
    
    Returns:
        Dictionary with integrity check results
    """
    integrity_result = {
        "success": False,
        "checks": {},
        "error": None
    }
    
    try:
        async with get_session() as session:
            # Check for orphaned sessions
            orphaned_sessions = await session.execute(
                text("""
                    SELECT COUNT(*) FROM user_sessions 
                    WHERE user_id NOT IN (SELECT id FROM users)
                """)
            )
            integrity_result["checks"]["orphaned_sessions"] = orphaned_sessions.scalar()
            
            # Check for orphaned LLM configs
            orphaned_llm_configs = await session.execute(
                text("""
                    SELECT COUNT(*) FROM llm_configs 
                    WHERE user_id NOT IN (SELECT id FROM users)
                """)
            )
            integrity_result["checks"]["orphaned_llm_configs"] = orphaned_llm_configs.scalar()
            
            # Check for orphaned Confluence configs
            orphaned_confluence_configs = await session.execute(
                text("""
                    SELECT COUNT(*) FROM confluence_configs 
                    WHERE user_id NOT IN (SELECT id FROM users)
                """)
            )
            integrity_result["checks"]["orphaned_confluence_configs"] = orphaned_confluence_configs.scalar()
            
            # Check for orphaned tool cache entries
            orphaned_cache_entries = await session.execute(
                text("""
                    SELECT COUNT(*) FROM tool_cache 
                    WHERE user_id NOT IN (SELECT id FROM users)
                """)
            )
            integrity_result["checks"]["orphaned_cache_entries"] = orphaned_cache_entries.scalar()
            
            # Check for orphaned background jobs
            orphaned_jobs = await session.execute(
                text("""
                    SELECT COUNT(*) FROM background_jobs 
                    WHERE user_id NOT IN (SELECT id FROM users)
                """)
            )
            integrity_result["checks"]["orphaned_jobs"] = orphaned_jobs.scalar()
            
            # Check if any orphaned records exist
            total_orphaned = sum(integrity_result["checks"].values())
            integrity_result["success"] = total_orphaned == 0
            
            if total_orphaned > 0:
                logger.warning("Database integrity issues found", 
                             orphaned_records=total_orphaned)
            else:
                logger.info("Database integrity check passed")
        
    except Exception as e:
        integrity_result["error"] = str(e)
        logger.error("Database integrity check failed", error=str(e))
    
    return integrity_result


# Convenience function for CLI usage
async def main():
    """Main function for CLI usage."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m app.utils.database <command>")
        print("Commands: init, stats, cleanup, maintenance, integrity")
        return
    
    command = sys.argv[1]
    
    if command == "init":
        result = await initialize_database()
        print(f"Database initialization: {result}")
    elif command == "stats":
        result = await get_database_stats()
        print(f"Database statistics: {result}")
    elif command == "cleanup":
        result = await perform_database_maintenance()
        print(f"Database cleanup: {result}")
    elif command == "maintenance":
        result = await perform_database_maintenance()
        print(f"Database maintenance: {result}")
    elif command == "integrity":
        result = await verify_database_integrity()
        print(f"Database integrity: {result}")
    else:
        print(f"Unknown command: {command}")


if __name__ == "__main__":
    asyncio.run(main())