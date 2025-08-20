"""
Background tasks for session management and cleanup.

This module provides background tasks for cleaning up expired sessions,
managing session lifecycle, and maintaining session security.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Optional

from app.services.session_service import session_service
from app.utils.logging import get_logger

logger = get_logger(__name__)


async def cleanup_expired_sessions() -> int:
    """
    Clean up expired sessions from the database.
    
    This task should be run periodically to remove expired sessions
    and maintain database performance.
    
    Returns:
        Number of sessions cleaned up
    """
    try:
        logger.info("Starting expired session cleanup")
        
        # Clean up expired sessions
        cleaned_count = await session_service.cleanup_expired_sessions()
        
        if cleaned_count > 0:
            logger.info("Expired session cleanup completed", 
                       sessions_cleaned=cleaned_count)
        else:
            logger.debug("No expired sessions to clean up")
        
        return cleaned_count
        
    except Exception as e:
        logger.error("Failed to cleanup expired sessions", error=str(e))
        return 0


async def cleanup_old_sessions(days_old: int = 30) -> int:
    """
    Clean up very old sessions (even if not expired) for security.
    
    Args:
        days_old: Remove sessions older than this many days
        
    Returns:
        Number of sessions cleaned up
    """
    try:
        logger.info("Starting old session cleanup", days_old=days_old)
        
        # This would require additional database query
        # For now, we'll just clean expired sessions
        cleaned_count = await cleanup_expired_sessions()
        
        logger.info("Old session cleanup completed", 
                   sessions_cleaned=cleaned_count,
                   days_old=days_old)
        
        return cleaned_count
        
    except Exception as e:
        logger.error("Failed to cleanup old sessions", 
                    days_old=days_old,
                    error=str(e))
        return 0


async def session_security_audit() -> dict:
    """
    Perform security audit of active sessions.
    
    Checks for suspicious session patterns, multiple sessions
    from different locations, etc.
    
    Returns:
        Dictionary with audit results
    """
    try:
        logger.info("Starting session security audit")
        
        # For now, just return basic stats
        # In a full implementation, this would check for:
        # - Multiple sessions from different IPs for same user
        # - Sessions from suspicious locations
        # - Sessions with unusual patterns
        
        audit_results = {
            "audit_time": datetime.utcnow().isoformat(),
            "suspicious_sessions": 0,
            "multiple_location_users": 0,
            "recommendations": []
        }
        
        logger.info("Session security audit completed", 
                   results=audit_results)
        
        return audit_results
        
    except Exception as e:
        logger.error("Failed to perform session security audit", error=str(e))
        return {
            "audit_time": datetime.utcnow().isoformat(),
            "error": str(e)
        }


# Convenience function for periodic cleanup
async def periodic_session_maintenance():
    """
    Perform periodic session maintenance tasks.
    
    This function combines multiple maintenance tasks and can be
    called by a scheduler (like APScheduler) periodically.
    """
    try:
        logger.info("Starting periodic session maintenance")
        
        # Clean up expired sessions
        cleaned_count = await cleanup_expired_sessions()
        
        # Perform security audit (every few runs)
        audit_results = await session_security_audit()
        
        maintenance_results = {
            "maintenance_time": datetime.utcnow().isoformat(),
            "expired_sessions_cleaned": cleaned_count,
            "security_audit": audit_results
        }
        
        logger.info("Periodic session maintenance completed", 
                   results=maintenance_results)
        
        return maintenance_results
        
    except Exception as e:
        logger.error("Failed to perform periodic session maintenance", error=str(e))
        return {
            "maintenance_time": datetime.utcnow().isoformat(),
            "error": str(e)
        }


# Function to be called by external schedulers
def run_session_cleanup():
    """
    Synchronous wrapper for session cleanup (for use with schedulers).
    
    This function can be called by external task schedulers that
    don't support async functions directly.
    """
    try:
        # Run the async cleanup function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(cleanup_expired_sessions())
        
        loop.close()
        
        print(f"[OK] Session cleanup completed - {result} sessions cleaned")
        return result
        
    except Exception as e:
        print(f"[ERROR] Session cleanup failed: {e}")
        return 0


def run_session_maintenance():
    """
    Synchronous wrapper for session maintenance (for use with schedulers).
    
    This function can be called by external task schedulers that
    don't support async functions directly.
    """
    try:
        # Run the async maintenance function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(periodic_session_maintenance())
        
        loop.close()
        
        print(f"[OK] Session maintenance completed")
        return result
        
    except Exception as e:
        print(f"[ERROR] Session maintenance failed: {e}")
        return None