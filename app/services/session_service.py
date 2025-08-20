"""
Session management service for JWT tokens and user sessions.

This module provides session management capabilities including
JWT token validation, session tracking, and user context management.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.database import get_db_session
from app.models.user import User, UserSession
from app.utils.jwt import validate_jwt_token, TokenPayload
from app.utils.logging import get_logger
from app.utils.audit_logging import log_authentication_event
from app.exceptions import AuthenticationError
from app.config import settings

logger = get_logger(__name__)


class SessionService:
    """
    Service for managing user sessions and JWT tokens.
    
    Provides session validation, cleanup, and user context management
    with proper security and audit logging.
    """
    
    def __init__(self) -> None:
        """Initialize the session service."""
        pass
    
    async def validate_session(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate session token and return user information.
        
        Args:
            token: JWT session token
            
        Returns:
            Dictionary with user session information if valid, None otherwise
        """
        try:
            # Validate JWT token
            token_payload = validate_jwt_token(token)
            
            # Get database session
            async with get_db_session() as db:
                # Check if session exists in database
                session_query = select(UserSession).where(
                    UserSession.session_id == token_payload.session_id,
                    UserSession.expires_at > datetime.now(timezone.utc)
                )
                
                result = await db.execute(session_query)
                db_session = result.scalar_one_or_none()
                
                if not db_session:
                    logger.warning(
                        "Session not found in database",
                        session_id=token_payload.session_id,
                        user_id=token_payload.user_id
                    )
                    return None
                
                # Get user information
                user_query = select(User).where(
                    User.id == token_payload.user_id,
                    User.active == True
                )
                
                result = await db.execute(user_query)
                user = result.scalar_one_or_none()
                
                if not user:
                    logger.warning(
                        "User not found or inactive",
                        user_id=token_payload.user_id,
                        session_id=token_payload.session_id
                    )
                    return None
                
                # Update session last accessed time
                db_session.last_accessed_at = datetime.now(timezone.utc)
                await db.commit()
                
                # Return session information
                session_info = {
                    "user_id": user.id,
                    "employee_id": user.employee_id,
                    "user": {
                        "id": user.id,
                        "employee_id": user.employee_id,
                        "name": user.name,
                        "email": user.email,
                        "display_name": user.display_name,
                        "avatar_url": user.avatar_url,
                        "jira_url": user.jira_url
                    },
                    "session_id": token_payload.session_id,
                    "expires_at": token_payload.expires_at,
                    "issued_at": token_payload.issued_at
                }
                
                logger.debug(
                    "Session validated successfully",
                    user_id=user.id,
                    employee_id=user.employee_id,
                    session_id=token_payload.session_id
                )
                
                return session_info
                
        except AuthenticationError as e:
            logger.warning(
                "Session validation failed",
                error_code=e.error_code,
                message=e.message
            )
            return None
        
        except Exception as e:
            logger.error("Session validation error", error=str(e))
            return None
    
    async def create_session(
        self,
        user_id: int,
        token_hash: str,
        expires_at: datetime,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> UserSession:
        """
        Create a new user session in the database.
        
        Args:
            user_id: User database ID
            token_hash: Hashed JWT token
            expires_at: Session expiration time
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Created UserSession object
        """
        try:
            async with get_db_session() as db:
                # Create new session
                session = UserSession(
                    user_id=user_id,
                    token_hash=token_hash,
                    expires_at=expires_at,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    created_at=datetime.now(timezone.utc),
                    last_accessed_at=datetime.now(timezone.utc)
                )
                
                db.add(session)
                await db.commit()
                await db.refresh(session)
                
                logger.info(
                    "Session created",
                    user_id=user_id,
                    session_id=session.session_id,
                    expires_at=expires_at.isoformat()
                )
                
                # Log authentication event
                log_authentication_event(
                    action="session_created",
                    user_id=user_id,
                    outcome="success",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"expires_at": expires_at.isoformat()}
                )
                
                return session
                
        except Exception as e:
            logger.error("Session creation failed", error=str(e), user_id=user_id)
            raise AuthenticationError(
                "Failed to create session",
                error_code="SESSION_CREATION_FAILED",
                details={"error": str(e)}
            ) from e
    
    async def invalidate_session(self, session_id: str, user_id: Optional[int] = None) -> bool:
        """
        Invalidate a user session.
        
        Args:
            session_id: Session ID to invalidate
            user_id: Optional user ID for additional validation
            
        Returns:
            True if session was invalidated, False otherwise
        """
        try:
            async with get_db_session() as db:
                # Build query
                query = delete(UserSession).where(UserSession.session_id == session_id)
                
                if user_id:
                    query = query.where(UserSession.user_id == user_id)
                
                # Execute deletion
                result = await db.execute(query)
                await db.commit()
                
                invalidated = result.rowcount > 0
                
                if invalidated:
                    logger.info(
                        "Session invalidated",
                        session_id=session_id,
                        user_id=user_id
                    )
                    
                    # Log authentication event
                    log_authentication_event(
                        action="session_invalidated",
                        user_id=user_id,
                        outcome="success",
                        details={"session_id": session_id}
                    )
                else:
                    logger.warning(
                        "Session not found for invalidation",
                        session_id=session_id,
                        user_id=user_id
                    )
                
                return invalidated
                
        except Exception as e:
            logger.error("Session invalidation failed", error=str(e), session_id=session_id)
            return False
    
    async def invalidate_all_user_sessions(self, user_id: int) -> int:
        """
        Invalidate all sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Number of sessions invalidated
        """
        try:
            async with get_db_session() as db:
                # Delete all sessions for user
                query = delete(UserSession).where(UserSession.user_id == user_id)
                result = await db.execute(query)
                await db.commit()
                
                invalidated_count = result.rowcount
                
                logger.info(
                    "All user sessions invalidated",
                    user_id=user_id,
                    count=invalidated_count
                )
                
                # Log authentication event
                log_authentication_event(
                    action="all_sessions_invalidated",
                    user_id=user_id,
                    outcome="success",
                    details={"invalidated_count": invalidated_count}
                )
                
                return invalidated_count
                
        except Exception as e:
            logger.error("Failed to invalidate all user sessions", error=str(e), user_id=user_id)
            return 0
    
    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions from the database.
        
        Returns:
            Number of sessions cleaned up
        """
        try:
            async with get_db_session() as db:
                # Delete expired sessions
                query = delete(UserSession).where(
                    UserSession.expires_at <= datetime.now(timezone.utc)
                )
                
                result = await db.execute(query)
                await db.commit()
                
                cleaned_count = result.rowcount
                
                if cleaned_count > 0:
                    logger.info(
                        "Expired sessions cleaned up",
                        count=cleaned_count
                    )
                
                return cleaned_count
                
        except Exception as e:
            logger.error("Session cleanup failed", error=str(e))
            return 0
    
    async def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of session information dictionaries
        """
        try:
            async with get_db_session() as db:
                # Get active sessions for user
                query = select(UserSession).where(
                    UserSession.user_id == user_id,
                    UserSession.expires_at > datetime.now(timezone.utc)
                ).order_by(UserSession.created_at.desc())
                
                result = await db.execute(query)
                sessions = result.scalars().all()
                
                session_list = []
                for session in sessions:
                    session_info = {
                        "session_id": session.session_id,
                        "created_at": session.created_at.isoformat(),
                        "expires_at": session.expires_at.isoformat(),
                        "last_accessed_at": session.last_accessed_at.isoformat() if session.last_accessed_at else None,
                        "ip_address": session.ip_address,
                        "user_agent": session.user_agent
                    }
                    session_list.append(session_info)
                
                return session_list
                
        except Exception as e:
            logger.error("Failed to get user sessions", error=str(e), user_id=user_id)
            return []
    
    async def extend_session(self, session_id: str, extend_minutes: int = None) -> bool:
        """
        Extend session expiration time.
        
        Args:
            session_id: Session ID to extend
            extend_minutes: Minutes to extend (uses config default if not provided)
            
        Returns:
            True if session was extended, False otherwise
        """
        try:
            if extend_minutes is None:
                extend_minutes = settings.session_timeout_minutes
            
            async with get_db_session() as db:
                # Get session
                query = select(UserSession).where(UserSession.session_id == session_id)
                result = await db.execute(query)
                session = result.scalar_one_or_none()
                
                if not session:
                    return False
                
                # Extend expiration time
                new_expires_at = datetime.now(timezone.utc) + timedelta(minutes=extend_minutes)
                session.expires_at = new_expires_at
                session.last_accessed_at = datetime.now(timezone.utc)
                
                await db.commit()
                
                logger.debug(
                    "Session extended",
                    session_id=session_id,
                    new_expires_at=new_expires_at.isoformat()
                )
                
                return True
                
        except Exception as e:
            logger.error("Session extension failed", error=str(e), session_id=session_id)
            return False


# Global session service instance
session_service = SessionService()


async def validate_user_session(token: str) -> Optional[Dict[str, Any]]:
    """
    Validate user session using the global session service.
    
    Args:
        token: JWT session token
        
    Returns:
        Session information if valid, None otherwise
    """
    return await session_service.validate_session(token)


async def create_user_session(
    user_id: int,
    token_hash: str,
    expires_at: datetime,
    **kwargs
) -> UserSession:
    """
    Create user session using the global session service.
    
    Args:
        user_id: User database ID
        token_hash: Hashed JWT token
        expires_at: Session expiration time
        **kwargs: Additional session parameters
        
    Returns:
        Created UserSession object
    """
    return await session_service.create_session(user_id, token_hash, expires_at, **kwargs)


async def invalidate_user_session(session_id: str, user_id: Optional[int] = None) -> bool:
    """
    Invalidate user session using the global session service.
    
    Args:
        session_id: Session ID to invalidate
        user_id: Optional user ID for validation
        
    Returns:
        True if session was invalidated, False otherwise
    """
    return await session_service.invalidate_session(session_id, user_id)