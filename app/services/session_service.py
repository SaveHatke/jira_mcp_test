"""
Session management service for user authentication and session handling.

This module provides comprehensive session management including JWT token
creation, validation, session storage, and automatic cleanup.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt, JWTError
import structlog

from app.config import settings
from app.database import get_session
from app.models.user import User
from app.models.session import UserSession
from app.exceptions import AuthenticationError, SecurityError, DatabaseError
from app.utils.encryption import hash_token
from app.utils.csrf import generate_csrf_token
from app.utils.logging import get_logger

logger = get_logger(__name__)


class SessionService:
    """
    Service for managing user sessions and JWT tokens.
    
    Provides methods for creating, validating, and managing user sessions
    with proper security practices and automatic cleanup.
    """
    
    def __init__(self) -> None:
        """Initialize session service."""
        pass
    
    async def create_session(
        self,
        user: User,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        timeout_minutes: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Create new user session with JWT token.
        
        Args:
            user: User instance
            user_agent: Optional user agent string
            ip_address: Optional IP address
            timeout_minutes: Optional custom timeout (uses config default if not provided)
            
        Returns:
            Dictionary with token, expiration, and CSRF token
            
        Raises:
            AuthenticationError: If session creation fails
            DatabaseError: If database operations fail
        """
        try:
            # Use configured timeout or provided timeout
            timeout = timeout_minutes or settings.session_timeout_minutes
            
            # Calculate expiration time
            expires_at = datetime.utcnow() + timedelta(minutes=timeout)
            
            # Create JWT payload
            payload = {
                'user_id': user.id,
                'employee_id': user.employee_id,
                'email': user.email,
                'display_name': user.display_name,
                'exp': expires_at,
                'iat': datetime.utcnow(),
                'iss': settings.app_name,
                'type': 'session'
            }
            
            # Generate JWT token
            token = jwt.encode(payload, settings.secret_key, algorithm='HS256')
            
            # Create session record in database
            async with get_session() as session:
                user_session = UserSession.create_session(
                    user_id=user.id,
                    token=token,
                    timeout_minutes=timeout,
                    user_agent=user_agent,
                    ip_address=ip_address
                )
                
                session.add(user_session)
                await session.commit()
                await session.refresh(user_session)
            
            # Generate CSRF token
            csrf_token = generate_csrf_token(session_id=str(user_session.id))
            
            logger.info("User session created", 
                       user_id=user.id,
                       employee_id=user.employee_id,
                       session_id=user_session.id,
                       expires_at=expires_at.isoformat(),
                       timeout_minutes=timeout)
            
            return {
                'token': token,
                'expires_at': expires_at,
                'timeout_minutes': timeout,
                'csrf_token': csrf_token,
                'session_id': user_session.id
            }
            
        except Exception as e:
            logger.error("Session creation failed", 
                        user_id=user.id,
                        error=str(e))
            raise AuthenticationError(
                "Failed to create user session",
                error_code="SESSION_CREATION_FAILED",
                details={"user_id": user.id, "error": str(e)}
            ) from e
    
    async def validate_session(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate JWT token and return user session information.
        
        Args:
            token: JWT token string
            
        Returns:
            Session information if valid, None otherwise
        """
        try:
            # Decode JWT token
            payload = jwt.decode(token, settings.secret_key, algorithms=['HS256'])
            
            # Validate token type
            if payload.get('type') != 'session':
                logger.warning("Invalid token type", token_type=payload.get('type'))
                return None
            
            # Check expiration
            exp_timestamp = payload.get('exp')
            if not exp_timestamp:
                logger.warning("Token missing expiration")
                return None
            
            expires_at = datetime.fromtimestamp(exp_timestamp)
            if datetime.utcnow() > expires_at:
                logger.info("Token expired", 
                           expires_at=expires_at.isoformat(),
                           user_id=payload.get('user_id'))
                return None
            
            # Verify session exists in database
            token_hash = hash_token(token)
            async with get_session() as session:
                stmt = select(UserSession).where(
                    UserSession.token_hash == token_hash,
                    UserSession.expires_at > datetime.utcnow()
                )
                result = await session.execute(stmt)
                user_session = result.scalar_one_or_none()
                
                if not user_session:
                    logger.warning("Session not found in database", 
                                  user_id=payload.get('user_id'))
                    return None
                
                # Get user information
                user = await session.get(User, payload['user_id'])
                if not user or not user.active:
                    logger.warning("User not found or inactive", 
                                  user_id=payload.get('user_id'))
                    return None
            
            # Return session information
            return {
                'user_id': user.id,
                'employee_id': user.employee_id,
                'email': user.email,
                'display_name': user.display_name,
                'name': user.name,
                'avatar_url': user.avatar_url,
                'session_id': user_session.id,
                'expires_at': expires_at,
                'user': user
            }
            
        except JWTError as e:
            logger.warning("JWT validation failed", error=str(e))
            return None
        except Exception as e:
            logger.error("Session validation failed", error=str(e))
            return None
    
    async def extend_session(self, token: str, additional_minutes: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Extend existing session expiration time.
        
        Args:
            token: Current JWT token
            additional_minutes: Additional minutes to extend (uses config default if not provided)
            
        Returns:
            New session information if successful, None otherwise
        """
        try:
            # Validate current session
            session_info = await self.validate_session(token)
            if not session_info:
                return None
            
            # Calculate new expiration
            extension_minutes = additional_minutes or settings.session_timeout_minutes
            new_expires_at = datetime.utcnow() + timedelta(minutes=extension_minutes)
            
            # Update session in database
            token_hash = hash_token(token)
            async with get_session() as session:
                stmt = select(UserSession).where(UserSession.token_hash == token_hash)
                result = await session.execute(stmt)
                user_session = result.scalar_one_or_none()
                
                if user_session:
                    user_session.extend_session(extension_minutes)
                    await session.commit()
            
            # Create new JWT token with extended expiration
            user = session_info['user']
            new_session = await self.create_session(
                user=user,
                timeout_minutes=extension_minutes
            )
            
            # Clean up old session
            await self.invalidate_session(token)
            
            logger.info("Session extended", 
                       user_id=user.id,
                       old_expires_at=session_info['expires_at'].isoformat(),
                       new_expires_at=new_expires_at.isoformat())
            
            return new_session
            
        except Exception as e:
            logger.error("Session extension failed", error=str(e))
            return None
    
    async def invalidate_session(self, token: str) -> bool:
        """
        Invalidate user session by removing it from database.
        
        Args:
            token: JWT token to invalidate
            
        Returns:
            True if session was invalidated, False otherwise
        """
        try:
            token_hash = hash_token(token)
            
            async with get_session() as session:
                stmt = delete(UserSession).where(UserSession.token_hash == token_hash)
                result = await session.execute(stmt)
                await session.commit()
                
                invalidated = result.rowcount > 0
                
                if invalidated:
                    logger.info("Session invalidated", token_hash=token_hash[:16] + "...")
                else:
                    logger.warning("Session not found for invalidation", token_hash=token_hash[:16] + "...")
                
                return invalidated
                
        except Exception as e:
            logger.error("Session invalidation failed", error=str(e))
            return False
    
    async def invalidate_all_user_sessions(self, user_id: int) -> int:
        """
        Invalidate all sessions for a specific user.
        
        Args:
            user_id: User ID
            
        Returns:
            Number of sessions invalidated
        """
        try:
            async with get_session() as session:
                stmt = delete(UserSession).where(UserSession.user_id == user_id)
                result = await session.execute(stmt)
                await session.commit()
                
                count = result.rowcount
                
                logger.info("All user sessions invalidated", 
                           user_id=user_id,
                           sessions_invalidated=count)
                
                return count
                
        except Exception as e:
            logger.error("Failed to invalidate all user sessions", 
                        user_id=user_id,
                        error=str(e))
            return 0
    
    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions from database.
        
        Returns:
            Number of expired sessions cleaned up
        """
        try:
            async with get_session() as session:
                stmt = delete(UserSession).where(UserSession.expires_at < datetime.utcnow())
                result = await session.execute(stmt)
                await session.commit()
                
                count = result.rowcount
                
                if count > 0:
                    logger.info("Expired sessions cleaned up", sessions_cleaned=count)
                
                return count
                
        except Exception as e:
            logger.error("Failed to cleanup expired sessions", error=str(e))
            return 0
    
    async def get_user_sessions(self, user_id: int) -> list:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of active session information
        """
        try:
            async with get_session() as session:
                stmt = select(UserSession).where(
                    UserSession.user_id == user_id,
                    UserSession.expires_at > datetime.utcnow()
                ).order_by(UserSession.created_at.desc())
                
                result = await session.execute(stmt)
                sessions = result.scalars().all()
                
                return [
                    {
                        'id': s.id,
                        'created_at': s.created_at,
                        'expires_at': s.expires_at,
                        'user_agent': s.user_agent,
                        'ip_address': s.ip_address,
                        'is_expired': s.is_expired(),
                        'time_until_expiry_seconds': int(s.time_until_expiry().total_seconds())
                    }
                    for s in sessions
                ]
                
        except Exception as e:
            logger.error("Failed to get user sessions", 
                        user_id=user_id,
                        error=str(e))
            return []


# Global session service instance
session_service = SessionService()


# Convenience functions
async def create_user_session(
    user: User,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None,
    timeout_minutes: Optional[int] = None
) -> Dict[str, Any]:
    """Create new user session."""
    return await session_service.create_session(user, user_agent, ip_address, timeout_minutes)


async def validate_user_session(token: str) -> Optional[Dict[str, Any]]:
    """Validate user session token."""
    return await session_service.validate_session(token)


async def invalidate_user_session(token: str) -> bool:
    """Invalidate user session."""
    return await session_service.invalidate_session(token)


async def cleanup_expired_sessions() -> int:
    """Clean up expired sessions."""
    return await session_service.cleanup_expired_sessions()