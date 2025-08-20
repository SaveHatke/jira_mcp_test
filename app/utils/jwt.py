"""
JWT (JSON Web Token) utilities for session management.

This module provides JWT token generation, validation, and management
for secure user authentication and session handling.
"""

import jwt
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass

from app.config import settings
from app.exceptions import AuthenticationError, SecurityError
from app.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class TokenPayload:
    """JWT token payload structure."""
    user_id: int
    employee_id: str
    session_id: str
    issued_at: datetime
    expires_at: datetime
    token_type: str = "access"


class JWTManager:
    """
    JWT token manager for authentication and session management.
    
    Provides secure JWT token generation, validation, and management
    with configurable expiration and proper security practices.
    """
    
    def __init__(self, secret_key: Optional[str] = None, algorithm: str = "HS256") -> None:
        """
        Initialize JWT manager.
        
        Args:
            secret_key: Secret key for JWT signing (uses app secret if not provided)
            algorithm: JWT signing algorithm
        """
        self.secret_key = secret_key or settings.secret_key
        self.algorithm = algorithm
        self.issuer = settings.app_name
    
    def generate_token(
        self,
        user_id: int,
        employee_id: str,
        session_id: Optional[str] = None,
        expires_in_minutes: Optional[int] = None
    ) -> str:
        """
        Generate JWT token for user session.
        
        Args:
            user_id: User database ID
            employee_id: Employee ID from Jira
            session_id: Session identifier (generated if not provided)
            expires_in_minutes: Token expiration in minutes (uses config default if not provided)
            
        Returns:
            JWT token string
            
        Raises:
            SecurityError: If token generation fails
        """
        try:
            # Generate session ID if not provided
            if not session_id:
                session_id = self._generate_session_id()
            
            # Calculate expiration time
            expires_in = expires_in_minutes or settings.session_timeout_minutes
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(minutes=expires_in)
            
            # Create token payload
            payload = {
                "user_id": user_id,
                "employee_id": employee_id,
                "session_id": session_id,
                "iat": int(now.timestamp()),
                "exp": int(expires_at.timestamp()),
                "iss": self.issuer,
                "sub": str(user_id),
                "jti": session_id,  # JWT ID for token tracking
                "type": "access"
            }
            
            # Generate JWT token
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
            
            logger.info(
                "JWT token generated",
                user_id=user_id,
                employee_id=employee_id,
                session_id=session_id,
                expires_at=expires_at.isoformat()
            )
            
            return token
            
        except Exception as e:
            logger.error("JWT token generation failed", error=str(e), user_id=user_id)
            raise SecurityError(
                "Failed to generate authentication token",
                error_code="JWT_GENERATION_FAILED",
                details={"error": str(e)}
            ) from e
    
    def validate_token(self, token: str) -> TokenPayload:
        """
        Validate JWT token and return payload.
        
        Args:
            token: JWT token string
            
        Returns:
            Token payload with user information
            
        Raises:
            AuthenticationError: If token is invalid or expired
        """
        try:
            if not token or not isinstance(token, str):
                raise AuthenticationError(
                    "Invalid token format",
                    error_code="INVALID_TOKEN_FORMAT"
                )
            
            # Decode and validate JWT token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "require": ["exp", "iat", "iss", "sub", "user_id", "employee_id", "session_id"]
                },
                issuer=self.issuer
            )
            
            # Extract and validate payload fields
            user_id = payload.get("user_id")
            employee_id = payload.get("employee_id")
            session_id = payload.get("session_id")
            issued_at = datetime.fromtimestamp(payload.get("iat"), tz=timezone.utc)
            expires_at = datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc)
            token_type = payload.get("type", "access")
            
            # Validate required fields
            if not all([user_id, employee_id, session_id]):
                raise AuthenticationError(
                    "Invalid token payload",
                    error_code="INVALID_TOKEN_PAYLOAD"
                )
            
            # Check if token is expired (additional check)
            if datetime.now(timezone.utc) >= expires_at:
                raise AuthenticationError(
                    "Token has expired",
                    error_code="TOKEN_EXPIRED"
                )
            
            # Create token payload object
            token_payload = TokenPayload(
                user_id=user_id,
                employee_id=employee_id,
                session_id=session_id,
                issued_at=issued_at,
                expires_at=expires_at,
                token_type=token_type
            )
            
            logger.debug(
                "JWT token validated successfully",
                user_id=user_id,
                employee_id=employee_id,
                session_id=session_id
            )
            
            return token_payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            raise AuthenticationError(
                "Token has expired",
                error_code="TOKEN_EXPIRED"
            )
        
        except jwt.InvalidTokenError as e:
            logger.warning("JWT token validation failed", error=str(e))
            raise AuthenticationError(
                "Invalid authentication token",
                error_code="INVALID_TOKEN",
                details={"error": str(e)}
            )
        
        except Exception as e:
            logger.error("JWT token validation error", error=str(e))
            raise AuthenticationError(
                "Token validation failed",
                error_code="TOKEN_VALIDATION_FAILED",
                details={"error": str(e)}
            ) from e
    
    def refresh_token(self, token: str, extend_minutes: Optional[int] = None) -> str:
        """
        Refresh JWT token with new expiration time.
        
        Args:
            token: Current JWT token
            extend_minutes: Minutes to extend token (uses config default if not provided)
            
        Returns:
            New JWT token with extended expiration
            
        Raises:
            AuthenticationError: If token is invalid or cannot be refreshed
        """
        try:
            # Validate current token
            payload = self.validate_token(token)
            
            # Generate new token with same user info but new expiration
            new_token = self.generate_token(
                user_id=payload.user_id,
                employee_id=payload.employee_id,
                session_id=payload.session_id,
                expires_in_minutes=extend_minutes
            )
            
            logger.info(
                "JWT token refreshed",
                user_id=payload.user_id,
                employee_id=payload.employee_id,
                session_id=payload.session_id
            )
            
            return new_token
            
        except AuthenticationError:
            # Re-raise authentication errors
            raise
        
        except Exception as e:
            logger.error("JWT token refresh failed", error=str(e))
            raise AuthenticationError(
                "Failed to refresh token",
                error_code="TOKEN_REFRESH_FAILED",
                details={"error": str(e)}
            ) from e
    
    def decode_token_without_verification(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode JWT token without signature verification (for debugging/logging).
        
        Args:
            token: JWT token string
            
        Returns:
            Token payload dictionary or None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                options={"verify_signature": False}
            )
            return payload
        except Exception:
            return None
    
    def get_token_expiration(self, token: str) -> Optional[datetime]:
        """
        Get token expiration time without full validation.
        
        Args:
            token: JWT token string
            
        Returns:
            Expiration datetime or None if invalid
        """
        try:
            payload = self.decode_token_without_verification(token)
            if payload and "exp" in payload:
                return datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        except Exception:
            pass
        return None
    
    def is_token_expired(self, token: str) -> bool:
        """
        Check if token is expired without full validation.
        
        Args:
            token: JWT token string
            
        Returns:
            True if token is expired, False otherwise
        """
        try:
            expiration = self.get_token_expiration(token)
            if expiration:
                return datetime.now(timezone.utc) >= expiration
        except Exception:
            pass
        return True
    
    def _generate_session_id(self) -> str:
        """
        Generate secure session ID.
        
        Returns:
            Session ID string
        """
        return secrets.token_urlsafe(32)
    
    def blacklist_token(self, token: str) -> bool:
        """
        Add token to blacklist (placeholder for future implementation).
        
        Args:
            token: JWT token to blacklist
            
        Returns:
            True if successfully blacklisted
        """
        # TODO: Implement token blacklisting with Redis or database
        # For now, we rely on session management in the database
        try:
            payload = self.decode_token_without_verification(token)
            if payload:
                session_id = payload.get("session_id")
                logger.info("Token blacklisted", session_id=session_id)
                return True
        except Exception:
            pass
        return False


# Global JWT manager instance
jwt_manager = JWTManager()


def generate_jwt_token(
    user_id: int,
    employee_id: str,
    session_id: Optional[str] = None,
    expires_in_minutes: Optional[int] = None
) -> str:
    """
    Generate JWT token using the global JWT manager.
    
    Args:
        user_id: User database ID
        employee_id: Employee ID from Jira
        session_id: Session identifier
        expires_in_minutes: Token expiration in minutes
        
    Returns:
        JWT token string
    """
    return jwt_manager.generate_token(user_id, employee_id, session_id, expires_in_minutes)


def validate_jwt_token(token: str) -> TokenPayload:
    """
    Validate JWT token using the global JWT manager.
    
    Args:
        token: JWT token string
        
    Returns:
        Token payload with user information
    """
    return jwt_manager.validate_token(token)


def refresh_jwt_token(token: str, extend_minutes: Optional[int] = None) -> str:
    """
    Refresh JWT token using the global JWT manager.
    
    Args:
        token: Current JWT token
        extend_minutes: Minutes to extend token
        
    Returns:
        New JWT token with extended expiration
    """
    return jwt_manager.refresh_token(token, extend_minutes)


def is_jwt_token_expired(token: str) -> bool:
    """
    Check if JWT token is expired using the global JWT manager.
    
    Args:
        token: JWT token string
        
    Returns:
        True if token is expired, False otherwise
    """
    return jwt_manager.is_token_expired(token)