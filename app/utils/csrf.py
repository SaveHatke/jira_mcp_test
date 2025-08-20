"""
CSRF (Cross-Site Request Forgery) protection utilities.

This module provides CSRF token generation, validation, and middleware
for protecting against CSRF attacks in form submissions.
"""

import secrets
import hashlib
import hmac
from typing import Optional
from datetime import datetime, timedelta

from app.config import settings
from app.exceptions import SecurityError
from app.utils.logging import get_logger

logger = get_logger(__name__)


class CSRFProtection:
    """
    CSRF protection manager for generating and validating tokens.
    
    Implements secure CSRF token generation and validation using
    HMAC-based tokens with timestamp validation.
    """
    
    def __init__(self, secret_key: Optional[str] = None, token_lifetime_hours: int = 24) -> None:
        """
        Initialize CSRF protection.
        
        Args:
            secret_key: Secret key for HMAC (uses app secret if not provided)
            token_lifetime_hours: Token lifetime in hours
        """
        self.secret_key = (secret_key or settings.secret_key).encode()
        self.token_lifetime_hours = token_lifetime_hours
    
    def generate_token(self, session_id: Optional[str] = None) -> str:
        """
        Generate CSRF token for a session.
        
        Args:
            session_id: Optional session identifier
            
        Returns:
            CSRF token string
        """
        try:
            # Generate random token data
            random_data = secrets.token_bytes(16)
            
            # Add timestamp
            timestamp = int(datetime.utcnow().timestamp())
            
            # Create payload: timestamp + random_data + session_id
            payload = f"{timestamp}:{random_data.hex()}"
            if session_id:
                payload += f":{session_id}"
            
            # Generate HMAC signature
            signature = hmac.new(
                self.secret_key,
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Return token: payload + signature
            token = f"{payload}:{signature}"
            
            logger.debug("CSRF token generated", session_id=session_id)
            return token
            
        except Exception as e:
            logger.error("CSRF token generation failed", error=str(e))
            raise SecurityError(
                "Failed to generate CSRF token",
                error_code="CSRF_TOKEN_GENERATION_FAILED",
                details={"error": str(e)}
            ) from e
    
    def validate_token(self, token: str, session_id: Optional[str] = None) -> bool:
        """
        Validate CSRF token.
        
        Args:
            token: CSRF token to validate
            session_id: Optional session identifier
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            if not token or not isinstance(token, str):
                return False
            
            # Split token into parts
            parts = token.split(':')
            if len(parts) < 3:  # timestamp:random_data:signature (minimum)
                return False
            
            # Extract signature
            signature = parts[-1]
            payload = ':'.join(parts[:-1])
            
            # Verify HMAC signature
            expected_signature = hmac.new(
                self.secret_key,
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                logger.warning("CSRF token signature validation failed")
                return False
            
            # Extract timestamp
            try:
                timestamp = int(parts[0])
            except (ValueError, IndexError):
                logger.warning("CSRF token timestamp parsing failed")
                return False
            
            # Check token age
            token_age = datetime.utcnow() - datetime.fromtimestamp(timestamp)
            max_age = timedelta(hours=self.token_lifetime_hours)
            
            if token_age > max_age:
                logger.warning("CSRF token expired", 
                              token_age_hours=token_age.total_seconds() / 3600,
                              max_age_hours=self.token_lifetime_hours)
                return False
            
            # Validate session ID if provided
            if session_id:
                if len(parts) < 4:  # timestamp:random_data:session_id:signature
                    return False
                token_session_id = parts[2]
                if not hmac.compare_digest(token_session_id, session_id):
                    logger.warning("CSRF token session ID mismatch")
                    return False
            
            logger.debug("CSRF token validation successful", session_id=session_id)
            return True
            
        except Exception as e:
            logger.error("CSRF token validation failed", error=str(e))
            return False
    
    def get_token_age(self, token: str) -> Optional[timedelta]:
        """
        Get the age of a CSRF token.
        
        Args:
            token: CSRF token
            
        Returns:
            Token age as timedelta, None if invalid
        """
        try:
            parts = token.split(':')
            if len(parts) < 3:
                return None
            
            timestamp = int(parts[0])
            return datetime.utcnow() - datetime.fromtimestamp(timestamp)
            
        except (ValueError, IndexError):
            return None


# Global CSRF protection instance
csrf_protection = CSRFProtection()


def generate_csrf_token(session_id: Optional[str] = None) -> str:
    """
    Generate CSRF token using the global protection instance.
    
    Args:
        session_id: Optional session identifier
        
    Returns:
        CSRF token
    """
    return csrf_protection.generate_token(session_id)


def validate_csrf_token(token: str, session_id: Optional[str] = None) -> bool:
    """
    Validate CSRF token using the global protection instance.
    
    Args:
        token: CSRF token to validate
        session_id: Optional session identifier
        
    Returns:
        True if valid, False otherwise
    """
    return csrf_protection.validate_token(token, session_id)


def get_csrf_token_from_request(request) -> Optional[str]:
    """
    Extract CSRF token from request (form data or headers).
    
    Args:
        request: FastAPI request object
        
    Returns:
        CSRF token if found, None otherwise
    """
    # Try form data first
    if hasattr(request, 'form'):
        try:
            form_data = request.form()
            if 'csrf_token' in form_data:
                return form_data['csrf_token']
        except Exception:
            pass
    
    # Try headers
    csrf_header = request.headers.get('X-CSRF-Token')
    if csrf_header:
        return csrf_header
    
    return None