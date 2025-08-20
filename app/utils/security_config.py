"""
Security configuration and utilities.

This module provides centralized security configuration management
and security-related utility functions.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import timedelta

from app.config import settings
from app.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SecurityConfig:
    """Security configuration settings."""
    
    # Session management
    session_timeout_minutes: int = 30
    session_cleanup_interval_hours: int = 24
    max_concurrent_sessions_per_user: int = 5
    
    # Password policy
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_special_chars: bool = True
    password_max_age_days: int = 90
    
    # Authentication
    max_login_attempts: int = 5
    login_lockout_duration_minutes: int = 15
    jwt_algorithm: str = "HS256"
    
    # CSRF protection
    csrf_token_lifetime_hours: int = 24
    csrf_require_referer_check: bool = True
    
    # Rate limiting
    rate_limit_requests_per_minute: int = 60
    rate_limit_burst_size: int = 10
    
    # Input validation
    max_input_length: int = 10000
    max_file_upload_size_mb: int = 10
    allowed_file_extensions: List[str] = None
    
    # Security headers
    enable_hsts: bool = True
    hsts_max_age_seconds: int = 31536000  # 1 year
    enable_csp: bool = True
    csp_report_only: bool = False
    
    # Audit logging
    audit_log_retention_days: int = 365
    audit_sensitive_actions: bool = True
    
    def __post_init__(self):
        """Initialize default values."""
        if self.allowed_file_extensions is None:
            self.allowed_file_extensions = ['.pem', '.crt', '.cer', '.p12', '.pfx']


class SecurityManager:
    """
    Central security configuration and policy manager.
    
    Provides security configuration management, policy enforcement,
    and security-related utility functions.
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None) -> None:
        """
        Initialize security manager.
        
        Args:
            config: Security configuration (uses defaults if not provided)
        """
        self.config = config or SecurityConfig()
        self._load_environment_overrides()
    
    def _load_environment_overrides(self) -> None:
        """Load security configuration overrides from environment."""
        try:
            # Override session timeout from app settings
            if hasattr(settings, 'session_timeout_minutes'):
                self.config.session_timeout_minutes = settings.session_timeout_minutes
            
            # Override other settings based on environment
            if settings.environment == "production":
                # Production security hardening
                self.config.csrf_require_referer_check = True
                self.config.enable_hsts = True
                self.config.csp_report_only = False
                self.config.max_login_attempts = 3
                self.config.login_lockout_duration_minutes = 30
            elif settings.environment == "development":
                # Development convenience settings
                self.config.max_login_attempts = 10
                self.config.login_lockout_duration_minutes = 5
                self.config.csp_report_only = True
            
            logger.info(
                "Security configuration loaded",
                environment=settings.environment,
                session_timeout=self.config.session_timeout_minutes,
                max_login_attempts=self.config.max_login_attempts
            )
            
        except Exception as e:
            logger.warning("Failed to load security environment overrides", error=str(e))
    
    def get_security_headers(self) -> Dict[str, str]:
        """
        Get security headers for HTTP responses.
        
        Returns:
            Dictionary of security headers
        """
        headers = {
            # Prevent clickjacking
            "X-Frame-Options": "DENY",
            
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # Enable XSS protection
            "X-XSS-Protection": "1; mode=block",
            
            # Referrer policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Permissions policy (formerly Feature Policy)
            "Permissions-Policy": (
                "geolocation=(), "
                "microphone=(), "
                "camera=(), "
                "payment=(), "
                "usb=(), "
                "magnetometer=(), "
                "gyroscope=(), "
                "speaker=()"
            ),
        }
        
        # Add HSTS header if enabled
        if self.config.enable_hsts:
            headers["Strict-Transport-Security"] = (
                f"max-age={self.config.hsts_max_age_seconds}; "
                "includeSubDomains; preload"
            )
        
        # Add CSP header
        if self.config.enable_csp:
            csp_policy = self._build_csp_policy()
            header_name = "Content-Security-Policy-Report-Only" if self.config.csp_report_only else "Content-Security-Policy"
            headers[header_name] = csp_policy
        
        return headers
    
    def _build_csp_policy(self) -> str:
        """
        Build Content Security Policy header value.
        
        Returns:
            CSP policy string
        """
        # Base CSP policy for server-rendered application
        policy_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",  # Allow inline scripts for HTMX/Alpine.js
            "style-src 'self' 'unsafe-inline'",   # Allow inline styles for TailwindCSS
            "img-src 'self' data: https:",        # Allow images from self, data URLs, and HTTPS
            "font-src 'self'",                    # Allow fonts from self only
            "connect-src 'self'",                 # Allow connections to self only
            "media-src 'none'",                   # No media sources
            "object-src 'none'",                  # No object/embed sources
            "frame-src 'none'",                   # No frames
            "worker-src 'none'",                  # No web workers
            "manifest-src 'self'",                # Allow manifest from self
            "base-uri 'self'",                    # Restrict base URI
            "form-action 'self'",                 # Restrict form actions to self
            "frame-ancestors 'none'",             # Prevent framing (same as X-Frame-Options)
        ]
        
        # Add report URI if in report-only mode
        if self.config.csp_report_only:
            policy_directives.append("report-uri /api/security/csp-report")
        
        return "; ".join(policy_directives)
    
    def validate_password_policy(self, password: str) -> Dict[str, Any]:
        """
        Validate password against security policy.
        
        Args:
            password: Password to validate
            
        Returns:
            Dictionary with validation results
        """
        import re
        
        results = {
            "valid": True,
            "score": 0,
            "requirements_met": [],
            "requirements_failed": [],
            "suggestions": []
        }
        
        # Check minimum length
        if len(password) >= self.config.password_min_length:
            results["requirements_met"].append("Minimum length")
            results["score"] += 20
        else:
            results["requirements_failed"].append(f"At least {self.config.password_min_length} characters")
            results["valid"] = False
        
        # Check uppercase requirement
        if self.config.password_require_uppercase:
            if re.search(r'[A-Z]', password):
                results["requirements_met"].append("Uppercase letter")
                results["score"] += 20
            else:
                results["requirements_failed"].append("At least one uppercase letter")
                results["valid"] = False
        
        # Check lowercase requirement
        if self.config.password_require_lowercase:
            if re.search(r'[a-z]', password):
                results["requirements_met"].append("Lowercase letter")
                results["score"] += 20
            else:
                results["requirements_failed"].append("At least one lowercase letter")
                results["valid"] = False
        
        # Check numbers requirement
        if self.config.password_require_numbers:
            if re.search(r'\d', password):
                results["requirements_met"].append("Number")
                results["score"] += 20
            else:
                results["requirements_failed"].append("At least one number")
                results["valid"] = False
        
        # Check special characters requirement
        if self.config.password_require_special_chars:
            if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                results["requirements_met"].append("Special character")
                results["score"] += 20
            else:
                results["requirements_failed"].append("At least one special character")
                results["valid"] = False
        
        # Additional scoring for length
        if len(password) >= 12:
            results["score"] += 10
        if len(password) >= 16:
            results["score"] += 10
        
        # Cap score at 100
        results["score"] = min(results["score"], 100)
        
        # Add suggestions
        if not results["valid"]:
            results["suggestions"].append("Ensure all requirements are met")
        
        if len(password) < 12:
            results["suggestions"].append("Consider using a longer password (12+ characters)")
        
        if len(set(password)) < len(password) * 0.7:
            results["suggestions"].append("Use more unique characters")
        
        return results
    
    def is_file_extension_allowed(self, filename: str) -> bool:
        """
        Check if file extension is allowed.
        
        Args:
            filename: Filename to check
            
        Returns:
            True if extension is allowed, False otherwise
        """
        if not filename or '.' not in filename:
            return False
        
        extension = '.' + filename.rsplit('.', 1)[1].lower()
        return extension in self.config.allowed_file_extensions
    
    def get_rate_limit_config(self) -> Dict[str, int]:
        """
        Get rate limiting configuration.
        
        Returns:
            Rate limiting configuration
        """
        return {
            "requests_per_minute": self.config.rate_limit_requests_per_minute,
            "burst_size": self.config.rate_limit_burst_size
        }
    
    def get_session_config(self) -> Dict[str, Any]:
        """
        Get session management configuration.
        
        Returns:
            Session configuration
        """
        return {
            "timeout_minutes": self.config.session_timeout_minutes,
            "cleanup_interval_hours": self.config.session_cleanup_interval_hours,
            "max_concurrent_sessions": self.config.max_concurrent_sessions_per_user
        }
    
    def get_csrf_config(self) -> Dict[str, Any]:
        """
        Get CSRF protection configuration.
        
        Returns:
            CSRF configuration
        """
        return {
            "token_lifetime_hours": self.config.csrf_token_lifetime_hours,
            "require_referer_check": self.config.csrf_require_referer_check
        }
    
    def should_audit_action(self, action: str) -> bool:
        """
        Check if action should be audited.
        
        Args:
            action: Action to check
            
        Returns:
            True if action should be audited, False otherwise
        """
        if not self.config.audit_sensitive_actions:
            return False
        
        # Always audit authentication and security events
        sensitive_actions = {
            'login', 'logout', 'register', 'password_change',
            'config_update', 'config_test', 'session_create',
            'session_invalidate', 'csrf_violation', 'rate_limit_exceeded'
        }
        
        return any(sensitive in action.lower() for sensitive in sensitive_actions)


# Global security manager instance
security_manager = SecurityManager()


def get_security_headers() -> Dict[str, str]:
    """
    Get security headers using the global security manager.
    
    Returns:
        Dictionary of security headers
    """
    return security_manager.get_security_headers()


def validate_password_strength(password: str) -> Dict[str, Any]:
    """
    Validate password strength using the global security manager.
    
    Args:
        password: Password to validate
        
    Returns:
        Password validation results
    """
    return security_manager.validate_password_policy(password)


def is_file_upload_allowed(filename: str) -> bool:
    """
    Check if file upload is allowed using the global security manager.
    
    Args:
        filename: Filename to check
        
    Returns:
        True if file is allowed, False otherwise
    """
    return security_manager.is_file_extension_allowed(filename)