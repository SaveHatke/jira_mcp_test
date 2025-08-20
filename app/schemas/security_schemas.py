"""
Security-related schemas for request/response validation.

This module defines Pydantic models for security operations,
CSRF protection, and input validation.
"""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator, EmailStr
import re
from urllib.parse import urlparse


class CSRFTokenRequest(BaseModel):
    """Schema for CSRF token generation request."""
    
    session_id: Optional[str] = Field(None, description="Session identifier for token binding")


class CSRFTokenResponse(BaseModel):
    """Schema for CSRF token response."""
    
    csrf_token: str = Field(..., description="Generated CSRF token")
    expires_in: int = Field(..., description="Token expiration time in seconds")


class SecureFormRequest(BaseModel):
    """Base schema for forms requiring CSRF protection."""
    
    csrf_token: str = Field(..., description="CSRF token for form protection")
    
    @field_validator('csrf_token')
    @classmethod
    def validate_csrf_token(cls, v):
        """Validate CSRF token format."""
        if not v or not v.strip():
            raise ValueError("CSRF token is required")
        return v.strip()


class ConfigurationTestRequest(BaseModel):
    """Schema for configuration testing requests."""
    
    config_type: str = Field(
        ..., 
        pattern="^(jira|confluence|llm)$",
        description="Type of configuration to test"
    )
    
    # Common fields
    url: Optional[str] = Field(None, description="Service URL")
    verify_ssl: Optional[bool] = Field(True, description="Verify SSL certificates")
    
    # Authentication fields
    pat: Optional[str] = Field(None, min_length=1, max_length=500, description="Personal Access Token")
    cookie: Optional[str] = Field(None, min_length=1, max_length=1000, description="Authentication cookie")
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        """Validate URL format."""
        if v:
            try:
                result = urlparse(v)
                if not all([result.scheme, result.netloc]):
                    raise ValueError("Invalid URL format")
                if result.scheme not in ['http', 'https']:
                    raise ValueError("URL must use HTTP or HTTPS protocol")
            except Exception:
                raise ValueError("Invalid URL format")
        return v
    
    @field_validator('pat')
    @classmethod
    def validate_pat(cls, v):
        """Validate PAT format."""
        if v:
            # Remove whitespace
            v = v.strip()
            if not v:
                raise ValueError("PAT cannot be empty")
            # Basic length validation
            if len(v) > 500:
                raise ValueError("PAT is too long")
        return v
    
    @field_validator('cookie')
    @classmethod
    def validate_cookie(cls, v):
        """Validate cookie format."""
        if v:
            v = v.strip()
            if not v:
                raise ValueError("Cookie cannot be empty")
            if len(v) > 1000:
                raise ValueError("Cookie is too long")
        return v


class ConfigurationTestResponse(BaseModel):
    """Schema for configuration test response."""
    
    success: bool = Field(..., description="Test success status")
    message: str = Field(..., description="Test result message")
    employee_id: Optional[str] = Field(None, description="Validated employee ID")
    error_code: Optional[str] = Field(None, description="Error code if test failed")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional test details")


class PasswordValidationRequest(BaseModel):
    """Schema for password validation request."""
    
    password: str = Field(..., min_length=1, description="Password to validate")
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v):
        """Validate password meets strength requirements."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        # Check for uppercase letter
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain at least one uppercase letter")
        
        # Check for lowercase letter
        if not re.search(r'[a-z]', v):
            raise ValueError("Password must contain at least one lowercase letter")
        
        # Check for digit
        if not re.search(r'\d', v):
            raise ValueError("Password must contain at least one number")
        
        # Check for special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        
        return v


class PasswordValidationResponse(BaseModel):
    """Schema for password validation response."""
    
    valid: bool = Field(..., description="Password validity status")
    strength_score: int = Field(..., ge=0, le=100, description="Password strength score (0-100)")
    requirements_met: List[str] = Field(..., description="List of requirements met")
    requirements_failed: List[str] = Field(..., description="List of requirements failed")
    suggestions: List[str] = Field(..., description="Suggestions for improvement")


class InputSanitizationRequest(BaseModel):
    """Schema for input sanitization request."""
    
    input_text: str = Field(..., description="Text to sanitize")
    sanitization_type: str = Field(
        "html",
        pattern="^(html|sql|xss|general)$",
        description="Type of sanitization to apply"
    )


class InputSanitizationResponse(BaseModel):
    """Schema for input sanitization response."""
    
    sanitized_text: str = Field(..., description="Sanitized text")
    removed_elements: List[str] = Field(..., description="List of removed/sanitized elements")
    is_safe: bool = Field(..., description="Whether input is considered safe")


class SecurityAuditRequest(BaseModel):
    """Schema for security audit logging request."""
    
    action: str = Field(..., min_length=1, max_length=100, description="Action being audited")
    resource: Optional[str] = Field(None, max_length=200, description="Resource being accessed")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional audit details")
    
    @field_validator('action')
    @classmethod
    def validate_action(cls, v):
        """Validate action name."""
        if not v or not v.strip():
            raise ValueError("Action cannot be empty")
        # Remove any potentially sensitive characters
        sanitized = re.sub(r'[^\w\s\-_.]', '', v.strip())
        return sanitized
    
    @field_validator('resource')
    @classmethod
    def validate_resource(cls, v):
        """Validate resource name."""
        if v:
            # Remove any potentially sensitive characters
            sanitized = re.sub(r'[^\w\s\-_./:]', '', v.strip())
            return sanitized
        return v


class SecurityAuditResponse(BaseModel):
    """Schema for security audit response."""
    
    audit_id: str = Field(..., description="Unique audit entry ID")
    timestamp: str = Field(..., description="Audit timestamp")
    success: bool = Field(..., description="Audit logging success status")


class EncryptionRequest(BaseModel):
    """Schema for encryption request."""
    
    plaintext: str = Field(..., min_length=1, description="Text to encrypt")
    
    @field_validator('plaintext')
    @classmethod
    def validate_plaintext(cls, v):
        """Validate plaintext input."""
        if not v or not v.strip():
            raise ValueError("Plaintext cannot be empty")
        return v


class EncryptionResponse(BaseModel):
    """Schema for encryption response."""
    
    encrypted_data: str = Field(..., description="Encrypted data")
    success: bool = Field(..., description="Encryption success status")


class DecryptionRequest(BaseModel):
    """Schema for decryption request."""
    
    encrypted_data: str = Field(..., min_length=1, description="Encrypted data to decrypt")
    
    @field_validator('encrypted_data')
    @classmethod
    def validate_encrypted_data(cls, v):
        """Validate encrypted data format."""
        if not v or not v.strip():
            raise ValueError("Encrypted data cannot be empty")
        return v.strip()


class DecryptionResponse(BaseModel):
    """Schema for decryption response."""
    
    plaintext: str = Field(..., description="Decrypted plaintext")
    success: bool = Field(..., description="Decryption success status")


class SessionValidationRequest(BaseModel):
    """Schema for session validation request."""
    
    session_token: str = Field(..., min_length=1, description="Session token to validate")
    
    @field_validator('session_token')
    @classmethod
    def validate_session_token(cls, v):
        """Validate session token format."""
        if not v or not v.strip():
            raise ValueError("Session token cannot be empty")
        return v.strip()


class SessionValidationResponse(BaseModel):
    """Schema for session validation response."""
    
    valid: bool = Field(..., description="Session validity status")
    user_id: Optional[int] = Field(None, description="User ID if session is valid")
    employee_id: Optional[str] = Field(None, description="Employee ID if session is valid")
    expires_at: Optional[str] = Field(None, description="Session expiration time")
    time_remaining: Optional[int] = Field(None, description="Time remaining in seconds")


class RateLimitStatus(BaseModel):
    """Schema for rate limit status."""
    
    allowed: bool = Field(..., description="Whether request is allowed")
    requests_remaining: int = Field(..., ge=0, description="Requests remaining in current window")
    reset_time: int = Field(..., description="Time when rate limit resets (Unix timestamp)")
    retry_after: Optional[int] = Field(None, description="Seconds to wait before retry")


class SecurityHeadersResponse(BaseModel):
    """Schema for security headers configuration."""
    
    headers: Dict[str, str] = Field(..., description="Security headers to apply")
    csp_policy: str = Field(..., description="Content Security Policy")
    frame_options: str = Field(..., description="X-Frame-Options setting")


class InputValidationError(BaseModel):
    """Schema for input validation error details."""
    
    field: str = Field(..., description="Field name with validation error")
    message: str = Field(..., description="Validation error message")
    code: str = Field(..., description="Error code")
    value: Optional[str] = Field(None, description="Invalid value (sanitized)")


class ValidationErrorResponse(BaseModel):
    """Schema for validation error response."""
    
    success: bool = Field(False, description="Always false for validation errors")
    message: str = Field(..., description="General error message")
    errors: List[InputValidationError] = Field(..., description="List of validation errors")
    error_code: str = Field("VALIDATION_ERROR", description="Error code")


class SecurityConfigRequest(BaseModel):
    """Schema for security configuration request."""
    
    session_timeout_minutes: Optional[int] = Field(
        None, 
        ge=15, 
        le=60, 
        description="Session timeout in minutes (15-60)"
    )
    
    password_min_length: Optional[int] = Field(
        None, 
        ge=8, 
        le=128, 
        description="Minimum password length (8-128)"
    )
    
    max_login_attempts: Optional[int] = Field(
        None, 
        ge=3, 
        le=10, 
        description="Maximum login attempts before lockout (3-10)"
    )
    
    csrf_token_lifetime_hours: Optional[int] = Field(
        None, 
        ge=1, 
        le=48, 
        description="CSRF token lifetime in hours (1-48)"
    )


class SecurityConfigResponse(BaseModel):
    """Schema for security configuration response."""
    
    session_timeout_minutes: int = Field(..., description="Current session timeout")
    password_min_length: int = Field(..., description="Current minimum password length")
    max_login_attempts: int = Field(..., description="Current maximum login attempts")
    csrf_token_lifetime_hours: int = Field(..., description="Current CSRF token lifetime")
    updated: bool = Field(..., description="Whether configuration was updated")