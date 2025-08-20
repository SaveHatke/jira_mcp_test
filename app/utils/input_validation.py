"""
Input validation utilities using Pydantic models.

This module provides comprehensive input validation for all requests
to prevent injection attacks and ensure data integrity.
"""

import re
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, field_validator, Field, ConfigDict
from datetime import datetime

from app.exceptions import ValidationError
from app.utils.logging import get_logger

logger = get_logger(__name__)


class InputSanitizer:
    """
    Input sanitization and validation utilities.
    
    Provides methods to sanitize and validate user input to prevent
    injection attacks and ensure data integrity.
    """
    
    # Patterns for common validation
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    URL_PATTERN = re.compile(r'^https?://[^\s/$.?#].[^\s]*$')
    EMPLOYEE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
    
    # Dangerous characters and patterns
    SQL_INJECTION_PATTERNS = [
        r"'|\\';|\\;|--|/\*|\*/",
        r"\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b",
        r"\b(or|and)\s+\d+\s*=\s*\d+",
        r"\b(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?"
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>.*?</iframe>",
        r"<object[^>]*>.*?</object>",
        r"<embed[^>]*>.*?</embed>"
    ]
    
    @classmethod
    def sanitize_string(cls, value: str, max_length: int = 1000) -> str:
        """
        Sanitize string input.
        
        Args:
            value: String to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
            
        Raises:
            ValidationError: If input is invalid
        """
        if not isinstance(value, str):
            raise ValidationError("Input must be a string")
        
        # Check length
        if len(value) > max_length:
            raise ValidationError(f"Input too long (max {max_length} characters)")
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Check for SQL injection patterns
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning("Potential SQL injection attempt detected", pattern=pattern)
                raise ValidationError("Invalid input detected")
        
        # Check for XSS patterns
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning("Potential XSS attempt detected", pattern=pattern)
                raise ValidationError("Invalid input detected")
        
        return value.strip()
    
    @classmethod
    def validate_email(cls, email: str) -> str:
        """
        Validate email address format.
        
        Args:
            email: Email address to validate
            
        Returns:
            Validated email address
            
        Raises:
            ValidationError: If email is invalid
        """
        email = cls.sanitize_string(email, max_length=255)
        
        if not cls.EMAIL_PATTERN.match(email):
            raise ValidationError("Invalid email address format")
        
        return email.lower()
    
    @classmethod
    def validate_url(cls, url: str) -> str:
        """
        Validate URL format.
        
        Args:
            url: URL to validate
            
        Returns:
            Validated URL
            
        Raises:
            ValidationError: If URL is invalid
        """
        url = cls.sanitize_string(url, max_length=2000)
        
        if not cls.URL_PATTERN.match(url):
            raise ValidationError("Invalid URL format")
        
        return url
    
    @classmethod
    def validate_employee_id(cls, employee_id: str) -> str:
        """
        Validate employee ID format.
        
        Args:
            employee_id: Employee ID to validate
            
        Returns:
            Validated employee ID
            
        Raises:
            ValidationError: If employee ID is invalid
        """
        employee_id = cls.sanitize_string(employee_id, max_length=50)
        
        if not cls.EMPLOYEE_ID_PATTERN.match(employee_id):
            raise ValidationError("Invalid employee ID format")
        
        return employee_id
    
    @classmethod
    def validate_password(cls, password: str) -> str:
        """
        Validate password strength.
        
        Args:
            password: Password to validate
            
        Returns:
            Validated password
            
        Raises:
            ValidationError: If password is invalid
        """
        if not isinstance(password, str):
            raise ValidationError("Password must be a string")
        
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long")
        
        if len(password) > 128:
            raise ValidationError("Password too long (max 128 characters)")
        
        # Check for required character types
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*(),.?\":{}|<>" for c in password)
        
        missing_requirements = []
        if not has_upper:
            missing_requirements.append("uppercase letter")
        if not has_lower:
            missing_requirements.append("lowercase letter")
        if not has_digit:
            missing_requirements.append("number")
        if not has_special:
            missing_requirements.append("special character")
        
        if missing_requirements:
            raise ValidationError(f"Password must contain: {', '.join(missing_requirements)}")
        
        return password
    
    @classmethod
    def validate_jira_pat(cls, pat: str) -> str:
        """
        Validate Jira PAT format.
        
        Args:
            pat: Jira Personal Access Token
            
        Returns:
            Validated PAT
            
        Raises:
            ValidationError: If PAT is invalid
        """
        pat = cls.sanitize_string(pat, max_length=200)
        
        # Basic PAT format validation (alphanumeric and some special chars)
        if not re.match(r'^[a-zA-Z0-9._-]+$', pat):
            raise ValidationError("Invalid PAT format")
        
        if len(pat) < 10:
            raise ValidationError("PAT too short")
        
        return pat
    
    @classmethod
    def validate_json_input(cls, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate JSON input data.
        
        Args:
            json_data: JSON data to validate
            
        Returns:
            Validated JSON data
            
        Raises:
            ValidationError: If JSON data is invalid
        """
        if not isinstance(json_data, dict):
            raise ValidationError("Input must be a JSON object")
        
        # Recursively validate string values
        def validate_recursive(obj: Any) -> Any:
            if isinstance(obj, dict):
                return {key: validate_recursive(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [validate_recursive(item) for item in obj]
            elif isinstance(obj, str):
                return cls.sanitize_string(obj, max_length=10000)
            else:
                return obj
        
        return validate_recursive(json_data)


class BaseValidationModel(BaseModel):
    """Base Pydantic model with common validation."""
    
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid"  # Forbid extra fields
    )


class LoginValidationModel(BaseValidationModel):
    """Validation model for login requests."""
    
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    csrf_token: str = Field(..., min_length=1, max_length=500)
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        """Validate username (employee ID)."""
        return InputSanitizer.validate_employee_id(v)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        """Validate password strength."""
        return InputSanitizer.validate_password(v)
    
    @field_validator('csrf_token')
    @classmethod
    def validate_csrf_token(cls, v):
        """Validate CSRF token format."""
        return InputSanitizer.sanitize_string(v, max_length=500)


class RegistrationValidationModel(BaseValidationModel):
    """Validation model for user registration."""
    
    jira_pat: str = Field(..., min_length=10, max_length=200)
    jira_url: str = Field(..., min_length=10, max_length=500)
    password: Optional[str] = Field(None, min_length=8, max_length=128)
    confirm_password: Optional[str] = Field(None, min_length=8, max_length=128)
    
    @field_validator('jira_pat')
    @classmethod
    def validate_jira_pat(cls, v):
        """Validate Jira PAT."""
        return InputSanitizer.validate_jira_pat(v)
    
    @field_validator('jira_url')
    @classmethod
    def validate_jira_url(cls, v):
        """Validate Jira URL."""
        return InputSanitizer.validate_url(v)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        """Validate password strength."""
        if v is not None:
            return InputSanitizer.validate_password(v)
        return v
    
    @field_validator('confirm_password')
    @classmethod
    def validate_passwords_match(cls, v, info):
        """Validate password confirmation."""
        if v is not None and 'password' in info.data and v != info.data['password']:
            raise ValueError('Passwords do not match')
        return v


class ConfigurationValidationModel(BaseValidationModel):
    """Validation model for configuration updates."""
    
    config_type: str = Field(..., pattern=r'^(jira|confluence|llm)$')
    url: Optional[str] = Field(None, max_length=500)
    pat: Optional[str] = Field(None, max_length=200)
    cookie: Optional[str] = Field(None, max_length=1000)
    verify_ssl: Optional[bool] = Field(None)
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        """Validate URL format."""
        if v is not None:
            return InputSanitizer.validate_url(v)
        return v
    
    @field_validator('pat')
    @classmethod
    def validate_pat(cls, v):
        """Validate PAT format."""
        if v is not None:
            return InputSanitizer.validate_jira_pat(v)
        return v
    
    @field_validator('cookie')
    @classmethod
    def validate_cookie(cls, v):
        """Validate cookie value."""
        if v is not None:
            return InputSanitizer.sanitize_string(v, max_length=1000)
        return v


class AIStoryValidationModel(BaseValidationModel):
    """Validation model for AI story generation."""
    
    requirements: str = Field(..., min_length=10, max_length=10000)
    story_format: str = Field(..., pattern=r'^(classic|bdd|custom)$')
    prompt_type: str = Field(..., pattern=r'^(default|custom)$')
    project_key: str = Field(..., min_length=1, max_length=20)
    max_story_points: Optional[int] = Field(None, ge=1, le=100)
    
    @field_validator('requirements')
    @classmethod
    def validate_requirements(cls, v):
        """Validate requirements text."""
        return InputSanitizer.sanitize_string(v, max_length=10000)
    
    @field_validator('project_key')
    @classmethod
    def validate_project_key(cls, v):
        """Validate project key format."""
        if not re.match(r'^[A-Z][A-Z0-9]*$', v.upper()):
            raise ValueError('Project key must be uppercase letters and numbers, starting with a letter')
        return v.upper()


def validate_request_data(model_class: BaseValidationModel, data: Dict[str, Any]) -> BaseValidationModel:
    """
    Validate request data using Pydantic model.
    
    Args:
        model_class: Pydantic model class to use for validation
        data: Data to validate
        
    Returns:
        Validated model instance
        
    Raises:
        ValidationError: If validation fails
    """
    try:
        return model_class(**data)
    except Exception as e:
        logger.warning("Input validation failed", error=str(e), data_keys=list(data.keys()))
        raise ValidationError(f"Input validation failed: {str(e)}")


def sanitize_log_data(data: Any) -> Any:
    """
    Sanitize data for logging (remove sensitive information).
    
    Args:
        data: Data to sanitize
        
    Returns:
        Sanitized data safe for logging
    """
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key contains sensitive information
            if any(sensitive in key_lower for sensitive in ['password', 'pat', 'token', 'cookie', 'secret', 'key']):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = sanitize_log_data(value)
        
        return sanitized
    
    elif isinstance(data, list):
        return [sanitize_log_data(item) for item in data]
    
    elif isinstance(data, str):
        # Redact potential sensitive strings
        if len(data) > 20 and any(char.isalnum() for char in data):
            # Looks like it might be a token or similar
            return f"{data[:4]}...{data[-4:]}"
        return data
    
    else:
        return data