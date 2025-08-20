"""
Input validation utilities with security best practices.

This module provides comprehensive input validation, sanitization,
and security utilities following enterprise security standards.
"""

import re
import html
import urllib.parse
from typing import Any, Dict, List, Optional, Union, Pattern
from email_validator import validate_email, EmailNotValidError
from pydantic import BaseModel, Field, validator
import bleach

from app.exceptions import ValidationError
from app.utils.logging import get_logger

logger = get_logger(__name__)

# Security patterns
MALICIOUS_PATTERNS = [
    # SQL injection patterns
    re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)", re.IGNORECASE),
    # XSS patterns
    re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
    # Path traversal
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    # Command injection
    re.compile(r"[;&|`$]"),
    # LDAP injection
    re.compile(r"[()=*!&|]"),
]

# Allowed HTML tags for rich text (if needed)
ALLOWED_HTML_TAGS = [
    'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
]

ALLOWED_HTML_ATTRIBUTES = {
    '*': ['class'],
}


class ValidationRules:
    """Common validation rules and patterns."""
    
    # Email validation
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    # Password strength requirements
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]')
    
    # URL validation
    URL_PATTERN = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    
    # Employee ID patterns (alphanumeric, 3-20 chars)
    EMPLOYEE_ID_PATTERN = re.compile(r'^[A-Za-z0-9]{3,20}$')
    
    # Project key pattern (Jira format: 2-10 uppercase letters)
    PROJECT_KEY_PATTERN = re.compile(r'^[A-Z]{2,10}$')
    
    # API token patterns (base64-like, 20-500 chars)
    API_TOKEN_PATTERN = re.compile(r'^[A-Za-z0-9+/=]{20,500}$')


def sanitize_string(value: str, max_length: Optional[int] = None) -> str:
    """
    Sanitize string input to prevent injection attacks.
    
    Args:
        value: Input string to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
        
    Raises:
        ValidationError: If input contains malicious patterns
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Remove null bytes and control characters
    sanitized = value.replace('\x00', '').replace('\r', '')
    
    # Normalize line endings
    sanitized = sanitized.replace('\r\n', '\n').replace('\r', '\n')
    
    # Check for malicious patterns
    for pattern in MALICIOUS_PATTERNS:
        if pattern.search(sanitized):
            logger.warning(
                "Malicious pattern detected in input",
                pattern=pattern.pattern,
                input_preview=sanitized[:50]
            )
            raise ValidationError(
                "Input contains potentially malicious content",
                validation_rule="malicious_pattern_check",
                error_code="MALICIOUS_INPUT_DETECTED"
            )
    
    # Trim whitespace
    sanitized = sanitized.strip()
    
    # Check length
    if max_length and len(sanitized) > max_length:
        raise ValidationError(
            f"Input exceeds maximum length of {max_length} characters",
            validation_rule="max_length",
            error_code="INPUT_TOO_LONG",
            details={"max_length": max_length, "actual_length": len(sanitized)}
        )
    
    return sanitized


def sanitize_html(value: str, strip_tags: bool = False) -> str:
    """
    Sanitize HTML content to prevent XSS attacks.
    
    Args:
        value: HTML content to sanitize
        strip_tags: Whether to strip all HTML tags
        
    Returns:
        Sanitized HTML content
    """
    if not isinstance(value, str):
        value = str(value)
    
    if strip_tags:
        # Strip all HTML tags
        return bleach.clean(value, tags=[], strip=True)
    else:
        # Allow only safe HTML tags
        return bleach.clean(
            value,
            tags=ALLOWED_HTML_TAGS,
            attributes=ALLOWED_HTML_ATTRIBUTES,
            strip=True
        )


def validate_email_address(email: str) -> str:
    """
    Validate and normalize email address.
    
    Args:
        email: Email address to validate
        
    Returns:
        Normalized email address
        
    Raises:
        ValidationError: If email is invalid
    """
    if not email or not isinstance(email, str):
        raise ValidationError(
            "Email address is required",
            field_name="email",
            validation_rule="required",
            error_code="EMAIL_REQUIRED"
        )
    
    email = email.strip().lower()
    
    try:
        # Use email-validator library for comprehensive validation
        validated_email = validate_email(email)
        return validated_email.email
    except EmailNotValidError as e:
        raise ValidationError(
            f"Invalid email address: {str(e)}",
            field_name="email",
            validation_rule="email_format",
            error_code="INVALID_EMAIL_FORMAT"
        ) from e


def validate_password(password: str) -> str:
    """
    Validate password strength requirements.
    
    Args:
        password: Password to validate
        
    Returns:
        Validated password
        
    Raises:
        ValidationError: If password doesn't meet requirements
    """
    if not password or not isinstance(password, str):
        raise ValidationError(
            "Password is required",
            field_name="password",
            validation_rule="required",
            error_code="PASSWORD_REQUIRED"
        )
    
    # Check minimum length
    if len(password) < ValidationRules.PASSWORD_MIN_LENGTH:
        raise ValidationError(
            f"Password must be at least {ValidationRules.PASSWORD_MIN_LENGTH} characters long",
            field_name="password",
            validation_rule="min_length",
            error_code="PASSWORD_TOO_SHORT",
            details={"min_length": ValidationRules.PASSWORD_MIN_LENGTH}
        )
    
    # Check complexity requirements
    if not ValidationRules.PASSWORD_PATTERN.match(password):
        raise ValidationError(
            "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character",
            field_name="password",
            validation_rule="complexity",
            error_code="PASSWORD_INSUFFICIENT_COMPLEXITY"
        )
    
    return password


def validate_url(url: str, require_https: bool = False) -> str:
    """
    Validate URL format and security.
    
    Args:
        url: URL to validate
        require_https: Whether to require HTTPS protocol
        
    Returns:
        Validated URL
        
    Raises:
        ValidationError: If URL is invalid or insecure
    """
    if not url or not isinstance(url, str):
        raise ValidationError(
            "URL is required",
            field_name="url",
            validation_rule="required",
            error_code="URL_REQUIRED"
        )
    
    url = url.strip()
    
    # Basic URL format validation
    if not ValidationRules.URL_PATTERN.match(url):
        raise ValidationError(
            "Invalid URL format",
            field_name="url",
            validation_rule="url_format",
            error_code="INVALID_URL_FORMAT"
        )
    
    # Check for HTTPS requirement
    if require_https and not url.startswith('https://'):
        raise ValidationError(
            "HTTPS is required for this URL",
            field_name="url",
            validation_rule="https_required",
            error_code="HTTPS_REQUIRED"
        )
    
    # Check for suspicious domains or IPs
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    
    if hostname:
        # Block localhost and private IPs in production
        if hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
            logger.warning("Localhost URL detected", url=url)
        
        # Block private IP ranges (basic check)
        if hostname.startswith(('10.', '172.', '192.168.')):
            logger.warning("Private IP URL detected", url=url, hostname=hostname)
    
    return url


def validate_employee_id(employee_id: str) -> str:
    """
    Validate employee ID format.
    
    Args:
        employee_id: Employee ID to validate
        
    Returns:
        Validated employee ID
        
    Raises:
        ValidationError: If employee ID is invalid
    """
    if not employee_id or not isinstance(employee_id, str):
        raise ValidationError(
            "Employee ID is required",
            field_name="employee_id",
            validation_rule="required",
            error_code="EMPLOYEE_ID_REQUIRED"
        )
    
    employee_id = employee_id.strip()
    
    if not ValidationRules.EMPLOYEE_ID_PATTERN.match(employee_id):
        raise ValidationError(
            "Employee ID must be 3-20 alphanumeric characters",
            field_name="employee_id",
            validation_rule="format",
            error_code="INVALID_EMPLOYEE_ID_FORMAT"
        )
    
    return employee_id


def validate_project_key(project_key: str) -> str:
    """
    Validate Jira project key format.
    
    Args:
        project_key: Project key to validate
        
    Returns:
        Validated project key
        
    Raises:
        ValidationError: If project key is invalid
    """
    if not project_key or not isinstance(project_key, str):
        raise ValidationError(
            "Project key is required",
            field_name="project_key",
            validation_rule="required",
            error_code="PROJECT_KEY_REQUIRED"
        )
    
    project_key = project_key.strip().upper()
    
    if not ValidationRules.PROJECT_KEY_PATTERN.match(project_key):
        raise ValidationError(
            "Project key must be 2-10 uppercase letters",
            field_name="project_key",
            validation_rule="format",
            error_code="INVALID_PROJECT_KEY_FORMAT"
        )
    
    return project_key


def validate_api_token(token: str, field_name: str = "token") -> str:
    """
    Validate API token format.
    
    Args:
        token: API token to validate
        field_name: Name of the field for error messages
        
    Returns:
        Validated token
        
    Raises:
        ValidationError: If token is invalid
    """
    if not token or not isinstance(token, str):
        raise ValidationError(
            f"{field_name.title()} is required",
            field_name=field_name,
            validation_rule="required",
            error_code="TOKEN_REQUIRED"
        )
    
    token = token.strip()
    
    if not ValidationRules.API_TOKEN_PATTERN.match(token):
        raise ValidationError(
            f"{field_name.title()} must be 20-500 alphanumeric characters",
            field_name=field_name,
            validation_rule="format",
            error_code="INVALID_TOKEN_FORMAT"
        )
    
    return token


class BaseValidationSchema(BaseModel):
    """Base Pydantic schema with common validation methods."""
    
    class Config:
        # Enable validation on assignment
        validate_assignment = True
        # Use enum values instead of enum objects
        use_enum_values = True
        # Allow population by field name or alias
        allow_population_by_field_name = True
    
    @validator('*', pre=True)
    def sanitize_strings(cls, v):
        """Sanitize all string inputs."""
        if isinstance(v, str):
            return sanitize_string(v)
        return v


def validate_file_upload(
    file_content: bytes,
    allowed_extensions: List[str],
    max_size: int = 5 * 1024 * 1024,  # 5MB default
    filename: Optional[str] = None
) -> None:
    """
    Validate uploaded file content and metadata.
    
    Args:
        file_content: File content as bytes
        allowed_extensions: List of allowed file extensions
        max_size: Maximum file size in bytes
        filename: Original filename (optional)
        
    Raises:
        ValidationError: If file validation fails
    """
    # Check file size
    if len(file_content) > max_size:
        raise ValidationError(
            f"File size exceeds maximum allowed size of {max_size} bytes",
            field_name="file",
            validation_rule="max_size",
            error_code="FILE_TOO_LARGE",
            details={"max_size": max_size, "actual_size": len(file_content)}
        )
    
    # Check file extension if filename provided
    if filename:
        filename = filename.lower()
        if not any(filename.endswith(ext.lower()) for ext in allowed_extensions):
            raise ValidationError(
                f"File type not allowed. Allowed extensions: {', '.join(allowed_extensions)}",
                field_name="file",
                validation_rule="file_extension",
                error_code="INVALID_FILE_TYPE",
                details={"allowed_extensions": allowed_extensions}
            )
    
    # Basic file content validation (check for null bytes)
    if b'\x00' in file_content:
        raise ValidationError(
            "File contains invalid null bytes",
            field_name="file",
            validation_rule="content_validation",
            error_code="INVALID_FILE_CONTENT"
        )


def validate_json_structure(
    data: Dict[str, Any],
    required_fields: List[str],
    optional_fields: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Validate JSON structure against expected schema.
    
    Args:
        data: JSON data to validate
        required_fields: List of required field names
        optional_fields: List of optional field names
        
    Returns:
        Validated JSON data
        
    Raises:
        ValidationError: If JSON structure is invalid
    """
    if not isinstance(data, dict):
        raise ValidationError(
            "Data must be a JSON object",
            validation_rule="type_check",
            error_code="INVALID_JSON_TYPE"
        )
    
    # Check required fields
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        raise ValidationError(
            f"Missing required fields: {', '.join(missing_fields)}",
            validation_rule="required_fields",
            error_code="MISSING_REQUIRED_FIELDS",
            details={"missing_fields": missing_fields}
        )
    
    # Check for unexpected fields
    allowed_fields = set(required_fields)
    if optional_fields:
        allowed_fields.update(optional_fields)
    
    unexpected_fields = [field for field in data.keys() if field not in allowed_fields]
    if unexpected_fields:
        logger.warning(
            "Unexpected fields in JSON data",
            unexpected_fields=unexpected_fields,
            allowed_fields=list(allowed_fields)
        )
    
    return data