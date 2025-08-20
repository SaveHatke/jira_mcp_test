"""
Custom exception hierarchy for the AI Jira Confluence Agent.

This module defines a comprehensive exception hierarchy following enterprise
development standards with proper error categorization and handling.
"""

from typing import Optional, Dict, Any


class AIAgentException(Exception):
    """
    Base exception for the AI Jira Confluence Agent application.
    
    All custom exceptions should inherit from this base class to ensure
    consistent error handling and logging throughout the application.
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize the base exception.
        
        Args:
            message: Human-readable error message
            error_code: Optional error code for programmatic handling
            details: Optional dictionary with additional error context
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}


class AuthenticationError(AIAgentException):
    """
    Authentication related errors.
    
    Raised when user authentication fails, tokens are invalid,
    or authorization is denied.
    """
    pass


class ConfigurationError(AIAgentException):
    """
    Configuration validation and management errors.
    
    Raised when configuration files are invalid, missing required
    settings, or contain incompatible values.
    """
    pass


class ExternalServiceError(AIAgentException):
    """
    External API and service integration errors.
    
    Raised when external services (Jira, Confluence, LLM) are
    unavailable, return errors, or timeout.
    """
    
    def __init__(
        self, 
        message: str, 
        service_name: str,
        status_code: Optional[int] = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize external service error.
        
        Args:
            message: Human-readable error message
            service_name: Name of the external service (jira, confluence, llm)
            status_code: HTTP status code if applicable
            error_code: Service-specific error code
            details: Additional error context
        """
        super().__init__(message, error_code, details)
        self.service_name = service_name
        self.status_code = status_code


class ValidationError(AIAgentException):
    """
    Business rule and input validation errors.
    
    Raised when user input fails validation, business rules
    are violated, or data integrity constraints are not met.
    """
    
    def __init__(
        self, 
        message: str, 
        field_name: Optional[str] = None,
        validation_rule: Optional[str] = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize validation error.
        
        Args:
            message: Human-readable error message
            field_name: Name of the field that failed validation
            validation_rule: Name of the validation rule that was violated
            error_code: Validation-specific error code
            details: Additional validation context
        """
        super().__init__(message, error_code, details)
        self.field_name = field_name
        self.validation_rule = validation_rule


class DatabaseError(AIAgentException):
    """
    Database operation and connectivity errors.
    
    Raised when database operations fail, connections are lost,
    or data integrity constraints are violated.
    """
    pass


class CacheError(AIAgentException):
    """
    Caching system errors.
    
    Raised when cache operations fail, cache is unavailable,
    or cache data is corrupted.
    """
    pass


class BackgroundJobError(AIAgentException):
    """
    Background job processing errors.
    
    Raised when background jobs fail, timeout, or encounter
    unrecoverable errors during execution.
    """
    
    def __init__(
        self, 
        message: str, 
        job_type: str,
        job_id: Optional[str] = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize background job error.
        
        Args:
            message: Human-readable error message
            job_type: Type of background job that failed
            job_id: Unique identifier of the failed job
            error_code: Job-specific error code
            details: Additional job context
        """
        super().__init__(message, error_code, details)
        self.job_type = job_type
        self.job_id = job_id


class SecurityError(AIAgentException):
    """
    Security and encryption related errors.
    
    Raised when encryption/decryption fails, security policies
    are violated, or unauthorized access is attempted.
    """
    pass


class RateLimitError(ExternalServiceError):
    """
    Rate limiting errors for external services.
    
    Raised when API rate limits are exceeded and requests
    need to be throttled or retried later.
    """
    
    def __init__(
        self, 
        message: str, 
        service_name: str,
        retry_after: Optional[int] = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize rate limit error.
        
        Args:
            message: Human-readable error message
            service_name: Name of the rate-limited service
            retry_after: Seconds to wait before retrying
            error_code: Rate limit specific error code
            details: Additional rate limit context
        """
        super().__init__(message, service_name, 429, error_code, details)
        self.retry_after = retry_after


class CircuitBreakerError(ExternalServiceError):
    """
    Circuit breaker pattern errors.
    
    Raised when circuit breaker is open and requests to
    external services are being blocked to prevent cascading failures.
    """
    
    def __init__(
        self, 
        message: str, 
        service_name: str,
        failure_count: int,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize circuit breaker error.
        
        Args:
            message: Human-readable error message
            service_name: Name of the service with open circuit breaker
            failure_count: Number of consecutive failures
            error_code: Circuit breaker specific error code
            details: Additional circuit breaker context
        """
        super().__init__(message, service_name, None, error_code, details)
        self.failure_count = failure_count