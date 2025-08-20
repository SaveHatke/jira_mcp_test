"""
Structured logging utilities with JSON output and PII redaction.

This module provides enterprise-grade logging capabilities with structured
JSON output, request correlation, and automatic PII redaction.
"""

import logging
import sys
import json
import re
from typing import Any, Dict, Optional, List
from datetime import datetime
import structlog
from structlog.types import FilteringBoundLogger

# PII patterns for redaction
PII_PATTERNS = [
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), '[EMAIL_REDACTED]'),
    # Phone numbers (various formats)
    (re.compile(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'), '[PHONE_REDACTED]'),
    # Social Security Numbers
    (re.compile(r'\b\d{3}-?\d{2}-?\d{4}\b'), '[SSN_REDACTED]'),
    # Credit card numbers (basic pattern)
    (re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'), '[CARD_REDACTED]'),
    # IP addresses
    (re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'), '[IP_REDACTED]'),
    # API keys and tokens (common patterns)
    (re.compile(r'\b[A-Za-z0-9]{32,}\b'), '[TOKEN_REDACTED]'),
]

# Sensitive field names that should be masked
SENSITIVE_FIELDS = {
    'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'auth', 'authorization',
    'cookie', 'session', 'pat', 'api_key', 'access_token', 'refresh_token',
    'private_key', 'public_key', 'certificate', 'cert', 'signature', 'hash'
}


def redact_pii(text: str) -> str:
    """
    Redact personally identifiable information from text.
    
    Args:
        text: Text that may contain PII
        
    Returns:
        Text with PII redacted
    """
    if not isinstance(text, str):
        text = str(text)
    
    redacted = text
    for pattern, replacement in PII_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    
    return redacted


def mask_sensitive_value(key: str, value: Any) -> Any:
    """
    Mask sensitive values based on field names.
    
    Args:
        key: Field name
        value: Field value
        
    Returns:
        Masked value if sensitive, original value otherwise
    """
    if not isinstance(key, str):
        return value
    
    key_lower = key.lower()
    
    # Check if field name indicates sensitive data
    for sensitive_field in SENSITIVE_FIELDS:
        if sensitive_field in key_lower:
            if isinstance(value, str) and value:
                if len(value) <= 4:
                    return '*' * len(value)
                else:
                    return value[:2] + '*' * (len(value) - 4) + value[-2:]
            else:
                return '[MASKED]'
    
    return value


def sanitize_log_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize log data by masking sensitive fields and redacting PII.
    
    Args:
        data: Dictionary of log data
        
    Returns:
        Sanitized dictionary
    """
    sanitized = {}
    
    for key, value in data.items():
        # Mask sensitive fields
        masked_value = mask_sensitive_value(key, value)
        
        # Redact PII from string values
        if isinstance(masked_value, str):
            masked_value = redact_pii(masked_value)
        elif isinstance(masked_value, dict):
            # Recursively sanitize nested dictionaries
            masked_value = sanitize_log_data(masked_value)
        elif isinstance(masked_value, list):
            # Sanitize list items
            masked_value = [
                sanitize_log_data(item) if isinstance(item, dict)
                else redact_pii(str(item)) if isinstance(item, str)
                else item
                for item in masked_value
            ]
        
        sanitized[key] = masked_value
    
    return sanitized


def add_request_context(logger, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add request context to log events.
    
    Args:
        logger: Structlog logger instance
        method_name: Log method name (info, error, etc.)
        event_dict: Event dictionary
        
    Returns:
        Event dictionary with request context
    """
    # Add timestamp in ISO format
    event_dict['timestamp'] = datetime.utcnow().isoformat() + 'Z'
    
    # Add service information
    event_dict['service'] = 'ai-jira-confluence-agent'
    
    # Sanitize the entire event dictionary
    event_dict = sanitize_log_data(event_dict)
    
    return event_dict


def json_serializer(obj: Any, **kwargs) -> str:
    """
    Custom JSON serializer for log events.
    
    Args:
        obj: Object to serialize
        **kwargs: Additional keyword arguments (ignored for compatibility)
        
    Returns:
        JSON string
    """
    def default(o):
        if isinstance(o, datetime):
            return o.isoformat()
        return str(o)
    
    return json.dumps(obj, default=default, ensure_ascii=False)


def configure_logging(
    level: str = "INFO",
    json_logs: bool = True,
    include_stdlib: bool = False,
    log_file: Optional[str] = None
) -> None:
    """
    Configure structured logging for the application.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_logs: Whether to output logs in JSON format
        include_stdlib: Whether to include stdlib logs in structured format
        log_file: Optional path to log file for persistent logging
    """
    # Configure structlog
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        add_request_context,
    ]
    
    if json_logs:
        processors.append(structlog.processors.JSONRenderer(serializer=json_serializer))
    else:
        processors.extend([
            structlog.dev.ConsoleRenderer(colors=True),
        ])
    
    # Create a custom logger factory that writes to both console and file
    class MultiWriteLoggerFactory:
        def __init__(self, file_path=None):
            self.file_path = file_path
            self._file_handle = None
            if file_path:
                import os
                log_dir = os.path.dirname(file_path)
                if log_dir and not os.path.exists(log_dir):
                    os.makedirs(log_dir, exist_ok=True)
                self._file_handle = open(file_path, 'a', encoding='utf-8')
        
        def __call__(self, name):
            return MultiWriteLogger(self._file_handle)
    
    class MultiWriteLogger:
        def __init__(self, file_handle=None):
            self.file_handle = file_handle
        
        def msg(self, message):
            # Write to console
            print(message, file=sys.stdout)
            # Write to file if available
            if self.file_handle:
                print(message, file=self.file_handle)
                self.file_handle.flush()
        
        def debug(self, message): self.msg(message)
        def info(self, message): self.msg(message)
        def warning(self, message): self.msg(message)
        def error(self, message): self.msg(message)
        def critical(self, message): self.msg(message)
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper())
        ),
        logger_factory=MultiWriteLoggerFactory(log_file),
        cache_logger_on_first_use=True,
    )
    
    # Configure standard library logging
    import os
    from logging.handlers import RotatingFileHandler
    
    # Create logs directory if it doesn't exist
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    
    # Configure handlers
    handlers = []
    
    # Console handler (always present)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))
    handlers.append(console_handler)
    
    # File handler (if log_file specified)
    if log_file:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(getattr(logging, level.upper()))
        handlers.append(file_handler)
    
    logging.basicConfig(
        format="%(message)s" if json_logs else "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
        level=getattr(logging, level.upper()),
    )
    
    if include_stdlib:
        # Wrap stdlib loggers with structlog
        structlog.configure(
            processors=processors,
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, level.upper())
            ),
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )


def get_logger(name: str) -> FilteringBoundLogger:
    """
    Get a structured logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured structlog logger
    """
    return structlog.get_logger(name)


class RequestContextMiddleware:
    """
    Middleware to add request context to all log events.
    
    This middleware extracts request information and makes it available
    to all log events during request processing.
    """
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Extract request information
            request_id = None
            user_id = None
            
            # Look for X-Request-ID header
            for name, value in scope.get("headers", []):
                if name == b"x-request-id":
                    request_id = value.decode()
                    break
            
            # Generate request ID if not provided
            if not request_id:
                import uuid
                request_id = str(uuid.uuid4())
            
            # Add request context to structlog
            structlog.contextvars.clear_contextvars()
            structlog.contextvars.bind_contextvars(
                x_request_id=request_id,
                method=scope.get("method"),
                path=scope.get("path"),
                user_id=user_id  # Will be updated by auth middleware
            )
        
        await self.app(scope, receive, send)


def log_function_call(
    include_args: bool = False,
    include_result: bool = False,
    mask_args: Optional[List[str]] = None
):
    """
    Decorator to log function calls with arguments and results.
    
    Args:
        include_args: Whether to log function arguments
        include_result: Whether to log function result
        mask_args: List of argument names to mask in logs
        
    Returns:
        Decorator function
    """
    def decorator(func):
        logger = get_logger(func.__module__)
        
        async def async_wrapper(*args, **kwargs):
            func_name = f"{func.__module__}.{func.__name__}"
            
            log_data = {"function": func_name}
            
            if include_args:
                # Sanitize arguments
                if mask_args:
                    sanitized_kwargs = {
                        k: mask_sensitive_value(k, v) if k in mask_args else v
                        for k, v in kwargs.items()
                    }
                else:
                    sanitized_kwargs = kwargs
                
                log_data["arguments"] = {
                    "args_count": len(args),
                    "kwargs": sanitized_kwargs
                }
            
            logger.debug("Function call started", **log_data)
            
            try:
                if hasattr(func, '__call__'):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                if include_result:
                    # Sanitize result
                    if isinstance(result, dict):
                        sanitized_result = sanitize_log_data(result)
                    else:
                        sanitized_result = str(result)[:100]  # Truncate long results
                    
                    log_data["result"] = sanitized_result
                
                logger.debug("Function call completed", **log_data)
                return result
                
            except Exception as e:
                log_data["error"] = str(e)
                logger.error("Function call failed", **log_data)
                raise
        
        def sync_wrapper(*args, **kwargs):
            func_name = f"{func.__module__}.{func.__name__}"
            
            log_data = {"function": func_name}
            
            if include_args:
                # Sanitize arguments
                if mask_args:
                    sanitized_kwargs = {
                        k: mask_sensitive_value(k, v) if k in mask_args else v
                        for k, v in kwargs.items()
                    }
                else:
                    sanitized_kwargs = kwargs
                
                log_data["arguments"] = {
                    "args_count": len(args),
                    "kwargs": sanitized_kwargs
                }
            
            logger.debug("Function call started", **log_data)
            
            try:
                result = func(*args, **kwargs)
                
                if include_result:
                    # Sanitize result
                    if isinstance(result, dict):
                        sanitized_result = sanitize_log_data(result)
                    else:
                        sanitized_result = str(result)[:100]  # Truncate long results
                    
                    log_data["result"] = sanitized_result
                
                logger.debug("Function call completed", **log_data)
                return result
                
            except Exception as e:
                log_data["error"] = str(e)
                logger.error("Function call failed", **log_data)
                raise
        
        # Return appropriate wrapper
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator