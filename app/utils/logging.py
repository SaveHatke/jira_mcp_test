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
    Configure comprehensive logging that captures ALL terminal output.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_logs: Whether to output logs in JSON format
        include_stdlib: Whether to include stdlib logs in structured format
        log_file: Optional path to log file for persistent logging
    """
    import os
    from logging.handlers import RotatingFileHandler
    
    # Create logs directory if it doesn't exist
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    
    # Create a comprehensive logger that captures everything
    class ComprehensiveLogger:
        def __init__(self, file_path=None):
            self.file_path = file_path
            self._file_handle = None
            self._original_stdout = sys.stdout
            self._original_stderr = sys.stderr
            
            if file_path:
                self._file_handle = open(file_path, 'a', encoding='utf-8', buffering=1)  # Line buffered
                
                # Create a custom stdout/stderr that writes to both console and file
                class TeeWriter:
                    def __init__(self, original_stream, file_handle):
                        self.original_stream = original_stream
                        self.file_handle = file_handle
                    
                    def write(self, text):
                        # Write to original stream (console)
                        self.original_stream.write(text)
                        self.original_stream.flush()
                        
                        # Write to file (avoid duplicates by checking if it's already a structured log)
                        if self.file_handle and text.strip():
                            # Skip if this looks like it's already been processed by our logger
                            if '"service": "ai-jira-confluence-agent"' in text:
                                # This is already a structured log, write as-is
                                if not text.endswith('\n'):
                                    text += '\n'
                                self.file_handle.write(text)
                            else:
                                # Plain text - convert to structured format
                                timestamp = datetime.utcnow().isoformat() + 'Z'
                                log_entry = {
                                    "event": text.strip(),
                                    "level": "info",
                                    "timestamp": timestamp,
                                    "service": "ai-jira-confluence-agent",
                                    "source": "stdout"
                                }
                                self.file_handle.write(json.dumps(log_entry) + '\n')
                            self.file_handle.flush()
                    
                    def flush(self):
                        self.original_stream.flush()
                        if self.file_handle:
                            self.file_handle.flush()
                    
                    def __getattr__(self, name):
                        return getattr(self.original_stream, name)
                
                # Replace stdout and stderr with tee writers
                sys.stdout = TeeWriter(self._original_stdout, self._file_handle)
                sys.stderr = TeeWriter(self._original_stderr, self._file_handle)
        
        def msg(self, message):
            # This will go through our tee writer
            print(message)
        
        def debug(self, message): self.msg(message)
        def info(self, message): self.msg(message)
        def warning(self, message): self.msg(message)
        def error(self, message): self.msg(message)
        def critical(self, message): self.msg(message)
        
        def close(self):
            # Restore original streams
            if hasattr(self, '_original_stdout'):
                sys.stdout = self._original_stdout
            if hasattr(self, '_original_stderr'):
                sys.stderr = self._original_stderr
            
            if self._file_handle:
                self._file_handle.close()
    
    # Create comprehensive logger factory
    class ComprehensiveLoggerFactory:
        def __init__(self, file_path=None):
            self.comprehensive_logger = ComprehensiveLogger(file_path)
        
        def __call__(self, name):
            return self.comprehensive_logger
    
    # Configure structlog processors
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
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper())
        ),
        logger_factory=ComprehensiveLoggerFactory(log_file),
        cache_logger_on_first_use=True,
    )
    
    # Configure standard library logging to also capture everything
    handlers = []
    
    # Console handler (writes to our tee'd stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))
    
    # Custom formatter that ensures consistent output
    class ComprehensiveFormatter(logging.Formatter):
        def format(self, record):
            if json_logs:
                # Create structured log entry
                log_data = {
                    "event": record.getMessage(),
                    "level": record.levelname.lower(),
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "service": "ai-jira-confluence-agent",
                    "logger": record.name,
                    "source": "stdlib"
                }
                
                # Add exception info if present
                if record.exc_info:
                    import traceback
                    log_data["exception"] = traceback.format_exception(*record.exc_info)
                
                return json.dumps(log_data)
            else:
                return super().format(record)
    
    console_handler.setFormatter(ComprehensiveFormatter())
    handlers.append(console_handler)
    
    # Configure root logger
    logging.basicConfig(
        handlers=handlers,
        level=getattr(logging, level.upper()),
        force=True  # Override any existing configuration
    )
    
    # Capture warnings
    import warnings
    logging.captureWarnings(True)
    
    # Set up exception hook to capture unhandled exceptions
    def exception_handler(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            # Allow keyboard interrupt to work normally
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        # Log the exception
        import traceback
        error_msg = {
            "event": "Unhandled exception occurred",
            "level": "critical",
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "service": "ai-jira-confluence-agent",
            "exception_type": exc_type.__name__,
            "exception_message": str(exc_value),
            "traceback": traceback.format_exception(exc_type, exc_value, exc_traceback),
            "source": "exception_hook"
        }
        
        print(json.dumps(error_msg), file=sys.stderr)
        
        # Call the original exception hook
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
    
    sys.excepthook = exception_handler
    
    # Log configuration completion
    print(f"[OK] Comprehensive logging configured - Level: {level}, JSON: {json_logs}, File: {log_file}")
    
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


def configure_uvicorn_logging(log_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Configure uvicorn logging to ensure all server output is captured.
    
    Args:
        log_file: Optional path to log file
        
    Returns:
        Uvicorn logging configuration
    """
    import os
    
    # Create logs directory if needed
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    
    # Custom formatter for uvicorn that outputs JSON
    class UvicornJSONFormatter(logging.Formatter):
        def format(self, record):
            log_data = {
                "event": record.getMessage(),
                "level": record.levelname.lower(),
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "service": "ai-jira-confluence-agent",
                "logger": record.name,
                "source": "uvicorn"
            }
            
            # Add extra fields if present
            if hasattr(record, 'client_addr'):
                log_data["client_addr"] = record.client_addr
            if hasattr(record, 'status_code'):
                log_data["status_code"] = record.status_code
            if hasattr(record, 'method'):
                log_data["method"] = record.method
            if hasattr(record, 'path'):
                log_data["path"] = record.path
            
            return json.dumps(log_data)
    
    # Configure handlers
    handlers = ["default"]
    if log_file:
        handlers.append("file")
    
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": UvicornJSONFormatter,
            },
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "uvicorn": {
                "handlers": handlers,
                "level": "INFO",
                "propagate": False,
            },
            "uvicorn.error": {
                "handlers": handlers,
                "level": "INFO",
                "propagate": False,
            },
            "uvicorn.access": {
                "handlers": handlers,
                "level": "INFO",
                "propagate": False,
            },
        },
    }
    
    # Add file handler if log file specified
    if log_file:
        config["handlers"]["file"] = {
            "formatter": "default",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": log_file,
            "maxBytes": 10 * 1024 * 1024,  # 10MB
            "backupCount": 5,
            "encoding": "utf-8",
        }
    
    return config


def setup_comprehensive_logging(
    level: str = "INFO",
    log_file: str = "logs/app.log"
) -> None:
    """
    Set up comprehensive logging that captures ALL output including:
    - Structured logs from the application
    - Print statements
    - Standard library logs
    - Uvicorn server logs
    - Unhandled exceptions
    - All stdout/stderr output
    
    Args:
        level: Logging level
        log_file: Path to log file
    """
    print(f"[STARTING] Setting up comprehensive logging - Level: {level}, File: {log_file}")
    
    try:
        # Configure main application logging
        configure_logging(
            level=level,
            json_logs=True,
            include_stdlib=True,
            log_file=log_file
        )
        
        print(f"[OK] Comprehensive logging setup completed")
        print(f"[INFO] All terminal output will be saved to: {log_file}")
        print(f"[INFO] Log level set to: {level}")
        
    except Exception as e:
        print(f"[ERROR] Failed to setup comprehensive logging: {e}")
        import traceback
        traceback.print_exc()
        raise


def get_uvicorn_log_config(log_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Get uvicorn logging configuration that integrates with our comprehensive logging.
    
    Args:
        log_file: Optional path to log file
        
    Returns:
        Uvicorn log configuration dictionary
    """
    return configure_uvicorn_logging(log_file)