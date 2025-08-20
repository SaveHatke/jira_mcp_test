"""Structured logging setup with OpenTelemetry integration."""

import logging
import structlog
from typing import Any, Dict
from app.config import settings


def setup_logging() -> None:
    """Configure structured logging with JSON output and OpenTelemetry integration."""
    
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, settings.log_level.upper()),
    )
    
    # Configure structlog
    structlog.configure(
        processors=[
            # Add log level and timestamp
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            # Add OpenTelemetry trace context
            add_trace_context,
            # JSON output for production
            structlog.processors.JSONRenderer() if not settings.debug 
            else structlog.dev.ConsoleRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def add_trace_context(logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add OpenTelemetry trace context to log records."""
    try:
        from opentelemetry import trace
        
        span = trace.get_current_span()
        if span and span.is_recording():
            span_context = span.get_span_context()
            event_dict["trace_id"] = format(span_context.trace_id, "032x")
            event_dict["span_id"] = format(span_context.span_id, "016x")
    except ImportError:
        # OpenTelemetry not available, skip trace context
        pass
    
    return event_dict