"""
Audit logging utilities for security and compliance.

This module provides comprehensive audit logging capabilities
without exposing sensitive data or PII.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
import json

from app.utils.logging import get_logger
from app.config import settings

logger = get_logger(__name__)


@dataclass
class AuditEvent:
    """Audit event data structure."""
    
    audit_id: str
    timestamp: datetime
    user_id: Optional[int]
    employee_id: Optional[str]
    session_id: Optional[str]
    action: str
    resource: Optional[str]
    outcome: str  # success, failure, error
    ip_address: Optional[str]
    user_agent: Optional[str]
    request_id: Optional[str]
    details: Optional[Dict[str, Any]]
    error_code: Optional[str]
    duration_ms: Optional[float]


class AuditLogger:
    """
    Audit logging manager for security events and user actions.
    
    Provides structured audit logging with PII redaction and
    compliance-friendly event tracking.
    """
    
    # Sensitive fields that should be redacted
    SENSITIVE_FIELDS = {
        'password', 'pat', 'token', 'cookie', 'secret', 'key',
        'authorization', 'auth', 'credential', 'private'
    }
    
    # PII fields that should be redacted
    PII_FIELDS = {
        'ssn', 'social_security', 'credit_card', 'phone', 'address',
        'birth_date', 'birthday', 'personal_id'
    }
    
    def __init__(self) -> None:
        """Initialize the audit logger."""
        pass
    
    def log_authentication_event(
        self,
        action: str,
        user_id: Optional[int] = None,
        employee_id: Optional[str] = None,
        outcome: str = "success",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log authentication-related events.
        
        Args:
            action: Authentication action (login, logout, register, etc.)
            user_id: User database ID
            employee_id: Employee ID (redacted in logs)
            outcome: Event outcome (success, failure, error)
            ip_address: Client IP address
            user_agent: Client user agent (redacted)
            request_id: Request correlation ID
            error_code: Error code if applicable
            details: Additional event details
            
        Returns:
            Audit event ID
        """
        return self._log_audit_event(
            action=f"auth_{action}",
            user_id=user_id,
            employee_id=employee_id,
            resource="authentication",
            outcome=outcome,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            error_code=error_code,
            details=details
        )
    
    def log_configuration_event(
        self,
        action: str,
        config_type: str,
        user_id: Optional[int] = None,
        employee_id: Optional[str] = None,
        outcome: str = "success",
        request_id: Optional[str] = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log configuration-related events.
        
        Args:
            action: Configuration action (create, update, test, delete)
            config_type: Type of configuration (jira, confluence, llm)
            user_id: User database ID
            employee_id: Employee ID
            outcome: Event outcome
            request_id: Request correlation ID
            error_code: Error code if applicable
            details: Additional event details
            
        Returns:
            Audit event ID
        """
        return self._log_audit_event(
            action=f"config_{action}",
            user_id=user_id,
            employee_id=employee_id,
            resource=f"configuration_{config_type}",
            outcome=outcome,
            request_id=request_id,
            error_code=error_code,
            details=details
        )
    
    def log_ai_story_event(
        self,
        action: str,
        user_id: Optional[int] = None,
        employee_id: Optional[str] = None,
        outcome: str = "success",
        request_id: Optional[str] = None,
        error_code: Optional[str] = None,
        duration_ms: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log AI story generation events.
        
        Args:
            action: AI action (generate, refine, create_issue, validate)
            user_id: User database ID
            employee_id: Employee ID
            outcome: Event outcome
            request_id: Request correlation ID
            error_code: Error code if applicable
            duration_ms: Operation duration in milliseconds
            details: Additional event details
            
        Returns:
            Audit event ID
        """
        return self._log_audit_event(
            action=f"ai_story_{action}",
            user_id=user_id,
            employee_id=employee_id,
            resource="ai_story_generator",
            outcome=outcome,
            request_id=request_id,
            error_code=error_code,
            duration_ms=duration_ms,
            details=details
        )
    
    def log_security_event(
        self,
        action: str,
        user_id: Optional[int] = None,
        employee_id: Optional[str] = None,
        outcome: str = "success",
        ip_address: Optional[str] = None,
        request_id: Optional[str] = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log security-related events.
        
        Args:
            action: Security action (csrf_validation, rate_limit, etc.)
            user_id: User database ID
            employee_id: Employee ID
            outcome: Event outcome
            ip_address: Client IP address
            request_id: Request correlation ID
            error_code: Error code if applicable
            details: Additional event details
            
        Returns:
            Audit event ID
        """
        return self._log_audit_event(
            action=f"security_{action}",
            user_id=user_id,
            employee_id=employee_id,
            resource="security_system",
            outcome=outcome,
            ip_address=ip_address,
            request_id=request_id,
            error_code=error_code,
            details=details
        )
    
    def log_data_access_event(
        self,
        action: str,
        resource: str,
        user_id: Optional[int] = None,
        employee_id: Optional[str] = None,
        outcome: str = "success",
        request_id: Optional[str] = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log data access events.
        
        Args:
            action: Data action (read, write, update, delete)
            resource: Resource being accessed
            user_id: User database ID
            employee_id: Employee ID
            outcome: Event outcome
            request_id: Request correlation ID
            error_code: Error code if applicable
            details: Additional event details
            
        Returns:
            Audit event ID
        """
        return self._log_audit_event(
            action=f"data_{action}",
            user_id=user_id,
            employee_id=employee_id,
            resource=resource,
            outcome=outcome,
            request_id=request_id,
            error_code=error_code,
            details=details
        )
    
    def _log_audit_event(
        self,
        action: str,
        user_id: Optional[int] = None,
        employee_id: Optional[str] = None,
        session_id: Optional[str] = None,
        resource: Optional[str] = None,
        outcome: str = "success",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        error_code: Optional[str] = None,
        duration_ms: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log audit event with PII redaction.
        
        Args:
            action: Action being audited
            user_id: User database ID
            employee_id: Employee ID
            session_id: Session ID
            resource: Resource being accessed
            outcome: Event outcome
            ip_address: Client IP address
            user_agent: Client user agent
            request_id: Request correlation ID
            error_code: Error code if applicable
            duration_ms: Operation duration
            details: Additional event details
            
        Returns:
            Audit event ID
        """
        try:
            # Generate audit ID
            audit_id = str(uuid.uuid4())
            
            # Create audit event
            audit_event = AuditEvent(
                audit_id=audit_id,
                timestamp=datetime.now(timezone.utc),
                user_id=user_id,
                employee_id=self._redact_employee_id(employee_id),
                session_id=session_id,
                action=action,
                resource=resource,
                outcome=outcome,
                ip_address=self._redact_ip_address(ip_address),
                user_agent=self._redact_user_agent(user_agent),
                request_id=request_id,
                details=self._redact_sensitive_data(details) if details else None,
                error_code=error_code,
                duration_ms=duration_ms
            )
            
            # Convert to dictionary for logging
            audit_dict = asdict(audit_event)
            
            # Convert datetime to ISO string
            audit_dict['timestamp'] = audit_event.timestamp.isoformat()
            
            # Log the audit event
            logger.info(
                "Audit event",
                audit_type="security_audit",
                **audit_dict
            )
            
            return audit_id
            
        except Exception as e:
            logger.error("Audit logging failed", error=str(e), action=action)
            # Return a fallback audit ID
            return str(uuid.uuid4())
    
    def _redact_employee_id(self, employee_id: Optional[str]) -> Optional[str]:
        """
        Redact employee ID for privacy.
        
        Args:
            employee_id: Employee ID to redact
            
        Returns:
            Redacted employee ID or None
        """
        if not employee_id:
            return None
        
        # Show only first 2 and last 2 characters
        if len(employee_id) <= 4:
            return "*" * len(employee_id)
        else:
            return f"{employee_id[:2]}{'*' * (len(employee_id) - 4)}{employee_id[-2:]}"
    
    def _redact_ip_address(self, ip_address: Optional[str]) -> Optional[str]:
        """
        Redact IP address for privacy.
        
        Args:
            ip_address: IP address to redact
            
        Returns:
            Redacted IP address or None
        """
        if not ip_address:
            return None
        
        # For IPv4, show only first two octets
        if '.' in ip_address:
            parts = ip_address.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.*.* "
        
        # For IPv6 or other formats, show only prefix
        if ':' in ip_address:
            parts = ip_address.split(':')
            if len(parts) >= 2:
                return f"{parts[0]}:{parts[1]}::*"
        
        # Fallback for unknown formats
        return "*.*.*.* "
    
    def _redact_user_agent(self, user_agent: Optional[str]) -> Optional[str]:
        """
        Redact user agent for privacy.
        
        Args:
            user_agent: User agent string to redact
            
        Returns:
            Redacted user agent or None
        """
        if not user_agent:
            return None
        
        # Extract browser and OS info, remove version details
        try:
            # Simple extraction of browser type
            if 'Chrome' in user_agent:
                browser = 'Chrome'
            elif 'Firefox' in user_agent:
                browser = 'Firefox'
            elif 'Safari' in user_agent:
                browser = 'Safari'
            elif 'Edge' in user_agent:
                browser = 'Edge'
            else:
                browser = 'Unknown'
            
            # Extract OS info
            if 'Windows' in user_agent:
                os_info = 'Windows'
            elif 'Mac' in user_agent or 'macOS' in user_agent:
                os_info = 'macOS'
            elif 'Linux' in user_agent:
                os_info = 'Linux'
            else:
                os_info = 'Unknown'
            
            return f"{browser}/{os_info}"
            
        except Exception:
            return "Unknown/Unknown"
    
    def _redact_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive data from audit details.
        
        Args:
            data: Dictionary containing audit details
            
        Returns:
            Dictionary with sensitive data redacted
        """
        if not isinstance(data, dict):
            return data
        
        redacted_data = {}
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key contains sensitive information
            is_sensitive = any(
                sensitive_field in key_lower 
                for sensitive_field in self.SENSITIVE_FIELDS | self.PII_FIELDS
            )
            
            if is_sensitive:
                # Redact sensitive values
                if isinstance(value, str):
                    if len(value) <= 4:
                        redacted_data[key] = "*" * len(value)
                    else:
                        redacted_data[key] = f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
                else:
                    redacted_data[key] = "[REDACTED]"
            elif isinstance(value, dict):
                # Recursively redact nested dictionaries
                redacted_data[key] = self._redact_sensitive_data(value)
            elif isinstance(value, list):
                # Handle lists
                redacted_list = []
                for item in value:
                    if isinstance(item, dict):
                        redacted_list.append(self._redact_sensitive_data(item))
                    else:
                        redacted_list.append(item)
                redacted_data[key] = redacted_list
            else:
                # Keep non-sensitive data as-is
                redacted_data[key] = value
        
        return redacted_data


# Global audit logger instance
audit_logger = AuditLogger()


def log_authentication_event(
    action: str,
    user_id: Optional[int] = None,
    employee_id: Optional[str] = None,
    outcome: str = "success",
    **kwargs
) -> str:
    """
    Log authentication event using the global audit logger.
    
    Args:
        action: Authentication action
        user_id: User database ID
        employee_id: Employee ID
        outcome: Event outcome
        **kwargs: Additional audit parameters
        
    Returns:
        Audit event ID
    """
    return audit_logger.log_authentication_event(
        action=action,
        user_id=user_id,
        employee_id=employee_id,
        outcome=outcome,
        **kwargs
    )


def log_security_event(
    action: str,
    outcome: str = "success",
    **kwargs
) -> str:
    """
    Log security event using the global audit logger.
    
    Args:
        action: Security action
        outcome: Event outcome
        **kwargs: Additional audit parameters
        
    Returns:
        Audit event ID
    """
    return audit_logger.log_security_event(
        action=action,
        outcome=outcome,
        **kwargs
    )


def log_configuration_event(
    action: str,
    config_type: str,
    user_id: Optional[int] = None,
    outcome: str = "success",
    **kwargs
) -> str:
    """
    Log configuration event using the global audit logger.
    
    Args:
        action: Configuration action
        config_type: Configuration type
        user_id: User database ID
        outcome: Event outcome
        **kwargs: Additional audit parameters
        
    Returns:
        Audit event ID
    """
    return audit_logger.log_configuration_event(
        action=action,
        config_type=config_type,
        user_id=user_id,
        outcome=outcome,
        **kwargs
    )