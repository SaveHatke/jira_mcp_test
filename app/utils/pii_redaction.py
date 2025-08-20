"""
PII (Personally Identifiable Information) redaction utilities.

This module provides utilities to redact sensitive personal information
from logs, error messages, and audit trails to ensure privacy compliance.
"""

import re
from typing import Any, Dict, List, Union, Optional
from dataclasses import dataclass

from app.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class RedactionRule:
    """Rule for redacting sensitive data."""
    
    pattern: str
    replacement: str
    field_names: List[str]
    description: str


class PIIRedactor:
    """
    PII redaction manager for sensitive data protection.
    
    Provides comprehensive redaction of personally identifiable information
    from various data structures and text content.
    """
    
    # Sensitive field names (case insensitive)
    SENSITIVE_FIELDS = {
        # Authentication and security
        'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'auth', 'authorization',
        'pat', 'personal_access_token', 'api_key', 'cookie', 'session', 'csrf_token',
        
        # Personal information
        'ssn', 'social_security', 'social_security_number', 'tax_id', 'national_id',
        'passport', 'driver_license', 'license_number', 'id_number',
        
        # Financial information
        'credit_card', 'card_number', 'account_number', 'routing_number', 'iban',
        'bank_account', 'payment_info', 'billing_info',
        
        # Contact information (partial redaction)
        'phone', 'phone_number', 'mobile', 'cell', 'telephone',
        'address', 'street', 'home_address', 'billing_address',
        
        # Personal details
        'birth_date', 'birthday', 'date_of_birth', 'dob', 'age',
        'personal_id', 'employee_ssn', 'medical_record'
    }
    
    # Redaction rules for pattern matching
    REDACTION_RULES = [
        RedactionRule(
            pattern=r'\b\d{3}-\d{2}-\d{4}\b',  # SSN format
            replacement='***-**-****',
            field_names=['ssn', 'social_security'],
            description='Social Security Number'
        ),
        RedactionRule(
            pattern=r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
            replacement='****-****-****-****',
            field_names=['credit_card', 'card_number'],
            description='Credit Card Number'
        ),
        RedactionRule(
            pattern=r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # Phone number
            replacement='***-***-****',
            field_names=['phone', 'phone_number', 'mobile'],
            description='Phone Number'
        ),
        RedactionRule(
            pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            replacement='[EMAIL_REDACTED]',
            field_names=['email', 'email_address'],
            description='Email Address'
        ),
        RedactionRule(
            pattern=r'\b\d{1,5}\s+\w+\s+\w+.*?\b',  # Street address
            replacement='[ADDRESS_REDACTED]',
            field_names=['address', 'street', 'home_address'],
            description='Street Address'
        )
    ]
    
    def __init__(self) -> None:
        """Initialize the PII redactor."""
        self.compiled_patterns = [
            (re.compile(rule.pattern, re.IGNORECASE), rule.replacement, rule.description)
            for rule in self.REDACTION_RULES
        ]
    
    def redact_text(self, text: str) -> str:
        """
        Redact PII from text content.
        
        Args:
            text: Text to redact
            
        Returns:
            Text with PII redacted
        """
        if not isinstance(text, str):
            return text
        
        redacted_text = text
        
        # Apply pattern-based redaction
        for pattern, replacement, description in self.compiled_patterns:
            if pattern.search(redacted_text):
                logger.debug(f"Redacting {description} from text")
                redacted_text = pattern.sub(replacement, redacted_text)
        
        return redacted_text
    
    def redact_field_value(self, field_name: str, value: Any) -> Any:
        """
        Redact value based on field name.
        
        Args:
            field_name: Name of the field
            value: Value to potentially redact
            
        Returns:
            Original value or redacted version
        """
        if not isinstance(value, str):
            return value
        
        field_lower = field_name.lower()
        
        # Check if field name indicates sensitive data
        if any(sensitive in field_lower for sensitive in self.SENSITIVE_FIELDS):
            return self._redact_sensitive_value(value, field_name)
        
        # Apply pattern-based redaction for text content
        return self.redact_text(value)
    
    def _redact_sensitive_value(self, value: str, field_name: str) -> str:
        """
        Redact sensitive field value.
        
        Args:
            value: Value to redact
            field_name: Field name for context
            
        Returns:
            Redacted value
        """
        field_lower = field_name.lower()
        
        # Full redaction for highly sensitive fields
        if any(sensitive in field_lower for sensitive in [
            'password', 'secret', 'token', 'key', 'pat', 'cookie', 'ssn', 'credit_card'
        ]):
            return '[REDACTED]'
        
        # Partial redaction for other sensitive fields
        if len(value) <= 4:
            return '*' * len(value)
        elif len(value) <= 8:
            return f"{value[:1]}{'*' * (len(value) - 2)}{value[-1:]}"
        else:
            return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
    
    def redact_dictionary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact PII from dictionary data.
        
        Args:
            data: Dictionary to redact
            
        Returns:
            Dictionary with PII redacted
        """
        if not isinstance(data, dict):
            return data
        
        redacted_data = {}
        
        for key, value in data.items():
            if isinstance(value, dict):
                redacted_data[key] = self.redact_dictionary(value)
            elif isinstance(value, list):
                redacted_data[key] = self.redact_list(value)
            else:
                redacted_data[key] = self.redact_field_value(key, value)
        
        return redacted_data
    
    def redact_list(self, data: List[Any]) -> List[Any]:
        """
        Redact PII from list data.
        
        Args:
            data: List to redact
            
        Returns:
            List with PII redacted
        """
        if not isinstance(data, list):
            return data
        
        redacted_list = []
        
        for item in data:
            if isinstance(item, dict):
                redacted_list.append(self.redact_dictionary(item))
            elif isinstance(item, list):
                redacted_list.append(self.redact_list(item))
            elif isinstance(item, str):
                redacted_list.append(self.redact_text(item))
            else:
                redacted_list.append(item)
        
        return redacted_list
    
    def redact_any(self, data: Any) -> Any:
        """
        Redact PII from any data structure.
        
        Args:
            data: Data to redact
            
        Returns:
            Data with PII redacted
        """
        if isinstance(data, dict):
            return self.redact_dictionary(data)
        elif isinstance(data, list):
            return self.redact_list(data)
        elif isinstance(data, str):
            return self.redact_text(data)
        else:
            return data
    
    def redact_employee_id(self, employee_id: str) -> str:
        """
        Redact employee ID for logging.
        
        Args:
            employee_id: Employee ID to redact
            
        Returns:
            Redacted employee ID
        """
        if not isinstance(employee_id, str) or not employee_id:
            return employee_id
        
        if len(employee_id) <= 4:
            return '*' * len(employee_id)
        else:
            return f"{employee_id[:2]}{'*' * (len(employee_id) - 4)}{employee_id[-2:]}"
    
    def redact_ip_address(self, ip_address: str) -> str:
        """
        Redact IP address for privacy.
        
        Args:
            ip_address: IP address to redact
            
        Returns:
            Redacted IP address
        """
        if not isinstance(ip_address, str) or not ip_address:
            return ip_address
        
        # IPv4 redaction
        if '.' in ip_address and ip_address.count('.') == 3:
            parts = ip_address.split('.')
            if len(parts) == 4 and all(part.isdigit() for part in parts):
                return f"{parts[0]}.{parts[1]}.*.* "
        
        # IPv6 redaction
        if ':' in ip_address:
            parts = ip_address.split(':')
            if len(parts) >= 2:
                return f"{parts[0]}:{parts[1]}::*"
        
        # Unknown format
        return "*.*.*.* "
    
    def redact_user_agent(self, user_agent: str) -> str:
        """
        Redact user agent for privacy.
        
        Args:
            user_agent: User agent string to redact
            
        Returns:
            Redacted user agent
        """
        if not isinstance(user_agent, str) or not user_agent:
            return user_agent
        
        try:
            # Extract browser type
            browser = 'Unknown'
            if 'Chrome' in user_agent:
                browser = 'Chrome'
            elif 'Firefox' in user_agent:
                browser = 'Firefox'
            elif 'Safari' in user_agent:
                browser = 'Safari'
            elif 'Edge' in user_agent:
                browser = 'Edge'
            
            # Extract OS
            os_info = 'Unknown'
            if 'Windows' in user_agent:
                os_info = 'Windows'
            elif 'Mac' in user_agent or 'macOS' in user_agent:
                os_info = 'macOS'
            elif 'Linux' in user_agent:
                os_info = 'Linux'
            elif 'Android' in user_agent:
                os_info = 'Android'
            elif 'iOS' in user_agent:
                os_info = 'iOS'
            
            return f"{browser}/{os_info}"
            
        except Exception:
            return "Unknown/Unknown"
    
    def create_redacted_error_message(self, error_message: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        Create error message with PII redacted.
        
        Args:
            error_message: Original error message
            context: Additional context that might contain PII
            
        Returns:
            Error message with PII redacted
        """
        # Redact the error message itself
        redacted_message = self.redact_text(error_message)
        
        # If context is provided, redact it and include safe parts
        if context:
            redacted_context = self.redact_dictionary(context)
            
            # Only include non-sensitive context information
            safe_context = {}
            for key, value in redacted_context.items():
                if not any(sensitive in key.lower() for sensitive in self.SENSITIVE_FIELDS):
                    safe_context[key] = value
            
            if safe_context:
                redacted_message += f" (Context: {safe_context})"
        
        return redacted_message


# Global PII redactor instance
pii_redactor = PIIRedactor()


def redact_pii_from_text(text: str) -> str:
    """
    Redact PII from text using the global redactor.
    
    Args:
        text: Text to redact
        
    Returns:
        Text with PII redacted
    """
    return pii_redactor.redact_text(text)


def redact_pii_from_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact PII from dictionary using the global redactor.
    
    Args:
        data: Dictionary to redact
        
    Returns:
        Dictionary with PII redacted
    """
    return pii_redactor.redact_dictionary(data)


def redact_pii_from_any(data: Any) -> Any:
    """
    Redact PII from any data structure using the global redactor.
    
    Args:
        data: Data to redact
        
    Returns:
        Data with PII redacted
    """
    return pii_redactor.redact_any(data)


def create_safe_error_message(error_message: str, context: Optional[Dict[str, Any]] = None) -> str:
    """
    Create safe error message with PII redacted using the global redactor.
    
    Args:
        error_message: Original error message
        context: Additional context
        
    Returns:
        Safe error message
    """
    return pii_redactor.create_redacted_error_message(error_message, context)