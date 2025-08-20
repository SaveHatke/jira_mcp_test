"""
Base service implementing business logic patterns and SOLID principles.

This module provides the abstract base class for all services,
implementing common patterns for business logic orchestration.
"""

from abc import ABC
from typing import Optional, Dict, Any, TypeVar, Generic
from sqlalchemy.ext.asyncio import AsyncSession

from app.exceptions import ValidationError, SecurityError
from app.utils.logging import get_logger

# Type variable for service classes
ServiceType = TypeVar('ServiceType')

logger = get_logger(__name__)


class BaseService(ABC):
    """
    Abstract base service implementing common business logic patterns.
    
    This class provides a foundation for all service classes, implementing
    common patterns and ensuring consistent behavior across the application.
    
    Principles implemented:
    - Single Responsibility: Each service handles one business domain
    - Open/Closed: Open for extension via inheritance, closed for modification
    - Liskov Substitution: All services follow the same contract
    - Interface Segregation: Services expose only relevant methods
    - Dependency Inversion: Services depend on abstractions (repositories)
    """
    
    def __init__(self, session: AsyncSession) -> None:
        """
        Initialize the base service with database session.
        
        Args:
            session: Async database session for repository operations
        """
        self._session = session
        self._logger = get_logger(self.__class__.__name__)
    
    def _validate_user_access(self, user_id: int, resource_user_id: int) -> None:
        """
        Validate that a user can access a resource.
        
        Ensures complete data isolation between users by verifying
        that the requesting user owns the resource.
        
        Args:
            user_id: ID of the user making the request
            resource_user_id: ID of the user who owns the resource
            
        Raises:
            SecurityError: If user doesn't have access to the resource
        """
        if user_id != resource_user_id:
            self._logger.warning(
                "Unauthorized access attempt",
                requesting_user_id=user_id,
                resource_user_id=resource_user_id
            )
            raise SecurityError(
                "Access denied: User does not have permission to access this resource",
                error_code="ACCESS_DENIED",
                details={
                    "requesting_user_id": user_id,
                    "resource_user_id": resource_user_id
                }
            )
    
    def _validate_required_fields(self, data: Dict[str, Any], required_fields: list[str]) -> None:
        """
        Validate that all required fields are present and not empty.
        
        Args:
            data: Dictionary of data to validate
            required_fields: List of field names that are required
            
        Raises:
            ValidationError: If any required field is missing or empty
        """
        missing_fields = []
        empty_fields = []
        
        for field in required_fields:
            if field not in data:
                missing_fields.append(field)
            elif not data[field] or (isinstance(data[field], str) and not data[field].strip()):
                empty_fields.append(field)
        
        if missing_fields or empty_fields:
            error_details = {}
            if missing_fields:
                error_details["missing_fields"] = missing_fields
            if empty_fields:
                error_details["empty_fields"] = empty_fields
            
            raise ValidationError(
                f"Required fields validation failed: {', '.join(missing_fields + empty_fields)}",
                error_code="REQUIRED_FIELDS_MISSING",
                details=error_details
            )
    
    def _validate_field_length(
        self, 
        value: str, 
        field_name: str, 
        min_length: Optional[int] = None,
        max_length: Optional[int] = None
    ) -> None:
        """
        Validate string field length constraints.
        
        Args:
            value: String value to validate
            field_name: Name of the field being validated
            min_length: Minimum allowed length (optional)
            max_length: Maximum allowed length (optional)
            
        Raises:
            ValidationError: If length constraints are violated
        """
        if not isinstance(value, str):
            raise ValidationError(
                f"Field '{field_name}' must be a string",
                field_name=field_name,
                validation_rule="type_check",
                error_code="INVALID_FIELD_TYPE"
            )
        
        length = len(value.strip())
        
        if min_length is not None and length < min_length:
            raise ValidationError(
                f"Field '{field_name}' must be at least {min_length} characters long",
                field_name=field_name,
                validation_rule="min_length",
                error_code="FIELD_TOO_SHORT",
                details={"min_length": min_length, "actual_length": length}
            )
        
        if max_length is not None and length > max_length:
            raise ValidationError(
                f"Field '{field_name}' must be no more than {max_length} characters long",
                field_name=field_name,
                validation_rule="max_length",
                error_code="FIELD_TOO_LONG",
                details={"max_length": max_length, "actual_length": length}
            )
    
    def _sanitize_input(self, value: str) -> str:
        """
        Sanitize user input to prevent injection attacks.
        
        Args:
            value: Input string to sanitize
            
        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            return str(value)
        
        # Remove null bytes and control characters
        sanitized = value.replace('\x00', '').replace('\r', '').replace('\n', ' ')
        
        # Trim whitespace
        sanitized = sanitized.strip()
        
        return sanitized
    
    async def _log_operation(
        self, 
        operation: str, 
        user_id: int,
        entity_type: Optional[str] = None,
        entity_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log business operations for audit purposes.
        
        Args:
            operation: Name of the operation being performed
            user_id: ID of the user performing the operation
            entity_type: Type of entity being operated on (optional)
            entity_id: ID of the entity being operated on (optional)
            details: Additional operation details (optional)
        """
        log_data = {
            "operation": operation,
            "user_id": user_id
        }
        
        if entity_type:
            log_data["entity_type"] = entity_type
        if entity_id:
            log_data["entity_id"] = entity_id
        if details:
            log_data["details"] = details
        
        self._logger.info(f"Business operation: {operation}", **log_data)


class UserScopedService(BaseService):
    """
    Base service for user-scoped business operations.
    
    Extends BaseService to provide additional patterns and utilities
    specifically for services that operate on user-scoped data.
    """
    
    def __init__(self, session: AsyncSession) -> None:
        """
        Initialize the user-scoped service.
        
        Args:
            session: Async database session for repository operations
        """
        super().__init__(session)
    
    async def _ensure_user_owns_resource(
        self, 
        user_id: int, 
        resource_id: int,
        resource_type: str,
        get_resource_func
    ) -> Any:
        """
        Ensure a user owns a resource before allowing operations.
        
        Args:
            user_id: ID of the user making the request
            resource_id: ID of the resource being accessed
            resource_type: Type of resource for error messages
            get_resource_func: Async function to retrieve the resource
            
        Returns:
            The resource if user owns it
            
        Raises:
            ValidationError: If resource doesn't exist
            SecurityError: If user doesn't own the resource
        """
        resource = await get_resource_func(resource_id)
        
        if not resource:
            raise ValidationError(
                f"{resource_type} not found",
                error_code="RESOURCE_NOT_FOUND",
                details={"resource_type": resource_type, "resource_id": resource_id}
            )
        
        if hasattr(resource, 'user_id'):
            self._validate_user_access(user_id, resource.user_id)
        
        return resource
    
    def _mask_sensitive_data(self, data: Dict[str, Any], sensitive_fields: list[str]) -> Dict[str, Any]:
        """
        Mask sensitive data in dictionaries for logging or API responses.
        
        Args:
            data: Dictionary containing potentially sensitive data
            sensitive_fields: List of field names to mask
            
        Returns:
            Dictionary with sensitive fields masked
        """
        masked_data = data.copy()
        
        for field in sensitive_fields:
            if field in masked_data and masked_data[field]:
                value = str(masked_data[field])
                if len(value) <= 4:
                    masked_data[field] = "*" * len(value)
                else:
                    # Show first 2 and last 2 characters, mask the rest
                    masked_data[field] = value[:2] + "*" * (len(value) - 4) + value[-2:]
        
        return masked_data
    
    async def _validate_user_configuration_access(
        self, 
        user_id: int, 
        config_type: str
    ) -> None:
        """
        Validate that a user can access their configuration.
        
        Args:
            user_id: ID of the user
            config_type: Type of configuration being accessed
            
        Raises:
            ValidationError: If user_id is invalid
        """
        if not user_id or user_id <= 0:
            raise ValidationError(
                "Invalid user ID for configuration access",
                error_code="INVALID_USER_ID",
                details={"user_id": user_id, "config_type": config_type}
            )
        
        await self._log_operation(
            f"access_{config_type}_config",
            user_id,
            entity_type="configuration",
            details={"config_type": config_type}
        )