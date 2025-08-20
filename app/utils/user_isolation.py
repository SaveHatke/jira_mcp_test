"""
User isolation utilities for ensuring multi-user data separation.

This module provides utilities and decorators to ensure that users
can only access their own data and that cross-user data access is
prevented at the application level.
"""

from functools import wraps
from typing import Optional, Any, Callable, Union
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.exceptions import AuthenticationError, SecurityError
from app.models.user import User
from app.utils.logging import get_logger

logger = get_logger(__name__)


class UserIsolationError(SecurityError):
    """Exception raised when user isolation is violated."""
    
    def __init__(self, message: str, user_id: Optional[int] = None, resource_id: Optional[Any] = None):
        super().__init__(
            message,
            error_code="USER_ISOLATION_VIOLATION",
            details={
                "user_id": user_id,
                "resource_id": resource_id,
                "violation_type": "cross_user_access"
            }
        )
        self.user_id = user_id
        self.resource_id = resource_id


def require_user_ownership(resource_user_id_field: str = "user_id"):
    """
    Decorator to ensure user can only access their own resources.
    
    Args:
        resource_user_id_field: Field name in the resource that contains the user ID
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract current user from request context or function arguments
            current_user_id = None
            
            # Look for user_id in kwargs
            if 'user_id' in kwargs:
                current_user_id = kwargs['user_id']
            
            # Look for user object in kwargs
            elif 'user' in kwargs:
                user = kwargs['user']
                if hasattr(user, 'id'):
                    current_user_id = user.id
            
            # Look for request object to get user from state
            elif 'request' in kwargs:
                request = kwargs['request']
                if hasattr(request, 'state') and hasattr(request.state, 'user_id'):
                    current_user_id = request.state.user_id
            
            if not current_user_id:
                logger.error("User isolation check failed - no user ID found")
                raise AuthenticationError(
                    "User authentication required for resource access",
                    error_code="USER_ID_REQUIRED"
                )
            
            # Execute the function
            result = await func(*args, **kwargs)
            
            # If result is a database object, check ownership
            if hasattr(result, resource_user_id_field):
                resource_user_id = getattr(result, resource_user_id_field)
                if resource_user_id != current_user_id:
                    logger.warning("User isolation violation detected",
                                  current_user_id=current_user_id,
                                  resource_user_id=resource_user_id,
                                  resource_type=type(result).__name__)
                    
                    raise UserIsolationError(
                        f"Access denied: resource belongs to different user",
                        user_id=current_user_id,
                        resource_id=getattr(result, 'id', None)
                    )
            
            return result
        
        return wrapper
    return decorator


def filter_by_user(query, user_id: int, user_field: str = "user_id"):
    """
    Add user filter to SQLAlchemy query to ensure user isolation.
    
    Args:
        query: SQLAlchemy query object
        user_id: Current user ID
        user_field: Field name to filter by (default: "user_id")
        
    Returns:
        Filtered query
    """
    try:
        # Add user filter to query
        filtered_query = query.filter(getattr(query.column_descriptions[0]['type'], user_field) == user_id)
        
        logger.debug("User isolation filter applied", 
                    user_id=user_id,
                    user_field=user_field)
        
        return filtered_query
        
    except Exception as e:
        logger.error("Failed to apply user isolation filter", 
                    user_id=user_id,
                    user_field=user_field,
                    error=str(e))
        raise SecurityError(
            "Failed to apply user isolation filter",
            error_code="USER_FILTER_FAILED",
            details={"user_id": user_id, "error": str(e)}
        ) from e


async def verify_user_ownership(
    session: AsyncSession,
    model_class: type,
    resource_id: Any,
    user_id: int,
    user_field: str = "user_id"
) -> bool:
    """
    Verify that a resource belongs to the specified user.
    
    Args:
        session: Database session
        model_class: SQLAlchemy model class
        resource_id: ID of the resource to check
        user_id: Current user ID
        user_field: Field name that contains the user ID
        
    Returns:
        True if user owns the resource, False otherwise
        
    Raises:
        SecurityError: If verification fails
    """
    try:
        # Query for the resource
        stmt = select(model_class).where(
            model_class.id == resource_id,
            getattr(model_class, user_field) == user_id
        )
        
        result = await session.execute(stmt)
        resource = result.scalar_one_or_none()
        
        is_owner = resource is not None
        
        logger.debug("User ownership verification", 
                    user_id=user_id,
                    resource_id=resource_id,
                    model_class=model_class.__name__,
                    is_owner=is_owner)
        
        return is_owner
        
    except Exception as e:
        logger.error("User ownership verification failed", 
                    user_id=user_id,
                    resource_id=resource_id,
                    model_class=model_class.__name__,
                    error=str(e))
        
        raise SecurityError(
            "Failed to verify user ownership",
            error_code="OWNERSHIP_VERIFICATION_FAILED",
            details={
                "user_id": user_id,
                "resource_id": resource_id,
                "model_class": model_class.__name__,
                "error": str(e)
            }
        ) from e


def ensure_user_isolation(user_id: int, resource_user_id: int, resource_type: str = "resource"):
    """
    Ensure that the current user can access the specified resource.
    
    Args:
        user_id: Current user ID
        resource_user_id: User ID that owns the resource
        resource_type: Type of resource for error messages
        
    Raises:
        UserIsolationError: If user doesn't own the resource
    """
    if user_id != resource_user_id:
        logger.warning("User isolation violation prevented",
                      current_user_id=user_id,
                      resource_user_id=resource_user_id,
                      resource_type=resource_type)
        
        raise UserIsolationError(
            f"Access denied: {resource_type} belongs to different user",
            user_id=user_id,
            resource_id=resource_user_id
        )


class UserContext:
    """
    Context manager for user-scoped operations.
    
    Provides a context where all database operations are automatically
    filtered by user ID to ensure data isolation.
    """
    
    def __init__(self, user_id: int, session: AsyncSession):
        """
        Initialize user context.
        
        Args:
            user_id: Current user ID
            session: Database session
        """
        self.user_id = user_id
        self.session = session
    
    async def __aenter__(self):
        """Enter the user context."""
        logger.debug("Entering user context", user_id=self.user_id)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit the user context."""
        logger.debug("Exiting user context", user_id=self.user_id)
    
    def filter_query(self, query, user_field: str = "user_id"):
        """
        Filter query by current user.
        
        Args:
            query: SQLAlchemy query
            user_field: Field name to filter by
            
        Returns:
            Filtered query
        """
        return filter_by_user(query, self.user_id, user_field)
    
    async def verify_ownership(self, model_class: type, resource_id: Any, user_field: str = "user_id") -> bool:
        """
        Verify ownership of a resource.
        
        Args:
            model_class: SQLAlchemy model class
            resource_id: Resource ID
            user_field: Field name that contains user ID
            
        Returns:
            True if user owns the resource
        """
        return await verify_user_ownership(
            self.session,
            model_class,
            resource_id,
            self.user_id,
            user_field
        )


def get_user_context(user_id: int, session: AsyncSession) -> UserContext:
    """
    Create a user context for scoped operations.
    
    Args:
        user_id: Current user ID
        session: Database session
        
    Returns:
        UserContext instance
    """
    return UserContext(user_id, session)


# Audit logging for user isolation
def log_user_access(user_id: int, resource_type: str, resource_id: Any, action: str, success: bool = True):
    """
    Log user access to resources for audit purposes.
    
    Args:
        user_id: User ID performing the action
        resource_type: Type of resource being accessed
        resource_id: ID of the resource
        action: Action being performed (read, write, delete, etc.)
        success: Whether the action was successful
    """
    logger.info("User resource access",
               user_id=user_id,
               resource_type=resource_type,
               resource_id=resource_id,
               action=action,
               success=success,
               audit=True)


# Validation functions
def validate_user_session_isolation(session_user_id: int, requested_user_id: int):
    """
    Validate that session user matches requested user for operations.
    
    Args:
        session_user_id: User ID from session
        requested_user_id: User ID being requested in operation
        
    Raises:
        UserIsolationError: If user IDs don't match
    """
    if session_user_id != requested_user_id:
        logger.warning("Session user isolation violation",
                      session_user_id=session_user_id,
                      requested_user_id=requested_user_id)
        
        raise UserIsolationError(
            "Session user does not match requested user",
            user_id=session_user_id,
            resource_id=requested_user_id
        )