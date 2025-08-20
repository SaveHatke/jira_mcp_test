"""
Authentication service for user registration, login, and session management.

This module provides comprehensive authentication services including
user registration with Jira PAT validation, secure login, and JWT
session management with proper security practices.
"""

from jose import jwt
from datetime import datetime, timedelta
from typing import Optional, Union
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.config import settings
from app.database import get_session
from app.models.user import User
from app.models.session import UserSession
from app.schemas.auth_schemas import (
    UserRegistrationRequest, 
    PasswordCreationRequest,
    LoginRequest,
    JiraValidationResult,
    UserProfileResponse
)
from app.services.jira_service import JiraAPIClient
from app.exceptions import (
    AuthenticationError, 
    ValidationError, 
    DatabaseError,
    ExternalServiceError
)
from app.utils.encryption import hash_password, verify_password, encrypt_sensitive_data
from app.utils.logging import get_logger

logger = get_logger(__name__)


class AuthenticationService:
    """
    Service for handling user authentication operations.
    
    Provides methods for user registration, login, session management,
    and user profile operations with proper security and validation.
    """
    
    def __init__(self) -> None:
        """Initialize authentication service."""
        self.jira_client = None
    
    async def validate_jira_pat(self, pat: str, jira_url: Optional[str] = None) -> JiraValidationResult:
        """
        Validate Jira PAT and extract user information.
        
        Args:
            pat: Jira Personal Access Token
            jira_url: Optional Jira base URL
            
        Returns:
            JiraValidationResult with validation status and user data
            
        Raises:
            ExternalServiceError: If Jira API call fails
            ValidationError: If PAT or user data is invalid
        """
        try:
            async with JiraAPIClient() as client:
                result = await client.validate_pat_and_get_user(pat, jira_url)
                
                logger.info("Jira PAT validation completed", 
                           valid=result.valid,
                           error_code=result.error_code if not result.valid else None)
                
                return result
                
        except Exception as e:
            logger.error("Jira PAT validation failed", error=str(e))
            raise
    
    async def check_user_exists(self, employee_id: str, email: str) -> Optional[User]:
        """
        Check if user already exists by employee ID or email.
        
        Args:
            employee_id: Employee ID from Jira
            email: Email address from Jira
            
        Returns:
            Existing user if found, None otherwise
        """
        try:
            async with get_session() as session:
                stmt = select(User).where(
                    or_(
                        User.employee_id == employee_id,
                        User.email == email
                    )
                )
                result = await session.execute(stmt)
                existing_user = result.scalar_one_or_none()
                
                if existing_user:
                    logger.info("Existing user found", 
                               employee_id=employee_id,
                               email=email,
                               existing_employee_id=existing_user.employee_id)
                
                return existing_user
                
        except Exception as e:
            logger.error("Error checking user existence", 
                        employee_id=employee_id,
                        email=email,
                        error=str(e))
            raise DatabaseError(
                "Failed to check user existence",
                error_code="USER_CHECK_FAILED",
                details={"employee_id": employee_id, "email": email, "error": str(e)}
            ) from e
    
    async def create_user_account(
        self, 
        jira_validation_result: JiraValidationResult,
        password: str,
        pat: str
    ) -> User:
        """
        Create new user account with encrypted PAT and hashed password.
        
        Args:
            jira_validation_result: Validated Jira user data
            password: User's chosen password
            pat: Jira Personal Access Token
            
        Returns:
            Created User instance
            
        Raises:
            ValidationError: If user data is invalid
            DatabaseError: If user creation fails
        """
        if not jira_validation_result.valid or not jira_validation_result.user_data:
            raise ValidationError(
                "Invalid Jira validation result for user creation",
                validation_rule="jira_validation",
                error_code="INVALID_JIRA_DATA"
            )
        
        user_data = jira_validation_result.user_data
        
        try:
            # Check if user already exists
            existing_user = await self.check_user_exists(
                user_data['employee_id'], 
                user_data['email']
            )
            
            if existing_user:
                raise ValidationError(
                    f"User already exists with employee ID '{user_data['employee_id']}' or email '{user_data['email']}'",
                    validation_rule="unique_user",
                    error_code="USER_ALREADY_EXISTS",
                    details={
                        "employee_id": user_data['employee_id'],
                        "email": user_data['email']
                    }
                )
            
            # Hash password
            hashed_password = hash_password(password)
            
            # Encrypt PAT
            encrypted_pat = encrypt_sensitive_data(pat)
            
            # Create user instance
            user = User(
                employee_id=user_data['employee_id'],
                name=user_data['name'],
                email=user_data['email'],
                display_name=user_data['display_name'],
                hashed_password=hashed_password,
                encrypted_jira_pat=encrypted_pat,
                jira_url=jira_validation_result.jira_url,
                avatar_url=user_data.get('avatar_url'),
                active=True
            )
            
            # Save to database
            async with get_session() as session:
                session.add(user)
                await session.commit()
                await session.refresh(user)
            
            logger.info("User account created successfully", 
                       user_id=user.id,
                       employee_id=user.employee_id,
                       email=user.email)
            
            return user
            
        except ValidationError:
            # Re-raise validation errors
            raise
        except Exception as e:
            logger.error("Failed to create user account", 
                        employee_id=user_data.get('employee_id'),
                        email=user_data.get('email'),
                        error=str(e))
            raise DatabaseError(
                "Failed to create user account",
                error_code="USER_CREATION_FAILED",
                details={"error": str(e)}
            ) from e
    
    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user with username and password.
        
        Args:
            username: Employee ID, Name, or Email Address
            password: User password
            
        Returns:
            Authenticated User if successful, None otherwise
            
        Raises:
            DatabaseError: If database query fails
        """
        try:
            async with get_session() as session:
                # Search by employee_id, name, or email
                stmt = select(User).where(
                    or_(
                        User.employee_id == username,
                        User.name == username,
                        User.email == username
                    )
                ).where(User.active == True)
                
                result = await session.execute(stmt)
                user = result.scalar_one_or_none()
                
                if not user:
                    logger.warning("User not found for authentication", username=username)
                    return None
                
                # Verify password
                if not verify_password(password, user.hashed_password):
                    logger.warning("Password verification failed", 
                                  user_id=user.id,
                                  employee_id=user.employee_id)
                    return None
                
                logger.info("User authentication successful", 
                           user_id=user.id,
                           employee_id=user.employee_id)
                
                return user
                
        except Exception as e:
            logger.error("Authentication query failed", 
                        username=username,
                        error=str(e))
            raise DatabaseError(
                "Authentication query failed",
                error_code="AUTH_QUERY_FAILED",
                details={"username": username, "error": str(e)}
            ) from e
    
    def create_jwt_token(self, user: User) -> str:
        """
        Create JWT token for user session.
        
        Args:
            user: User instance
            
        Returns:
            JWT token string
            
        Raises:
            AuthenticationError: If token creation fails
        """
        try:
            # Calculate expiration time
            expiration = datetime.utcnow() + timedelta(minutes=settings.session_timeout_minutes)
            
            # Create JWT payload
            payload = {
                'user_id': user.id,
                'employee_id': user.employee_id,
                'email': user.email,
                'exp': expiration,
                'iat': datetime.utcnow(),
                'iss': settings.app_name
            }
            
            # Generate JWT token
            token = jwt.encode(payload, settings.secret_key, algorithm='HS256')
            
            logger.info("JWT token created", 
                       user_id=user.id,
                       employee_id=user.employee_id,
                       expires_at=expiration.isoformat())
            
            return token
            
        except Exception as e:
            logger.error("JWT token creation failed", 
                        user_id=user.id,
                        error=str(e))
            raise AuthenticationError(
                "Failed to create authentication token",
                error_code="TOKEN_CREATION_FAILED",
                details={"user_id": user.id, "error": str(e)}
            ) from e
    
    def validate_jwt_token(self, token: str) -> Optional[dict]:
        """
        Validate JWT token and extract payload.
        
        Args:
            token: JWT token string
            
        Returns:
            Token payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=['HS256'])
            
            # Check if token is expired
            if datetime.utcnow() > datetime.fromtimestamp(payload['exp']):
                logger.warning("JWT token expired", 
                              user_id=payload.get('user_id'),
                              expired_at=datetime.fromtimestamp(payload['exp']).isoformat())
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired during validation")
            return None
        except jwt.JWTError as e:
            logger.warning("Invalid JWT token", error=str(e))
            return None
        except Exception as e:
            logger.error("JWT token validation failed", error=str(e))
            return None
    
    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User instance if found, None otherwise
        """
        try:
            async with get_session() as session:
                user = await session.get(User, user_id)
                return user
        except Exception as e:
            logger.error("Failed to get user by ID", 
                        user_id=user_id,
                        error=str(e))
            return None
    
    async def change_password(self, user: User, current_password: str, new_password: str) -> bool:
        """
        Change user password.
        
        Args:
            user: User instance
            current_password: Current password
            new_password: New password
            
        Returns:
            True if password changed successfully, False otherwise
            
        Raises:
            AuthenticationError: If current password is invalid
            DatabaseError: If password update fails
        """
        try:
            # Verify current password
            if not verify_password(current_password, user.hashed_password):
                raise AuthenticationError(
                    "Current password is incorrect",
                    error_code="INVALID_CURRENT_PASSWORD"
                )
            
            # Hash new password
            new_hashed_password = hash_password(new_password)
            
            # Update password in database
            async with get_session() as session:
                # Refresh user instance in this session
                await session.merge(user)
                user.hashed_password = new_hashed_password
                await session.commit()
            
            logger.info("Password changed successfully", 
                       user_id=user.id,
                       employee_id=user.employee_id)
            
            return True
            
        except AuthenticationError:
            # Re-raise authentication errors
            raise
        except Exception as e:
            logger.error("Password change failed", 
                        user_id=user.id,
                        error=str(e))
            raise DatabaseError(
                "Failed to change password",
                error_code="PASSWORD_CHANGE_FAILED",
                details={"user_id": user.id, "error": str(e)}
            ) from e
    
    def get_user_profile(self, user: User) -> UserProfileResponse:
        """
        Get user profile information.
        
        Args:
            user: User instance
            
        Returns:
            UserProfileResponse with user information
        """
        return UserProfileResponse(
            employee_id=user.employee_id,
            name=user.name,
            email=user.email,
            display_name=user.display_name,
            avatar_url=user.avatar_url,
            jira_url=user.jira_url,
            active=user.active,
            created_at=user.created_at.isoformat()
        )


# Global authentication service instance
auth_service = AuthenticationService()


# Convenience functions
async def validate_jira_pat(pat: str, jira_url: Optional[str] = None) -> JiraValidationResult:
    """Validate Jira PAT and get user information."""
    return await auth_service.validate_jira_pat(pat, jira_url)


async def create_user_account(
    jira_validation_result: JiraValidationResult,
    password: str,
    pat: str
) -> User:
    """Create new user account."""
    return await auth_service.create_user_account(jira_validation_result, password, pat)


async def authenticate_user(username: str, password: str) -> Optional[User]:
    """Authenticate user with credentials."""
    return await auth_service.authenticate_user(username, password)