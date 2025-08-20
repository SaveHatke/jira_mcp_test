"""
Authentication schemas for request/response validation.

This module defines Pydantic models for user registration, login,
and authentication-related API operations.
"""

from typing import Optional
from pydantic import BaseModel, Field, EmailStr, validator
import re


class JiraUserResponse(BaseModel):
    """Schema for Jira /myself API response."""
    
    name: str = Field(..., description="Employee ID from Jira")
    emailAddress: EmailStr = Field(..., description="Email address from Jira API")
    displayName: str = Field(..., description="Display name")
    active: bool = Field(..., description="User active status")
    deleted: bool = Field(..., description="User deleted status")
    self: str = Field(..., description="Self URL for extracting Jira base URL")
    avatarUrls: dict = Field(..., description="Avatar URLs")
    
    # Optional fields that might be present
    key: Optional[str] = Field(None, description="User key")
    timeZone: Optional[str] = Field(None, description="User timezone")
    locale: Optional[str] = Field(None, description="User locale")
    groups: Optional[dict] = Field(None, description="User groups")
    applicationRoles: Optional[dict] = Field(None, description="Application roles")
    expand: Optional[str] = Field(None, description="Expand parameter")
    
    class Config:
        """Pydantic configuration."""
        # Allow extra fields that we don't explicitly define
        extra = "allow"


class UserRegistrationRequest(BaseModel):
    """Schema for user registration request."""
    
    jira_pat: str = Field(
        ..., 
        min_length=1,
        max_length=500,
        description="Jira Personal Access Token"
    )
    
    @validator('jira_pat')
    def validate_jira_pat(cls, v):
        """Validate Jira PAT format."""
        if not v or not v.strip():
            raise ValueError("Jira PAT cannot be empty")
        return v.strip()


class PasswordCreationRequest(BaseModel):
    """Schema for password creation during registration."""
    
    password: str = Field(
        ..., 
        min_length=8,
        description="User password with strength requirements"
    )
    
    confirm_password: str = Field(
        ..., 
        description="Password confirmation"
    )
    
    @validator('password')
    def validate_password_strength(cls, v):
        """Validate password meets strength requirements."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        # Check for uppercase letter
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain at least one uppercase letter")
        
        # Check for lowercase letter
        if not re.search(r'[a-z]', v):
            raise ValueError("Password must contain at least one lowercase letter")
        
        # Check for digit
        if not re.search(r'\d', v):
            raise ValueError("Password must contain at least one number")
        
        # Check for special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        
        return v
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        """Validate password confirmation matches."""
        if 'password' in values and v != values['password']:
            raise ValueError("Passwords do not match")
        return v


class UserRegistrationResponse(BaseModel):
    """Schema for user registration response."""
    
    success: bool = Field(..., description="Registration success status")
    message: str = Field(..., description="Success or error message")
    user_details: Optional[dict] = Field(None, description="User details from Jira")
    redirect_url: Optional[str] = Field(None, description="URL to redirect to after success")


class LoginRequest(BaseModel):
    """Schema for user login request."""
    
    username: str = Field(
        ..., 
        min_length=1,
        description="Employee ID, Name, or Email Address"
    )
    
    password: str = Field(
        ..., 
        min_length=1,
        description="User password"
    )
    
    @validator('username')
    def validate_username(cls, v):
        """Validate username is not empty."""
        if not v or not v.strip():
            raise ValueError("Username cannot be empty")
        return v.strip()


class LoginResponse(BaseModel):
    """Schema for user login response."""
    
    success: bool = Field(..., description="Login success status")
    message: str = Field(..., description="Success or error message")
    redirect_url: Optional[str] = Field(None, description="URL to redirect to after login")
    session_expires_at: Optional[str] = Field(None, description="Session expiration time")


class UserProfileResponse(BaseModel):
    """Schema for user profile information."""
    
    employee_id: str = Field(..., description="Employee ID")
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    display_name: str = Field(..., description="Display name")
    avatar_url: Optional[str] = Field(None, description="Avatar URL")
    jira_url: str = Field(..., description="Jira base URL")
    active: bool = Field(..., description="Account active status")
    created_at: str = Field(..., description="Account creation timestamp")


class PasswordChangeRequest(BaseModel):
    """Schema for password change request."""
    
    current_password: str = Field(
        ..., 
        min_length=1,
        description="Current password"
    )
    
    new_password: str = Field(
        ..., 
        min_length=8,
        description="New password with strength requirements"
    )
    
    confirm_new_password: str = Field(
        ..., 
        description="New password confirmation"
    )
    
    @validator('new_password')
    def validate_new_password_strength(cls, v):
        """Validate new password meets strength requirements."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        # Check for uppercase letter
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain at least one uppercase letter")
        
        # Check for lowercase letter
        if not re.search(r'[a-z]', v):
            raise ValueError("Password must contain at least one lowercase letter")
        
        # Check for digit
        if not re.search(r'\d', v):
            raise ValueError("Password must contain at least one number")
        
        # Check for special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        
        return v
    
    @validator('confirm_new_password')
    def new_passwords_match(cls, v, values):
        """Validate new password confirmation matches."""
        if 'new_password' in values and v != values['new_password']:
            raise ValueError("New passwords do not match")
        return v


class JiraValidationResult(BaseModel):
    """Schema for Jira PAT validation result."""
    
    valid: bool = Field(..., description="Validation success status")
    user_data: Optional[dict] = Field(None, description="Parsed user data from Jira")
    jira_url: Optional[str] = Field(None, description="Extracted Jira base URL")
    error_message: Optional[str] = Field(None, description="Error message if validation failed")
    error_code: Optional[str] = Field(None, description="Error code for programmatic handling")