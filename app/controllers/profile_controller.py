"""
Profile controller for user profile management.

This module provides user profile viewing and management functionality,
including password changes and account information display.
"""

from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import structlog
import bcrypt

from app.controllers.auth_controller import require_authentication
from app.models.user import User
from app.utils.logging import get_logger
from app.database import get_session
from sqlalchemy import select

logger = get_logger(__name__)

# Initialize router and templates
router = APIRouter(tags=["profile"])
templates = Jinja2Templates(directory="templates")


@router.get("/profile", response_class=HTMLResponse)
async def show_profile(
    request: Request,
    user: User = Depends(require_authentication)
):
    """
    Display user profile page with account information and settings.
    
    Shows the user's profile information including personal details,
    account status, and security settings with options to change password.
    """
    # Get session information
    from app.controllers.auth_controller import get_session_info
    session_info = get_session_info(request)
    
    logger.info("Profile page accessed", 
               user_id=user.id,
               employee_id=user.employee_id,
               session_id=session_info.get('session_id'))
    
    return templates.TemplateResponse(
        "profile/index.html",
        {
            "request": request,
            "user": user,
            "session_info": session_info,
            "csrf_token": session_info.get('csrf_token', '')
        }
    )


@router.post("/profile/change-password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: User = Depends(require_authentication)
):
    """
    Handle password change requests.
    
    Validates the current password, checks new password requirements,
    and updates the user's password if all validations pass.
    """
    # Get session information
    from app.controllers.auth_controller import get_session_info
    session_info = get_session_info(request)
    
    try:
        # Validate current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), user.hashed_password.encode('utf-8')):
            logger.warning("Password change failed - incorrect current password", 
                          user_id=user.id,
                          employee_id=user.employee_id)
            
            return templates.TemplateResponse(
                "profile/index.html",
                {
                    "request": request,
                    "user": user,
                    "session_info": session_info,
                    "csrf_token": session_info.get('csrf_token', ''),
                    "error": "Current password is incorrect."
                },
                status_code=400
            )
        
        # Validate new password confirmation
        if new_password != confirm_password:
            logger.warning("Password change failed - passwords don't match", 
                          user_id=user.id,
                          employee_id=user.employee_id)
            
            return templates.TemplateResponse(
                "profile/index.html",
                {
                    "request": request,
                    "user": user,
                    "session_info": session_info,
                    "csrf_token": session_info.get('csrf_token', ''),
                    "error": "New passwords do not match."
                },
                status_code=400
            )
        
        # Validate new password requirements
        if len(new_password) < 8:
            return templates.TemplateResponse(
                "profile/index.html",
                {
                    "request": request,
                    "user": user,
                    "session_info": session_info,
                    "csrf_token": session_info.get('csrf_token', ''),
                    "error": "Password must be at least 8 characters long."
                },
                status_code=400
            )
        
        # Check password complexity
        has_upper = any(c.isupper() for c in new_password)
        has_lower = any(c.islower() for c in new_password)
        has_digit = any(c.isdigit() for c in new_password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in new_password)
        
        if not all([has_upper, has_lower, has_digit, has_special]):
            return templates.TemplateResponse(
                "profile/index.html",
                {
                    "request": request,
                    "user": user,
                    "session_info": session_info,
                    "csrf_token": session_info.get('csrf_token', ''),
                    "error": "Password must contain uppercase, lowercase, numbers, and special characters."
                },
                status_code=400
            )
        
        # Hash new password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)
        
        # Update password in database
        async with get_session() as db_session:
            # Get fresh user instance
            stmt = select(User).where(User.id == user.id)
            result = await db_session.execute(stmt)
            db_user = result.scalar_one_or_none()
            
            if not db_user:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Update password
            db_user.hashed_password = hashed_password.decode('utf-8')
            
            await db_session.commit()
            await db_session.refresh(db_user)
        
        logger.info("Password changed successfully", 
                   user_id=user.id,
                   employee_id=user.employee_id)
        
        return templates.TemplateResponse(
            "profile/index.html",
            {
                "request": request,
                "user": user,
                "session_info": session_info,
                "csrf_token": session_info.get('csrf_token', ''),
                "success": "Password changed successfully."
            }
        )
        
    except Exception as e:
        logger.error("Error changing password", 
                    user_id=user.id,
                    employee_id=user.employee_id,
                    error=str(e),
                    exc_info=True)
        
        return templates.TemplateResponse(
            "profile/index.html",
            {
                "request": request,
                "user": user,
                "session_info": session_info,
                "csrf_token": session_info.get('csrf_token', ''),
                "error": "An error occurred while changing your password. Please try again."
            },
            status_code=500
        )