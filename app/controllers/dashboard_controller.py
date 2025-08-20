"""
Dashboard controller for main application interface.

This module provides the main dashboard interface after user authentication,
showing feature cards and user profile information.
"""

from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import structlog

from app.controllers.auth_controller import require_authentication
from app.models.user import User
from app.utils.logging import get_logger

logger = get_logger(__name__)

# Initialize router and templates
router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="templates")


@router.get("/dashboard", response_class=HTMLResponse)
async def show_dashboard(
    request: Request,
    user: User = Depends(require_authentication)
):
    """
    Display main dashboard with feature cards and user profile.
    
    Shows the main application dashboard with available features
    and user profile information after successful authentication.
    """
    # Get session information
    from app.controllers.auth_controller import get_session_info
    session_info = get_session_info(request)
    
    logger.info("Dashboard accessed", 
               user_id=user.id,
               employee_id=user.employee_id,
               session_id=session_info.get('session_id'))
    
    # Check if user has completed configuration
    # We need to reload the user with relationships to avoid DetachedInstanceError
    try:
        from app.database import get_session
        from sqlalchemy.orm import selectinload
        from sqlalchemy import select
        
        async with get_session() as db_session:
            # Reload user with relationships
            stmt = select(User).options(
                selectinload(User.llm_config),
                selectinload(User.confluence_config)
            ).where(User.id == user.id)
            
            result = await db_session.execute(stmt)
            fresh_user = result.scalar_one_or_none()
            
            if fresh_user:
                configuration_complete = fresh_user.is_configuration_complete()
            else:
                configuration_complete = False
                
    except Exception as e:
        logger.error("Error checking user configuration", 
                    user_id=user.id,
                    error=str(e),
                    exc_info=True)
        # Fallback: assume configuration is not complete
        configuration_complete = False
    
    return templates.TemplateResponse(
        "dashboard/index.html",
        {
            "request": request,
            "user": user,
            "session_info": session_info,
            "configuration_complete": configuration_complete,
            "csrf_token": session_info.get('csrf_token', '')
        }
    )