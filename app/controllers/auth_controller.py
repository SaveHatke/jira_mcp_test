"""
Authentication controller for handling user registration and login.

This module provides FastAPI route handlers for user authentication
operations including registration with Jira PAT validation, login,
and session management.
"""

from fastapi import APIRouter, Request, Form, HTTPException, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from typing import Optional
import structlog

from app.schemas.auth_schemas import (
    UserRegistrationRequest,
    PasswordCreationRequest,
    LoginRequest,
    UserRegistrationResponse,
    LoginResponse
)
from app.services.auth_service import auth_service
from app.exceptions import (
    AuthenticationError,
    ValidationError,
    ExternalServiceError,
    DatabaseError
)
from app.utils.logging import get_logger
from app.config import settings
from app.models.user import User

logger = get_logger(__name__)

# Initialize router and templates
router = APIRouter(prefix="/auth", tags=["authentication"])
templates = Jinja2Templates(directory="templates")


@router.get("/register", response_class=HTMLResponse)
async def show_registration_form(request: Request):
    """
    Display user registration form.
    
    Shows the initial registration form where users enter their Jira PAT
    for validation and account creation.
    """
    return templates.TemplateResponse(
        "auth/register.html",
        {"request": request, "step": "pat_entry"}
    )


@router.post("/register/validate-pat")
async def validate_jira_pat(
    request: Request,
    jira_pat: str = Form(..., description="Jira Personal Access Token"),
    jira_url: str = Form(..., description="Jira base URL")
):
    """
    Validate Jira PAT and show user confirmation.
    
    Validates the provided Jira PAT, extracts user information,
    and displays confirmation form for the user to review their details.
    """
    try:
        # Validate PAT with Jira API
        validation_result = await auth_service.validate_jira_pat(jira_pat, jira_url)
        
        if not validation_result.valid:
            logger.warning("Jira PAT validation failed", 
                          error_code=validation_result.error_code,
                          error_message=validation_result.error_message)
            
            return templates.TemplateResponse(
                "auth/register.html",
                {
                    "request": request,
                    "step": "pat_entry",
                    "error": validation_result.error_message,
                    "jira_pat": jira_pat,
                    "jira_url": jira_url
                }
            )
        
        # Check if user already exists
        existing_user = await auth_service.check_user_exists(
            validation_result.user_data['employee_id'],
            validation_result.user_data['email']
        )
        
        if existing_user:
            logger.warning("User already exists", 
                          employee_id=validation_result.user_data['employee_id'],
                          email=validation_result.user_data['email'])
            
            return templates.TemplateResponse(
                "auth/register.html",
                {
                    "request": request,
                    "step": "pat_entry",
                    "error": f"User already exists with Employee ID '{validation_result.user_data['employee_id']}' or email '{validation_result.user_data['email']}'. Please use the login page.",
                    "jira_pat": jira_pat,
                    "jira_url": jira_url
                }
            )
        
        logger.info("Jira PAT validation successful", 
                   employee_id=validation_result.user_data['employee_id'],
                   email=validation_result.user_data['email'])
        
        # Show confirmation form with user details
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "step": "user_confirmation",
                "user_data": validation_result.user_data,
                "jira_url": validation_result.jira_url,
                "jira_pat": jira_pat,  # Keep for next step
                "success_message": "User authenticated successfully"
            }
        )
        
    except ValidationError as e:
        logger.error("Validation error during PAT validation", 
                    error=str(e),
                    error_code=e.error_code)
        
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "step": "pat_entry",
                "error": str(e),
                "jira_pat": jira_pat,
                "jira_url": jira_url
            }
        )
        
    except ExternalServiceError as e:
        logger.error("External service error during PAT validation", 
                    error=str(e),
                    service=e.service_name)
        
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "step": "pat_entry",
                "error": f"Unable to connect to Jira: {e.message}",
                "jira_pat": jira_pat,
                "jira_url": jira_url
            }
        )
        
    except Exception as e:
        logger.error("Unexpected error during PAT validation", error=str(e))
        
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "step": "pat_entry",
                "error": "An unexpected error occurred. Please try again.",
                "jira_pat": jira_pat,
                "jira_url": jira_url
            }
        )


@router.post("/register/create-password")
async def show_password_creation_form(
    request: Request,
    employee_id: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    display_name: str = Form(...),
    avatar_url: Optional[str] = Form(None),
    jira_url: str = Form(...),
    jira_pat: str = Form(...)
):
    """
    Show password creation form after user confirms their details.
    
    Displays the password creation form with strength requirements
    after the user has confirmed their Jira details are correct.
    """
    user_data = {
        'employee_id': employee_id,
        'name': name,
        'email': email,
        'display_name': display_name,
        'avatar_url': avatar_url
    }
    
    return templates.TemplateResponse(
        "auth/register.html",
        {
            "request": request,
            "step": "password_creation",
            "user_data": user_data,
            "jira_url": jira_url,
            "jira_pat": jira_pat
        }
    )


@router.post("/register/complete")
async def complete_registration(
    request: Request,
    employee_id: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    display_name: str = Form(...),
    avatar_url: Optional[str] = Form(None),
    jira_url: str = Form(...),
    jira_pat: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    """
    Complete user registration by creating the account.
    
    Creates the user account with encrypted PAT and hashed password
    after validating the password meets strength requirements.
    """
    try:
        # Validate password requirements
        password_request = PasswordCreationRequest(
            password=password,
            confirm_password=confirm_password
        )
        
        # Reconstruct user data and validation result
        user_data = {
            'employee_id': employee_id,
            'name': name,
            'email': email,
            'display_name': display_name,
            'avatar_url': avatar_url
        }
        
        # Create a validation result object for user creation
        from app.schemas.auth_schemas import JiraValidationResult
        validation_result = JiraValidationResult(
            valid=True,
            user_data=user_data,
            jira_url=jira_url
        )
        
        # Create user account
        user = await auth_service.create_user_account(
            validation_result,
            password,
            jira_pat
        )
        
        logger.info("User registration completed successfully", 
                   user_id=user.id,
                   employee_id=user.employee_id)
        
        # Show success page with redirect to login
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "step": "success",
                "success_message": "User creation successful! You can now log in with your credentials.",
                "redirect_url": "/auth/login"
            }
        )
        
    except ValidationError as e:
        logger.error("Validation error during registration completion", 
                    error=str(e),
                    employee_id=employee_id)
        
        user_data = {
            'employee_id': employee_id,
            'name': name,
            'email': email,
            'display_name': display_name,
            'avatar_url': avatar_url
        }
        
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "step": "password_creation",
                "user_data": user_data,
                "jira_url": jira_url,
                "jira_pat": jira_pat,
                "error": str(e)
            }
        )
        
    except DatabaseError as e:
        logger.error("Database error during registration completion", 
                    error=str(e),
                    employee_id=employee_id)
        
        user_data = {
            'employee_id': employee_id,
            'name': name,
            'email': email,
            'display_name': display_name,
            'avatar_url': avatar_url
        }
        
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "step": "password_creation",
                "user_data": user_data,
                "jira_url": jira_url,
                "jira_pat": jira_pat,
                "error": "Failed to create user account. Please try again."
            }
        )
        
    except Exception as e:
        logger.error("Unexpected error during registration completion", 
                    error=str(e),
                    employee_id=employee_id)
        
        user_data = {
            'employee_id': employee_id,
            'name': name,
            'email': email,
            'display_name': display_name,
            'avatar_url': avatar_url
        }
        
        return templates.TemplateResponse(
            "auth/register.html",
            {
                "request": request,
                "step": "password_creation",
                "user_data": user_data,
                "jira_url": jira_url,
                "jira_pat": jira_pat,
                "error": "An unexpected error occurred. Please try again."
            }
        )


@router.get("/login", response_class=HTMLResponse)
async def show_login_form(request: Request):
    """
    Display user login form.
    
    Shows the login form where users can enter their Employee ID
    along with their password. Includes CSRF token.
    """
    # Generate CSRF token for the form
    from app.utils.csrf import generate_csrf_token
    csrf_token = generate_csrf_token()
    
    return templates.TemplateResponse(
        "auth/login.html",
        {
            "request": request,
            "csrf_token": csrf_token,
            "session_timeout_minutes": settings.session_timeout_minutes
        }
    )


@router.post("/login")
async def login_user(
    request: Request,
    username: str = Form(..., description="Employee ID (case insensitive)"),
    password: str = Form(..., description="User password"),
    csrf_token: str = Form(..., description="CSRF protection token")
):
    """
    Authenticate user and create session.
    
    Validates user credentials, CSRF token, and creates a JWT session token
    with configurable expiration time and proper security measures.
    Only accepts Employee ID as username (case insensitive).
    """
    try:
        # Normalize username to lowercase for case-insensitive comparison
        username = username.strip().lower()
        
        # Generate a fresh CSRF token for the response (in case of error)
        from app.utils.csrf import generate_csrf_token
        fresh_csrf_token = generate_csrf_token()
        
        # Validate CSRF token (for login, we don't require session-based validation)
        from app.utils.csrf import validate_csrf_token
        if not validate_csrf_token(csrf_token, session_id=None):
            logger.warning("CSRF token validation failed during login", username=username)
            
            # Log security event
            from app.utils.audit_logging import log_security_event
            log_security_event(
                action="csrf_validation_failed",
                outcome="failure",
                ip_address=request.headers.get("x-forwarded-for", getattr(request.client, "host", "unknown")),
                request_id=getattr(request.state, "request_id", None),
                details={"context": "login", "username": username}
            )
            
            return templates.TemplateResponse(
                "auth/login.html",
                {
                    "request": request,
                    "error": "Security validation failed. Please try again.",
                    "username": username,
                    "csrf_token": fresh_csrf_token,
                    "session_timeout_minutes": settings.session_timeout_minutes
                }
            )
        
        # Validate login request
        login_request = LoginRequest(username=username, password=password)
        
        # Authenticate user (only by employee ID, case insensitive)
        user = await auth_service.authenticate_user_by_employee_id(username, password)
        
        if not user:
            logger.warning("Login failed - invalid credentials", username=username)
            
            # Log authentication failure
            from app.utils.audit_logging import log_authentication_event
            log_authentication_event(
                action="login",
                outcome="failure",
                ip_address=request.headers.get("x-forwarded-for", getattr(request.client, "host", "unknown")),
                user_agent=request.headers.get("user-agent", "unknown"),
                request_id=getattr(request.state, "request_id", None),
                error_code="INVALID_CREDENTIALS",
                details={"username": username}
            )
            
            return templates.TemplateResponse(
                "auth/login.html",
                {
                    "request": request,
                    "error": "Invalid Employee ID or password",
                    "username": username,
                    "csrf_token": fresh_csrf_token,
                    "session_timeout_minutes": settings.session_timeout_minutes
                }
            )
        
        # Get client information for session
        client_ip = "unknown"
        if hasattr(request, "client") and request.client:
            client_ip = request.client.host
        
        # Check for forwarded headers (behind proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Create JWT token
        from app.utils.jwt import generate_jwt_token
        jwt_token = generate_jwt_token(
            user_id=user.id,
            employee_id=user.employee_id,
            expires_in_minutes=settings.session_timeout_minutes
        )
        
        # Create session in database
        from app.services.session_service import session_service
        from app.utils.encryption import hash_token
        from datetime import datetime, timezone, timedelta
        
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.session_timeout_minutes)
        token_hash = hash_token(jwt_token)
        
        db_session = await session_service.create_session(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        session_info = {
            'token': jwt_token,
            'session_id': db_session.session_id,
            'expires_at': expires_at
        }
        
        # Set secure cookie with JWT token
        response = RedirectResponse(url="/dashboard", status_code=302)
        response.set_cookie(
            key="session_token",
            value=session_info['token'],
            max_age=settings.session_timeout_minutes * 60,
            httponly=True,
            secure=not settings.debug,  # Use secure cookies in production
            samesite="lax"
        )
        
        logger.info("User login successful", 
                   user_id=user.id,
                   employee_id=user.employee_id,
                   session_id=session_info['session_id'],
                   client_ip=client_ip,
                   timeout_minutes=settings.session_timeout_minutes)
        
        # Log successful authentication
        from app.utils.audit_logging import log_authentication_event
        log_authentication_event(
            action="login",
            user_id=user.id,
            employee_id=user.employee_id,
            outcome="success",
            ip_address=client_ip,
            user_agent=user_agent,
            request_id=getattr(request.state, "request_id", None),
            details={"session_timeout_minutes": settings.session_timeout_minutes}
        )
        
        return response
        
    except ValidationError as e:
        logger.error("Validation error during login", 
                    error=str(e),
                    username=username)
        
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "error": str(e),
                "username": username,
                "csrf_token": fresh_csrf_token,
                "session_timeout_minutes": settings.session_timeout_minutes
            }
        )
        
    except AuthenticationError as e:
        logger.error("Authentication error during login", 
                    error=str(e),
                    username=username)
        
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "error": "Authentication failed. Please try again.",
                "username": username,
                "csrf_token": fresh_csrf_token,
                "session_timeout_minutes": settings.session_timeout_minutes
            }
        )
        
    except Exception as e:
        logger.error("Unexpected error during login", 
                    error=str(e),
                    username=username)
        
        return templates.TemplateResponse(
            "auth/login.html",
            {
                "request": request,
                "error": "An unexpected error occurred. Please try again.",
                "username": username,
                "csrf_token": fresh_csrf_token,
                "session_timeout_minutes": settings.session_timeout_minutes
            }
        )


@router.post("/logout")
async def logout_user(request: Request):
    """
    Log out user and clear session.
    
    Invalidates the session in database, clears the session cookie,
    and redirects to login page.
    """
    try:
        # Get current session token
        token = request.cookies.get("session_token")
        
        if token:
            # Invalidate session in database
            from app.services.session_service import session_service
            await session_service.invalidate_session(token)
            
            # Log user information if available
            user_id = getattr(request.state, 'user_id', None)
            employee_id = getattr(request.state, 'user', {}).get('employee_id', 'unknown')
            
            logger.info("User logged out", 
                       user_id=user_id,
                       employee_id=employee_id)
        
        # Create response and clear cookie
        response = RedirectResponse(url="/auth/login", status_code=302)
        response.delete_cookie(key="session_token")
        
        return response
        
    except Exception as e:
        logger.error("Error during logout", error=str(e))
        
        # Still redirect to login even if logout fails
        response = RedirectResponse(url="/auth/login", status_code=302)
        response.delete_cookie(key="session_token")
        
        return response


@router.get("/logout")
async def logout_user_get(request: Request):
    """
    Handle GET request to logout (for direct URL access).
    
    Redirects to POST logout or directly logs out user.
    """
    try:
        # Get current session token
        token = request.cookies.get("session_token")
        
        if token:
            # Invalidate session in database
            from app.services.session_service import session_service
            await session_service.invalidate_session(token)
            
            # Log user information if available
            user_id = getattr(request.state, 'user_id', None)
            employee_id = getattr(request.state, 'user', {}).get('employee_id', 'unknown')
            
            logger.info("User logged out via GET", 
                       user_id=user_id,
                       employee_id=employee_id)
        
        # Create response and clear cookie
        response = RedirectResponse(url="/auth/login", status_code=302)
        response.delete_cookie(key="session_token")
        
        return response
        
    except Exception as e:
        logger.error("Error during GET logout", error=str(e))
        
        # Still redirect to login even if logout fails
        response = RedirectResponse(url="/auth/login", status_code=302)
        response.delete_cookie(key="session_token")
        
        return response


# Dependency for getting current user from request state (set by middleware)
async def get_current_user(request: Request) -> Optional[User]:
    """
    Get current authenticated user from request state.
    
    The authentication middleware validates the session and sets the user
    in request.state, so we just need to retrieve it from there.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Current user if authenticated, None otherwise
    """
    try:
        # Get user from request state (set by authentication middleware)
        user = getattr(request.state, 'user', None)
        
        if user and isinstance(user, User) and user.active:
            return user
        
        return None
        
    except Exception as e:
        logger.error("Error getting current user from request state", error=str(e))
        return None


# Dependency for requiring authentication
async def require_authentication(request: Request) -> User:
    """
    Require user authentication for protected routes.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Current authenticated user
        
    Raises:
        HTTPException: If user is not authenticated
    """
    user = await get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user


# Dependency for getting session information
def get_session_info(request: Request) -> dict:
    """
    Get session information from request state.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Dictionary with session information
    """
    return {
        'user_id': getattr(request.state, 'user_id', None),
        'session_id': getattr(request.state, 'session_id', None),
        'expires_at': getattr(request.state, 'session_expires_at', None),
        'csrf_token': getattr(request.state, 'csrf_token', ''),
        'client_ip': getattr(request.state, 'client_ip', 'unknown'),
        'client_user_agent': getattr(request.state, 'client_user_agent', 'unknown')
    }

@router.post("/extend-session")
async def extend_user_session(
    request: Request,
    user: User = Depends(require_authentication)
):
    """
    Extend current user session.
    
    Extends the current session expiration time and returns
    new session information.
    """
    try:
        # Get current session token
        token = request.cookies.get("session_token")
        if not token:
            logger.warning("No session token found for extension", user_id=user.id)
            from fastapi.responses import JSONResponse
            return JSONResponse(
                {"error": "No active session found"},
                status_code=401
            )
        
        # Extend session
        from app.services.session_service import session_service
        new_session_info = await session_service.extend_session(token)
        
        if not new_session_info:
            logger.warning("Failed to extend session", user_id=user.id)
            from fastapi.responses import JSONResponse
            return JSONResponse(
                {"error": "Failed to extend session"},
                status_code=400
            )
        
        logger.info("Session extended successfully", 
                   user_id=user.id,
                   employee_id=user.employee_id,
                   new_expires_at=new_session_info['expires_at'].isoformat())
        
        # Return success response with new session cookie
        from fastapi.responses import JSONResponse
        response = JSONResponse({
            "success": True,
            "message": "Session extended successfully",
            "expires_at": new_session_info['expires_at'].isoformat(),
            "timeout_minutes": new_session_info['timeout_minutes']
        })
        
        # Update session cookie
        response.set_cookie(
            key="session_token",
            value=new_session_info['token'],
            max_age=settings.session_timeout_minutes * 60,
            httponly=True,
            secure=not settings.debug,
            samesite="lax"
        )
        
        return response
        
    except Exception as e:
        logger.error("Session extension failed", 
                    user_id=user.id,
                    error=str(e))
        
        from fastapi.responses import JSONResponse
        return JSONResponse(
            {"error": "Session extension failed"},
            status_code=500
        )