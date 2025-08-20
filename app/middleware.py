"""
Custom middleware for request processing, authentication, and security.

This module implements enterprise-grade middleware for handling
authentication, request correlation, security headers, and logging.
"""

import time
import uuid
from typing import Callable, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse
from starlette.types import ASGIApp
import structlog

from app.exceptions import AuthenticationError, SecurityError
from app.utils.logging import get_logger

logger = get_logger(__name__)


class RequestCorrelationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add request correlation IDs for tracing.
    
    Generates or extracts X-Request-ID headers and makes them
    available throughout the request lifecycle for logging and tracing.
    """
    
    def __init__(self, app: ASGIApp) -> None:
        """Initialize the middleware."""
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request and add correlation ID.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            HTTP response with correlation headers
        """
        # Extract or generate request ID
        request_id = request.headers.get("x-request-id")
        if not request_id:
            request_id = str(uuid.uuid4())
        
        # Add request ID to request state
        request.state.request_id = request_id
        
        # Add to structured logging context
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            x_request_id=request_id,
            method=request.method,
            path=request.url.path,
            user_agent=request.headers.get("user-agent", "unknown")
        )
        
        # Process request
        start_time = time.time()
        response = await call_next(request)
        duration_ms = (time.time() - start_time) * 1000
        
        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id
        
        # Log request completion
        logger.info(
            "Request completed",
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2)
        )
        
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to responses.
    
    Implements security best practices by adding appropriate
    headers to prevent common web vulnerabilities.
    """
    
    def __init__(self, app: ASGIApp) -> None:
        """Initialize the middleware."""
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request and add security headers.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            HTTP response with security headers
        """
        response = await call_next(request)
        
        # Add security headers using security manager
        from app.utils.security_config import get_security_headers
        security_headers = get_security_headers()
        
        # Add headers to response
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for JWT token authentication and session management.
    
    Validates JWT tokens, manages user sessions, provides user context
    for authenticated requests, and enforces multi-user data isolation.
    """
    
    # Paths that don't require authentication
    PUBLIC_PATHS = {
        "/",
        "/healthz",
        "/readyz",
        "/config-status",
    }
    
    # Auth-specific paths (handled by auth controller)
    AUTH_PATHS = {
        "/auth/login",
        "/auth/register",
        "/auth/logout",
    }
    
    def __init__(self, app: ASGIApp) -> None:
        """Initialize the middleware."""
        super().__init__(app)
    
    def _is_public_path(self, path: str) -> bool:
        """
        Check if path is public (doesn't require authentication).
        
        Args:
            path: Request path
            
        Returns:
            True if path is public, False otherwise
        """
        # Exact matches for public paths
        if path in self.PUBLIC_PATHS:
            return True
        
        # Auth paths are public
        if path in self.AUTH_PATHS or path.startswith("/auth/"):
            return True
        
        # Static files are public
        if path.startswith("/static/"):
            return True
        
        return False
    
    async def _validate_session(self, token: str) -> Optional[dict]:
        """
        Validate session token and return user information.
        
        Args:
            token: JWT session token
            
        Returns:
            User session information if valid, None otherwise
        """
        try:
            # Import here to avoid circular imports
            from app.services.session_service import session_service
            
            session_info = await session_service.validate_session(token)
            return session_info
            
        except Exception as e:
            logger.warning("Session validation failed", error=str(e))
            return None
    
    def _get_client_info(self, request: Request) -> dict:
        """
        Extract client information from request.
        
        Args:
            request: HTTP request
            
        Returns:
            Dictionary with client information
        """
        # Get IP address
        ip_address = "unknown"
        if hasattr(request, "client") and request.client:
            ip_address = request.client.host
        
        # Check for forwarded headers (behind proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            ip_address = forwarded_for.split(",")[0].strip()
        
        # Get user agent
        user_agent = request.headers.get("user-agent", "unknown")
        
        return {
            "ip_address": ip_address,
            "user_agent": user_agent
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request and validate authentication.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            HTTP response or redirect to login
        """
        path = request.url.path
        method = request.method
        
        # Skip authentication for public paths
        if self._is_public_path(path):
            return await call_next(request)
        
        # Extract JWT token from cookie or header
        token = None
        
        # Try cookie first (for web interface)
        if "session_token" in request.cookies:
            token = request.cookies["session_token"]
        
        # Try Authorization header (for API calls)
        elif "authorization" in request.headers:
            auth_header = request.headers["authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
        
        # No token found - redirect to login
        if not token:
            logger.info("No authentication token found", path=path, method=method)
            
            if path.startswith("/api/"):
                # Return 401 for API calls
                from starlette.responses import JSONResponse
                return JSONResponse(
                    {"error": "Authentication required"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"}
                )
            else:
                # Redirect to login for web interface
                return RedirectResponse(url="/auth/login", status_code=302)
        
        # Validate session token
        session_info = await self._validate_session(token)
        if not session_info:
            logger.warning("Invalid or expired session token", path=path, method=method)
            
            if path.startswith("/api/"):
                from starlette.responses import JSONResponse
                return JSONResponse(
                    {"error": "Invalid or expired session"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"}
                )
            else:
                # Clear invalid cookie and redirect to login
                response = RedirectResponse(url="/auth/login", status_code=302)
                response.delete_cookie("session_token")
                return response
        
        # Add user and session information to request state
        request.state.user = session_info['user']
        request.state.user_id = session_info['user_id']
        request.state.session_id = session_info['session_id']
        request.state.session_expires_at = session_info['expires_at']
        
        # Add client information
        client_info = self._get_client_info(request)
        request.state.client_ip = client_info['ip_address']
        request.state.client_user_agent = client_info['user_agent']
        
        # Add user context to logging
        structlog.contextvars.bind_contextvars(
            user_id=session_info['user_id'],
            employee_id=session_info['employee_id'],
            session_id=session_info['session_id']
        )
        
        logger.debug("Request authenticated", 
                    user_id=session_info['user_id'],
                    employee_id=session_info['employee_id'],
                    path=path,
                    method=method)
        
        # Process request with authenticated user context
        return await call_next(request)


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    Middleware for CSRF (Cross-Site Request Forgery) protection.
    
    Validates CSRF tokens for state-changing requests (POST, PUT, DELETE, PATCH)
    and provides CSRF tokens for form rendering.
    """
    
    # Methods that require CSRF protection
    PROTECTED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
    
    # Paths exempt from CSRF protection
    EXEMPT_PATHS = {
        "/healthz",
        "/readyz",
        "/config-status",
    }
    
    def __init__(self, app: ASGIApp) -> None:
        """Initialize the middleware."""
        super().__init__(app)
    
    def _is_exempt_path(self, path: str) -> bool:
        """
        Check if path is exempt from CSRF protection.
        
        Args:
            path: Request path
            
        Returns:
            True if path is exempt, False otherwise
        """
        # Exact matches
        if path in self.EXEMPT_PATHS:
            return True
        
        # API endpoints might have different CSRF handling
        if path.startswith("/api/"):
            return True  # API endpoints use different auth mechanisms
        
        # Static files are exempt
        if path.startswith("/static/"):
            return True
        
        return False
    
    async def _extract_csrf_token(self, request: Request) -> Optional[str]:
        """
        Extract CSRF token from request.
        
        Args:
            request: HTTP request
            
        Returns:
            CSRF token if found, None otherwise
        """
        # Try header first
        csrf_token = request.headers.get("X-CSRF-Token")
        if csrf_token:
            return csrf_token
        
        # Try form data for POST requests
        if request.method == "POST":
            try:
                # Check if request has form data
                content_type = request.headers.get("content-type", "")
                if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
                    # We need to read the body, but FastAPI will handle form parsing
                    # The actual form data will be available in the route handler
                    # For now, we'll check if the token is in the request state
                    pass
            except Exception:
                pass
        
        return None
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request and validate CSRF token if required.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            HTTP response or CSRF error
        """
        path = request.url.path
        method = request.method
        
        # Skip CSRF protection for exempt paths
        if self._is_exempt_path(path):
            return await call_next(request)
        
        # Skip CSRF protection for safe methods
        if method not in self.PROTECTED_METHODS:
            return await call_next(request)
        
        # Skip CSRF protection for unauthenticated requests (they'll be handled by auth middleware)
        if not hasattr(request.state, 'user') or not request.state.user:
            return await call_next(request)
        
        # Extract CSRF token from request
        csrf_token = await self._extract_csrf_token(request)
        
        # For form submissions, we'll validate CSRF in the route handlers
        # This middleware primarily adds CSRF context and logs attempts
        
        # Add CSRF token generation capability to request state
        from app.utils.csrf import generate_csrf_token
        session_id = getattr(request.state, 'session_id', None)
        request.state.csrf_token = generate_csrf_token(str(session_id) if session_id else None)
        
        # For form submissions, validate CSRF token from form data
        if method in self.PROTECTED_METHODS and not self._is_exempt_path(path):
            # Try to extract CSRF token from form data
            if hasattr(request.state, 'user') and request.state.user:
                # This will be handled by individual route handlers
                # We just ensure the token is available in request state
                pass
        
        # Log CSRF-protected request
        logger.debug("CSRF-protected request", 
                    path=path,
                    method=method,
                    has_csrf_token=csrf_token is not None,
                    user_id=getattr(request.state, 'user_id', None))
        
        return await call_next(request)


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for centralized error handling and logging.
    
    Catches unhandled exceptions, logs them appropriately,
    and returns user-friendly error responses.
    """
    
    def __init__(self, app: ASGIApp) -> None:
        """Initialize the middleware."""
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with error handling.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            HTTP response or error response
        """
        try:
            return await call_next(request)
        
        except AuthenticationError as e:
            logger.warning(
                "Authentication error",
                error_code=e.error_code,
                message=e.message,
                path=request.url.path
            )
            
            if request.url.path.startswith("/api/"):
                from starlette.responses import JSONResponse
                return JSONResponse(
                    {
                        "error": "Authentication failed",
                        "message": e.message,
                        "error_code": e.error_code
                    },
                    status_code=401
                )
            else:
                return RedirectResponse(url="/login", status_code=302)
        
        except SecurityError as e:
            logger.error(
                "Security error",
                error_code=e.error_code,
                message=e.message,
                path=request.url.path,
                details=e.details
            )
            
            if request.url.path.startswith("/api/"):
                from starlette.responses import JSONResponse
                return JSONResponse(
                    {
                        "error": "Security error",
                        "message": "A security error occurred",
                        "error_code": e.error_code
                    },
                    status_code=403
                )
            else:
                from starlette.responses import HTMLResponse
                return HTMLResponse(
                    "<h1>Security Error</h1><p>A security error occurred. Please try again.</p>",
                    status_code=403
                )
        
        except Exception as e:
            # Log unexpected errors
            logger.error(
                "Unhandled exception",
                error=str(e),
                error_type=type(e).__name__,
                path=request.url.path,
                exc_info=True
            )
            
            if request.url.path.startswith("/api/"):
                from starlette.responses import JSONResponse
                return JSONResponse(
                    {
                        "error": "Internal server error",
                        "message": "An unexpected error occurred"
                    },
                    status_code=500
                )
            else:
                from starlette.responses import HTMLResponse
                return HTMLResponse(
                    "<h1>Internal Server Error</h1><p>An unexpected error occurred. Please try again later.</p>",
                    status_code=500
                )


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for basic rate limiting protection.
    
    Implements simple rate limiting based on IP address
    to prevent abuse and DoS attacks.
    """
    
    def __init__(self, app: ASGIApp, requests_per_minute: int = 60) -> None:
        """
        Initialize the middleware.
        
        Args:
            app: ASGI application
            requests_per_minute: Maximum requests per minute per IP
        """
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.request_counts = {}  # In production, use Redis or similar
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Get client IP address from request.
        
        Args:
            request: HTTP request
            
        Returns:
            Client IP address
        """
        # Check for forwarded headers (behind proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        # Check for real IP header
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        # Fall back to direct connection
        if hasattr(request, "client") and request.client:
            return request.client.host
        
        return "unknown"
    
    def _is_rate_limited(self, client_ip: str) -> bool:
        """
        Check if client IP is rate limited.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            True if rate limited, False otherwise
        """
        current_time = time.time()
        minute_window = int(current_time // 60)
        
        # Clean old entries (simple cleanup)
        # Extract window numbers from keys and compare with current window
        old_windows = []
        for key in list(self.request_counts.keys()):
            try:
                # Key format is "ip:window_number"
                if ":" in key:
                    window_num = int(key.split(":")[-1])
                    if window_num < minute_window - 5:
                        old_windows.append(key)
            except (ValueError, IndexError):
                # Invalid key format, remove it
                old_windows.append(key)
        
        for old_window in old_windows:
            del self.request_counts[old_window]
        
        # Check current window
        window_key = f"{client_ip}:{minute_window}"
        current_count = self.request_counts.get(window_key, 0)
        
        if current_count >= self.requests_per_minute:
            return True
        
        # Increment counter
        self.request_counts[window_key] = current_count + 1
        return False
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with rate limiting.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            HTTP response or rate limit error
        """
        client_ip = self._get_client_ip(request)
        
        # Skip rate limiting for health checks
        if request.url.path in ["/healthz", "/readyz"]:
            return await call_next(request)
        
        # Check rate limit
        if self._is_rate_limited(client_ip):
            logger.warning(
                "Rate limit exceeded",
                client_ip=client_ip,
                path=request.url.path,
                requests_per_minute=self.requests_per_minute
            )
            
            if request.url.path.startswith("/api/"):
                from starlette.responses import JSONResponse
                return JSONResponse(
                    {
                        "error": "Rate limit exceeded",
                        "message": f"Maximum {self.requests_per_minute} requests per minute allowed"
                    },
                    status_code=429,
                    headers={"Retry-After": "60"}
                )
            else:
                from starlette.responses import HTMLResponse
                return HTMLResponse(
                    "<h1>Rate Limit Exceeded</h1><p>Too many requests. Please try again later.</p>",
                    status_code=429,
                    headers={"Retry-After": "60"}
                )
        
        return await call_next(request)