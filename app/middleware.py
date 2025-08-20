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
        
        # Add security headers
        security_headers = {
            # Prevent clickjacking
            "X-Frame-Options": "DENY",
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            # Enable XSS protection
            "X-XSS-Protection": "1; mode=block",
            # Referrer policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            # Content Security Policy (basic)
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'"
            ),
        }
        
        # Add headers to response
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for JWT token authentication and session management.
    
    Validates JWT tokens, manages user sessions, and provides
    user context for authenticated requests.
    """
    
    # Paths that don't require authentication
    PUBLIC_PATHS = {
        "/",
        "/login",
        "/register",
        "/healthz",
        "/readyz",
        "/static",
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
        # Exact matches
        if path in self.PUBLIC_PATHS:
            return True
        
        # Prefix matches for static files
        if path.startswith("/static/"):
            return True
        
        return False
    
    async def _get_user_from_token(self, token: str) -> Optional[dict]:
        """
        Extract user information from JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            User information if token is valid, None otherwise
        """
        try:
            # Import here to avoid circular imports
            from app.services.auth_service import AuthService
            from app.database import get_session
            
            async with get_session() as session:
                auth_service = AuthService(session)
                user = await auth_service.validate_jwt_token(token)
                return user
        except Exception as e:
            logger.warning("Token validation failed", error=str(e))
            return None
    
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
        
        # No token found
        if not token:
            logger.info("No authentication token found", path=path)
            if request.url.path.startswith("/api/"):
                # Return 401 for API calls
                from starlette.responses import JSONResponse
                return JSONResponse(
                    {"error": "Authentication required"},
                    status_code=401
                )
            else:
                # Redirect to login for web interface
                return RedirectResponse(url="/login", status_code=302)
        
        # Validate token and get user
        user = await self._get_user_from_token(token)
        if not user:
            logger.warning("Invalid authentication token", path=path)
            if request.url.path.startswith("/api/"):
                from starlette.responses import JSONResponse
                return JSONResponse(
                    {"error": "Invalid or expired token"},
                    status_code=401
                )
            else:
                # Clear invalid cookie and redirect to login
                response = RedirectResponse(url="/login", status_code=302)
                response.delete_cookie("session_token")
                return response
        
        # Add user to request state
        request.state.user = user
        
        # Add user ID to logging context
        structlog.contextvars.bind_contextvars(user_id=user.get("id"))
        
        # Process request with authenticated user
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
        old_windows = [w for w in self.request_counts.keys() if w < minute_window - 5]
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