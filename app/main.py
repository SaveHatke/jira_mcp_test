"""FastAPI application entry point with health endpoints."""

from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
import structlog
import uuid
import sys
from contextlib import asynccontextmanager

from app.config import settings
from app.utils.logging import configure_logging, get_logger
from app.utils.config_loader import initialize_app_configuration
from app.services.config_service import get_config_service
from app.controllers.config_management_controller import router as config_management_router

# Try to import database functionality - fallback if compatibility issues
try:
    from app.database import db_manager
    DATABASE_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] Database functionality not available: {e}")
    print("[INFO] Running in compatibility mode without database features")
    DATABASE_AVAILABLE = False
    db_manager = None


# Setup comprehensive logging that captures ALL terminal output
from app.utils.logging import setup_comprehensive_logging
setup_comprehensive_logging(
    level=settings.log_level,
    log_file=settings.log_file
)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events with comprehensive error handling."""
    startup_success = False
    
    try:
        # Startup
        print("[STARTING] Jira Intelligence Agent startup sequence")
        logger.info("Starting Jira Intelligence Agent", version="1.0.0")
        
        # Initialize configuration system first
        try:
            print("[INFO] Initializing configuration system...")
            initialize_app_configuration()
            print("[OK] Configuration system initialized")
            logger.info("Configuration system initialized successfully")
        except Exception as e:
            print(f"[ERROR] Failed to initialize configuration system: {e}")
            logger.error("Failed to initialize configuration system", error=str(e))
            import traceback
            traceback.print_exc()
            raise
        
        if DATABASE_AVAILABLE and db_manager:
            try:
                print("[INFO] Initializing database...")
                await db_manager.initialize()
                print("[OK] Database initialized")
                logger.info("Database initialized successfully")
            except Exception as e:
                print(f"[ERROR] Database initialization failed: {e}")
                logger.error("Database initialization failed", error=str(e))
                import traceback
                traceback.print_exc()
                raise
        else:
            print("[WARNING] Database not available - running in compatibility mode")
            logger.warning("Database not available - running in compatibility mode")
        
        print("[SUCCESS] Application startup completed successfully")
        startup_success = True
        
        yield
        
    except Exception as e:
        print(f"[CRITICAL] Application startup failed: {e}")
        logger.critical("Application startup failed", error=str(e))
        import traceback
        traceback.print_exc()
        
        if not startup_success:
            print("[FAILED] Exiting due to startup failure")
            sys.exit(1)
        raise
    
    finally:
        # Shutdown
        try:
            print("[INFO] Starting application shutdown...")
            logger.info("Shutting down Jira Intelligence Agent")
            
            if DATABASE_AVAILABLE and db_manager:
                try:
                    await db_manager.shutdown()
                    print("[OK] Database shutdown completed")
                    logger.info("Database shutdown completed")
                except Exception as e:
                    print(f"[ERROR] Database shutdown failed: {e}")
                    logger.error("Database shutdown failed", error=str(e))
            
            print("[COMPLETED] Application shutdown completed")
            
        except Exception as e:
            print(f"[ERROR] Error during shutdown: {e}")
            logger.error("Error during shutdown", error=str(e))


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="Jira Intelligence Agent (JIA) - Enterprise-ready multi-user web application for AI-powered Jira story generation",
    version="1.0.0",
    debug=settings.debug,
    lifespan=lifespan
)

# Configure CORS (disabled by default for server-rendered app)
# CORS is disabled for security as this is a server-rendered application
# Only enable minimal CORS in development for debugging tools
if settings.debug:
    # Very restrictive CORS even in development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
        allow_credentials=False,  # Disabled for security
        allow_methods=["GET"],  # Only GET requests
        allow_headers=["Content-Type", "X-Request-ID"],
    )
else:
    # Production: CORS completely disabled for security
    # Server-rendered applications don't need CORS
    pass

# Add custom middleware for authentication and security
from app.middleware import (
    RequestCorrelationMiddleware,
    SecurityHeadersMiddleware,
    AuthenticationMiddleware,
    CSRFProtectionMiddleware,
    ErrorHandlingMiddleware,
    RateLimitingMiddleware
)

# Add middleware in reverse order (last added = first executed)
app.add_middleware(ErrorHandlingMiddleware)
app.add_middleware(RateLimitingMiddleware, requests_per_minute=120)  # Allow more requests for development
app.add_middleware(CSRFProtectionMiddleware)
app.add_middleware(AuthenticationMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestCorrelationMiddleware)

# Include routers
app.include_router(config_management_router)

# Import and include authentication router
from app.controllers.auth_controller import router as auth_router
app.include_router(auth_router)

# Import and include dashboard router
from app.controllers.dashboard_controller import router as dashboard_router
app.include_router(dashboard_router)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup Jinja2 templates with auto-escaping enabled for XSS prevention
templates = Jinja2Templates(directory="templates")

# Configure Jinja2 environment for security
templates.env.autoescape = True  # Enable auto-escaping for XSS prevention
templates.env.trim_blocks = True
templates.env.lstrip_blocks = True

# Add security-related template globals
def csrf_token():
    """Template function to generate CSRF tokens."""
    from app.utils.csrf import generate_csrf_token
    return generate_csrf_token()

def is_development():
    """Template function to check if in development mode."""
    return settings.debug

templates.env.globals['csrf_token'] = csrf_token
templates.env.globals['is_development'] = is_development


@app.middleware("http")
async def add_request_id_middleware(request: Request, call_next):
    """Add X-Request-ID to all requests for tracing."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    
    # Add request ID to structured logging context
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(x_request_id=request_id)
    
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.get("/healthz")
async def health_check():
    """Liveness probe endpoint."""
    return {"status": "healthy", "service": settings.app_name}


@app.get("/readyz")
async def readiness_check():
    """Readiness probe endpoint."""
    try:
        # Check configuration system
        try:
            config_service = get_config_service()
            validation_results = config_service.validate_all_configs()
            failed_validations = [name for name, result in validation_results.items() if not result]
            config_ready = len(failed_validations) == 0
            config_status = "ready" if config_ready else f"validation_failed: {failed_validations}"
        except Exception:
            config_ready = False
            config_status = "not_available"
        
        if DATABASE_AVAILABLE and db_manager:
            # Check database health
            db_health = await db_manager.health_check()
            
            is_ready = (
                db_health.get("initialized", False) and
                db_health.get("connectivity", False) and
                config_ready
            )
            
            return {
                "status": "ready" if is_ready else "not_ready",
                "service": settings.app_name,
                "database": db_health,
                "configuration": config_status
            }
        else:
            # No database - basic readiness
            return {
                "status": "ready" if config_ready else "not_ready",
                "service": settings.app_name,
                "database": "not_available_compatibility_mode",
                "configuration": config_status,
                "note": "Running without database due to compatibility issues"
            }
    
    except Exception as e:
        logger.error("Readiness check failed", error=str(e))
        return {
            "status": "not_ready",
            "service": settings.app_name,
            "error": str(e)
        }


@app.get("/config-status")
async def configuration_status():
    """Get current configuration system status."""
    try:
        config_service = get_config_service()
        status = config_service.get_config_status()
        return JSONResponse(content=status)
        
    except Exception as e:
        logger.error("Error getting configuration status", error=str(e))
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get configuration status: {e}"}
        )


@app.get("/")
async def root(request: Request):
    """Root endpoint - redirect to login/dashboard based on auth."""
    from app.controllers.auth_controller import get_current_user
    
    # Check if user is authenticated
    user = await get_current_user(request)
    if user:
        # Redirect to dashboard if authenticated
        return RedirectResponse(url="/dashboard", status_code=302)
    else:
        # Redirect to login if not authenticated
        return RedirectResponse(url="/auth/login", status_code=302)


if __name__ == "__main__":
    import uvicorn
    from app.utils.logging import get_uvicorn_log_config
    
    print("[STARTING] Uvicorn server with comprehensive logging")
    
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
        log_config=get_uvicorn_log_config(settings.log_file),
        access_log=True
    )