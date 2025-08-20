"""FastAPI application entry point with health endpoints."""

from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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


# Setup structured logging
configure_logging(
    level=settings.log_level,
    json_logs=settings.json_logs
)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("Starting Jira Intelligence Agent", version="1.0.0")
    
    # Initialize configuration system first
    try:
        initialize_app_configuration()
        logger.info("Configuration system initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize configuration system", error=str(e))
        sys.exit(1)
    
    if DATABASE_AVAILABLE and db_manager:
        try:
            await db_manager.initialize()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error("Database initialization failed", error=str(e))
    else:
        logger.warning("Database not available - running in compatibility mode")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Jira Intelligence Agent")
    if DATABASE_AVAILABLE and db_manager:
        try:
            await db_manager.shutdown()
            logger.info("Database shutdown completed")
        except Exception as e:
            logger.error("Database shutdown failed", error=str(e))


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="Jira Intelligence Agent (JIA) - Enterprise-ready multi-user web application for AI-powered Jira story generation",
    version="1.0.0",
    debug=settings.debug,
    lifespan=lifespan
)

# Configure CORS (disabled by default for server-rendered app)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],  # Disabled by default
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Include routers
app.include_router(config_management_router)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup Jinja2 templates
templates = Jinja2Templates(directory="templates")


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
async def root():
    """Root endpoint - will redirect to login/dashboard based on auth."""
    return {"message": "Jira Intelligence Agent", "status": "running"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )