"""FastAPI application entry point with health endpoints."""

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import structlog
import uuid
from contextlib import asynccontextmanager

from app.config import settings
from app.database import create_tables
from app.utils.logging import setup_logging


# Setup structured logging
setup_logging()
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("Starting Jira Intelligence Agent", version="1.0.0")
    create_tables()
    logger.info("Database tables created/verified")
    yield
    # Shutdown
    logger.info("Shutting down Jira Intelligence Agent")


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
    # TODO: Add database connectivity check
    # TODO: Add configuration file validation
    return {
        "status": "ready",
        "service": settings.app_name,
        "database": "connected",
        "configuration": "loaded"
    }


@app.get("/")
async def root():
    """Root endpoint - will redirect to login/dashboard based on auth."""
    return {"message": "Jira Intelligence Agent", "status": "running"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )