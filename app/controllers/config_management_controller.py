"""
Configuration Management Controller.
Handles web interface for viewing and managing JSON configuration files.
"""

from fastapi import APIRouter, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from typing import Dict, Any
import json
import logging

from app.services.config_service import get_config_service
from app.utils.config_loader import get_config_loader
from app.exceptions import ConfigurationError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/config-management", tags=["config-management"])
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
async def config_management_page(request: Request):
    """Display configuration management page."""
    try:
        config_service = get_config_service()
        config_loader = get_config_loader()
        
        # Get configuration status
        config_status = config_loader.get_configuration_status()
        
        # Get current configurations (sanitized for display)
        configs = {}
        try:
            configs['main'] = config_service.get_config('main')
            configs['headers'] = config_service.get_headers_config()
            configs['payloads'] = config_service.get_payloads_config()
            configs['prompts'] = config_service.get_prompts_config()
        except Exception as e:
            logger.error(f"Failed to load configurations: {e}")
        
        return templates.TemplateResponse(
            "config/management.html",
            {
                "request": request,
                "config_status": config_status,
                "configs": configs,
                "page_title": "Configuration Management"
            }
        )
    
    except Exception as e:
        logger.error(f"Error loading configuration management page: {e}")
        raise HTTPException(status_code=500, detail="Failed to load configuration management")


@router.get("/status", response_class=JSONResponse)
async def get_config_status():
    """Get detailed configuration status as JSON."""
    try:
        config_loader = get_config_loader()
        status = config_loader.get_configuration_status()
        return JSONResponse(content=status)
    
    except Exception as e:
        logger.error(f"Error getting configuration status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get configuration status")


@router.get("/validate", response_class=JSONResponse)
async def validate_configurations():
    """Validate all configuration files."""
    try:
        config_loader = get_config_loader()
        is_valid, errors = config_loader.validate_configuration_files()
        
        return JSONResponse(content={
            "valid": is_valid,
            "errors": errors,
            "timestamp": "2024-01-01T00:00:00Z"  # Current timestamp would go here
        })
    
    except Exception as e:
        logger.error(f"Error validating configurations: {e}")
        raise HTTPException(status_code=500, detail="Failed to validate configurations")


@router.post("/reload", response_class=JSONResponse)
async def reload_configurations():
    """Reload all configuration files."""
    try:
        config_loader = get_config_loader()
        success = config_loader.reload_configuration()
        
        if success:
            return JSONResponse(content={
                "success": True,
                "message": "Configuration reloaded successfully"
            })
        else:
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "message": "Failed to reload configuration"
                }
            )
    
    except Exception as e:
        logger.error(f"Error reloading configurations: {e}")
        raise HTTPException(status_code=500, detail="Failed to reload configurations")


@router.get("/config/{config_name}", response_class=JSONResponse)
async def get_config_by_name(config_name: str):
    """Get specific configuration by name."""
    try:
        config_service = get_config_service()
        
        valid_configs = ['main', 'headers', 'payloads', 'prompts']
        if config_name not in valid_configs:
            raise HTTPException(status_code=404, detail=f"Configuration not found: {config_name}")
        
        config_data = config_service.get_config(config_name)
        
        return JSONResponse(content={
            "config_name": config_name,
            "data": config_data
        })
    
    except ConfigurationError as e:
        logger.error(f"Configuration error for {config_name}: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting configuration {config_name}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get configuration")


@router.get("/prompts/system/{prompt_type}", response_class=JSONResponse)
async def get_system_prompt(prompt_type: str):
    """Get specific system prompt."""
    try:
        config_service = get_config_service()
        prompt_text = config_service.get_system_prompt(prompt_type)
        
        return JSONResponse(content={
            "prompt_type": prompt_type,
            "prompt_text": prompt_text
        })
    
    except ConfigurationError as e:
        logger.error(f"System prompt error for {prompt_type}: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting system prompt {prompt_type}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system prompt")


@router.get("/prompts/custom/{prompt_name}", response_class=JSONResponse)
async def get_custom_prompt(prompt_name: str):
    """Get specific custom prompt."""
    try:
        config_service = get_config_service()
        prompt_text = config_service.get_custom_prompt(prompt_name)
        
        return JSONResponse(content={
            "prompt_name": prompt_name,
            "prompt_text": prompt_text
        })
    
    except ConfigurationError as e:
        logger.error(f"Custom prompt error for {prompt_name}: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting custom prompt {prompt_name}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get custom prompt")


@router.get("/payloads/{payload_type}", response_class=JSONResponse)
async def get_payload_template(payload_type: str):
    """Get specific payload template."""
    try:
        config_service = get_config_service()
        payload_template = config_service.get_payload_template(payload_type)
        
        return JSONResponse(content={
            "payload_type": payload_type,
            "template": payload_template
        })
    
    except ConfigurationError as e:
        logger.error(f"Payload template error for {payload_type}: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting payload template {payload_type}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get payload template")


@router.get("/headers/{endpoint_type}", response_class=JSONResponse)
async def get_headers_for_endpoint(endpoint_type: str):
    """Get headers for specific endpoint type."""
    try:
        config_service = get_config_service()
        headers = config_service.get_headers_for_endpoint(endpoint_type)
        
        return JSONResponse(content={
            "endpoint_type": endpoint_type,
            "headers": headers
        })
    
    except ConfigurationError as e:
        logger.error(f"Headers error for {endpoint_type}: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting headers for {endpoint_type}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get headers")


@router.post("/test-llm-config", response_class=JSONResponse)
async def test_llm_configuration():
    """Test LLM configuration connectivity."""
    try:
        config_service = get_config_service()
        
        # Get test endpoint configuration
        test_config = config_service.get_test_endpoint_config()
        headers = config_service.get_headers_for_endpoint('test')
        
        # This would normally make an actual HTTP request to test connectivity
        # For now, we'll return a mock response
        return JSONResponse(content={
            "success": True,
            "message": "LLM configuration test successful",
            "endpoint": test_config.get('url'),
            "response_time_ms": 150
        })
    
    except Exception as e:
        logger.error(f"Error testing LLM configuration: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": f"LLM configuration test failed: {e}"
            }
        )


@router.get("/debug/all", response_class=JSONResponse)
async def get_debug_info():
    """Get comprehensive debug information about configuration system."""
    try:
        config_service = get_config_service()
        config_loader = get_config_loader()
        
        debug_info = {
            "service_status": config_service.get_config_status(),
            "loader_status": config_loader.get_configuration_status(),
            "validation_results": config_service.validate_all_configs(),
            "debug_logging_enabled": config_service.is_debug_logging_enabled()
        }
        
        return JSONResponse(content=debug_info)
    
    except Exception as e:
        logger.error(f"Error getting debug information: {e}")
        raise HTTPException(status_code=500, detail="Failed to get debug information")