"""
Configuration Service for managing JSON configuration files.
Handles loading, validation, and runtime updates of configuration files.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from app.utils.validation import ConfigValidator
from app.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class ConfigFileHandler(FileSystemEventHandler):
    """File system event handler for configuration file changes."""
    
    def __init__(self, config_service: 'ConfigService'):
        self.config_service = config_service
    
    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory and event.src_path.endswith('.json'):
            logger.info(f"Configuration file modified: {event.src_path}")
            self.config_service.reload_config_file(event.src_path)


class ConfigService:
    """Service for managing JSON configuration files."""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.configs: Dict[str, Dict[str, Any]] = {}
        self.file_timestamps: Dict[str, datetime] = {}
        self.validator = ConfigValidator()
        self.observer: Optional[Observer] = None
        
        # Configuration file mappings
        self.config_files = {
            'main': 'config.json',
            'headers': 'header.json',
            'payloads': 'payload.json',
            'prompts': 'prompts.json'
        }
        
        self._ensure_config_directory()
        self._load_all_configs()
        self._start_file_watcher()
    
    def _ensure_config_directory(self) -> None:
        """Ensure configuration directory exists."""
        if not self.config_dir.exists():
            self.config_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created configuration directory: {self.config_dir}")
    
    def _load_all_configs(self) -> None:
        """Load all configuration files."""
        print("[INFO] Loading configuration files...")
        
        for config_name, filename in self.config_files.items():
            try:
                self._load_config_file(config_name, filename)
                print(f"[OK] Loaded {filename}")
            except Exception as e:
                print(f"[ERROR] Failed to load {filename}: {e}")
                raise ConfigurationError(f"Failed to load {filename}: {e}")
        
        print("[SUCCESS] All configuration files loaded")
    
    def _load_config_file(self, config_name: str, filename: str) -> None:
        """Load a single configuration file."""
        file_path = self.config_dir / filename
        
        if not file_path.exists():
            raise ConfigurationError(f"Configuration file not found: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Validate configuration
            self.validator.validate_config(config_name, config_data)
            
            # Store configuration and timestamp
            self.configs[config_name] = config_data
            self.file_timestamps[config_name] = datetime.fromtimestamp(file_path.stat().st_mtime)
            
            logger.info(f"Loaded configuration: {config_name} from {filename}")
            
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in {filename}: {e}")
        except Exception as e:
            raise ConfigurationError(f"Error loading {filename}: {e}")
    
    def _start_file_watcher(self) -> None:
        """Start file system watcher for configuration changes."""
        try:
            self.observer = Observer()
            event_handler = ConfigFileHandler(self)
            self.observer.schedule(event_handler, str(self.config_dir), recursive=False)
            self.observer.start()
            logger.info("Configuration file watcher started")
        except Exception as e:
            logger.warning(f"Failed to start file watcher: {e}")
    
    def reload_config_file(self, file_path: str) -> None:
        """Reload a specific configuration file."""
        try:
            file_path_obj = Path(file_path)
            filename = file_path_obj.name
            
            # Find config name by filename
            config_name = None
            for name, fname in self.config_files.items():
                if fname == filename:
                    config_name = name
                    break
            
            if config_name:
                self._load_config_file(config_name, filename)
                logger.info(f"Reloaded configuration: {config_name}")
            else:
                logger.warning(f"Unknown configuration file: {filename}")
                
        except Exception as e:
            logger.error(f"Failed to reload configuration file {file_path}: {e}")
    
    def get_config(self, config_name: str) -> Dict[str, Any]:
        """Get configuration by name."""
        if config_name not in self.configs:
            raise ConfigurationError(f"Configuration not found: {config_name}")
        return self.configs[config_name].copy()
    
    def get_llm_config(self) -> Dict[str, Any]:
        """Get LLM configuration."""
        return self.get_config('main').get('llm', {})
    
    def get_headers_config(self) -> Dict[str, Any]:
        """Get headers configuration."""
        return self.get_config('headers')
    
    def get_payloads_config(self) -> Dict[str, Any]:
        """Get payloads configuration."""
        return self.get_config('payloads')
    
    def get_prompts_config(self) -> Dict[str, Any]:
        """Get prompts configuration."""
        return self.get_config('prompts')
    
    def get_test_endpoint_config(self) -> Dict[str, Any]:
        """Get test endpoint configuration."""
        llm_config = self.get_llm_config()
        return llm_config.get('test_endpoint', {})
    
    def get_integration_endpoint_config(self) -> Dict[str, Any]:
        """Get integration endpoint configuration."""
        llm_config = self.get_llm_config()
        return llm_config.get('integration_endpoint', {})
    
    def get_llm_parameters(self) -> Dict[str, Any]:
        """Get LLM parameters."""
        llm_config = self.get_llm_config()
        return llm_config.get('parameters', {})
    
    def get_retry_settings(self, endpoint_type: str = 'integration') -> Dict[str, Any]:
        """Get retry settings for specified endpoint type."""
        llm_config = self.get_llm_config()
        endpoint_config = llm_config.get(f'{endpoint_type}_endpoint', {})
        return endpoint_config.get('retry_settings', {})
    
    def get_system_prompt(self, prompt_type: str) -> str:
        """Get system prompt by type."""
        prompts = self.get_prompts_config()
        system_prompts = prompts.get('system_prompts', {})
        
        if prompt_type not in system_prompts:
            raise ConfigurationError(f"System prompt not found: {prompt_type}")
        
        return system_prompts[prompt_type]
    
    def get_custom_prompt(self, prompt_name: str) -> str:
        """Get custom prompt by name."""
        prompts = self.get_prompts_config()
        custom_prompts = prompts.get('custom_prompts', {})
        
        if prompt_name not in custom_prompts:
            raise ConfigurationError(f"Custom prompt not found: {prompt_name}")
        
        return custom_prompts[prompt_name]
    
    def get_payload_template(self, payload_type: str) -> Dict[str, Any]:
        """Get payload template by type."""
        payloads = self.get_payloads_config()
        
        if payload_type not in payloads:
            raise ConfigurationError(f"Payload template not found: {payload_type}")
        
        return payloads[payload_type].copy()
    
    def get_headers_for_endpoint(self, endpoint_type: str) -> Dict[str, str]:
        """Get headers for specified endpoint type."""
        headers_config = self.get_headers_config()
        
        if endpoint_type == 'test':
            return headers_config.get('test_headers', {}).copy()
        elif endpoint_type == 'integration':
            return headers_config.get('integration_headers', {}).copy()
        else:
            raise ConfigurationError(f"Unknown endpoint type: {endpoint_type}")
    
    def get_authentication_config(self) -> Dict[str, Any]:
        """Get authentication configuration."""
        headers_config = self.get_headers_config()
        return headers_config.get('authentication', {})
    
    def format_authentication_header(self, cookie_value: str) -> Dict[str, str]:
        """Format authentication header with cookie value."""
        auth_config = self.get_authentication_config()
        headers_config = self.get_headers_config()
        
        cookie_header_name = headers_config.get('cookie_header_name', 'X-Company-Auth')
        header_format = auth_config.get('header_format', 'Bearer {cookie_value}')
        
        formatted_value = header_format.format(cookie_value=cookie_value)
        
        return {cookie_header_name: formatted_value}
    
    def is_debug_logging_enabled(self) -> bool:
        """Check if debug logging is enabled."""
        llm_config = self.get_llm_config()
        return llm_config.get('debug_logging', False)
    
    def get_cache_config(self) -> Dict[str, Any]:
        """Get cache configuration."""
        main_config = self.get_config('main')
        return main_config.get('cache', {})
    
    def get_background_jobs_config(self) -> Dict[str, Any]:
        """Get background jobs configuration."""
        main_config = self.get_config('main')
        return main_config.get('background_jobs', {})
    
    def validate_all_configs(self) -> Dict[str, bool]:
        """Validate all loaded configurations."""
        validation_results = {}
        
        for config_name in self.configs:
            try:
                self.validator.validate_config(config_name, self.configs[config_name])
                validation_results[config_name] = True
            except Exception as e:
                validation_results[config_name] = False
                logger.error(f"Validation failed for {config_name}: {e}")
        
        return validation_results
    
    def get_config_status(self) -> Dict[str, Any]:
        """Get status of all configuration files."""
        status = {
            'loaded_configs': list(self.configs.keys()),
            'file_timestamps': {name: ts.isoformat() for name, ts in self.file_timestamps.items()},
            'validation_results': self.validate_all_configs(),
            'watcher_active': self.observer is not None and self.observer.is_alive()
        }
        
        return status
    
    def stop_file_watcher(self) -> None:
        """Stop the file system watcher."""
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            logger.info("Configuration file watcher stopped")


# Global configuration service instance
config_service = ConfigService()


def get_config_service() -> ConfigService:
    """Get the global configuration service instance."""
    return config_service