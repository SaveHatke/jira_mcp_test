"""
Configuration loader utility for initializing and managing configuration files.
Provides startup validation and error handling for configuration management.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, List, Tuple
import logging

from app.services.config_service import ConfigService
from app.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class ConfigurationLoader:
    """Utility for loading and validating configuration files at startup."""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_service: ConfigService = None
    
    def initialize_configuration(self) -> ConfigService:
        """
        Initialize configuration system with validation and error handling.
        
        Returns:
            ConfigService: Initialized configuration service
            
        Raises:
            ConfigurationError: If configuration initialization fails
        """
        print("[INFO] Initializing configuration system...")
        
        try:
            # Check if configuration directory exists
            if not self.config_dir.exists():
                print(f"[WARNING] Configuration directory not found: {self.config_dir}")
                self._create_default_configs()
            
            # Validate all configuration files exist
            missing_files = self._check_required_files()
            if missing_files:
                print(f"[ERROR] Missing configuration files: {', '.join(missing_files)}")
                raise ConfigurationError(f"Missing required configuration files: {missing_files}")
            
            # Initialize configuration service
            self.config_service = ConfigService(str(self.config_dir))
            
            # Validate all configurations
            validation_results = self.config_service.validate_all_configs()
            failed_validations = [name for name, result in validation_results.items() if not result]
            
            if failed_validations:
                print(f"[ERROR] Configuration validation failed for: {', '.join(failed_validations)}")
                raise ConfigurationError(f"Configuration validation failed: {failed_validations}")
            
            print("[SUCCESS] Configuration system initialized successfully")
            return self.config_service
            
        except Exception as e:
            print(f"[FAILED] Configuration initialization failed: {e}")
            raise ConfigurationError(f"Failed to initialize configuration: {e}")
    
    def _check_required_files(self) -> List[str]:
        """Check if all required configuration files exist."""
        required_files = [
            'config.json',
            'header.json',
            'payload.json',
            'prompts.json'
        ]
        
        missing_files = []
        for filename in required_files:
            file_path = self.config_dir / filename
            if not file_path.exists():
                missing_files.append(filename)
        
        return missing_files
    
    def _create_default_configs(self) -> None:
        """Create default configuration files if they don't exist."""
        print("[INFO] Creating default configuration files...")
        
        # Create configuration directory
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Create default configurations
        default_configs = self._get_default_configurations()
        
        for filename, config_data in default_configs.items():
            file_path = self.config_dir / filename
            if not file_path.exists():
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(config_data, f, indent=2)
                    print(f"[OK] Created default {filename}")
                except Exception as e:
                    print(f"[ERROR] Failed to create {filename}: {e}")
                    raise ConfigurationError(f"Failed to create default {filename}: {e}")
    
    def _get_default_configurations(self) -> Dict[str, Dict[str, Any]]:
        """Get default configuration data for all files."""
        return {
            'config.json': {
                "llm": {
                    "test_endpoint": {
                        "url": "https://company-llm.internal/api/v1/test",
                        "timeout": 10,
                        "retry_settings": {
                            "max_retries": 3,
                            "backoff_factor": 2,
                            "retry_delay": 1
                        }
                    },
                    "integration_endpoint": {
                        "url": "https://company-llm.internal/api/v1/chat/completions",
                        "timeout": 30,
                        "retry_settings": {
                            "max_retries": 5,
                            "backoff_factor": 2,
                            "retry_delay": 2
                        }
                    },
                    "parameters": {
                        "model": "company-gpt-4",
                        "temperature": 0.7,
                        "max_tokens": 4000,
                        "stream": True
                    },
                    "debug_logging": False,
                    "header_file": "config/header.json",
                    "payload_file": "config/payload.json",
                    "prompts_file": "config/prompts.json"
                },
                "cache": {
                    "tool_list_ttl": 21600,
                    "session_ttl": 1800
                },
                "background_jobs": {
                    "tool_refresh_interval": 21600,
                    "max_retries": 5,
                    "retry_backoff": 2
                }
            },
            'header.json': {
                "test_headers": {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "JiraIntelligenceAgent/1.0",
                    "X-API-Version": "v1"
                },
                "integration_headers": {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "JiraIntelligenceAgent/1.0",
                    "X-API-Version": "v1",
                    "X-Stream": "true"
                },
                "cookie_header_name": "X-Company-Auth",
                "authentication": {
                    "type": "cookie",
                    "cookie_field": "company_session",
                    "header_format": "Bearer {cookie_value}"
                }
            },
            'payload.json': {
                "test_payload": {
                    "method": "GET",
                    "endpoint": "/user/info",
                    "body": None,
                    "query_params": {
                        "format": "json"
                    }
                },
                "chat_completion": {
                    "method": "POST",
                    "endpoint": "/chat/completions",
                    "body": {
                        "model": "{model}",
                        "messages": [
                            {
                                "role": "system",
                                "content": "{system_prompt}"
                            },
                            {
                                "role": "user",
                                "content": "{user_prompt}"
                            }
                        ],
                        "temperature": "{temperature}",
                        "max_tokens": "{max_tokens}",
                        "stream": "{stream}"
                    }
                }
            },
            'prompts.json': {
                "system_instructions": {
                    "base": "You are an AI assistant specialized in creating well-structured Jira stories, tasks, and sub-tasks for enterprise development teams.",
                    "story_creation": "Create detailed Jira stories following the specified format with comprehensive acceptance criteria and proper story point estimation."
                },
                "system_prompts": {
                    "classic_story": "Create a Jira story using the Classic format with Summary, Description, Acceptance Criteria, Story Points, and STLC Notes.",
                    "bdd_story": "Create a Jira story using Behavior-Driven Development format with Given-When-Then scenarios.",
                    "test_connection": "You are testing the connection to the Company LLM service. Respond with your user information including username and userID for validation purposes."
                },
                "custom_prompts": {
                    "epic_breakdown": "Break down this epic into smaller, manageable stories that are independently deliverable.",
                    "technical_debt": "Create technical debt stories focusing on code quality, performance, or architectural improvements."
                }
            }
        }
    
    def validate_configuration_files(self) -> Tuple[bool, List[str]]:
        """
        Validate all configuration files without initializing the service.
        
        Returns:
            Tuple[bool, List[str]]: (success, list of error messages)
        """
        errors = []
        
        try:
            # Check if files exist
            missing_files = self._check_required_files()
            if missing_files:
                errors.append(f"Missing configuration files: {', '.join(missing_files)}")
                return False, errors
            
            # Validate JSON syntax
            for filename in ['config.json', 'header.json', 'payload.json', 'prompts.json']:
                file_path = self.config_dir / filename
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        json.load(f)
                except json.JSONDecodeError as e:
                    errors.append(f"Invalid JSON in {filename}: {e}")
                except Exception as e:
                    errors.append(f"Error reading {filename}: {e}")
            
            if errors:
                return False, errors
            
            return True, []
            
        except Exception as e:
            errors.append(f"Configuration validation failed: {e}")
            return False, errors
    
    def get_configuration_status(self) -> Dict[str, Any]:
        """
        Get detailed status of configuration system.
        
        Returns:
            Dict containing configuration status information
        """
        status = {
            'config_directory': str(self.config_dir),
            'directory_exists': self.config_dir.exists(),
            'required_files': {},
            'service_initialized': self.config_service is not None
        }
        
        # Check each required file
        required_files = ['config.json', 'header.json', 'payload.json', 'prompts.json']
        for filename in required_files:
            file_path = self.config_dir / filename
            file_status = {
                'exists': file_path.exists(),
                'size': file_path.stat().st_size if file_path.exists() else 0,
                'modified': file_path.stat().st_mtime if file_path.exists() else None
            }
            
            # Validate JSON syntax
            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        json.load(f)
                    file_status['valid_json'] = True
                except Exception as e:
                    file_status['valid_json'] = False
                    file_status['json_error'] = str(e)
            
            status['required_files'][filename] = file_status
        
        # Add service status if initialized
        if self.config_service:
            status['service_status'] = self.config_service.get_config_status()
        
        return status
    
    def reload_configuration(self) -> bool:
        """
        Reload configuration service.
        
        Returns:
            bool: True if reload successful, False otherwise
        """
        try:
            if self.config_service:
                self.config_service.stop_file_watcher()
            
            self.config_service = ConfigService(str(self.config_dir))
            print("[OK] Configuration reloaded successfully")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to reload configuration: {e}")
            return False


# Global configuration loader instance
config_loader = ConfigurationLoader()


def get_config_loader() -> ConfigurationLoader:
    """Get the global configuration loader instance."""
    return config_loader


def initialize_app_configuration() -> ConfigService:
    """Initialize application configuration at startup."""
    return config_loader.initialize_configuration()