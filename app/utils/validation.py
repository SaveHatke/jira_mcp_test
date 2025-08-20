"""
Configuration validation utilities.
Provides validation for JSON configuration files.
"""

from typing import Dict, Any, List
import re
from urllib.parse import urlparse

from app.exceptions import ConfigurationError


class ConfigValidator:
    """Validator for configuration files."""
    
    def __init__(self):
        self.validation_rules = {
            'main': self._validate_main_config,
            'headers': self._validate_headers_config,
            'payloads': self._validate_payloads_config,
            'prompts': self._validate_prompts_config
        }
    
    def validate_config(self, config_name: str, config_data: Dict[str, Any]) -> None:
        """Validate configuration data."""
        if config_name not in self.validation_rules:
            raise ConfigurationError(f"No validation rules for config: {config_name}")
        
        validator_func = self.validation_rules[config_name]
        validator_func(config_data)
    
    def _validate_main_config(self, config: Dict[str, Any]) -> None:
        """Validate main configuration file."""
        # Validate LLM configuration
        if 'llm' not in config:
            raise ConfigurationError("Missing 'llm' section in main config")
        
        llm_config = config['llm']
        
        # Validate endpoints
        self._validate_endpoint_config(llm_config, 'test_endpoint')
        self._validate_endpoint_config(llm_config, 'integration_endpoint')
        
        # Validate parameters
        if 'parameters' not in llm_config:
            raise ConfigurationError("Missing 'parameters' in LLM config")
        
        params = llm_config['parameters']
        required_params = ['model', 'temperature', 'max_tokens']
        for param in required_params:
            if param not in params:
                raise ConfigurationError(f"Missing required parameter: {param}")
        
        # Validate temperature range
        temp = params.get('temperature')
        if not isinstance(temp, (int, float)) or temp < 0 or temp > 2:
            raise ConfigurationError("Temperature must be between 0 and 2")
        
        # Validate max_tokens
        max_tokens = params.get('max_tokens')
        if not isinstance(max_tokens, int) or max_tokens <= 0:
            raise ConfigurationError("max_tokens must be a positive integer")
        
        # Validate file paths
        required_files = ['header_file', 'payload_file', 'prompts_file']
        for file_key in required_files:
            if file_key not in llm_config:
                raise ConfigurationError(f"Missing file path: {file_key}")
            
            file_path = llm_config[file_key]
            if not isinstance(file_path, str) or not file_path.endswith('.json'):
                raise ConfigurationError(f"Invalid file path for {file_key}: {file_path}")
        
        # Validate cache configuration
        if 'cache' in config:
            cache_config = config['cache']
            if 'tool_list_ttl' in cache_config:
                ttl = cache_config['tool_list_ttl']
                if not isinstance(ttl, int) or ttl <= 0:
                    raise ConfigurationError("tool_list_ttl must be a positive integer")
        
        # Validate background jobs configuration
        if 'background_jobs' in config:
            jobs_config = config['background_jobs']
            if 'max_retries' in jobs_config:
                retries = jobs_config['max_retries']
                if not isinstance(retries, int) or retries < 0:
                    raise ConfigurationError("max_retries must be a non-negative integer")
    
    def _validate_endpoint_config(self, llm_config: Dict[str, Any], endpoint_key: str) -> None:
        """Validate endpoint configuration."""
        if endpoint_key not in llm_config:
            raise ConfigurationError(f"Missing '{endpoint_key}' in LLM config")
        
        endpoint = llm_config[endpoint_key]
        
        # Validate URL
        if 'url' not in endpoint:
            raise ConfigurationError(f"Missing 'url' in {endpoint_key}")
        
        url = endpoint['url']
        if not self._is_valid_url(url):
            raise ConfigurationError(f"Invalid URL in {endpoint_key}: {url}")
        
        # Validate timeout
        if 'timeout' not in endpoint:
            raise ConfigurationError(f"Missing 'timeout' in {endpoint_key}")
        
        timeout = endpoint['timeout']
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ConfigurationError(f"Invalid timeout in {endpoint_key}: {timeout}")
        
        # Validate retry settings
        if 'retry_settings' in endpoint:
            retry_settings = endpoint['retry_settings']
            self._validate_retry_settings(retry_settings, endpoint_key)
    
    def _validate_retry_settings(self, retry_settings: Dict[str, Any], context: str) -> None:
        """Validate retry settings."""
        required_fields = ['max_retries', 'backoff_factor', 'retry_delay']
        
        for field in required_fields:
            if field not in retry_settings:
                raise ConfigurationError(f"Missing '{field}' in retry_settings for {context}")
            
            value = retry_settings[field]
            if not isinstance(value, (int, float)) or value < 0:
                raise ConfigurationError(f"Invalid {field} in retry_settings for {context}: {value}")
    
    def _validate_headers_config(self, config: Dict[str, Any]) -> None:
        """Validate headers configuration file."""
        required_sections = ['test_headers', 'integration_headers', 'authentication']
        
        for section in required_sections:
            if section not in config:
                raise ConfigurationError(f"Missing '{section}' in headers config")
        
        # Validate header sections contain valid HTTP headers
        for header_section in ['test_headers', 'integration_headers']:
            headers = config[header_section]
            if not isinstance(headers, dict):
                raise ConfigurationError(f"{header_section} must be a dictionary")
            
            for header_name, header_value in headers.items():
                if not isinstance(header_name, str) or not isinstance(header_value, str):
                    raise ConfigurationError(f"Invalid header in {header_section}: {header_name}")
        
        # Validate authentication configuration
        auth_config = config['authentication']
        required_auth_fields = ['type', 'cookie_field', 'header_format']
        
        for field in required_auth_fields:
            if field not in auth_config:
                raise ConfigurationError(f"Missing '{field}' in authentication config")
        
        # Validate authentication type
        auth_type = auth_config['type']
        if auth_type not in ['cookie', 'bearer', 'basic']:
            raise ConfigurationError(f"Invalid authentication type: {auth_type}")
        
        # Validate header format contains placeholder
        header_format = auth_config['header_format']
        if '{cookie_value}' not in header_format:
            raise ConfigurationError("header_format must contain {cookie_value} placeholder")
    
    def _validate_payloads_config(self, config: Dict[str, Any]) -> None:
        """Validate payloads configuration file."""
        required_payloads = ['test_payload', 'chat_completion', 'story_generation']
        
        for payload_name in required_payloads:
            if payload_name not in config:
                raise ConfigurationError(f"Missing payload template: {payload_name}")
            
            payload = config[payload_name]
            self._validate_payload_template(payload, payload_name)
    
    def _validate_payload_template(self, payload: Dict[str, Any], name: str) -> None:
        """Validate individual payload template."""
        required_fields = ['method', 'endpoint']
        
        for field in required_fields:
            if field not in payload:
                raise ConfigurationError(f"Missing '{field}' in payload template: {name}")
        
        # Validate HTTP method
        method = payload['method']
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        if method not in valid_methods:
            raise ConfigurationError(f"Invalid HTTP method in {name}: {method}")
        
        # Validate endpoint
        endpoint = payload['endpoint']
        if not isinstance(endpoint, str) or not endpoint.startswith('/'):
            raise ConfigurationError(f"Invalid endpoint in {name}: {endpoint}")
        
        # Validate body structure for POST requests
        if method in ['POST', 'PUT', 'PATCH'] and 'body' in payload:
            body = payload['body']
            if body is not None and not isinstance(body, dict):
                raise ConfigurationError(f"Invalid body structure in {name}")
    
    def _validate_prompts_config(self, config: Dict[str, Any]) -> None:
        """Validate prompts configuration file."""
        required_sections = ['system_instructions', 'system_prompts']
        
        for section in required_sections:
            if section not in config:
                raise ConfigurationError(f"Missing '{section}' in prompts config")
            
            section_data = config[section]
            if not isinstance(section_data, dict):
                raise ConfigurationError(f"{section} must be a dictionary")
            
            # Validate all prompts are non-empty strings
            for prompt_name, prompt_text in section_data.items():
                if not isinstance(prompt_text, str) or not prompt_text.strip():
                    raise ConfigurationError(f"Invalid prompt in {section}: {prompt_name}")
        
        # Validate required system prompts
        system_prompts = config['system_prompts']
        required_prompts = ['classic_story', 'bdd_story', 'test_connection']
        
        for prompt_name in required_prompts:
            if prompt_name not in system_prompts:
                raise ConfigurationError(f"Missing required system prompt: {prompt_name}")
        
        # Validate optional sections
        optional_sections = ['custom_prompts', 'validation_prompts']
        for section in optional_sections:
            if section in config:
                section_data = config[section]
                if not isinstance(section_data, dict):
                    raise ConfigurationError(f"{section} must be a dictionary")
                
                for prompt_name, prompt_text in section_data.items():
                    if not isinstance(prompt_text, str) or not prompt_text.strip():
                        raise ConfigurationError(f"Invalid prompt in {section}: {prompt_name}")
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def validate_json_structure(self, json_data: Any) -> List[str]:
        """Validate basic JSON structure and return any issues."""
        issues = []
        
        if not isinstance(json_data, dict):
            issues.append("Root element must be a JSON object")
            return issues
        
        # Check for empty configuration
        if not json_data:
            issues.append("Configuration cannot be empty")
        
        # Check for null values in critical paths
        def check_null_values(obj: Any, path: str = "") -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    if value is None and key in ['url', 'endpoint', 'method']:
                        issues.append(f"Critical field cannot be null: {current_path}")
                    elif isinstance(value, (dict, list)):
                        check_null_values(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]"
                    check_null_values(item, current_path)
        
        check_null_values(json_data)
        
        return issues