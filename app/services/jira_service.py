"""
Jira REST API client for user validation and integration.

This module provides a client for interacting with Jira REST API,
specifically for validating PAT tokens and extracting user information.
"""

import httpx
from typing import Optional, Dict, Any
from urllib.parse import urlparse, urljoin
import structlog

from app.config import settings
from app.exceptions import ExternalServiceError, ValidationError
from app.schemas.auth_schemas import JiraUserResponse, JiraValidationResult
from app.utils.retry import with_external_service_retry

logger = structlog.get_logger(__name__)


class JiraAPIClient:
    """
    Client for Jira REST API operations.
    
    Provides methods for validating PAT tokens, extracting user information,
    and performing other Jira-related operations with proper error handling
    and retry logic.
    """
    
    def __init__(self, timeout: int = None) -> None:
        """
        Initialize Jira API client.
        
        Args:
            timeout: Request timeout in seconds (uses config default if not provided)
        """
        self.timeout = timeout or settings.jira_timeout_seconds
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = httpx.AsyncClient(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.aclose()
    
    def _extract_jira_base_url(self, self_url: str) -> str:
        """
        Extract Jira base URL from the self field.
        
        Args:
            self_url: Self URL from Jira API response
            
        Returns:
            Base Jira URL (domain only)
            
        Raises:
            ValidationError: If URL parsing fails
        """
        try:
            parsed = urlparse(self_url)
            if not parsed.scheme or not parsed.netloc:
                raise ValidationError(
                    "Invalid self URL format",
                    field_name="self_url",
                    validation_rule="url_format"
                )
            
            # Extract base URL (scheme + netloc)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            logger.debug("Extracted Jira base URL", 
                        self_url=self_url, 
                        base_url=base_url)
            
            return base_url
            
        except Exception as e:
            logger.error("Failed to extract Jira base URL", 
                        self_url=self_url, 
                        error=str(e))
            raise ValidationError(
                f"Failed to parse Jira URL: {e}",
                field_name="self_url",
                validation_rule="url_parsing",
                details={"self_url": self_url, "error": str(e)}
            ) from e
    
    def _validate_jira_user_data(self, user_data: Dict[str, Any]) -> None:
        """
        Validate Jira user data meets requirements.
        
        Args:
            user_data: User data from Jira API
            
        Raises:
            ValidationError: If user data is invalid
        """
        # Check if user is active
        if not user_data.get('active', False):
            raise ValidationError(
                "User account is not active in Jira",
                field_name="active",
                validation_rule="user_active",
                error_code="USER_NOT_ACTIVE"
            )
        
        # Check if user is deleted
        if user_data.get('deleted', False):
            raise ValidationError(
                "User account is deleted in Jira",
                field_name="deleted",
                validation_rule="user_not_deleted",
                error_code="USER_DELETED"
            )
        
        # Validate required fields
        required_fields = ['name', 'emailAddress', 'displayName', 'self']  # Use emailAddress from Jira API
        missing_fields = []
        
        for field in required_fields:
            if not user_data.get(field):
                missing_fields.append(field)
        
        if missing_fields:
            raise ValidationError(
                f"Missing required user fields: {', '.join(missing_fields)}",
                validation_rule="required_fields",
                error_code="MISSING_USER_FIELDS",
                details={"missing_fields": missing_fields}
            )
    
    @with_external_service_retry(service_name="jira", max_attempts=3, base_delay=1.0)
    async def validate_pat_and_get_user(self, pat: str, jira_url: Optional[str] = None) -> JiraValidationResult:
        """
        Validate Jira PAT and extract user information.
        
        Args:
            pat: Jira Personal Access Token
            jira_url: Optional Jira base URL (will be extracted from response if not provided)
            
        Returns:
            JiraValidationResult with validation status and user data
            
        Raises:
            ExternalServiceError: If Jira API call fails
            ValidationError: If user data is invalid
        """
        if not self.session:
            raise ExternalServiceError(
                "Jira client session not initialized",
                service_name="jira",
                error_code="SESSION_NOT_INITIALIZED"
            )
        
        try:
            # If jira_url is provided, use it; otherwise try to determine from PAT
            if jira_url:
                api_url = urljoin(jira_url.rstrip('/'), '/rest/api/2/myself')
            else:
                # For now, we'll require the user to provide the Jira URL
                # In a real implementation, we might try to detect it from the PAT format
                # or use common patterns, but for security and reliability, explicit URL is better
                raise ValidationError(
                    "Jira URL is required for PAT validation. Please provide your Jira base URL (e.g., https://your-company.atlassian.net)",
                    field_name="jira_url",
                    validation_rule="required",
                    error_code="JIRA_URL_REQUIRED"
                )
            
            # Prepare headers with PAT authentication
            headers = {
                'Authorization': f'Bearer {pat}',
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            logger.info("Validating Jira PAT", 
                       api_url=api_url,
                       pat_length=len(pat))
            
            # Make API call to /myself endpoint
            response = await self.session.get(api_url, headers=headers)
            
            # Handle different response status codes
            if response.status_code == 401:
                logger.warning("Jira PAT authentication failed", 
                              status_code=response.status_code)
                return JiraValidationResult(
                    valid=False,
                    error_message="Invalid Jira Personal Access Token",
                    error_code="INVALID_PAT"
                )
            
            elif response.status_code == 403:
                logger.warning("Jira PAT access forbidden", 
                              status_code=response.status_code)
                return JiraValidationResult(
                    valid=False,
                    error_message="Jira PAT does not have required permissions",
                    error_code="INSUFFICIENT_PERMISSIONS"
                )
            
            elif response.status_code != 200:
                logger.error("Jira API call failed", 
                            status_code=response.status_code,
                            response_text=response.text)
                raise ExternalServiceError(
                    f"Jira API returned status {response.status_code}",
                    service_name="jira",
                    status_code=response.status_code,
                    error_code="API_ERROR",
                    details={"response": response.text}
                )
            
            # Parse response JSON
            try:
                user_data = response.json()
            except Exception as e:
                logger.error("Failed to parse Jira API response", 
                            error=str(e),
                            response_text=response.text)
                raise ExternalServiceError(
                    "Invalid JSON response from Jira API",
                    service_name="jira",
                    error_code="INVALID_JSON_RESPONSE",
                    details={"error": str(e)}
                ) from e
            
            # Validate response structure
            try:
                jira_user = JiraUserResponse(**user_data)
            except Exception as e:
                logger.error("Invalid Jira user response structure", 
                            error=str(e),
                            user_data=user_data)
                raise ValidationError(
                    f"Invalid Jira user data structure: {e}",
                    validation_rule="response_structure",
                    error_code="INVALID_USER_DATA_STRUCTURE",
                    details={"error": str(e), "user_data": user_data}
                ) from e
            
            # Validate user meets requirements
            self._validate_jira_user_data(user_data)
            
            # Extract Jira base URL from self field
            extracted_jira_url = self._extract_jira_base_url(jira_user.self)
            
            # Prepare user data for response
            processed_user_data = {
                'employee_id': jira_user.name,
                'name': jira_user.name,
                'email': jira_user.emailAddress,  # Use emailAddress from Jira API
                'display_name': jira_user.displayName,
                'active': jira_user.active,
                'deleted': jira_user.deleted,
                'avatar_url': jira_user.avatarUrls.get('48x48'),
                'self_url': jira_user.self
            }
            
            logger.info("Jira PAT validation successful", 
                       employee_id=jira_user.name,
                       email=jira_user.emailAddress,
                       jira_url=extracted_jira_url)
            
            return JiraValidationResult(
                valid=True,
                user_data=processed_user_data,
                jira_url=extracted_jira_url
            )
            
        except (ValidationError, ExternalServiceError):
            # Re-raise our custom exceptions
            raise
        except Exception as e:
            logger.error("Unexpected error during Jira PAT validation", 
                        error=str(e))
            raise ExternalServiceError(
                f"Unexpected error validating Jira PAT: {e}",
                service_name="jira",
                error_code="UNEXPECTED_ERROR",
                details={"error": str(e)}
            ) from e
    
    async def test_connection(self, pat: str, jira_url: str) -> bool:
        """
        Test Jira connection with PAT.
        
        Args:
            pat: Jira Personal Access Token
            jira_url: Jira base URL
            
        Returns:
            True if connection is successful, False otherwise
        """
        try:
            result = await self.validate_pat_and_get_user(pat, jira_url)
            return result.valid
        except Exception as e:
            logger.error("Jira connection test failed", 
                        jira_url=jira_url,
                        error=str(e))
            return False


# Convenience function for one-off PAT validation
async def validate_jira_pat(pat: str, jira_url: str) -> JiraValidationResult:
    """
    Validate Jira PAT and get user information.
    
    Args:
        pat: Jira Personal Access Token
        jira_url: Jira base URL
        
    Returns:
        JiraValidationResult with validation status and user data
    """
    async with JiraAPIClient() as client:
        return await client.validate_pat_and_get_user(pat, jira_url)