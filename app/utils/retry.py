"""
Retry mechanisms with exponential backoff and circuit breaker patterns.

This module implements enterprise-grade retry and circuit breaker patterns
for handling transient failures and preventing cascading failures.
"""

import asyncio
import time
from typing import Any, Callable, Optional, Dict, List, Type, Union
from functools import wraps
from enum import Enum
import random

from app.exceptions import ExternalServiceError, RateLimitError, CircuitBreakerError
from app.utils.logging import get_logger

logger = get_logger(__name__)


class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Blocking requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class RetryStrategy:
    """
    Configuration for retry behavior.
    
    Implements exponential backoff with jitter to prevent thundering herd.
    """
    
    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
        retryable_exceptions: Optional[List[Type[Exception]]] = None
    ) -> None:
        """
        Initialize retry strategy.
        
        Args:
            max_attempts: Maximum number of retry attempts
            base_delay: Base delay in seconds for first retry
            max_delay: Maximum delay in seconds between retries
            exponential_base: Base for exponential backoff calculation
            jitter: Whether to add random jitter to delays
            retryable_exceptions: List of exception types that should trigger retries
        """
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
        self.retryable_exceptions = retryable_exceptions or [
            ExternalServiceError,
            ConnectionError,
            TimeoutError
        ]
    
    def calculate_delay(self, attempt: int) -> float:
        """
        Calculate delay for a given attempt number.
        
        Args:
            attempt: Current attempt number (0-based)
            
        Returns:
            Delay in seconds
        """
        # Exponential backoff: base_delay * (exponential_base ^ attempt)
        delay = self.base_delay * (self.exponential_base ** attempt)
        
        # Cap at max_delay
        delay = min(delay, self.max_delay)
        
        # Add jitter to prevent thundering herd
        if self.jitter:
            # Add random jitter of ±25%
            jitter_range = delay * 0.25
            delay += random.uniform(-jitter_range, jitter_range)
            delay = max(0.1, delay)  # Ensure minimum delay
        
        return delay
    
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """
        Determine if an exception should trigger a retry.
        
        Args:
            exception: Exception that occurred
            attempt: Current attempt number (0-based)
            
        Returns:
            True if should retry, False otherwise
        """
        # Check if we've exceeded max attempts
        if attempt >= self.max_attempts:
            return False
        
        # Check if exception type is retryable
        for retryable_type in self.retryable_exceptions:
            if isinstance(exception, retryable_type):
                # Special handling for rate limit errors
                if isinstance(exception, RateLimitError):
                    return True
                
                # Don't retry circuit breaker errors
                if isinstance(exception, CircuitBreakerError):
                    return False
                
                return True
        
        return False


class CircuitBreaker:
    """
    Circuit breaker implementation to prevent cascading failures.
    
    Monitors failure rates and opens the circuit when failures exceed
    threshold, preventing further requests to failing services.
    """
    
    def __init__(
        self,
        service_name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: Type[Exception] = ExternalServiceError
    ) -> None:
        """
        Initialize circuit breaker.
        
        Args:
            service_name: Name of the service being protected
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            expected_exception: Exception type that counts as failure
        """
        self.service_name = service_name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self._state = CircuitBreakerState.CLOSED
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._next_attempt_time = 0.0
    
    @property
    def state(self) -> CircuitBreakerState:
        """Get current circuit breaker state."""
        return self._state
    
    @property
    def failure_count(self) -> int:
        """Get current failure count."""
        return self._failure_count
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt to reset."""
        return (
            self._state == CircuitBreakerState.OPEN and
            time.time() >= self._next_attempt_time
        )
    
    def _record_success(self) -> None:
        """Record successful operation."""
        self._failure_count = 0
        self._state = CircuitBreakerState.CLOSED
        
        logger.info(
            "Circuit breaker reset to CLOSED",
            service_name=self.service_name,
            state=self._state.value
        )
    
    def _record_failure(self, exception: Exception) -> None:
        """Record failed operation."""
        self._failure_count += 1
        self._last_failure_time = time.time()
        
        if self._failure_count >= self.failure_threshold:
            self._state = CircuitBreakerState.OPEN
            self._next_attempt_time = time.time() + self.recovery_timeout
            
            logger.warning(
                "Circuit breaker opened due to failures",
                service_name=self.service_name,
                failure_count=self._failure_count,
                failure_threshold=self.failure_threshold,
                recovery_timeout=self.recovery_timeout,
                exception=str(exception)
            )
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function
            
        Returns:
            Function result
            
        Raises:
            CircuitBreakerError: If circuit is open
            Exception: Original exception from function
        """
        # Check if circuit is open
        if self._state == CircuitBreakerState.OPEN:
            if not self._should_attempt_reset():
                raise CircuitBreakerError(
                    f"Circuit breaker is OPEN for service '{self.service_name}'",
                    service_name=self.service_name,
                    failure_count=self._failure_count
                )
            else:
                # Attempt to reset - move to half-open
                self._state = CircuitBreakerState.HALF_OPEN
                logger.info(
                    "Circuit breaker attempting reset",
                    service_name=self.service_name,
                    state=self._state.value
                )
        
        try:
            # Execute the function
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            # Record success
            self._record_success()
            return result
            
        except Exception as e:
            # Check if this is a failure we should track
            if isinstance(e, self.expected_exception):
                self._record_failure(e)
            
            # Re-raise the original exception
            raise


# Global circuit breakers registry
_circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(
    service_name: str,
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
    expected_exception: Type[Exception] = ExternalServiceError
) -> CircuitBreaker:
    """
    Get or create a circuit breaker for a service.
    
    Args:
        service_name: Name of the service
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds to wait before attempting recovery
        expected_exception: Exception type that counts as failure
        
    Returns:
        Circuit breaker instance
    """
    if service_name not in _circuit_breakers:
        _circuit_breakers[service_name] = CircuitBreaker(
            service_name=service_name,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            expected_exception=expected_exception
        )
    
    return _circuit_breakers[service_name]


def with_retry(
    strategy: Optional[RetryStrategy] = None,
    circuit_breaker: Optional[CircuitBreaker] = None
):
    """
    Decorator to add retry logic and circuit breaker to functions.
    
    Args:
        strategy: Retry strategy configuration
        circuit_breaker: Circuit breaker instance
        
    Returns:
        Decorated function with retry logic
    """
    if strategy is None:
        strategy = RetryStrategy()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(strategy.max_attempts):
                try:
                    # Use circuit breaker if provided
                    if circuit_breaker:
                        return await circuit_breaker.call(func, *args, **kwargs)
                    else:
                        if asyncio.iscoroutinefunction(func):
                            return await func(*args, **kwargs)
                        else:
                            return func(*args, **kwargs)
                
                except Exception as e:
                    last_exception = e
                    
                    # Check if we should retry
                    if not strategy.should_retry(e, attempt):
                        logger.error(
                            "Function failed, not retrying",
                            function=func.__name__,
                            attempt=attempt + 1,
                            max_attempts=strategy.max_attempts,
                            exception=str(e)
                        )
                        raise
                    
                    # Calculate delay for next attempt
                    if attempt < strategy.max_attempts - 1:  # Don't delay after last attempt
                        delay = strategy.calculate_delay(attempt)
                        
                        logger.warning(
                            "Function failed, retrying",
                            function=func.__name__,
                            attempt=attempt + 1,
                            max_attempts=strategy.max_attempts,
                            delay_seconds=delay,
                            exception=str(e)
                        )
                        
                        # Handle rate limit delays
                        if isinstance(e, RateLimitError) and e.retry_after:
                            delay = max(delay, e.retry_after)
                        
                        await asyncio.sleep(delay)
            
            # All attempts failed
            logger.error(
                "Function failed after all retry attempts",
                function=func.__name__,
                max_attempts=strategy.max_attempts,
                final_exception=str(last_exception)
            )
            raise last_exception
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            # For sync functions, convert to async and run
            async def async_func():
                return func(*args, **kwargs)
            
            return asyncio.run(async_wrapper())
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# Convenience decorators for common retry patterns
def with_external_service_retry(
    service_name: str,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    failure_threshold: int = 5
):
    """
    Decorator for external service calls with retry and circuit breaker.
    
    Args:
        service_name: Name of the external service
        max_attempts: Maximum retry attempts
        base_delay: Base delay between retries
        failure_threshold: Circuit breaker failure threshold
        
    Returns:
        Configured retry decorator
    """
    strategy = RetryStrategy(
        max_attempts=max_attempts,
        base_delay=base_delay,
        retryable_exceptions=[ExternalServiceError, ConnectionError, TimeoutError]
    )
    
    circuit_breaker = get_circuit_breaker(
        service_name=service_name,
        failure_threshold=failure_threshold
    )
    
    return with_retry(strategy=strategy, circuit_breaker=circuit_breaker)


def with_database_retry(max_attempts: int = 3, base_delay: float = 0.5):
    """
    Decorator for database operations with retry logic.
    
    Args:
        max_attempts: Maximum retry attempts
        base_delay: Base delay between retries
        
    Returns:
        Configured retry decorator
    """
    from app.exceptions import DatabaseError
    
    strategy = RetryStrategy(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=5.0,
        retryable_exceptions=[DatabaseError, ConnectionError]
    )
    
    return with_retry(strategy=strategy)