"""
Background job model for Huey job tracking.

This module defines the BackgroundJob SQLAlchemy model for tracking
background jobs with user isolation and status management.
"""

from datetime import datetime
from typing import Optional, Dict, Any
import json
from sqlalchemy import String, Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel


class BackgroundJob(BaseModel):
    """
    Background job model for Huey job tracking with user isolation.
    
    Tracks background jobs with status, payload, and results while
    ensuring complete user data isolation.
    """
    
    __tablename__ = 'background_jobs'
    
    # Foreign key to user
    user_id: Mapped[int] = mapped_column(
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Reference to the user who owns this job"
    )
    
    # Job identification
    job_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Type of background job (tool_refresh, ai_generation, etc.)"
    )
    
    job_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        unique=True,
        index=True,
        comment="Unique job identifier from Huey"
    )
    
    # Job data
    payload: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="JSON serialized job payload/parameters"
    )
    
    # Job status
    status: Mapped[str] = mapped_column(
        String(20),
        default='pending',
        nullable=False,
        index=True,
        comment="Job status (pending, running, completed, failed, cancelled)"
    )
    
    # Job results
    result: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="JSON serialized job result or error information"
    )
    
    # Timing information
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when job execution started"
    )
    
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when job execution completed"
    )
    
    # Retry information
    retry_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
        comment="Number of retry attempts"
    )
    
    max_retries: Mapped[int] = mapped_column(
        default=5,
        nullable=False,
        comment="Maximum number of retry attempts"
    )
    
    # Error information
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Error message if job failed"
    )
    
    # Relationship to user
    user: Mapped["User"] = relationship(
        "User", 
        back_populates="background_jobs",
        lazy="select"
    )
    
    def get_payload(self) -> Optional[Dict[str, Any]]:
        """
        Deserialize and return the job payload.
        
        Returns:
            Dictionary containing the job payload, or None if no payload
            
        Raises:
            ValueError: If payload cannot be deserialized
        """
        if not self.payload:
            return None
        
        try:
            return json.loads(self.payload)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to deserialize job payload: {e}")
    
    def set_payload(self, data: Dict[str, Any]) -> None:
        """
        Serialize and store the job payload.
        
        Args:
            data: Dictionary containing job payload
            
        Raises:
            ValueError: If data cannot be serialized
        """
        try:
            self.payload = json.dumps(data, ensure_ascii=False)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Failed to serialize job payload: {e}")
    
    def get_result(self) -> Optional[Dict[str, Any]]:
        """
        Deserialize and return the job result.
        
        Returns:
            Dictionary containing the job result, or None if no result
            
        Raises:
            ValueError: If result cannot be deserialized
        """
        if not self.result:
            return None
        
        try:
            return json.loads(self.result)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to deserialize job result: {e}")
    
    def set_result(self, data: Dict[str, Any]) -> None:
        """
        Serialize and store the job result.
        
        Args:
            data: Dictionary containing job result
            
        Raises:
            ValueError: If data cannot be serialized
        """
        try:
            self.result = json.dumps(data, ensure_ascii=False)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Failed to serialize job result: {e}")
    
    def start_job(self, job_id: Optional[str] = None) -> None:
        """
        Mark job as started.
        
        Args:
            job_id: Optional Huey job ID
        """
        self.status = 'running'
        self.started_at = datetime.utcnow()
        if job_id:
            self.job_id = job_id
    
    def complete_job(self, result_data: Optional[Dict[str, Any]] = None) -> None:
        """
        Mark job as completed successfully.
        
        Args:
            result_data: Optional result data to store
        """
        self.status = 'completed'
        self.completed_at = datetime.utcnow()
        if result_data:
            self.set_result(result_data)
    
    def fail_job(self, error_message: str, result_data: Optional[Dict[str, Any]] = None) -> None:
        """
        Mark job as failed.
        
        Args:
            error_message: Error message describing the failure
            result_data: Optional error details to store
        """
        self.status = 'failed'
        self.completed_at = datetime.utcnow()
        self.error_message = error_message
        if result_data:
            self.set_result(result_data)
    
    def cancel_job(self) -> None:
        """
        Mark job as cancelled.
        """
        self.status = 'cancelled'
        self.completed_at = datetime.utcnow()
    
    def increment_retry(self) -> bool:
        """
        Increment retry count and check if more retries are allowed.
        
        Returns:
            True if more retries are allowed, False otherwise
        """
        self.retry_count += 1
        return self.retry_count < self.max_retries
    
    def is_terminal_status(self) -> bool:
        """
        Check if job is in a terminal status (completed, failed, cancelled).
        
        Returns:
            True if job is in terminal status, False otherwise
        """
        return self.status in ['completed', 'failed', 'cancelled']
    
    def is_running(self) -> bool:
        """
        Check if job is currently running.
        
        Returns:
            True if job is running, False otherwise
        """
        return self.status == 'running'
    
    def get_duration(self) -> Optional[float]:
        """
        Get job execution duration in seconds.
        
        Returns:
            Duration in seconds, or None if job hasn't completed
        """
        if not self.started_at:
            return None
        
        end_time = self.completed_at or datetime.utcnow()
        return (end_time - self.started_at).total_seconds()
    
    @classmethod
    def create_job(
        cls,
        user_id: int,
        job_type: str,
        payload: Optional[Dict[str, Any]] = None,
        max_retries: int = 5
    ) -> "BackgroundJob":
        """
        Create a new background job.
        
        Args:
            user_id: ID of the user
            job_type: Type of job to create
            payload: Optional job payload
            max_retries: Maximum number of retry attempts
            
        Returns:
            New BackgroundJob instance
        """
        job = cls(
            user_id=user_id,
            job_type=job_type,
            max_retries=max_retries
        )
        
        if payload:
            job.set_payload(payload)
        
        return job
    
    def to_dict(self, include_data: bool = False) -> dict:
        """
        Convert job to dictionary representation.
        
        Args:
            include_data: Whether to include payload and result data
            
        Returns:
            Dictionary representation of job
        """
        exclude_fields = [] if include_data else ['payload', 'result']
        result = super().to_dict(exclude_fields=exclude_fields)
        
        # Add computed fields
        result['is_terminal'] = self.is_terminal_status()
        result['is_running'] = self.is_running()
        result['duration_seconds'] = self.get_duration()
        
        if include_data:
            try:
                result['parsed_payload'] = self.get_payload()
                result['parsed_result'] = self.get_result()
            except ValueError:
                result['parsed_payload'] = None
                result['parsed_result'] = None
        
        return result
    
    def __repr__(self) -> str:
        """String representation of the job."""
        return f"<BackgroundJob(id={self.id}, user_id={self.user_id}, type='{self.job_type}', status='{self.status}')>"