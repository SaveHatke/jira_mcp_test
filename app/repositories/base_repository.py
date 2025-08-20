"""
Base repository implementing the Repository pattern with OOP principles.

This module provides the abstract base class for all repositories,
implementing common database operations and following SOLID principles.
"""

from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Optional, List, Dict, Any, Type
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import select, update, delete, func
from sqlalchemy.exc import SQLAlchemyError

from app.exceptions import DatabaseError

# Type variable for model classes
ModelType = TypeVar('ModelType', bound=DeclarativeBase)
CreateSchemaType = TypeVar('CreateSchemaType')
UpdateSchemaType = TypeVar('UpdateSchemaType')


class BaseRepository(Generic[ModelType], ABC):
    """
    Abstract base repository implementing common CRUD operations.
    
    This class follows the Repository pattern and provides a consistent
    interface for data access operations across all entities.
    
    Principles implemented:
    - Single Responsibility: Handles only data access concerns
    - Open/Closed: Open for extension via inheritance, closed for modification
    - Liskov Substitution: All repositories can be used interchangeably
    - Interface Segregation: Provides focused interface for data operations
    - Dependency Inversion: Depends on abstractions (SQLAlchemy) not concretions
    """
    
    def __init__(self, model: Type[ModelType], session: AsyncSession) -> None:
        """
        Initialize the repository with model class and database session.
        
        Args:
            model: SQLAlchemy model class
            session: Async database session
        """
        self._model = model
        self._session = session
    
    async def create(self, obj_in: CreateSchemaType) -> ModelType:
        """
        Create a new entity in the database.
        
        Args:
            obj_in: Pydantic schema with creation data
            
        Returns:
            Created model instance
            
        Raises:
            DatabaseError: If creation fails
        """
        try:
            # Convert Pydantic model to dict, excluding unset values
            create_data = obj_in.model_dump(exclude_unset=True)
            db_obj = self._model(**create_data)
            
            self._session.add(db_obj)
            await self._session.commit()
            await self._session.refresh(db_obj)
            
            return db_obj
        except SQLAlchemyError as e:
            await self._session.rollback()
            raise DatabaseError(
                f"Failed to create {self._model.__name__}",
                error_code="DB_CREATE_FAILED",
                details={"model": self._model.__name__, "error": str(e)}
            ) from e
    
    async def get_by_id(self, entity_id: int) -> Optional[ModelType]:
        """
        Retrieve an entity by its primary key.
        
        Args:
            entity_id: Primary key value
            
        Returns:
            Model instance if found, None otherwise
            
        Raises:
            DatabaseError: If query fails
        """
        try:
            result = await self._session.execute(
                select(self._model).where(self._model.id == entity_id)
            )
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            raise DatabaseError(
                f"Failed to get {self._model.__name__} by id {entity_id}",
                error_code="DB_GET_FAILED",
                details={"model": self._model.__name__, "id": entity_id, "error": str(e)}
            ) from e
    
    async def get_by_field(self, field_name: str, value: Any) -> Optional[ModelType]:
        """
        Retrieve an entity by a specific field value.
        
        Args:
            field_name: Name of the field to search by
            value: Value to search for
            
        Returns:
            Model instance if found, None otherwise
            
        Raises:
            DatabaseError: If query fails
        """
        try:
            field = getattr(self._model, field_name)
            result = await self._session.execute(
                select(self._model).where(field == value)
            )
            return result.scalar_one_or_none()
        except (AttributeError, SQLAlchemyError) as e:
            raise DatabaseError(
                f"Failed to get {self._model.__name__} by {field_name}",
                error_code="DB_GET_BY_FIELD_FAILED",
                details={
                    "model": self._model.__name__, 
                    "field": field_name, 
                    "value": value, 
                    "error": str(e)
                }
            ) from e
    
    async def get_multi(
        self, 
        skip: int = 0, 
        limit: int = 100,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[ModelType]:
        """
        Retrieve multiple entities with pagination and filtering.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            filters: Optional dictionary of field filters
            
        Returns:
            List of model instances
            
        Raises:
            DatabaseError: If query fails
        """
        try:
            query = select(self._model)
            
            # Apply filters if provided
            if filters:
                for field_name, value in filters.items():
                    if hasattr(self._model, field_name):
                        field = getattr(self._model, field_name)
                        query = query.where(field == value)
            
            query = query.offset(skip).limit(limit)
            result = await self._session.execute(query)
            return result.scalars().all()
        except SQLAlchemyError as e:
            raise DatabaseError(
                f"Failed to get multiple {self._model.__name__} records",
                error_code="DB_GET_MULTI_FAILED",
                details={
                    "model": self._model.__name__, 
                    "skip": skip, 
                    "limit": limit, 
                    "filters": filters,
                    "error": str(e)
                }
            ) from e
    
    async def update(self, entity_id: int, obj_in: UpdateSchemaType) -> Optional[ModelType]:
        """
        Update an existing entity.
        
        Args:
            entity_id: Primary key of entity to update
            obj_in: Pydantic schema with update data
            
        Returns:
            Updated model instance if found, None otherwise
            
        Raises:
            DatabaseError: If update fails
        """
        try:
            # Get existing entity
            db_obj = await self.get_by_id(entity_id)
            if not db_obj:
                return None
            
            # Convert Pydantic model to dict, excluding unset values
            update_data = obj_in.model_dump(exclude_unset=True)
            
            # Update fields
            for field, value in update_data.items():
                if hasattr(db_obj, field):
                    setattr(db_obj, field, value)
            
            await self._session.commit()
            await self._session.refresh(db_obj)
            
            return db_obj
        except SQLAlchemyError as e:
            await self._session.rollback()
            raise DatabaseError(
                f"Failed to update {self._model.__name__} with id {entity_id}",
                error_code="DB_UPDATE_FAILED",
                details={
                    "model": self._model.__name__, 
                    "id": entity_id, 
                    "error": str(e)
                }
            ) from e
    
    async def delete(self, entity_id: int) -> bool:
        """
        Delete an entity by its primary key.
        
        Args:
            entity_id: Primary key of entity to delete
            
        Returns:
            True if entity was deleted, False if not found
            
        Raises:
            DatabaseError: If deletion fails
        """
        try:
            result = await self._session.execute(
                delete(self._model).where(self._model.id == entity_id)
            )
            await self._session.commit()
            
            return result.rowcount > 0
        except SQLAlchemyError as e:
            await self._session.rollback()
            raise DatabaseError(
                f"Failed to delete {self._model.__name__} with id {entity_id}",
                error_code="DB_DELETE_FAILED",
                details={
                    "model": self._model.__name__, 
                    "id": entity_id, 
                    "error": str(e)
                }
            ) from e
    
    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """
        Count entities with optional filtering.
        
        Args:
            filters: Optional dictionary of field filters
            
        Returns:
            Number of matching entities
            
        Raises:
            DatabaseError: If count fails
        """
        try:
            query = select(func.count(self._model.id))
            
            # Apply filters if provided
            if filters:
                for field_name, value in filters.items():
                    if hasattr(self._model, field_name):
                        field = getattr(self._model, field_name)
                        query = query.where(field == value)
            
            result = await self._session.execute(query)
            return result.scalar()
        except SQLAlchemyError as e:
            raise DatabaseError(
                f"Failed to count {self._model.__name__} records",
                error_code="DB_COUNT_FAILED",
                details={
                    "model": self._model.__name__, 
                    "filters": filters,
                    "error": str(e)
                }
            ) from e
    
    async def exists(self, entity_id: int) -> bool:
        """
        Check if an entity exists by its primary key.
        
        Args:
            entity_id: Primary key to check
            
        Returns:
            True if entity exists, False otherwise
            
        Raises:
            DatabaseError: If existence check fails
        """
        try:
            result = await self._session.execute(
                select(func.count(self._model.id)).where(self._model.id == entity_id)
            )
            count = result.scalar()
            return count > 0
        except SQLAlchemyError as e:
            raise DatabaseError(
                f"Failed to check existence of {self._model.__name__} with id {entity_id}",
                error_code="DB_EXISTS_FAILED",
                details={
                    "model": self._model.__name__, 
                    "id": entity_id, 
                    "error": str(e)
                }
            ) from e


class UserScopedRepository(BaseRepository[ModelType], ABC):
    """
    Base repository for user-scoped entities.
    
    Extends BaseRepository to automatically filter all operations
    by user_id, ensuring complete data isolation between users.
    """
    
    def __init__(self, model: Type[ModelType], session: AsyncSession) -> None:
        """
        Initialize the user-scoped repository.
        
        Args:
            model: SQLAlchemy model class (must have user_id field)
            session: Async database session
        """
        super().__init__(model, session)
        
        # Verify model has user_id field
        if not hasattr(model, 'user_id'):
            raise ValueError(f"Model {model.__name__} must have user_id field for user-scoped repository")
    
    async def get_by_id_for_user(self, entity_id: int, user_id: int) -> Optional[ModelType]:
        """
        Retrieve an entity by ID for a specific user.
        
        Args:
            entity_id: Primary key value
            user_id: User ID for data isolation
            
        Returns:
            Model instance if found and belongs to user, None otherwise
        """
        try:
            result = await self._session.execute(
                select(self._model).where(
                    self._model.id == entity_id,
                    self._model.user_id == user_id
                )
            )
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            raise DatabaseError(
                f"Failed to get {self._model.__name__} by id {entity_id} for user {user_id}",
                error_code="DB_GET_USER_SCOPED_FAILED",
                details={
                    "model": self._model.__name__, 
                    "id": entity_id, 
                    "user_id": user_id,
                    "error": str(e)
                }
            ) from e
    
    async def get_multi_for_user(
        self, 
        user_id: int,
        skip: int = 0, 
        limit: int = 100,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[ModelType]:
        """
        Retrieve multiple entities for a specific user.
        
        Args:
            user_id: User ID for data isolation
            skip: Number of records to skip
            limit: Maximum number of records to return
            filters: Optional dictionary of additional field filters
            
        Returns:
            List of model instances belonging to the user
        """
        try:
            query = select(self._model).where(self._model.user_id == user_id)
            
            # Apply additional filters if provided
            if filters:
                for field_name, value in filters.items():
                    if hasattr(self._model, field_name):
                        field = getattr(self._model, field_name)
                        query = query.where(field == value)
            
            query = query.offset(skip).limit(limit)
            result = await self._session.execute(query)
            return result.scalars().all()
        except SQLAlchemyError as e:
            raise DatabaseError(
                f"Failed to get multiple {self._model.__name__} records for user {user_id}",
                error_code="DB_GET_MULTI_USER_SCOPED_FAILED",
                details={
                    "model": self._model.__name__, 
                    "user_id": user_id,
                    "skip": skip, 
                    "limit": limit, 
                    "filters": filters,
                    "error": str(e)
                }
            ) from e
    
    async def delete_for_user(self, entity_id: int, user_id: int) -> bool:
        """
        Delete an entity by ID for a specific user.
        
        Args:
            entity_id: Primary key of entity to delete
            user_id: User ID for data isolation
            
        Returns:
            True if entity was deleted, False if not found or not owned by user
        """
        try:
            result = await self._session.execute(
                delete(self._model).where(
                    self._model.id == entity_id,
                    self._model.user_id == user_id
                )
            )
            await self._session.commit()
            
            return result.rowcount > 0
        except SQLAlchemyError as e:
            await self._session.rollback()
            raise DatabaseError(
                f"Failed to delete {self._model.__name__} with id {entity_id} for user {user_id}",
                error_code="DB_DELETE_USER_SCOPED_FAILED",
                details={
                    "model": self._model.__name__, 
                    "id": entity_id, 
                    "user_id": user_id,
                    "error": str(e)
                }
            ) from e