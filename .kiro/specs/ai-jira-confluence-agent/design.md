# Design Document

## Overview

This design document outlines the technical architecture for the AI Jira Confluence Agent - a multi-user enterprise web application that enables users to register with Jira PAT tokens, configure integrations with Company LLM, Jira MCP, and Confluence MCP, then use AI-powered workflows to generate and create Jira stories/tasks/sub-tasks.

The system follows a layered architecture with clear separation of concerns, implementing enterprise-grade security, performance, and scalability patterns while maintaining simplicity through server-rendered templates and local resource management.

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Browser                           │
├─────────────────────────────────────────────────────────────────┤
│  TailwindCSS (local) │ HTMX (vendored) │ Alpine.js (vendored)   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     FastAPI Application                         │
├─────────────────────────────────────────────────────────────────┤
│  Controllers │ Services │ Repositories │ Models │ Middleware    │
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
            ┌─────────────┐ ┌─────────┐ ┌─────────────┐
            │   SQLite    │ │  Huey   │ │   Cache     │
            │  Database   │ │ Queue   │ │ (diskcache) │
            └─────────────┘ └─────────┘ └─────────────┘
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
            ┌─────────────┐ ┌─────────┐ ┌─────────────┐
            │ Company LLM │ │Jira MCP │ │Confluence   │
            │   Service   │ │ Server  │ │MCP Server   │
            └─────────────┘ └─────────┘ └─────────────┘
```

### Layered Architecture

#### 1. Presentation Layer
- **Jinja2 Templates**: Server-rendered HTML with TailwindCSS styling
- **HTMX**: Progressive enhancement for forms and dynamic content
- **Alpine.js**: Client-side reactivity for UI components
- **Static Assets**: Pre-built TailwindCSS, vendored JavaScript files

#### 2. Application Layer (Controllers)
- **Authentication Controller**: Registration, login, session management
- **Dashboard Controller**: Main navigation and feature cards
- **Configuration Controller**: Jira, Confluence, LLM setup
- **AI Story Controller**: Issue creation workflow
- **API Controller**: RESTful endpoints for AJAX operations

#### 3. Business Logic Layer (Services)
- **Authentication Service**: User validation, JWT token management
- **Configuration Service**: Integration testing and validation
- **AI Service**: LangChain orchestration, prompt management
- **MCP Service**: Tool list caching, external API calls
- **Validation Service**: Business rules, story validation

#### 4. Data Access Layer (Repositories)
- **User Repository**: User account management
- **Configuration Repository**: User-specific configurations
- **Cache Repository**: Tool lists, session data
- **Job Repository**: Background task management

#### 5. Data Layer
- **SQLite Database**: Primary data storage with SQLAlchemy ORM
- **Alembic Migrations**: Database schema versioning
- **Huey Queue**: Background job processing
- **Diskcache**: Tool list and session caching

## Components and Interfaces

### Core Components

#### 1. Authentication System
```python
class AuthenticationService:
    def register_user(self, jira_pat: str) -> UserRegistrationResult
    def validate_jira_credentials(self, pat: str, url: str) -> JiraValidationResult
    def create_user_account(self, user_data: UserData, password: str) -> User
    def authenticate_user(self, username: str, password: str) -> AuthResult
    def create_jwt_token(self, user: User) -> str
    def validate_jwt_token(self, token: str) -> User
```

#### 2. Configuration Management
```python
class ConfigurationService:
    def save_llm_config(self, user_id: int, cookie: str) -> LLMConfig
    def test_llm_connection(self, config: LLMConfig) -> TestResult
    def save_confluence_config(self, user_id: int, config: ConfluenceConfig) -> ConfluenceConfig
    def test_confluence_connection(self, config: ConfluenceConfig) -> TestResult
    def validate_employee_ids(self, jira_id: str, confluence_id: str, llm_id: str) -> ValidationResult
```

#### 3. AI Story Generation
```python
class AIStoryService:
    def generate_draft(self, requirements: str, format: StoryFormat, prompt: str) -> StoryDraft
    def refine_story(self, draft: StoryDraft, instructions: str) -> StoryDraft
    def validate_story(self, story: StoryDraft, rules: ValidationRules) -> ValidationResult
    def create_jira_issue(self, story: StoryDraft, user: User) -> JiraIssue
```

#### 4. MCP Integration
```python
class MCPService:
    def fetch_tool_lists(self, user: User) -> ToolList
    def cache_tool_lists(self, user_id: int, tools: ToolList) -> None
    def get_cached_tools(self, user_id: int) -> Optional[ToolList]
    def refresh_tool_cache(self, user_id: int) -> None
```

### External Interfaces

#### 1. Jira REST API
```python
class JiraAPIClient:
    def get_current_user(self, pat: str, base_url: str) -> JiraUser
    def create_issue(self, issue_data: IssueData, pat: str, base_url: str) -> JiraIssue
    def get_projects(self, pat: str, base_url: str) -> List[Project]
```

#### 2. Confluence REST API
```python
class ConfluenceAPIClient:
    def get_current_user(self, pat: str, base_url: str) -> ConfluenceUser
    def validate_connection(self, config: ConfluenceConfig) -> bool
```

#### 3. Company LLM API
```python
class CompanyLLMClient:
    def get_user_info(self, headers: Dict[str, str]) -> LLMUser
    def generate_content(self, prompt: str, headers: Dict[str, str]) -> LLMResponse
    def stream_content(self, prompt: str, headers: Dict[str, str]) -> Iterator[str]
```

## Data Models

### Database Schema

#### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    encrypted_jira_pat TEXT NOT NULL,
    jira_url VARCHAR(500) NOT NULL,
    avatar_url VARCHAR(500),
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### User Sessions Table
```sql
CREATE TABLE user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

#### LLM Configurations Table
```sql
CREATE TABLE llm_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    encrypted_cookie TEXT NOT NULL,
    tested_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

#### Confluence Configurations Table
```sql
CREATE TABLE confluence_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url VARCHAR(500) NOT NULL,
    encrypted_pat TEXT NOT NULL,
    verify_ssl BOOLEAN DEFAULT FALSE,
    ssl_cert_path VARCHAR(500),
    tested_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

#### Tool Cache Table
```sql
CREATE TABLE tool_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    source VARCHAR(20) NOT NULL, -- 'jira' or 'confluence'
    tool_data TEXT NOT NULL, -- JSON blob
    refreshed_at TIMESTAMP NOT NULL,
    ttl_seconds INTEGER DEFAULT 21600, -- 6 hours
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

#### Background Jobs Table
```sql
CREATE TABLE background_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    job_type VARCHAR(50) NOT NULL,
    payload TEXT, -- JSON
    status VARCHAR(20) DEFAULT 'pending', -- pending, running, completed, failed
    result TEXT, -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### SQLAlchemy Models

#### User Model
```python
class User(Base):
    __tablename__ = 'users'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    employee_id: Mapped[str] = mapped_column(String(50), unique=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(255), unique=True)
    display_name: Mapped[str] = mapped_column(String(100))
    hashed_password: Mapped[str] = mapped_column(String(255))
    encrypted_jira_pat: Mapped[str] = mapped_column(Text)
    jira_url: Mapped[str] = mapped_column(String(500))
    avatar_url: Mapped[Optional[str]] = mapped_column(String(500))
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    updated_at: Mapped[datetime] = mapped_column(default=func.now(), onupdate=func.now())
    
    # Relationships
    sessions: Mapped[List["UserSession"]] = relationship(back_populates="user")
    llm_config: Mapped[Optional["LLMConfig"]] = relationship(back_populates="user")
    confluence_config: Mapped[Optional["ConfluenceConfig"]] = relationship(back_populates="user")
```

#### Configuration Models
```python
class LLMConfig(Base):
    __tablename__ = 'llm_configs'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    encrypted_cookie: Mapped[str] = mapped_column(Text)
    tested_at: Mapped[Optional[datetime]]
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    updated_at: Mapped[datetime] = mapped_column(default=func.now(), onupdate=func.now())
    
    user: Mapped["User"] = relationship(back_populates="llm_config")

class ConfluenceConfig(Base):
    __tablename__ = 'confluence_configs'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    url: Mapped[str] = mapped_column(String(500))
    encrypted_pat: Mapped[str] = mapped_column(Text)
    verify_ssl: Mapped[bool] = mapped_column(default=False)
    ssl_cert_path: Mapped[Optional[str]] = mapped_column(String(500))
    tested_at: Mapped[Optional[datetime]]
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    updated_at: Mapped[datetime] = mapped_column(default=func.now(), onupdate=func.now())
    
    user: Mapped["User"] = relationship(back_populates="confluence_config")
```

## Error Handling

### Exception Hierarchy
```python
class AIAgentException(Exception):
    """Base exception for the application"""
    pass

class AuthenticationError(AIAgentException):
    """Authentication related errors"""
    pass

class ConfigurationError(AIAgentException):
    """Configuration validation errors"""
    pass

class ExternalServiceError(AIAgentException):
    """External API call errors"""
    pass

class ValidationError(AIAgentException):
    """Business rule validation errors"""
    pass
```

### Error Handling Strategy
1. **Controller Level**: Catch and convert exceptions to user-friendly messages
2. **Service Level**: Implement retry logic with exponential backoff
3. **Repository Level**: Handle database connection and constraint errors
4. **External API Level**: Circuit breaker pattern for persistent failures

### Logging Strategy
```python
# Structured logging with context
logger.info(
    "user_authentication_success",
    extra={
        "user_id": user.id,
        "employee_id": user.employee_id,
        "x_request_id": request_id,
        "duration_ms": duration
    }
)
```

## Testing Strategy

### Unit Testing
- **Models**: SQLAlchemy model validation and relationships
- **Services**: Business logic with mocked dependencies
- **Repositories**: Database operations with test database
- **Utilities**: Encryption, validation, and helper functions

### Integration Testing
- **API Endpoints**: Full request/response cycle testing
- **Database**: Migration and data integrity testing
- **External Services**: Mock external APIs for reliable testing
- **Authentication Flow**: End-to-end user registration and login

### Test Structure
```python
# Test organization
tests/
├── unit/
│   ├── test_models.py
│   ├── test_services.py
│   └── test_repositories.py
├── integration/
│   ├── test_api_endpoints.py
│   ├── test_auth_flow.py
│   └── test_database.py
└── fixtures/
    ├── users.py
    └── configurations.py
```

### Testing Tools
- **pytest**: Test framework with fixtures and parametrization
- **pytest-asyncio**: Async test support
- **httpx**: HTTP client testing
- **SQLAlchemy testing**: In-memory database for fast tests
- **Factory Boy**: Test data generation

## Security Considerations

### Data Protection
1. **Encryption at Rest**: AES-256 encryption for PATs and cookies
2. **Password Hashing**: bcrypt with salt for user passwords
3. **JWT Tokens**: Signed tokens with configurable expiration
4. **CSRF Protection**: Token-based CSRF protection for forms

### Input Validation
1. **Pydantic Models**: Request/response validation
2. **SQL Injection Prevention**: SQLAlchemy ORM parameterized queries
3. **XSS Prevention**: Jinja2 auto-escaping enabled
4. **File Upload Validation**: SSL certificate file type and size limits

### Access Control
1. **Session Management**: Secure session handling with timeout
2. **User Isolation**: Strict user-based data filtering
3. **API Rate Limiting**: Prevent abuse of external API calls
4. **Audit Logging**: Track user actions without exposing sensitive data

## Performance Optimization

### Caching Strategy
1. **Tool Lists**: 6-hour TTL with background refresh
2. **User Sessions**: In-memory caching with Redis fallback
3. **Configuration Data**: Application-level caching
4. **Static Assets**: Browser caching with versioning

### Database Optimization
1. **Indexing**: Strategic indexes on frequently queried columns
2. **Connection Pooling**: SQLAlchemy connection pool management
3. **Query Optimization**: Eager loading for relationships
4. **Pagination**: Limit result sets for large data queries

### Async Operations
1. **Background Jobs**: Huey for long-running tasks
2. **External API Calls**: Async HTTP clients with connection pooling
3. **Database Operations**: Async SQLAlchemy for I/O operations
4. **Real-time Features**: SSE for streaming AI responses

## Deployment Architecture

### Application Structure
```
ai-jira-confluence-agent/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application
│   ├── config.py              # Configuration management
│   ├── database.py            # Database setup
│   ├── dependencies.py        # Dependency injection
│   ├── middleware.py          # Custom middleware
│   ├── controllers/           # Request handlers
│   ├── services/              # Business logic
│   ├── repositories/          # Data access
│   ├── models/                # SQLAlchemy models
│   ├── schemas/               # Pydantic schemas
│   └── utils/                 # Utilities and helpers
├── templates/                 # Jinja2 templates
├── static/                    # Static assets
├── config/                    # JSON configuration files
├── migrations/                # Alembic migrations
├── tests/                     # Test suite
├── tools/                     # Build tools
├── requirements.txt           # Python dependencies
├── manage.py                  # Management commands
└── start.py                   # Startup script
```

### Environment Configuration
```python
# Development
DEBUG = True
LOG_LEVEL = "DEBUG"
SESSION_TIMEOUT = 15  # minutes
DATABASE_URL = "sqlite:///./dev.db"

# Production
DEBUG = False
LOG_LEVEL = "INFO"
SESSION_TIMEOUT = 30  # minutes
DATABASE_URL = "sqlite:///./prod.db"
OTEL_EXPORTER_OTLP_ENDPOINT = "http://otel-collector:4318/v1/traces"
```

This design provides a solid foundation for implementing the AI Jira Confluence Agent with enterprise-grade architecture, security, and performance characteristics while maintaining simplicity and maintainability.