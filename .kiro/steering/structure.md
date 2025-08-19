# Project Structure

## Directory Organization

```
ai-jira-confluence-agent/
├── app/                       # Main application code
│   ├── __init__.py
│   ├── main.py               # FastAPI application entry point
│   ├── config.py             # Configuration management
│   ├── database.py           # Database setup and connection
│   ├── dependencies.py       # Dependency injection
│   ├── middleware.py         # Custom middleware (auth, logging, CORS)
│   ├── controllers/          # Request handlers (routes)
│   │   ├── auth_controller.py
│   │   ├── dashboard_controller.py
│   │   ├── config_controller.py
│   │   └── ai_story_controller.py
│   ├── services/             # Business logic layer
│   │   ├── auth_service.py
│   │   ├── config_service.py
│   │   ├── ai_service.py
│   │   └── mcp_service.py
│   ├── repositories/         # Data access layer
│   │   ├── user_repository.py
│   │   ├── config_repository.py
│   │   └── cache_repository.py
│   ├── models/               # SQLAlchemy database models
│   │   ├── user.py
│   │   ├── config.py
│   │   └── job.py
│   ├── schemas/              # Pydantic request/response models
│   │   ├── auth_schemas.py
│   │   ├── config_schemas.py
│   │   └── story_schemas.py
│   └── utils/                # Utilities and helpers
│       ├── encryption.py
│       ├── validation.py
│       └── logging.py
├── templates/                # Jinja2 HTML templates
│   ├── base.html
│   ├── auth/
│   │   ├── login.html
│   │   └── register.html
│   ├── dashboard/
│   │   └── index.html
│   ├── config/
│   │   └── index.html
│   └── ai/
│       └── story_creator.html
├── static/                   # Static assets
│   ├── css/
│   │   └── tailwind.min.css  # Pre-built TailwindCSS
│   ├── js/
│   │   ├── htmx.min.js       # Vendored HTMX
│   │   └── alpine.min.js     # Vendored Alpine.js
│   └── images/
├── config/                   # JSON configuration files
│   ├── config.json           # LLM endpoints and settings
│   ├── header.json           # API headers
│   ├── payload.json          # Request templates
│   └── prompts.json          # AI prompts
├── migrations/               # Alembic database migrations
│   ├── versions/
│   ├── alembic.ini
│   └── env.py
├── tests/                    # Test suite
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── tools/                    # Build and development tools
├── requirements.txt          # Python dependencies
├── manage.py                 # Management commands
└── start.py                  # Environment-aware startup script
```

## Key Architectural Patterns

### Layered Architecture
- **Controllers**: Handle HTTP requests, validation, response formatting
- **Services**: Implement business logic, orchestrate operations
- **Repositories**: Abstract data access, handle database operations
- **Models**: Define data structures and relationships

### Configuration Management
- All external service configurations in `/config/` JSON files
- Runtime configuration updates without restart
- Environment-specific settings via pydantic-settings

### Security Isolation
- Complete user data isolation at database level
- Encrypted sensitive data (PATs, cookies) in separate columns
- User-scoped caching and session management

### Background Processing
- Huey tasks for long-running operations (tool list refresh, AI generation)
- Job tracking with user isolation
- Retry logic with exponential backoff

## File Naming Conventions

### Python Files
- `snake_case` for all Python files and modules
- Service files: `*_service.py`
- Repository files: `*_repository.py`
- Controller files: `*_controller.py`
- Model files: singular nouns (`user.py`, `config.py`)

### Templates
- Organized by feature area (`auth/`, `dashboard/`, `config/`, `ai/`)
- Use descriptive names (`story_creator.html`, `login.html`)

### Static Assets
- Vendored libraries in `/static/js/` with version in filename
- CSS organized by framework (`tailwind.min.css`)
- Images in `/static/images/` with descriptive names

## Data Flow Patterns

### Request Processing
1. **Middleware**: Authentication, logging, request ID injection
2. **Controller**: Route handling, input validation
3. **Service**: Business logic, external API calls
4. **Repository**: Database operations
5. **Response**: Template rendering or JSON API response

### Background Jobs
1. **Controller**: Enqueue job with user context
2. **Huey Task**: Execute with retry logic
3. **Service**: Perform operation (tool refresh, AI generation)
4. **Repository**: Update job status and results

### Configuration Loading
1. **Startup**: Load and validate all JSON config files
2. **Runtime**: Hot-reload configurations on file changes
3. **User Context**: Apply user-specific overrides and settings