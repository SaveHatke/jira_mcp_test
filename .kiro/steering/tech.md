# Technology Stack

## Backend Framework
- **FastAPI**: Main web framework with server-rendered templates
- **Jinja2**: Templating engine for server-side rendering
- **SQLAlchemy**: ORM with SQLite database
- **Alembic**: Database migrations
- **Pydantic Settings**: Environment variable management
- **Uvicorn**: ASGI server with standard extensions

## Frontend Technologies
- **TailwindCSS**: Pre-built CSS file served locally
- **HTMX**: Form enhancements and dynamic content (vendored locally)
- **Alpine.js**: Reactive states and client-side interactivity (vendored locally)

## AI and Integration
- **LangChain**: AI orchestration and prompt management
- **mcp-atlassian**: MCP server for Jira and Confluence integrations
- **Custom Company LLM**: Configurable via JSON files
- **Server-Sent Events (SSE)**: Real-time AI streaming
- **WebSocket**: Optional full-duplex communication

## Data and Background Processing
- **SQLite**: Primary database with encryption for sensitive data
- **Huey**: Background job processing with SQLite backend
- **Diskcache**: Tool list and session caching
- **APScheduler**: Periodic task scheduling

## Security and Observability
- **JWT**: Session management with CSRF protection
- **AES-256**: Encryption for PATs and cookies
- **bcrypt**: Password hashing
- **Structlog**: JSON logging
- **OpenTelemetry**: Distributed tracing
- **OTLP**: Trace export

## Configuration Management
All configurations stored in JSON files for runtime modification:
- `config.json`: LLM endpoints, timeouts, retry settings
- `header.json`: API headers and authentication
- `payload.json`: Request payload templates
- `prompts.json`: System and custom prompts

## Common Commands

### Development
```bash
python manage.py dev          # Development with watch + reload
python manage.py prod        # Production server
```

### Database
```bash
alembic upgrade head          # Run migrations
alembic revision --autogenerate -m "description"  # Create migration
```

### Background Services
```bash
huey_consumer app.tasks.huey  # Start background job processor
```

### Health Checks
- `/healthz` - Liveness probe
- `/readyz` - Readiness probe

## Architecture Principles
- **Layered Architecture**: Controllers → Services → Repositories → Models
- **OOP with SOLID Principles**: Proper encapsulation and dependency injection
- **Enterprise Security**: Input validation, output encoding, audit logging
- **Performance**: Async operations, caching, connection pooling
- **Observability**: Structured logging, distributed tracing, metrics