# Reference Implementation

This directory contains existing backend logic that serves as reference material for the AI Jira Confluence Agent development.

## Files

- **`app.py`** - Main backend application logic with MCP server integration
- **`custom_llm.py`** - Custom LLM integration and API client logic

## Usage Guidelines

### For Development Reference
When implementing the actual features, I will:

1. **📖 Review** these reference files first
2. **🔍 Analyze** the patterns and logic you used  
3. **🏗️ Adapt** to fit our enterprise architecture (controllers → services → repositories)
4. **✨ Enhance** with proper error handling, logging, and testing
5. **📝 Document** any changes or improvements made

### Integration Approach
- **Extract core functionality** from reference implementations
- **Adapt to layered architecture** with proper separation of concerns
- **Add enterprise features**: comprehensive error handling, structured logging, security
- **Maintain compatibility** with your existing MCP and LLM integration patterns

### Code Quality Standards
When adapting reference code:
- ✅ Add proper type hints and documentation
- ✅ Implement comprehensive error handling  
- ✅ Add structured logging with PII redaction
- ✅ Follow OOP principles and SOLID design
- ✅ Add unit tests and integration tests
- ✅ Ensure security best practices (encryption, validation)

## Notes
- Reference code will be used as foundation for Tasks 3, 4, and 5
- Always adapt to fit our enterprise patterns while preserving functionality
- Prioritize maintainability and testability over direct code reuse