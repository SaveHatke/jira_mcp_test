#!/usr/bin/env python3
"""Management commands for the Jira Intelligence Agent (JIA)."""

import sys
import subprocess
from pathlib import Path


def dev():
    """Run development server with watch and reload."""
    print("[STARTING] Development server with auto-reload and comprehensive logging...")
    
    # Import here to ensure logging is set up
    try:
        from app.config import settings
        from app.utils.logging import setup_comprehensive_logging
        
        # Setup comprehensive logging
        setup_comprehensive_logging(
            level="DEBUG",
            log_file=settings.log_file
        )
        
        print(f"[OK] Comprehensive logging configured for development")
        print(f"[INFO] All output will be saved to: {settings.log_file}")
        
    except Exception as e:
        print(f"[WARNING] Could not setup comprehensive logging: {e}")
    
    subprocess.run([
        sys.executable, "-m", "uvicorn",
        "app.main:app",
        "--reload",
        "--host", "127.0.0.1",
        "--port", "8000",
        "--log-level", "debug",
        "--access-log"
    ])


def prod():
    """Run production server."""
    print("[STARTING] Production server with comprehensive logging...")
    
    # Import here to ensure logging is set up
    try:
        from app.config import settings
        from app.utils.logging import setup_comprehensive_logging
        
        # Setup comprehensive logging
        setup_comprehensive_logging(
            level=settings.log_level,
            log_file=settings.log_file
        )
        
        print(f"[OK] Comprehensive logging configured for production")
        print(f"[INFO] All output will be saved to: {settings.log_file}")
        
    except Exception as e:
        print(f"[WARNING] Could not setup comprehensive logging: {e}")
    
    subprocess.run([
        sys.executable, "-m", "uvicorn",
        "app.main:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--workers", "4",
        "--access-log"
    ])


def build():
    """Build CSS and other assets."""
    print("Building assets...")
    # TODO: Implement CSS build process
    print("Asset build not yet implemented")


def test():
    """Run test suite."""
    print("Running tests...")
    subprocess.run([sys.executable, "-m", "pytest", "tests/", "-v"])


def migrate():
    """Run database migrations."""
    print("Running database migrations...")
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"])


def makemigrations():
    """Create new database migration."""
    message = input("Migration message: ")
    subprocess.run([
        sys.executable, "-m", "alembic", "revision",
        "--autogenerate", "-m", message
    ])


def help_text():
    """Show available commands."""
    print("""
Available commands:
  dev           - Run development server with auto-reload
  prod          - Run production server
  build         - Build CSS and other assets
  test          - Run test suite
  migrate       - Run database migrations
  makemigrations - Create new database migration
  help          - Show this help message
    """)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        help_text()
        sys.exit(1)
    
    command = sys.argv[1]
    
    commands = {
        "dev": dev,
        "prod": prod,
        "build": build,
        "test": test,
        "migrate": migrate,
        "makemigrations": makemigrations,
        "help": help_text,
    }
    
    if command in commands:
        commands[command]()
    else:
        print(f"Unknown command: {command}")
        help_text()
        sys.exit(1)