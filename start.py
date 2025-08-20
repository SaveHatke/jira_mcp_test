#!/usr/bin/env python3
"""Environment-aware startup script for the Jira Intelligence Agent (JIA)."""

import sys
import os
import subprocess
import venv
from pathlib import Path


def check_python_version():
    """Ensure Python 3.8+ is being used."""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    print(f"[OK] Python {sys.version_info.major}.{sys.version_info.minor} detected")


def setup_virtual_environment():
    """Create and activate virtual environment if it doesn't exist."""
    venv_path = Path("venv")
    
    if not venv_path.exists():
        print("Creating virtual environment...")
        venv.create(venv_path, with_pip=True)
        print("[OK] Virtual environment created")
    else:
        print("[OK] Virtual environment exists")
    
    # Activate virtual environment
    if os.name == 'nt':  # Windows
        activate_script = venv_path / "Scripts" / "activate.bat"
        python_exe = venv_path / "Scripts" / "python.exe"
    else:  # Unix/Linux/macOS
        activate_script = venv_path / "bin" / "activate"
        python_exe = venv_path / "bin" / "python"
    
    return str(python_exe)


def upgrade_pip(python_exe):
    """Upgrade pip to latest version."""
    print("Upgrading pip...")
    result = subprocess.run([
        python_exe, "-m", "pip", "install", "--upgrade", "pip"
    ], capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[OK] Pip upgraded successfully")
    else:
        print(f"Warning: Pip upgrade failed: {result.stderr}")


def install_dependencies(python_exe):
    """Install dependencies from requirements.txt."""
    requirements_file = Path("requirements.txt")
    
    if not requirements_file.exists():
        print("Error: requirements.txt not found")
        sys.exit(1)
    
    print("Installing dependencies...")
    result = subprocess.run([
        python_exe, "-m", "pip", "install", "-r", "requirements.txt"
    ], capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[OK] Dependencies installed successfully")
    else:
        print(f"Error installing dependencies: {result.stderr}")
        sys.exit(1)


def verify_database_connectivity():
    """Verify database connectivity and run migrations."""
    print("Verifying database connectivity...")
    
    try:
        from app.database import engine
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("[OK] Database connection successful")
    except Exception as e:
        print(f"Error connecting to database: {e}")
        sys.exit(1)
    
    # Run migrations
    print("Running database migrations...")
    result = subprocess.run([
        sys.executable, "-m", "alembic", "upgrade", "head"
    ], capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[OK] Database migrations completed")
    else:
        print(f"Error running migrations: {result.stderr}")
        sys.exit(1)


def validate_configuration_files():
    """Validate required configuration files exist."""
    config_dir = Path("config")
    required_files = [
        "config.json",
        "header.json", 
        "payload.json",
        "prompts.json"
    ]
    
    print("Validating configuration files...")
    
    if not config_dir.exists():
        print("Warning: config/ directory not found - will be created on first run")
        return
    
    missing_files = []
    for file_name in required_files:
        file_path = config_dir / file_name
        if not file_path.exists():
            missing_files.append(file_name)
    
    if missing_files:
        print(f"Warning: Missing configuration files: {', '.join(missing_files)}")
        print("These will need to be created before full functionality is available")
    else:
        print("[OK] All configuration files present")


def start_application(environment="development"):
    """Start the FastAPI application."""
    print(f"Starting application in {environment} mode...")
    
    if environment == "development":
        os.environ["DEBUG"] = "true"
        os.environ["LOG_LEVEL"] = "DEBUG"
        subprocess.run([
            sys.executable, "-m", "uvicorn",
            "app.main:app",
            "--reload",
            "--host", "127.0.0.1",
            "--port", "8000"
        ])
    else:  # production
        os.environ["DEBUG"] = "false"
        os.environ["LOG_LEVEL"] = "INFO"
        subprocess.run([
            sys.executable, "-m", "uvicorn",
            "app.main:app",
            "--host", "0.0.0.0",
            "--port", "8000",
            "--workers", "4"
        ])


def main():
    """Main startup routine."""
    environment = sys.argv[1] if len(sys.argv) > 1 else "development"
    
    if environment not in ["development", "production"]:
        print("Usage: python start.py [development|production]")
        sys.exit(1)
    
    print(f"Starting Jira Intelligence Agent ({environment} mode)")
    print("=" * 50)
    
    try:
        check_python_version()
        python_exe = setup_virtual_environment()
        upgrade_pip(python_exe)
        install_dependencies(python_exe)
        verify_database_connectivity()
        validate_configuration_files()
        
        print("=" * 50)
        print("[SUCCESS] Startup checks completed successfully!")
        print("=" * 50)
        
        start_application(environment)
        
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Startup interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Startup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()