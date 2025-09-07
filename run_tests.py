#!/usr/bin/env python3
"""
Test runner script for Paylens API tests.
"""
import subprocess
import sys
import os
from pathlib import Path


def run_command(command, description):
    """Run a command and handle errors."""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {command}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=False)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed with exit code {e.returncode}")
        return False


def main():
    """Main test runner function."""
    # Change to the project root directory
    project_root = Path(__file__).parent
    os.chdir(project_root)
    
    print("🧪 Paylens API Test Runner")
    print(f"Project root: {project_root}")
    
    # Check if we're in a virtual environment
    if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("⚠️  Warning: Not running in a virtual environment")
        print("   Consider activating your virtual environment first")
    
    # Install test dependencies if requirements-test.txt exists
    if Path("requirements-test.txt").exists():
        print("\n📦 Installing test dependencies...")
        if not run_command("pip install -r requirements-test.txt", "Install test dependencies"):
            print("❌ Failed to install test dependencies")
            return 1
    
    # Run linting first
    print("\n🔍 Running linting...")
    run_command("python -m flake8 app/ tests/ --max-line-length=100 --ignore=E203,W503", "Linting")
    
    # Run type checking
    print("\n🔍 Running type checking...")
    run_command("python -m mypy app/ --ignore-missing-imports", "Type checking")
    
    # Run tests with coverage
    print("\n🧪 Running tests with coverage...")
    if not run_command("python -m pytest tests/ -v --cov=app --cov-report=term-missing --cov-report=html:htmlcov", "Test execution"):
        print("❌ Tests failed")
        return 1
    
    # Generate coverage report
    print("\n📊 Coverage report generated in htmlcov/index.html")
    
    # Run specific test categories
    print("\n🎯 Running specific test categories...")
    
    # Unit tests
    run_command("python -m pytest tests/services/ -v -m unit", "Unit tests")
    
    # Integration tests
    run_command("python -m pytest tests/controllers/ -v -m integration", "Integration tests")
    
    # Model tests
    run_command("python -m pytest tests/models/ -v", "Model tests")
    
    # Validation tests
    run_command("python -m pytest tests/validation/ -v", "Validation tests")
    
    # Middleware tests
    run_command("python -m pytest tests/middleware/ -v", "Middleware tests")
    
    print("\n🎉 All tests completed!")
    print("\n📋 Test Summary:")
    print("   - Unit tests for services")
    print("   - Integration tests for controllers")
    print("   - Model validation tests")
    print("   - Validation utility tests")
    print("   - Middleware authentication tests")
    print("   - Code coverage report generated")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
