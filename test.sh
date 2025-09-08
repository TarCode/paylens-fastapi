#!/bin/bash
# Simple test runner script for Paylens API

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BLUE}🧪 Paylens API Test Runner${NC}"
echo -e "${BLUE}==========================${NC}"

# Check if virtual environment exists and activate it
if [ -d "env" ]; then
    echo -e "${YELLOW}📦 Activating virtual environment...${NC}"
    source env/bin/activate
elif [ -d "venv" ]; then
    echo -e "${YELLOW}📦 Activating virtual environment...${NC}"
    source venv/bin/activate
else
    echo -e "${YELLOW}⚠️  No virtual environment found. Consider creating one with:${NC}"
    echo -e "${YELLOW}   python -m venv env && source env/bin/activate${NC}"
fi

# Function to show usage
show_usage() {
    echo -e "${BLUE}Usage: $0 [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  --quick          Quick test run (skip Docker, linting, type checking)"
    echo "  --unit           Run only unit tests"
    echo "  --integration    Run only integration tests"
    echo "  --models         Run only model tests"
    echo "  --validation     Run only validation tests"
    echo "  --middleware     Run only middleware tests"
    echo "  --services       Run only service tests"
    echo "  --controllers    Run only controller tests"
    echo "  --skip-docker    Skip Docker database setup"
    echo "  --help           Show this help message"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0                    # Run full test suite"
    echo "  $0 --quick           # Quick test run"
    echo "  $0 --unit            # Run only unit tests"
    echo "  $0 --skip-docker     # Run tests without Docker"
}

# Parse command line arguments
QUICK=false
SKIP_DOCKER=false
TEST_TYPE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK=true
            shift
            ;;
        --unit)
            TEST_TYPE="unit"
            shift
            ;;
        --integration)
            TEST_TYPE="integration"
            shift
            ;;
        --models)
            TEST_TYPE="models"
            shift
            ;;
        --validation)
            TEST_TYPE="validation"
            shift
            ;;
        --middleware)
            TEST_TYPE="middleware"
            shift
            ;;
        --services)
            TEST_TYPE="services"
            shift
            ;;
        --controllers)
            TEST_TYPE="controllers"
            shift
            ;;
        --skip-docker)
            SKIP_DOCKER=true
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
done

# Install test dependencies if needed
if [ -f "requirements-test.txt" ]; then
    echo -e "${YELLOW}📦 Installing test dependencies...${NC}"
    pip install -r requirements-test.txt
fi

# Run tests based on options
if [ "$QUICK" = true ]; then
    echo -e "${YELLOW}⚡ Running quick tests...${NC}"
    python -m pytest tests/ -v --tb=short
elif [ -n "$TEST_TYPE" ]; then
    echo -e "${YELLOW}🎯 Running $TEST_TYPE tests...${NC}"
    case $TEST_TYPE in
        unit)
            python -m pytest tests/services/ -v --tb=short
            ;;
        integration)
            python -m pytest tests/controllers/ -v --tb=short
            ;;
        models)
            python -m pytest tests/models/ -v --tb=short
            ;;
        validation)
            python -m pytest tests/validation/ -v --tb=short
            ;;
        middleware)
            python -m pytest tests/middleware/ -v --tb=short
            ;;
        services)
            python -m pytest tests/services/ -v --tb=short
            ;;
        controllers)
            python -m pytest tests/controllers/ -v --tb=short
            ;;
    esac
else
    # Full test suite
    echo -e "${YELLOW}🚀 Running full test suite...${NC}"
    python -m pytest tests/ -v --cov=app --cov-report=term-missing --cov-report=html:htmlcov --tb=short
fi

# Check exit code
if [ $? -eq 0 ]; then
    echo -e "${GREEN}🎉 Tests completed successfully!${NC}"
else
    echo -e "${RED}❌ Tests failed!${NC}"
    exit 1
fi