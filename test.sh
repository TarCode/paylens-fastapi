#!/bin/bash
# Simple wrapper script for running tests easily

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
    echo "  --cleanup        Clean up test artifacts and stop containers"
    echo "  --help           Show this help message"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0                    # Run full test suite"
    echo "  $0 --quick           # Quick test run"
    echo "  $0 --unit            # Run only unit tests"
    echo "  $0 --skip-docker     # Run tests without Docker"
    echo "  $0 --cleanup         # Clean up test environment"
}

# Parse command line arguments
QUICK=false
CLEANUP_ONLY=false
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
        --cleanup)
            CLEANUP_ONLY=true
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

# Build the Python command
PYTHON_CMD="python setup_and_test.py"

if [ "$CLEANUP_ONLY" = true ]; then
    echo -e "${YELLOW}🧹 Running cleanup only...${NC}"
    $PYTHON_CMD --cleanup-only
    exit $?
fi

if [ "$QUICK" = true ]; then
    echo -e "${YELLOW}⚡ Running quick tests...${NC}"
    $PYTHON_CMD --quick
elif [ -n "$TEST_TYPE" ]; then
    echo -e "${YELLOW}🎯 Running $TEST_TYPE tests...${NC}"
    case $TEST_TYPE in
        unit)
            $PYTHON_CMD --test-path "tests/services/" --skip-docker
            ;;
        integration)
            $PYTHON_CMD --test-path "tests/controllers/" --skip-docker
            ;;
        models)
            $PYTHON_CMD --test-path "tests/models/" --skip-docker
            ;;
        validation)
            $PYTHON_CMD --test-path "tests/validation/" --skip-docker
            ;;
        middleware)
            $PYTHON_CMD --test-path "tests/middleware/" --skip-docker
            ;;
        services)
            $PYTHON_CMD --test-path "tests/services/" --skip-docker
            ;;
        controllers)
            $PYTHON_CMD --test-path "tests/controllers/" --skip-docker
            ;;
    esac
else
    # Full test suite
    if [ "$SKIP_DOCKER" = true ]; then
        echo -e "${YELLOW}🐳 Skipping Docker setup...${NC}"
        $PYTHON_CMD --skip-docker
    else
        echo -e "${YELLOW}🚀 Running full test suite...${NC}"
        $PYTHON_CMD
    fi
fi

# Check exit code
if [ $? -eq 0 ]; then
    echo -e "${GREEN}🎉 Tests completed successfully!${NC}"
else
    echo -e "${RED}❌ Tests failed!${NC}"
    exit 1
fi
