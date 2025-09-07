# Database commands
migrate:
	docker-compose -f docker-compose.dev.yml run --rm migrate

resetdb:
	docker-compose -f docker-compose.dev.yml run --rm resetdb

up:
	docker-compose -f docker-compose.dev.yml up --build

down:
	docker-compose -f docker-compose.dev.yml down

# Test commands
test: test-full

test-full:
	@echo "🧪 Running full test suite..."
	./test.sh

test-quick:
	@echo "⚡ Running quick tests..."
	./test.sh --quick

test-unit:
	@echo "🔬 Running unit tests..."
	./test.sh --unit

test-integration:
	@echo "🔗 Running integration tests..."
	./test.sh --integration

test-models:
	@echo "📊 Running model tests..."
	./test.sh --models

test-validation:
	@echo "✅ Running validation tests..."
	./test.sh --validation

test-middleware:
	@echo "🛡️ Running middleware tests..."
	./test.sh --middleware

test-services:
	@echo "⚙️ Running service tests..."
	./test.sh --services

test-controllers:
	@echo "🎮 Running controller tests..."
	./test.sh --controllers

test-no-docker:
	@echo "🐳 Running tests without Docker..."
	./test.sh --skip-docker

test-cleanup:
	@echo "🧹 Cleaning up test environment..."
	./test.sh --cleanup

# Development commands
setup-test-env:
	@echo "🔧 Setting up test environment..."
	python setup_and_test.py --skip-docker --skip-linting --skip-type-checking

install-deps:
	@echo "📦 Installing dependencies..."
	pip install -r requirements.txt
	pip install -r requirements-test.txt

# Help command
help:
	@echo "Available commands:"
	@echo ""
	@echo "Database:"
	@echo "  migrate      - Run database migrations"
	@echo "  resetdb      - Reset database"
	@echo "  up           - Start all services"
	@echo "  down         - Stop all services"
	@echo ""
	@echo "Testing:"
	@echo "  test         - Run full test suite (same as test-full)"
	@echo "  test-full    - Run complete test suite with all checks"
	@echo "  test-quick   - Run quick tests (skip Docker, linting, type checking)"
	@echo "  test-unit    - Run only unit tests"
	@echo "  test-integration - Run only integration tests"
	@echo "  test-models  - Run only model tests"
	@echo "  test-validation - Run only validation tests"
	@echo "  test-middleware - Run only middleware tests"
	@echo "  test-services - Run only service tests"
	@echo "  test-controllers - Run only controller tests"
	@echo "  test-no-docker - Run tests without Docker setup"
	@echo "  test-cleanup - Clean up test artifacts"
	@echo ""
	@echo "Development:"
	@echo "  setup-test-env - Set up test environment"
	@echo "  install-deps  - Install all dependencies"
	@echo "  help         - Show this help message"