"""
Test configuration and fixtures for the Paylens API tests.
"""
import os
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
import uuid

# Set test environment variables
os.environ["JWT_SECRET"] = "test-jwt-secret"
os.environ["REFRESH_TOKEN_SECRET"] = "test-refresh-secret"
os.environ["JWT_EXPIRES_IN"] = "1h"
os.environ["REFRESH_TOKEN_EXPIRES_IN"] = "7d"
os.environ["BCRYPT_ROUNDS"] = "4"  # Faster for tests
os.environ["DATABASE_URL"] = "postgresql://test:test@localhost:5432/test_db"

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from models.user import (
    UserInternal, UserResponse, CreateUserData, UpdateUserData, 
    UserRole, SubscriptionTier, GoogleProfile, AuthTokens, JWTPayload
)
from services.auth_service import AuthService
from services.user_service import UserService


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_db_service():
    """Mock database service for testing."""
    mock_service = AsyncMock()
    mock_service.query = AsyncMock(return_value={"rows": []})
    mock_service.fetchrow = AsyncMock(return_value=None)
    mock_service.execute = AsyncMock(return_value="INSERT 0 1")
    mock_service.initialize = AsyncMock()
    mock_service.close = AsyncMock()
    mock_service.health_check = AsyncMock(return_value=True)
    return mock_service


@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "id": str(uuid.uuid4()),
        "email": "test@example.com",
        "password": "hashed_password_123",
        "google_id": None,
        "first_name": "John",
        "last_name": "Doe",
        "company_name": "Test Company",
        "role": UserRole.USER,
        "subscription_tier": SubscriptionTier.FREE,
        "monthly_limit": 5,
        "usage_count": 0,
        "last_usage_reset": datetime.now(timezone.utc),
        "billing_period_start": datetime.now(timezone.utc),
        "is_active": True,
        "email_verified": True,
        "email_verification_token": None,
        "password_reset_token": None,
        "password_reset_expires": None,
        "stripe_customer_id": None,
        "subscription_id": None,
        "subscription_status": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }


@pytest.fixture
def sample_user_internal(sample_user_data):
    """Create a UserInternal instance from sample data."""
    return UserInternal(**sample_user_data)


@pytest.fixture
def sample_create_user_data():
    """Sample CreateUserData for testing."""
    return CreateUserData(
        email="test@example.com",
        password="TestPassword123!",
        first_name="John",
        last_name="Doe",
        company_name="Test Company"
    )


@pytest.fixture
def sample_google_profile():
    """Sample Google profile for testing."""
    return GoogleProfile(
        id="google_123456789",
        email="test@example.com",
        verified_email=True,
        name="John Doe",
        given_name="John",
        family_name="Doe",
        picture="https://example.com/photo.jpg",
        locale="en"
    )


@pytest.fixture
def sample_auth_tokens():
    """Sample auth tokens for testing."""
    return AuthTokens(
        access_token="test_access_token",
        refresh_token="test_refresh_token"
    )


@pytest.fixture
def auth_service():
    """Create AuthService instance for testing."""
    return AuthService()


@pytest.fixture
def user_service():
    """Create UserService instance for testing."""
    return UserService()


@pytest.fixture
def mock_user_service():
    """Mock user service for testing."""
    return AsyncMock(spec=UserService)


@pytest.fixture
def mock_auth_service():
    """Mock auth service for testing."""
    return AsyncMock(spec=AuthService)


@pytest.fixture
def valid_jwt_payload():
    """Valid JWT payload for testing."""
    return {
        "id": str(uuid.uuid4()),
        "email": "test@example.com",
        "role": "user",
        "subscription_tier": "free",
        "usage_count": 0,
        "monthly_limit": 5,
        "last_usage_reset": datetime.now(timezone.utc).isoformat(),
        "billing_period_start": datetime.now(timezone.utc).isoformat(),
        "iat": int(datetime.now(timezone.utc).timestamp())
    }


@pytest.fixture
def expired_jwt_payload():
    """Expired JWT payload for testing."""
    return {
        "id": str(uuid.uuid4()),
        "email": "test@example.com",
        "role": "user",
        "subscription_tier": "free",
        "usage_count": 0,
        "monthly_limit": 5,
        "last_usage_reset": datetime.now(timezone.utc).isoformat(),
        "billing_period_start": datetime.now(timezone.utc).isoformat(),
        "iat": int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp()),
        "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
    }


@pytest.fixture
def mock_fastapi_app():
    """Mock FastAPI app for testing."""
    from fastapi import FastAPI
    from app.controllers.auth import auth_router
    
    app = FastAPI()
    app.include_router(auth_router)
    return app


@pytest.fixture
def client(mock_fastapi_app):
    """Create test client for FastAPI app."""
    from fastapi.testclient import TestClient
    return TestClient(mock_fastapi_app)


@pytest.fixture
def mock_current_user():
    """Mock current user for authentication tests."""
    return {
        "id": str(uuid.uuid4()),
        "email": "test@example.com",
        "role": "user",
        "subscription_tier": "free",
        "usage_count": 0,
        "monthly_limit": 5,
        "last_usage_reset": datetime.now(timezone.utc),
        "billing_period_start": datetime.now(timezone.utc)
    }


# Database mock fixtures
@pytest.fixture
def mock_db_query_result():
    """Mock database query result."""
    return {
        "rows": [
            {
                "id": str(uuid.uuid4()),
                "email": "test@example.com",
                "password": "hashed_password",
                "google_id": None,
                "first_name": "John",
                "last_name": "Doe",
                "company_name": "Test Company",
                "role": "user",
                "subscription_tier": "free",
                "monthly_limit": 5,
                "usage_count": 0,
                "last_usage_reset": datetime.now(timezone.utc),
                "billing_period_start": datetime.now(timezone.utc),
                "is_active": True,
                "email_verified": True,
                "email_verification_token": None,
                "password_reset_token": None,
                "password_reset_expires": None,
                "stripe_customer_id": None,
                "subscription_id": None,
                "subscription_status": None,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
        ]
    }


@pytest.fixture
def mock_empty_db_result():
    """Mock empty database query result."""
    return {"rows": []}


# Test data generators
@pytest.fixture
def generate_test_users():
    """Generate multiple test users."""
    def _generate(count: int = 3):
        users = []
        for i in range(count):
            user_data = {
                "id": str(uuid.uuid4()),
                "email": f"test{i}@example.com",
                "password": f"hashed_password_{i}",
                "google_id": None,
                "first_name": f"User{i}",
                "last_name": "Test",
                "company_name": f"Company {i}",
                "role": UserRole.USER,
                "subscription_tier": SubscriptionTier.FREE,
                "monthly_limit": 5,
                "usage_count": 0,
                "last_usage_reset": datetime.now(timezone.utc),
                "billing_period_start": datetime.now(timezone.utc),
                "is_active": True,
                "email_verified": True,
                "email_verification_token": None,
                "password_reset_token": None,
                "password_reset_expires": None,
                "stripe_customer_id": None,
                "subscription_id": None,
                "subscription_status": None,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
            users.append(UserInternal(**user_data))
        return users
    return _generate


# Utility fixtures
@pytest.fixture
def freeze_time():
    """Freeze time for testing."""
    from freezegun import freeze_time
    return freeze_time


@pytest.fixture
def faker():
    """Faker instance for generating test data."""
    from faker import Faker
    return Faker()


@pytest.fixture(autouse=True)
def mock_database_services(mock_db_service):
    """Automatically mock database services for all tests."""
    with patch('services.db_service.db_service', mock_db_service), \
         patch('services.user_service.db_service', mock_db_service):
        yield
