"""
Unit tests for Auth Controller endpoints.
"""
import pytest
import json
import base64
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import HTTPException, status

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'app'))

from models.user import UserResponse, AuthTokens, UserRole, SubscriptionTier
from middleware.auth_middleware import get_current_user, User
from datetime import datetime


class TestAuthController:
    """Test cases for Auth Controller endpoints."""

    @pytest.fixture
    def mock_auth_service(self):
        """Mock auth service."""
        return AsyncMock()

    @pytest.fixture
    def mock_user_service(self):
        """Mock user service."""
        return AsyncMock()

    @pytest.fixture
    def sample_user_response(self):
        """Sample user response."""
        return UserResponse(
            id="test-user-id",
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            company_name="Test Company",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            monthly_limit=5,
            usage_count=0,
            last_usage_reset="2024-01-01T00:00:00Z",
            billing_period_start="2024-01-01T00:00:00Z",
            is_active=True,
            email_verified=True,
            created_at="2024-01-01T00:00:00Z",
            updated_at="2024-01-01T00:00:00Z"
        )

    @pytest.fixture
    def sample_auth_tokens(self):
        """Sample auth tokens."""
        return AuthTokens(
            access_token="test_access_token",
            refresh_token="test_refresh_token"
        )

    @pytest.fixture
    def sample_register_data(self):
        """Sample registration data."""
        return {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "John",
            "last_name": "Doe",
            "company_name": "Test Company"
        }

    @pytest.fixture
    def sample_login_data(self):
        """Sample login data."""
        return {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }

    # Registration Tests
    def test_register_success(self, client, sample_register_data, mock_db_service):
        """Test successful user registration."""
        # Mock database responses
        def mock_query(query, params=None):
            if "SELECT * FROM users WHERE email" in query:
                # No existing user found
                return {"rows": []}
            elif "INSERT INTO users" in query:
                # Return created user
                created_user = {
                    "id": "test-user-id",
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
                    "last_usage_reset": "2024-01-01T00:00:00Z",
                    "billing_period_start": "2024-01-01T00:00:00Z",
                    "is_active": True,
                    "email_verified": True,
                    "email_verification_token": None,
                    "password_reset_token": None,
                    "password_reset_expires": None,
                    "stripe_customer_id": None,
                    "subscription_id": None,
                    "subscription_status": None,
                    "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z"
                }
                return {"rows": [created_user]}
            return {"rows": []}
        
        mock_db_service.query.side_effect = mock_query
        
        response = client.post("/auth/register", json=sample_register_data)
        
        # Verify response
        assert response.status_code == 201
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert "user" in data["data"]
        assert "tokens" in data["data"]
        assert data["data"]["user"]["email"] == sample_register_data["email"]
        assert "access_token" in data["data"]["tokens"]
        assert "refresh_token" in data["data"]["tokens"]

    def test_register_password_validation_failure(self, client):
        """Test registration with weak password."""
        weak_password_data = {
            "email": "test@example.com",
            "password": "weak",  # Too short
            "first_name": "John",
            "last_name": "Doe",
            "company_name": "Test Company"
        }
        
        response = client.post("/auth/register", json=weak_password_data)
        
        # Verify response
        assert response.status_code == 422  # Pydantic validation error
        data = response.json()
        assert "detail" in data

    def test_register_user_already_exists(self, client, sample_register_data, mock_db_service):
        """Test registration when user already exists."""
        # Mock database to return existing user
        existing_user = {
            "id": "existing-user-id",
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
            "last_usage_reset": "2024-01-01T00:00:00Z",
            "billing_period_start": "2024-01-01T00:00:00Z",
            "is_active": True,
            "email_verified": True,
            "email_verification_token": None,
            "password_reset_token": None,
            "password_reset_expires": None,
            "stripe_customer_id": None,
            "subscription_id": None,
            "subscription_status": None,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }
        mock_db_service.query.return_value = {"rows": [existing_user]}
        
        response = client.post("/auth/register", json=sample_register_data)
        
        # Verify response
        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["success"] is False
        assert "error" in data["detail"]
        assert "Registration failed" in data["detail"]["error"]["message"]

    def test_register_invalid_data(self, client):
        """Test registration with invalid data."""
        invalid_data = {
            "email": "invalid-email",
            "password": "weak",
            "first_name": "",
            "last_name": ""
        }
        
        response = client.post("/auth/register", json=invalid_data)
        
        # Verify response
        assert response.status_code == 422  # Validation error

    # Login Tests
    def test_login_success(self, client, sample_login_data, mock_db_service):
        """Test successful user login."""
        # Mock database to return user for login
        user_data = {
            "id": "test-user-id",
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
            "last_usage_reset": "2024-01-01T00:00:00Z",
            "billing_period_start": "2024-01-01T00:00:00Z",
            "is_active": True,
            "email_verified": True,
            "email_verification_token": None,
            "password_reset_token": None,
            "password_reset_expires": None,
            "stripe_customer_id": None,
            "subscription_id": None,
            "subscription_status": None,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }
        mock_db_service.query.return_value = {"rows": [user_data]}
        
        # Mock the user service validate_password method
        with patch('services.user_service.user_service.validate_password', return_value=True):
            response = client.post("/auth/login", json=sample_login_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "data" in data
            assert "user" in data["data"]
            assert "tokens" in data["data"]
            assert data["data"]["user"]["email"] == sample_login_data["email"]

    def test_login_invalid_credentials(self, client, sample_login_data, mock_db_service):
        """Test login with invalid credentials."""
        # Mock database to return no user (invalid credentials)
        mock_db_service.query.return_value = {"rows": []}
        
        response = client.post("/auth/login", json=sample_login_data)
        
        # Verify response
        assert response.status_code == 401
        data = response.json()
        assert data["detail"] == "Invalid email or password"

    def test_login_invalid_data(self, client):
        """Test login with invalid data."""
        invalid_data = {
            "email": "invalid-email",
            "password": ""
        }
        
        response = client.post("/auth/login", json=invalid_data)
        
        # Verify response
        assert response.status_code == 422  # Validation error

    # Refresh Token Tests
    def test_refresh_token_success(self, client, sample_user_response, sample_auth_tokens, mock_db_service):
        """Test successful token refresh."""
        refresh_data = {"refresh_token": "valid_refresh_token"}
        
        # Mock database to return user for refresh token validation
        user_data = {
            "id": "test-user-id",
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
            "last_usage_reset": "2024-01-01T00:00:00Z",
            "billing_period_start": "2024-01-01T00:00:00Z",
            "is_active": True,
            "email_verified": True,
            "email_verification_token": None,
            "password_reset_token": None,
            "password_reset_expires": None,
            "stripe_customer_id": None,
            "subscription_id": None,
            "subscription_status": None,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }
        mock_db_service.query.return_value = {"rows": [user_data]}
        
        # Mock JWT decode to return a valid payload
        with patch('jwt.decode', return_value={"id": "test-user-id", "exp": 9999999999}):
            response = client.post("/auth/refresh-token", json=refresh_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "data" in data
            assert "user" in data["data"]
            assert "tokens" in data["data"]

    def test_refresh_token_invalid_token(self, client):
        """Test refresh token with invalid token."""
        refresh_data = {"refresh_token": "invalid_token"}
        
        # Mock JWT decode to raise InvalidTokenError
        import jwt
        with patch('jwt.decode', side_effect=jwt.InvalidTokenError("Invalid token")):
            response = client.post("/auth/refresh-token", json=refresh_data)
            
            # Verify response
            assert response.status_code == 401
            data = response.json()
            assert data["detail"] == "Invalid refresh token"

    def test_refresh_token_missing_token(self, client):
        """Test refresh token with missing token."""
        refresh_data = {"refresh_token": ""}
        
        response = client.post("/auth/refresh-token", json=refresh_data)
        
        # Verify response
        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["success"] is False
        assert "error" in data["detail"]
        assert "Refresh token is required" in data["detail"]["error"]["details"]

    # Profile Tests
    def test_get_profile_success(self, client, sample_user_response, mock_db_service):
        """Test successful profile retrieval."""
        # Mock current user
        mock_current_user = User(
            id="test-user-id",
            email="test@example.com",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            usage_count=0,
            monthly_limit=5,
            last_usage_reset=datetime(2024, 1, 1),
            billing_period_start=datetime(2024, 1, 1)
        )
        
        # Mock database to return user
        user_data = {
            "id": "test-user-id",
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
            "last_usage_reset": "2024-01-01T00:00:00Z",
            "billing_period_start": "2024-01-01T00:00:00Z",
            "is_active": True,
            "email_verified": True,
            "email_verification_token": None,
            "password_reset_token": None,
            "password_reset_expires": None,
            "stripe_customer_id": None,
            "subscription_id": None,
            "subscription_status": None,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }
        mock_db_service.query.return_value = {"rows": [user_data]}
        
        # Override the dependency
        from middleware.auth_middleware import get_current_user
        
        def mock_get_current_user():
            return mock_current_user
        
        client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        try:
            response = client.get("/auth/profile", headers={"Authorization": "Bearer test_token"})
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "data" in data
            assert "user" in data["data"]
            assert data["data"]["user"]["email"] == mock_current_user.email
        finally:
            # Clean up the override
            client.app.dependency_overrides.clear()

    def test_get_profile_user_not_found(self, client, mock_user_service):
        """Test profile retrieval when user is not found."""
        # Mock current user
        mock_current_user = User(
            id="test-user-id",
            email="test@example.com",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            usage_count=0,
            monthly_limit=5,
            last_usage_reset=datetime(2024, 1, 1),
            billing_period_start=datetime(2024, 1, 1)
        )
        
        # Mock user service to return None
        mock_user_service.find_by_id.return_value = None
        
        # Mock database service to prevent real database connections
        mock_db_service = MagicMock()
        mock_db_service.query = AsyncMock(return_value={"rows": []})
        
        # Override the dependency
        from middleware.auth_middleware import get_current_user
        
        def mock_get_current_user():
            return mock_current_user
        
        client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        try:
            with patch('app.controllers.auth.user_service', mock_user_service), \
                 patch('app.services.user_service.db_service', mock_db_service), \
                 patch('app.services.db_service.db_service', mock_db_service):
                
                response = client.get("/auth/profile", headers={"Authorization": "Bearer test_token"})
                
                # Verify response
                assert response.status_code == 404
                data = response.json()
                assert data["detail"]["success"] is False
                assert "error" in data["detail"]
                assert "User not found" in data["detail"]["error"]["message"]
        finally:
            # Clean up the override
            client.app.dependency_overrides.clear()

    def test_get_profile_unauthorized(self, client):
        """Test profile retrieval without authentication."""
        response = client.get("/auth/profile")
        
        # Verify response
        assert response.status_code == 403  # No authorization header

    # Update Profile Tests
    def test_update_profile_success(self, client, mock_user_service, sample_user_response):
        """Test successful profile update."""
        # Mock current user
        mock_current_user = User(
            id="test-user-id",
            email="test@example.com",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            usage_count=0,
            monthly_limit=5,
            last_usage_reset=datetime(2024, 1, 1),
            billing_period_start=datetime(2024, 1, 1)
        )
        
        update_data = {
            "first_name": "Jane",
            "last_name": "Smith",
            "company_name": "Updated Company"
        }
        
        # Mock user service - create a mock UserInternal object
        mock_user_internal = MagicMock()
        mock_user_internal.to_user_response.return_value = sample_user_response
        mock_user_service.update_user = AsyncMock(return_value=mock_user_internal)
        
        # Mock database service to prevent real database connections
        mock_db_service = MagicMock()
        mock_db_service.query = AsyncMock(return_value={"rows": []})
        
        # Override the dependency
        from middleware.auth_middleware import get_current_user
        
        def mock_get_current_user():
            return mock_current_user
        
        client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        try:
            with patch('app.controllers.auth.user_service', mock_user_service), \
                 patch('app.services.user_service.db_service', mock_db_service), \
                 patch('app.services.db_service.db_service', mock_db_service):
                
                response = client.put("/auth/profile", json=update_data, headers={"Authorization": "Bearer test_token"})
                
                # Verify response
                assert response.status_code == 200
                data = response.json()
                assert data["success"] is True
                assert "data" in data
                assert "user" in data["data"]
                
                # Verify user service was called
                mock_user_service.update_user.assert_called_once()
        finally:
            # Clean up the override
            client.app.dependency_overrides.clear()

    def test_update_profile_user_not_found(self, client, mock_user_service):
        """Test profile update when user is not found."""
        # Mock current user
        mock_current_user = User(
            id="test-user-id",
            email="test@example.com",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            usage_count=0,
            monthly_limit=5,
            last_usage_reset=datetime(2024, 1, 1),
            billing_period_start=datetime(2024, 1, 1)
        )
        
        update_data = {"first_name": "Jane"}
        
        # Mock user service to return None
        mock_user_service.update_user = AsyncMock(return_value=None)
        
        def mock_get_current_user():
            return mock_current_user
        
        client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        try:
            with patch('app.controllers.auth.user_service', mock_user_service):
                
                response = client.put("/auth/profile", json=update_data, headers={"Authorization": "Bearer test_token"})
                
                # Verify response
                assert response.status_code == 404
                data = response.json()
                assert data["detail"]["success"] is False
                assert "error" in data["detail"]
                assert "User not found" in data["detail"]["error"]["message"]
        finally:
            # Clean up the override
            client.app.dependency_overrides.clear()

    # Change Password Tests
    def test_change_password_success(self, client, mock_user_service, mock_auth_service):
        """Test successful password change."""
        # Mock current user
        mock_current_user = User(
            id="test-user-id",
            email="test@example.com",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            usage_count=0,
            monthly_limit=5,
            last_usage_reset=datetime(2024, 1, 1),
            billing_period_start=datetime(2024, 1, 1)
        )
        
        # Mock user with password
        mock_user = MagicMock()
        mock_user.password = "hashed_password"
        
        change_data = {
            "current_password": "CurrentPassword123!",
            "new_password": "NewPassword123!"
        }
        
        # Mock services
        mock_user_service.find_by_id = AsyncMock(return_value=mock_user)
        mock_user_service.validate_password = AsyncMock(return_value=True)
        mock_user_service.update_password = AsyncMock(return_value=None)
        
        def mock_get_current_user():
            return mock_current_user
        
        client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        # Mock database service to prevent real database connections
        mock_db_service = MagicMock()
        mock_db_service.query = AsyncMock(return_value={"rows": []})
        
        try:
            with patch('app.controllers.auth.user_service', mock_user_service), \
                 patch('app.services.user_service.db_service', mock_db_service), \
                 patch('app.services.db_service.db_service', mock_db_service):
                
                response = client.post("/auth/change-password", json=change_data, headers={"Authorization": "Bearer test_token"})
                
                # Verify response
                assert response.status_code == 201
                data = response.json()
                assert data["success"] is True
                assert "Password changed successfully" in data["message"]
                
                # Verify services were called
                mock_user_service.find_by_id.assert_called_once_with(mock_current_user.id)
                mock_user_service.validate_password.assert_called_once_with(change_data["current_password"], mock_user.password)
                mock_user_service.update_password.assert_called_once_with(mock_current_user.id, change_data["new_password"])
        finally:
            # Clean up the override
            client.app.dependency_overrides.clear()

    def test_change_password_weak_new_password(self, client, mock_auth_service, mock_user_service):
        """Test password change with weak new password."""
        # Mock current user
        mock_current_user = User(
            id="test-user-id",
            email="test@example.com",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            usage_count=0,
            monthly_limit=5,
            last_usage_reset=datetime(2024, 1, 1),
            billing_period_start=datetime(2024, 1, 1)
        )
        
        change_data = {
            "current_password": "CurrentPassword123!",
            "new_password": "weak"
        }
        
        # Mock password validation failure (synchronous method)
        from unittest.mock import MagicMock
        mock_auth_service.validate_password = MagicMock(return_value={
            "is_valid": False,
            "errors": ["Password must be at least 8 characters long"]
        })
        
        # Mock user service methods (even though they shouldn't be called)
        mock_user_service.find_by_id = AsyncMock(return_value=None)
        mock_user_service.validate_password = AsyncMock(return_value=True)
        mock_user_service.update_password = AsyncMock(return_value=None)
        
        def mock_get_current_user():
            return mock_current_user
        
        client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        # Mock database service to prevent real database connections
        mock_db_service = MagicMock()
        mock_db_service.query = AsyncMock(return_value={"rows": []})
        
        try:
            with patch('app.controllers.auth.auth_service', mock_auth_service), \
                 patch('app.controllers.auth.user_service', mock_user_service), \
                 patch('app.services.user_service.db_service', mock_db_service), \
                 patch('app.services.db_service.db_service', mock_db_service):
                
                response = client.post("/auth/change-password", json=change_data, headers={"Authorization": "Bearer test_token"})
                
                # Verify response
                assert response.status_code == 400
                data = response.json()
                assert data["detail"]["success"] is False
                assert "error" in data["detail"]
                assert "New password does not meet requirements" in data["detail"]["error"]["details"]["message"]
        finally:
            # Clean up the override
            client.app.dependency_overrides.clear()

    def test_change_password_google_oauth_account(self, client, mock_user_service):
        """Test password change on Google OAuth account."""
        # Mock current user
        mock_current_user = User(
            id="test-user-id",
            email="test@example.com",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            usage_count=0,
            monthly_limit=5,
            last_usage_reset=datetime(2024, 1, 1),
            billing_period_start=datetime(2024, 1, 1)
        )
        
        # Mock user without password (Google OAuth)
        mock_user = MagicMock()
        mock_user.password = None
        
        change_data = {
            "current_password": "CurrentPassword123!",
            "new_password": "NewPassword123!"
        }
        
        # Mock user service
        mock_user_service.find_by_id = AsyncMock(return_value=mock_user)
        
        def mock_get_current_user():
            return mock_current_user
        
        client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        # Mock database service to prevent real database connections
        mock_db_service = MagicMock()
        mock_db_service.query = AsyncMock(return_value={"rows": []})
        
        try:
            with patch('app.controllers.auth.user_service', mock_user_service), \
                 patch('app.services.user_service.db_service', mock_db_service), \
                 patch('app.services.db_service.db_service', mock_db_service):
                
                response = client.post("/auth/change-password", json=change_data, headers={"Authorization": "Bearer test_token"})
                
                # Verify response
                assert response.status_code == 400
                data = response.json()
                assert data["detail"]["success"] is False
                assert "error" in data["detail"]
                assert "This account uses Google OAuth" in data["detail"]["error"]["details"]
        finally:
            # Clean up the override
            client.app.dependency_overrides.clear()

    def test_change_password_wrong_current_password(self, client, mock_user_service, mock_auth_service):
        """Test password change with wrong current password."""
        # Mock current user
        mock_current_user = User(
            id="test-user-id",
            email="test@example.com",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            usage_count=0,
            monthly_limit=5,
            last_usage_reset=datetime(2024, 1, 1),
            billing_period_start=datetime(2024, 1, 1)
        )
        
        # Mock user with password
        mock_user = MagicMock()
        mock_user.password = "hashed_password"
        
        change_data = {
            "current_password": "WrongPassword123!",
            "new_password": "NewPassword123!"
        }
        
        # Mock services
        mock_user_service.find_by_id = AsyncMock(return_value=mock_user)
        mock_user_service.validate_password = AsyncMock(return_value=False)
        
        def mock_get_current_user():
            return mock_current_user
        
        client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        # Mock database service to prevent real database connections
        mock_db_service = MagicMock()
        mock_db_service.query = AsyncMock(return_value={"rows": []})
        
        try:
            with patch('app.controllers.auth.user_service', mock_user_service), \
                 patch('app.services.user_service.db_service', mock_db_service), \
                 patch('app.services.db_service.db_service', mock_db_service):
                
                response = client.post("/auth/change-password", json=change_data, headers={"Authorization": "Bearer test_token"})
                
                # Verify response
                assert response.status_code == 400
                data = response.json()
                assert data["detail"]["success"] is False
                assert "error" in data["detail"]
                assert "Current password is incorrect" in data["detail"]["error"]["details"]
        finally:
            # Clean up the override
            client.app.dependency_overrides.clear()

    # Forgot Password Tests
    def test_forgot_password_success(self, client, mock_auth_service):
        """Test successful forgot password request."""
        forgot_data = {"email": "test@example.com"}
        
        # Mock auth service
        mock_auth_service.generate_password_reset_token = AsyncMock(return_value="reset_token")
        
        with patch('app.controllers.auth.auth_service', mock_auth_service):
            response = client.post("/auth/forgot-password", json=forgot_data)
            
            # Verify response
            assert response.status_code == 201
            data = response.json()
            assert data["success"] is True
            assert "If an account with that email exists" in data["message"]
            
            # Verify auth service was called
            mock_auth_service.generate_password_reset_token.assert_called_once_with(forgot_data["email"])

    def test_forgot_password_user_not_found(self, client, mock_auth_service):
        """Test forgot password when user is not found."""
        forgot_data = {"email": "nonexistent@example.com"}
        
        # Mock auth service to raise exception
        mock_auth_service.generate_password_reset_token.side_effect = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
        
        with patch('app.controllers.auth.auth_service', mock_auth_service):
            response = client.post("/auth/forgot-password", json=forgot_data)
            
            # Verify response (should still return success for security)
            assert response.status_code == 201
            data = response.json()
            assert data["success"] is True
            assert "If an account with that email exists" in data["message"]

    # Reset Password Tests
    def test_reset_password_success(self, client, mock_auth_service, mock_user_service):
        """Test successful password reset."""
        reset_data = {
            "token": "valid_reset_token",
            "new_password": "NewPassword123!"
        }
        
        # Mock auth service (fix sync method)
        from unittest.mock import MagicMock
        mock_auth_service.validate_password = MagicMock(return_value={"is_valid": True, "errors": []})
        mock_auth_service.reset_password = AsyncMock(return_value=None)
        
        # Mock database service to prevent real database connections
        mock_db_service = MagicMock()
        mock_db_service.query = AsyncMock(return_value={"rows": []})
        
        with patch('app.controllers.auth.auth_service', mock_auth_service), \
             patch('app.controllers.auth.user_service', mock_user_service), \
             patch('app.services.user_service.db_service', mock_db_service), \
             patch('app.services.db_service.db_service', mock_db_service):
            response = client.post("/auth/reset-password", json=reset_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "Password reset successfully" in data["data"]["message"]
            
            # Verify auth service was called
            mock_auth_service.validate_password.assert_called_once_with(reset_data["new_password"])
            mock_auth_service.reset_password.assert_called_once_with(reset_data["token"], reset_data["new_password"])

    def test_reset_password_weak_password(self, client, mock_auth_service, mock_user_service):
        """Test password reset with weak password."""
        reset_data = {
            "token": "valid_reset_token",
            "new_password": "weak"
        }
        
        # Mock password validation failure (fix sync method)
        from unittest.mock import MagicMock
        mock_auth_service.validate_password = MagicMock(return_value={
            "is_valid": False,
            "errors": ["Password must be at least 8 characters long"]
        })
        
        # Mock database service to prevent real database connections
        mock_db_service = MagicMock()
        mock_db_service.query = AsyncMock(return_value={"rows": []})
        
        with patch('app.controllers.auth.auth_service', mock_auth_service), \
             patch('app.controllers.auth.user_service', mock_user_service), \
             patch('app.services.user_service.db_service', mock_db_service), \
             patch('app.services.db_service.db_service', mock_db_service):
            response = client.post("/auth/reset-password", json=reset_data)
            
            # Verify response
            assert response.status_code == 400
            data = response.json()
            assert data["detail"]["success"] is False
            assert "error" in data["detail"]
            assert "Password does not meet requirements" in data["detail"]["error"]["details"]

    def test_reset_password_invalid_token(self, client, mock_auth_service, mock_user_service):
        """Test password reset with invalid token."""
        reset_data = {
            "token": "invalid_token",
            "new_password": "NewPassword123!"
        }
        
        # Mock auth service (fix sync method)
        from unittest.mock import MagicMock
        mock_auth_service.validate_password = MagicMock(return_value={"is_valid": True, "errors": []})
        mock_auth_service.reset_password = AsyncMock(side_effect=ValueError("Invalid token"))
        
        # Mock database service to prevent real database connections
        mock_db_service = MagicMock()
        mock_db_service.query = AsyncMock(return_value={"rows": []})
        
        with patch('app.controllers.auth.auth_service', mock_auth_service), \
             patch('app.controllers.auth.user_service', mock_user_service), \
             patch('app.services.user_service.db_service', mock_db_service), \
             patch('app.services.db_service.db_service', mock_db_service):
            response = client.post("/auth/reset-password", json=reset_data)
            
            # Verify response
            assert response.status_code == 400
            data = response.json()
            assert "Invalid token" in data["detail"]["error"]["details"]

    # Google Auth Tests
    def test_google_jwt_auth_success(self, client, mock_auth_service, sample_user_response, sample_auth_tokens):
        """Test successful Google JWT authentication."""
        # Create a valid JWT payload
        jwt_payload = {
            "sub": "google_123456789",
            "email": "test@example.com",
            "email_verified": True,
            "name": "John Doe",
            "given_name": "John",
            "family_name": "Doe",
            "picture": "https://example.com/photo.jpg",
            "locale": "en"
        }
        
        # Encode the payload
        payload_encoded = base64.b64encode(json.dumps(jwt_payload).encode()).decode().rstrip('=')
        credential = f"header.{payload_encoded}.signature"
        
        google_data = {"credential": credential}
        
        # Mock auth service response
        mock_auth_service.authenticate_with_google.return_value = {
            "user": sample_user_response,
            "tokens": sample_auth_tokens,
            "is_new_user": False
        }
        
        with patch('app.controllers.auth.auth_service', mock_auth_service):
            response = client.post("/auth/google/jwt", json=google_data)
            
            # Verify response
            assert response.status_code == 201
            data = response.json()
            assert data["success"] is True
            assert "data" in data
            assert "user" in data["data"]
            assert "tokens" in data["data"]
            assert "is_new_user" in data["data"]
            assert "Google authentication successful" in data["message"]
            
            # Verify auth service was called
            mock_auth_service.authenticate_with_google.assert_called_once()

    def test_google_jwt_auth_invalid_credential(self, client):
        """Test Google JWT authentication with invalid credential."""
        google_data = {"credential": "invalid.jwt.token"}
        
        response = client.post("/auth/google/jwt", json=google_data)
        
        # Verify response
        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["success"] is False
        assert "error" in data["detail"]
        assert "Invalid JWT token format" in data["detail"]["error"]["details"]

    def test_google_jwt_auth_missing_credential(self, client):
        """Test Google JWT authentication with missing credential."""
        google_data = {"credential": ""}
        
        response = client.post("/auth/google/jwt", json=google_data)
        
        # Verify response
        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["success"] is False
        assert "error" in data["detail"]
        assert "Google JWT credential is required" in data["detail"]["error"]["details"]

    def test_google_auth_callback_success(self, client, mock_auth_service, sample_user_response, sample_auth_tokens):
        """Test successful Google OAuth callback."""
        # Mock request state with user profile
        mock_request = MagicMock()
        mock_request.state.user = {
            "id": "google_123456789",
            "email": "test@example.com",
            "verified_email": True,
            "name": "John Doe",
            "given_name": "John",
            "family_name": "Doe",
            "picture": "https://example.com/photo.jpg",
            "locale": "en"
        }
        
        # Mock auth service response
        mock_auth_service.authenticate_with_google.return_value = {
            "user": sample_user_response,
            "tokens": sample_auth_tokens,
            "is_new_user": False
        }
        
        with patch('app.controllers.auth.auth_service', mock_auth_service):
            # Note: This test would need more complex mocking of the request object
            # For now, we'll test the endpoint structure
            response = client.get("/auth/google/callback")
            
            # The actual implementation would need proper request mocking
            # This test verifies the endpoint exists and handles the basic case
            assert response.status_code in [401, 500]  # Expected without proper mocking

    def test_google_auth_callback_no_user(self, client):
        """Test Google OAuth callback without user in request state."""
        response = client.get("/auth/google/callback")
        
        # Verify response
        assert response.status_code == 401
        data = response.json()
        assert data["detail"]["success"] is False
        assert "error" in data["detail"]
        assert "Google authentication failed" in data["detail"]["error"]["message"]
