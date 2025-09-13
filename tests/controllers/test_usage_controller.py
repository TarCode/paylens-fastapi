"""
Unit tests for Usage Controller endpoints.
"""
import pytest
import time
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import HTTPException, status

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'app'))

from models.user import UserRole, SubscriptionTier
from middleware.auth_middleware import get_current_user, User
from datetime import datetime


class TestUsageController:
    """Test cases for Usage Controller endpoints."""

    @pytest.fixture(autouse=True)
    def clear_rate_limit_cache(self):
        """Clear rate limiting cache before each test."""
        from controllers.usage import recent_requests
        recent_requests.clear()
        yield
        recent_requests.clear()

    @pytest.fixture
    def mock_user_service(self):
        """Mock user service."""
        return AsyncMock()

    @pytest.fixture
    def mock_auth_service(self):
        """Mock auth service."""
        return AsyncMock()

    @pytest.fixture
    def sample_current_user(self):
        """Sample current user for authentication."""
        return User(
            id="test-user-id",
            email="test@example.com",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            usage_count=0,
            monthly_limit=5,
            last_usage_reset=datetime(2024, 1, 1),
            billing_period_start=datetime(2024, 1, 1)
        )

    @pytest.fixture
    def sample_user_internal(self):
        """Sample UserInternal object."""
        from models.user import UserInternal
        return UserInternal(
            id="test-user-id",
            email="test@example.com",
            password="hashed_password",
            google_id=None,
            first_name="John",
            last_name="Doe",
            company_name="Test Company",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            monthly_limit=5,
            usage_count=0,
            last_usage_reset=datetime(2024, 1, 1),
            billing_period_start=datetime(2024, 1, 1),
            is_active=True,
            email_verified=True,
            email_verification_token=None,
            password_reset_token=None,
            password_reset_expires=None,
            stripe_customer_id=None,
            subscription_id=None,
            subscription_status=None,
            created_at=datetime(2024, 1, 1),
            updated_at=datetime(2024, 1, 1)
        )

    @pytest.fixture
    def sample_auth_tokens(self):
        """Sample auth tokens."""
        from models.user import AuthTokens
        return AuthTokens(
            access_token="new_access_token",
            refresh_token="new_refresh_token"
        )

    @pytest.fixture
    def usage_client(self):
        """Create test client with usage router."""
        from fastapi import FastAPI
        from controllers.usage import usage_router
        
        app = FastAPI()
        app.include_router(usage_router)
        
        return TestClient(app)

    # Increment Usage Tests
    def test_increment_usage_success(self, usage_client, sample_current_user, sample_user_internal, sample_auth_tokens, mock_user_service, mock_auth_service):
        """Test successful usage increment."""
        # Mock user service increment result
        updated_user = sample_user_internal.model_copy()
        updated_user.usage_count = 1
        
        increment_result = {
            "user": updated_user,
            "can_increment": True,
            "was_reset": False
        }
        mock_user_service.increment_usage_count.return_value = increment_result
        
        # Mock auth service token generation
        mock_auth_service.generate_tokens.return_value = sample_auth_tokens
        
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        # Mock the request object
        with patch('controllers.usage.user_service', mock_user_service), \
             patch('controllers.usage.auth_service', mock_auth_service):
            
            response = usage_client.post("/usage/increment")
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert "user" in data
            assert "tokens" in data
            assert "usage_count" in data
            assert "monthly_limit" in data
            assert "was_reset" in data
            assert data["usage_count"] == 1
            assert data["monthly_limit"] == 5
            assert data["was_reset"] is False
            
            # Verify services were called
            mock_user_service.increment_usage_count.assert_called_once_with(sample_current_user.id)
            mock_auth_service.generate_tokens.assert_called_once_with(updated_user)
        
        # Clean up
        usage_client.app.dependency_overrides.clear()

    def test_increment_usage_limit_exceeded(self, usage_client, sample_current_user, sample_user_internal, mock_user_service):
        """Test usage increment when limit is exceeded."""
        # Mock user service increment result - limit exceeded
        user_at_limit = sample_user_internal.model_copy()
        user_at_limit.usage_count = 5  # At limit
        
        increment_result = {
            "user": user_at_limit,
            "can_increment": False,
            "error": "Usage limit exceeded. Current: 5, Limit: 5",
            "was_reset": False
        }
        mock_user_service.increment_usage_count.return_value = increment_result
        
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        with patch('controllers.usage.user_service', mock_user_service):
            response = usage_client.post("/usage/increment")
            
            # Verify response
            assert response.status_code == 429
            data = response.json()
            assert data["detail"]["success"] is False
            assert "error" in data["detail"]
            assert data["detail"]["error"]["code"] == "USAGE_LIMIT_EXCEEDED"
            assert data["detail"]["error"]["current_usage"] == 5
            assert data["detail"]["error"]["limit"] == 5
            assert data["detail"]["error"]["was_reset"] is False
            
            # Verify service was called
            mock_user_service.increment_usage_count.assert_called_once_with(sample_current_user.id)
        
        # Clean up
        usage_client.app.dependency_overrides.clear()

    def test_increment_usage_user_not_found(self, usage_client, sample_current_user, mock_user_service):
        """Test usage increment when user is not found."""
        # Mock user service increment result - user not found
        increment_result = {
            "user": None,
            "can_increment": False,
            "error": "User not found"
        }
        mock_user_service.increment_usage_count.return_value = increment_result
        
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        with patch('controllers.usage.user_service', mock_user_service):
            response = usage_client.post("/usage/increment")
            
            # Verify response
            assert response.status_code == 404
            data = response.json()
            assert data["detail"]["success"] is False
            assert "error" in data["detail"]
            assert "User not found" in data["detail"]["error"]["message"]
            
            # Verify service was called
            mock_user_service.increment_usage_count.assert_called_once_with(sample_current_user.id)
        
        # Clean up
        usage_client.app.dependency_overrides.clear()

    def test_increment_usage_rate_limiting(self, usage_client, sample_current_user, mock_user_service):
        """Test usage increment rate limiting (deduplication)."""
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        with patch('controllers.usage.user_service', mock_user_service):
            # Make first request
            response1 = usage_client.post("/usage/increment")
            # First request should fail due to mocking, but that's not the point here
            
            # Make second request immediately (should be rate limited)
            response2 = usage_client.post("/usage/increment")
            
            # The second request should be rate limited
            assert response2.status_code == 429
            data = response2.json()
            assert data["detail"]["success"] is False
            assert "error" in data["detail"]
            assert data["detail"]["error"]["code"] == "REQUEST_TOO_FREQUENT"
            assert "Request too frequent" in data["detail"]["error"]["message"]
        
        # Clean up
        usage_client.app.dependency_overrides.clear()

    def test_increment_usage_after_reset(self, usage_client, sample_current_user, sample_user_internal, sample_auth_tokens, mock_user_service, mock_auth_service):
        """Test usage increment after monthly reset."""
        # Mock user service increment result with reset
        reset_user = sample_user_internal.model_copy()
        reset_user.usage_count = 1  # First usage after reset
        
        increment_result = {
            "user": reset_user,
            "can_increment": True,
            "was_reset": True
        }
        mock_user_service.increment_usage_count.return_value = increment_result
        mock_auth_service.generate_tokens.return_value = sample_auth_tokens
        
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        with patch('controllers.usage.user_service', mock_user_service), \
             patch('controllers.usage.auth_service', mock_auth_service):
            
            response = usage_client.post("/usage/increment")
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert data["was_reset"] is True
            assert data["usage_count"] == 1
        
        # Clean up
        usage_client.app.dependency_overrides.clear()

    def test_increment_usage_service_error(self, usage_client, sample_current_user, mock_user_service):
        """Test usage increment when service throws an error."""
        # Mock user service to throw an exception
        mock_user_service.increment_usage_count.side_effect = Exception("Database error")
        
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        with patch('controllers.usage.user_service', mock_user_service):
            response = usage_client.post("/usage/increment")
            
            # Verify response
            assert response.status_code == 500
            data = response.json()
            assert data["detail"]["success"] is False
            assert "error" in data["detail"]
            assert "Failed to increment usage" in data["detail"]["error"]["message"]
        
        # Clean up
        usage_client.app.dependency_overrides.clear()

    def test_increment_usage_unauthorized(self, usage_client):
        """Test usage increment without authentication."""
        response = usage_client.post("/usage/increment")
        
        # Verify response
        assert response.status_code == 403  # No authorization header

    # Get Usage Tests
    def test_get_usage_success(self, usage_client, sample_current_user, sample_user_internal, mock_user_service):
        """Test successful usage retrieval."""
        # Mock user service
        user_with_usage = sample_user_internal.model_copy()
        user_with_usage.usage_count = 3
        user_with_usage.monthly_limit = 5
        
        mock_user_service.find_by_id.return_value = user_with_usage
        
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        with patch('controllers.usage.user_service', mock_user_service):
            response = usage_client.get("/usage/")
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert "usage_count" in data
            assert "monthly_limit" in data
            assert "subscription_tier" in data
            assert "usage_percentage" in data
            assert data["usage_count"] == 3
            assert data["monthly_limit"] == 5
            assert data["subscription_tier"] == "free"
            assert data["usage_percentage"] == 60  # 3/5 * 100 = 60%
            
            # Verify service was called
            mock_user_service.find_by_id.assert_called_once_with(sample_current_user.id)
        
        # Clean up
        usage_client.app.dependency_overrides.clear()

    def test_get_usage_unlimited_tier(self, usage_client, sample_current_user, sample_user_internal, mock_user_service):
        """Test usage retrieval for unlimited subscription tier."""
        # Mock user with enterprise tier (unlimited)
        enterprise_user = sample_user_internal.model_copy()
        enterprise_user.subscription_tier = SubscriptionTier.ENTERPRISE
        enterprise_user.usage_count = 1000
        enterprise_user.monthly_limit = -1  # Unlimited
        
        mock_user_service.find_by_id.return_value = enterprise_user
        
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        with patch('controllers.usage.user_service', mock_user_service):
            response = usage_client.get("/usage/")
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert data["usage_count"] == 1000
            assert data["monthly_limit"] == -1
            assert data["subscription_tier"] == "enterprise"
            assert data["usage_percentage"] == 0  # 0% for unlimited
        
        # Clean up
        usage_client.app.dependency_overrides.clear()

    def test_get_usage_user_not_found(self, usage_client, sample_current_user, mock_user_service):
        """Test usage retrieval when user is not found."""
        # Mock user service to return None
        mock_user_service.find_by_id.return_value = None
        
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        with patch('controllers.usage.user_service', mock_user_service):
            response = usage_client.get("/usage/")
            
            # Verify response
            assert response.status_code == 404
            data = response.json()
            assert data["detail"]["success"] is False
            assert "error" in data["detail"]
            assert "User not found" in data["detail"]["error"]["message"]
            
            # Verify service was called
            mock_user_service.find_by_id.assert_called_once_with(sample_current_user.id)
        
        # Clean up
        usage_client.app.dependency_overrides.clear()

    def test_get_usage_service_error(self, usage_client, sample_current_user, mock_user_service):
        """Test usage retrieval when service throws an error."""
        # Mock user service to throw an exception
        mock_user_service.find_by_id.side_effect = Exception("Database error")
        
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        with patch('controllers.usage.user_service', mock_user_service):
            response = usage_client.get("/usage/")
            
            # Verify response
            assert response.status_code == 500
            data = response.json()
            assert data["detail"]["success"] is False
            assert "error" in data["detail"]
            assert "Failed to get usage data" in data["detail"]["error"]["message"]
        
        # Clean up
        usage_client.app.dependency_overrides.clear()

    def test_get_usage_unauthorized(self, usage_client):
        """Test usage retrieval without authentication."""
        response = usage_client.get("/usage/")
        
        # Verify response
        assert response.status_code == 403  # No authorization header

    # Edge Cases and Integration Tests
    def test_usage_percentage_calculation_edge_cases(self, usage_client, sample_current_user, sample_user_internal, mock_user_service):
        """Test usage percentage calculation for edge cases."""
        test_cases = [
            {"usage": 0, "limit": 5, "expected": 0},
            {"usage": 5, "limit": 5, "expected": 100},
            {"usage": 3, "limit": 10, "expected": 30},
            {"usage": 1, "limit": 3, "expected": 33},  # Should round to 33
            {"usage": 2, "limit": 3, "expected": 67},  # Should round to 67
            {"usage": 100, "limit": 0, "expected": 0},  # Division by zero protection
        ]
        
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        for test_case in test_cases:
            # Mock user with specific usage/limit
            test_user = sample_user_internal.model_copy()
            test_user.usage_count = test_case["usage"]
            test_user.monthly_limit = test_case["limit"]
            
            mock_user_service.find_by_id.return_value = test_user
            
            with patch('controllers.usage.user_service', mock_user_service):
                response = usage_client.get("/usage/")
                
                # Verify response
                assert response.status_code == 200
                data = response.json()
                assert data["usage_percentage"] == test_case["expected"], \
                    f"Failed for usage={test_case['usage']}, limit={test_case['limit']}"
        
        # Clean up
        usage_client.app.dependency_overrides.clear()

    def test_rate_limiting_cache_cleanup(self, usage_client, sample_current_user, mock_user_service):
        """Test that rate limiting cache gets cleaned up properly."""
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        # Import the recent_requests cache to manipulate it
        from controllers.usage import recent_requests, REQUEST_DEDUPE_WINDOW
        
        # Add some old entries to the cache
        old_time = time.time() - (REQUEST_DEDUPE_WINDOW * 3)  # Very old
        recent_requests["old-user-1"] = old_time
        recent_requests["old-user-2"] = old_time
        
        initial_cache_size = len(recent_requests)
        
        with patch('controllers.usage.user_service', mock_user_service):
            # This request should trigger cache cleanup
            response = usage_client.post("/usage/increment")
            
            # Verify old entries were cleaned up
            final_cache_size = len(recent_requests)
            assert final_cache_size < initial_cache_size
            assert "old-user-1" not in recent_requests
            assert "old-user-2" not in recent_requests
        
        # Clean up
        usage_client.app.dependency_overrides.clear()
        recent_requests.clear()

    def test_different_subscription_tiers(self, usage_client, sample_current_user, sample_user_internal, mock_user_service):
        """Test usage retrieval for different subscription tiers."""
        tiers = [
            SubscriptionTier.FREE,
            SubscriptionTier.PRO,
            SubscriptionTier.BUSINESS,
            SubscriptionTier.ENTERPRISE
        ]
        
        # Override dependencies
        def mock_get_current_user():
            return sample_current_user
        
        usage_client.app.dependency_overrides[get_current_user] = mock_get_current_user
        
        for tier in tiers:
            # Mock user with specific tier
            tier_user = sample_user_internal.model_copy()
            tier_user.subscription_tier = tier
            
            mock_user_service.find_by_id.return_value = tier_user
            
            with patch('controllers.usage.user_service', mock_user_service):
                response = usage_client.get("/usage/")
                
                # Verify response
                assert response.status_code == 200
                data = response.json()
                assert data["subscription_tier"] == tier.value
        
        # Clean up
        usage_client.app.dependency_overrides.clear()
