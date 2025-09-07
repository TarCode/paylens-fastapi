"""
Unit tests for UserService.
"""
import pytest
import bcrypt
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from typing import List

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'app'))

from services.user_service import UserService
from models.user import (
    CreateUserData, UpdateUserData, UserInternal, UserRole, 
    SubscriptionTier, dict_to_userdb
)


class TestUserService:
    """Test cases for UserService."""

    @pytest.fixture
    def user_service(self):
        """Create UserService instance for testing."""
        return UserService()

    @pytest.fixture
    def mock_db_service(self):
        """Mock database service."""
        return AsyncMock()

    @pytest.fixture
    def sample_create_user_data(self):
        """Sample create user data."""
        return CreateUserData(
            email="test@example.com",
            password="TestPassword123!",
            first_name="John",
            last_name="Doe",
            company_name="Test Company"
        )

    @pytest.fixture
    def sample_create_user_data_google(self):
        """Sample create user data for Google OAuth."""
        return CreateUserData(
            email="test@example.com",
            password=None,  # No password for Google OAuth
            google_id="google_123456789",
            first_name="John",
            last_name="Doe",
            company_name="Test Company"
        )

    @pytest.fixture
    def sample_update_user_data(self):
        """Sample update user data."""
        return UpdateUserData(
            first_name="Jane",
            last_name="Smith",
            company_name="Updated Company"
        )

    @pytest.fixture
    def sample_db_user_data(self):
        """Sample database user data."""
        return {
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
    def sample_user_internal(self, sample_db_user_data):
        """Sample user internal from database data."""
        return dict_to_userdb(sample_db_user_data).to_user_internal()

    # User Creation Tests
    @pytest.mark.asyncio
    async def test_create_user_success(self, user_service, mock_db_service, sample_create_user_data, sample_db_user_data):
        """Test successful user creation."""
        # Mock database service
        mock_db_service.query.return_value = {"rows": [sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.create_user(sample_create_user_data)
            
            # Verify the result
            assert isinstance(result, UserInternal)
            assert result.email == sample_create_user_data.email
            assert result.first_name == sample_create_user_data.first_name
            assert result.last_name == sample_create_user_data.last_name
            assert result.company_name == sample_create_user_data.company_name
            assert result.role == UserRole.USER
            assert result.subscription_tier == SubscriptionTier.FREE
            assert result.is_active is True
            assert result.email_verified is True
            
            # Verify database was called
            mock_db_service.query.assert_called_once()
            call_args = mock_db_service.query.call_args
            assert "INSERT INTO users" in call_args[0][0]
            assert call_args[0][1][1] == sample_create_user_data.email  # email parameter

    @pytest.mark.asyncio
    async def test_create_user_google_oauth(self, user_service, mock_db_service, sample_create_user_data_google, sample_db_user_data):
        """Test user creation for Google OAuth."""
        # Create modified database data with Google ID
        google_db_data = sample_db_user_data.copy()
        google_db_data["google_id"] = sample_create_user_data_google.google_id
        google_db_data["password"] = None
        
        # Mock database service
        mock_db_service.query.return_value = {"rows": [google_db_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.create_user(sample_create_user_data_google)
            
            # Verify the result
            assert isinstance(result, UserInternal)
            assert result.email == sample_create_user_data_google.email
            assert result.google_id == sample_create_user_data_google.google_id
            assert result.password is None  # No password for Google OAuth
            
            # Verify database was called
            mock_db_service.query.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_user_password_hashing(self, user_service, mock_db_service, sample_create_user_data, sample_db_user_data):
        """Test that password is properly hashed during user creation."""
        # Mock database service
        mock_db_service.query.return_value = {"rows": [sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.create_user(sample_create_user_data)
            
            # Verify database was called with hashed password
            call_args = mock_db_service.query.call_args
            hashed_password = call_args[0][1][2]  # password parameter
            
            # Verify password is hashed (not plain text)
            assert hashed_password != sample_create_user_data.password
            assert hashed_password.startswith("$2b$")  # bcrypt hash format
            
            # Verify the hash is valid
            assert bcrypt.checkpw(
                sample_create_user_data.password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )

    @pytest.mark.asyncio
    async def test_create_user_database_failure(self, user_service, mock_db_service, sample_create_user_data):
        """Test user creation when database fails."""
        # Mock database service to return empty result
        mock_db_service.query.return_value = {"rows": []}
        
        with patch('services.user_service.db_service', mock_db_service):
            with pytest.raises(Exception) as exc_info:
                await user_service.create_user(sample_create_user_data)
            
            assert "Failed to create user" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_user_subscription_tier_assignment(self, user_service, mock_db_service, sample_db_user_data):
        """Test subscription tier assignment based on company name."""
        # Test with company name
        user_data_with_company = CreateUserData(
            email="test@example.com",
            password="TestPassword123!",
            first_name="John",
            last_name="Doe",
            company_name="Test Company"
        )
        
        mock_db_service.query.return_value = {"rows": [sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.create_user(user_data_with_company)
            
            # Verify subscription tier is set correctly
            assert result.subscription_tier == SubscriptionTier.FREE
            assert result.monthly_limit == 5  # Free tier limit

    # User Retrieval Tests
    @pytest.mark.asyncio
    async def test_find_by_email_success(self, user_service, mock_db_service, sample_db_user_data):
        """Test successful user retrieval by email."""
        email = "test@example.com"
        
        # Mock database service
        mock_db_service.query.return_value = {"rows": [sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.find_by_email(email)
            
            # Verify the result
            assert isinstance(result, UserInternal)
            assert result.email == email
            
            # Verify database was called correctly
            mock_db_service.query.assert_called_once_with("SELECT * FROM users WHERE email = $1", [email])

    @pytest.mark.asyncio
    async def test_find_by_email_not_found(self, user_service, mock_db_service):
        """Test user retrieval by email when user doesn't exist."""
        email = "nonexistent@example.com"
        
        # Mock database service to return empty result
        mock_db_service.query.return_value = {"rows": []}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.find_by_email(email)
            
            # Verify no user is returned
            assert result is None

    @pytest.mark.asyncio
    async def test_find_by_id_success(self, user_service, mock_db_service, sample_db_user_data):
        """Test successful user retrieval by ID."""
        user_id = "test-user-id"
        
        # Mock database service
        mock_db_service.query.return_value = {"rows": [sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.find_by_id(user_id)
            
            # Verify the result
            assert isinstance(result, UserInternal)
            assert result.id == user_id
            
            # Verify database was called correctly
            mock_db_service.query.assert_called_once_with("SELECT * FROM users WHERE id = $1", [user_id])

    @pytest.mark.asyncio
    async def test_find_by_id_not_found(self, user_service, mock_db_service):
        """Test user retrieval by ID when user doesn't exist."""
        user_id = "nonexistent-user-id"
        
        # Mock database service to return empty result
        mock_db_service.query.return_value = {"rows": []}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.find_by_id(user_id)
            
            # Verify no user is returned
            assert result is None

    @pytest.mark.asyncio
    async def test_find_by_google_id_success(self, user_service, mock_db_service, sample_db_user_data):
        """Test successful user retrieval by Google ID."""
        google_id = "google_123456789"
        
        # Mock database service
        mock_db_service.query.return_value = {"rows": [sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.find_by_google_id(google_id)
            
            # Verify the result
            assert isinstance(result, UserInternal)
            
            # Verify database was called correctly
            mock_db_service.query.assert_called_once_with("SELECT * FROM users WHERE google_id = $1", [google_id])

    @pytest.mark.asyncio
    async def test_find_by_google_id_not_found(self, user_service, mock_db_service):
        """Test user retrieval by Google ID when user doesn't exist."""
        google_id = "nonexistent_google_id"
        
        # Mock database service to return empty result
        mock_db_service.query.return_value = {"rows": []}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.find_by_google_id(google_id)
            
            # Verify no user is returned
            assert result is None

    # User Update Tests
    @pytest.mark.asyncio
    async def test_update_user_success(self, user_service, mock_db_service, sample_update_user_data, sample_db_user_data):
        """Test successful user update."""
        user_id = "test-user-id"
        
        # Mock database service
        mock_db_service.query.return_value = {"rows": [sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.update_user(user_id, sample_update_user_data)
            
            # Verify the result
            assert isinstance(result, UserInternal)
            assert result.id == user_id
            
            # Verify database was called
            mock_db_service.query.assert_called_once()
            call_args = mock_db_service.query.call_args
            assert "UPDATE users" in call_args[0][0]
            assert "first_name = $1" in call_args[0][0]
            assert "last_name = $2" in call_args[0][0]
            assert "company_name = $3" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_update_user_empty_update(self, user_service, mock_db_service, sample_db_user_data):
        """Test user update with empty update data."""
        user_id = "test-user-id"
        empty_update = UpdateUserData()  # No fields set
        
        # Mock database service
        mock_db_service.query.return_value = {"rows": [sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.update_user(user_id, empty_update)
            
            # Should return the user without updating
            assert isinstance(result, UserInternal)
            assert result.id == user_id

    @pytest.mark.asyncio
    async def test_update_user_not_found(self, user_service, mock_db_service, sample_update_user_data):
        """Test user update when user doesn't exist."""
        user_id = "nonexistent-user-id"
        
        # Mock database service to return empty result
        mock_db_service.query.return_value = {"rows": []}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.update_user(user_id, sample_update_user_data)
            
            # Verify no user is returned
            assert result is None

    # Password Validation Tests
    @pytest.mark.asyncio
    async def test_validate_password_success(self, user_service):
        """Test successful password validation."""
        plain_password = "TestPassword123!"
        hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        result = await user_service.validate_password(plain_password, hashed_password)
        
        assert result is True

    @pytest.mark.asyncio
    async def test_validate_password_failure(self, user_service):
        """Test password validation failure."""
        plain_password = "TestPassword123!"
        wrong_password = "WrongPassword456!"
        hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        result = await user_service.validate_password(wrong_password, hashed_password)
        
        assert result is False

    # Password Update Tests
    @pytest.mark.asyncio
    async def test_update_password_success(self, user_service, mock_db_service):
        """Test successful password update."""
        user_id = "test-user-id"
        new_password = "NewPassword123!"
        
        # Mock database service
        mock_db_service.query.return_value = {"rows": []}
        
        with patch('services.user_service.db_service', mock_db_service):
            await user_service.update_password(user_id, new_password)
            
            # Verify database was called
            mock_db_service.query.assert_called_once()
            call_args = mock_db_service.query.call_args
            assert "UPDATE users" in call_args[0][0]
            assert "password = $1" in call_args[0][0]
            
            # Verify password is hashed
            hashed_password = call_args[0][1][0]
            assert hashed_password != new_password
            assert hashed_password.startswith("$2b$")
            assert bcrypt.checkpw(new_password.encode('utf-8'), hashed_password.encode('utf-8'))

    # User Deactivation Tests
    @pytest.mark.asyncio
    async def test_deactivate_user_success(self, user_service, mock_db_service):
        """Test successful user deactivation."""
        user_id = "test-user-id"
        
        # Mock database service
        mock_db_service.query.return_value = {"rows": []}
        
        with patch('services.user_service.db_service', mock_db_service):
            await user_service.deactivate_user(user_id)
            
            # Verify database was called
            mock_db_service.query.assert_called_once()
            call_args = mock_db_service.query.call_args
            assert "UPDATE users" in call_args[0][0]
            assert "is_active = false" in call_args[0][0]
            assert call_args[0][1][0] == user_id

    # Usage Count Tests
    @pytest.mark.asyncio
    async def test_increment_usage_count_success(self, user_service, mock_db_service, sample_db_user_data):
        """Test successful usage count increment."""
        user_id = "test-user-id"
        
        # Mock database service for check_and_reset_monthly_usage
        mock_db_service.query.return_value = {"rows": [sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.increment_usage_count(user_id)
            
            # Verify the result
            assert result["can_increment"] is True
            assert result["user"] is not None
            assert "was_reset" in result

    @pytest.mark.asyncio
    async def test_increment_usage_count_limit_exceeded(self, user_service, mock_db_service, sample_db_user_data):
        """Test usage count increment when limit is exceeded."""
        user_id = "test-user-id"
        
        # Create user at limit
        user_at_limit = sample_db_user_data.copy()
        user_at_limit["usage_count"] = 5  # At free tier limit
        user_at_limit["monthly_limit"] = 5
        
        # Mock database service
        mock_db_service.query.return_value = {"rows": []}  # No rows returned (limit exceeded)
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.increment_usage_count(user_id)
            
            # Verify the result
            assert result["can_increment"] is False
            assert "error" in result
            assert "Usage limit exceeded" in result["error"]

    @pytest.mark.asyncio
    async def test_increment_usage_count_user_not_found(self, user_service, mock_db_service):
        """Test usage count increment when user is not found."""
        user_id = "nonexistent-user-id"
        
        # Mock database service to return empty result
        mock_db_service.query.return_value = {"rows": []}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.increment_usage_count(user_id)
            
            # Verify the result
            assert result["can_increment"] is False
            assert result["user"] is None
            assert "User not found" in result["error"]

    # Monthly Usage Reset Tests
    @pytest.mark.asyncio
    async def test_reset_monthly_usage_specific_user(self, user_service, mock_db_service, sample_db_user_data):
        """Test monthly usage reset for specific user."""
        user_id = "test-user-id"
        
        # Mock database service
        mock_db_service.query.return_value = {"rows": [sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.reset_monthly_usage(user_id)
            
            # Verify the result
            assert result["reset_count"] == 1
            assert len(result["errors"]) == 0
            
            # Verify database was called
            mock_db_service.query.assert_called_once()
            call_args = mock_db_service.query.call_args
            assert "UPDATE users" in call_args[0][0]
            assert "usage_count = 0" in call_args[0][0]
            assert call_args[0][1][0] == user_id

    @pytest.mark.asyncio
    async def test_reset_monthly_usage_all_users(self, user_service, mock_db_service, sample_db_user_data):
        """Test monthly usage reset for all users."""
        # Mock database service
        mock_db_service.query.return_value = {"rows": [sample_db_user_data, sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.reset_monthly_usage()
            
            # Verify the result
            assert result["reset_count"] == 2
            assert len(result["errors"]) == 0
            
            # Verify database was called
            mock_db_service.query.assert_called_once()
            call_args = mock_db_service.query.call_args
            assert "UPDATE users" in call_args[0][0]
            assert "billing_period_start < DATE_TRUNC" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_reset_monthly_usage_database_error(self, user_service, mock_db_service):
        """Test monthly usage reset with database error."""
        user_id = "test-user-id"
        
        # Mock database service to raise exception
        mock_db_service.query.side_effect = Exception("Database error")
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.reset_monthly_usage(user_id)
            
            # Verify the result
            assert result["reset_count"] == 0
            assert len(result["errors"]) == 1
            assert "Database error" in result["errors"][0]

    # Monthly Usage Check Tests
    @pytest.mark.asyncio
    async def test_check_and_reset_monthly_usage_no_reset_needed(self, user_service, mock_db_service, sample_db_user_data):
        """Test monthly usage check when no reset is needed."""
        user_id = "test-user-id"
        
        # Mock database service
        mock_db_service.query.return_value = {"rows": [sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.check_and_reset_monthly_usage(user_id)
            
            # Verify the result
            assert result["was_reset"] is False
            assert result["user"] is not None

    @pytest.mark.asyncio
    async def test_check_and_reset_monthly_usage_user_not_found(self, user_service, mock_db_service):
        """Test monthly usage check when user is not found."""
        user_id = "nonexistent-user-id"
        
        # Mock database service to return empty result
        mock_db_service.query.return_value = {"rows": []}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.check_and_reset_monthly_usage(user_id)
            
            # Verify the result
            assert result["was_reset"] is False
            assert result["user"] is None

    # Get All Users Tests
    @pytest.mark.asyncio
    async def test_get_all_users_success(self, user_service, mock_db_service, sample_db_user_data):
        """Test successful retrieval of all users."""
        # Mock database service
        mock_db_service.query.return_value = {"rows": [sample_db_user_data, sample_db_user_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.get_all_users(limit=10, offset=0)
            
            # Verify the result
            assert isinstance(result, list)
            assert len(result) == 2
            assert all(isinstance(user, UserInternal) for user in result)
            
            # Verify database was called
            mock_db_service.query.assert_called_once()
            call_args = mock_db_service.query.call_args
            assert "SELECT * FROM users" in call_args[0][0]
            assert call_args[0][1][0] == 10  # limit
            assert call_args[0][1][1] == 0   # offset

    @pytest.mark.asyncio
    async def test_get_all_users_empty(self, user_service, mock_db_service):
        """Test retrieval of all users when no users exist."""
        # Mock database service to return empty result
        mock_db_service.query.return_value = {"rows": []}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.get_all_users()
            
            # Verify the result
            assert isinstance(result, list)
            assert len(result) == 0

    # User Stats Tests
    @pytest.mark.asyncio
    async def test_get_user_stats_success(self, user_service, mock_db_service):
        """Test successful retrieval of user stats."""
        user_id = "test-user-id"
        stats_data = {
            "usage_count": 5,
            "monthly_limit": 10,
            "subscription_tier": "free",
            "registration_date": datetime.now(timezone.utc),
            "last_updated": datetime.now(timezone.utc)
        }
        
        # Mock database service
        mock_db_service.query.return_value = {"rows": [stats_data]}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.get_user_stats(user_id)
            
            # Verify the result
            assert result is not None
            assert result["usage_count"] == 5
            assert result["monthly_limit"] == 10
            assert result["subscription_tier"] == "free"
            
            # Verify database was called
            mock_db_service.query.assert_called_once()
            call_args = mock_db_service.query.call_args
            assert "SELECT" in call_args[0][0]
            assert call_args[0][1][0] == user_id

    @pytest.mark.asyncio
    async def test_get_user_stats_not_found(self, user_service, mock_db_service):
        """Test user stats retrieval when user doesn't exist."""
        user_id = "nonexistent-user-id"
        
        # Mock database service to return empty result
        mock_db_service.query.return_value = {"rows": []}
        
        with patch('services.user_service.db_service', mock_db_service):
            result = await user_service.get_user_stats(user_id)
            
            # Verify no stats are returned
            assert result is None

    # Utility Method Tests
    def test_get_monthly_limit(self, user_service):
        """Test monthly limit calculation for different tiers."""
        # Test different subscription tiers
        assert user_service._get_monthly_limit("free") == 5
        assert user_service._get_monthly_limit("pro") == 100
        assert user_service._get_monthly_limit("business") == 1000
        assert user_service._get_monthly_limit("enterprise") == -1  # unlimited
        assert user_service._get_monthly_limit("unknown") == 5  # default

    def test_camel_to_snake(self, user_service):
        """Test camelCase to snake_case conversion."""
        # Test various camelCase inputs
        assert user_service._camel_to_snake("firstName") == "first_name"
        assert user_service._camel_to_snake("lastName") == "last_name"
        assert user_service._camel_to_snake("companyName") == "company_name"
        assert user_service._camel_to_snake("emailVerified") == "email_verified"
        assert user_service._camel_to_snake("subscriptionTier") == "subscription_tier"
        assert user_service._camel_to_snake("monthlyLimit") == "monthly_limit"
        assert user_service._camel_to_snake("usageCount") == "usage_count"
        assert user_service._camel_to_snake("lastUsageReset") == "last_usage_reset"
        assert user_service._camel_to_snake("billingPeriodStart") == "billing_period_start"
        assert user_service._camel_to_snake("emailVerificationToken") == "email_verification_token"
        assert user_service._camel_to_snake("passwordResetToken") == "password_reset_token"
        assert user_service._camel_to_snake("passwordResetExpires") == "password_reset_expires"
        assert user_service._camel_to_snake("stripeCustomerId") == "stripe_customer_id"
        assert user_service._camel_to_snake("subscriptionId") == "subscription_id"
        assert user_service._camel_to_snake("subscriptionStatus") == "subscription_status"
        assert user_service._camel_to_snake("createdAt") == "created_at"
        assert user_service._camel_to_snake("updatedAt") == "updated_at"
        
        # Test already snake_case
        assert user_service._camel_to_snake("first_name") == "first_name"
        assert user_service._camel_to_snake("email") == "email"
        
        # Test single word
        assert user_service._camel_to_snake("email") == "email"
        assert user_service._camel_to_snake("id") == "id"
