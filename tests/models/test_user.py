"""
Unit tests for User models.
"""
import pytest
from datetime import datetime, timezone, timedelta
from pydantic import ValidationError

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'app'))

from models.user import (
    UserRole, SubscriptionTier, UserResponse, UserDB, UserInternal,
    CreateUserData, UpdateUserData, LoginData, AuthTokens, JWTPayload,
    GoogleProfile, dict_to_userdb
)


class TestUserModels:
    """Test cases for User models."""

    @pytest.fixture
    def sample_datetime(self):
        """Sample datetime for testing."""
        return datetime.now(timezone.utc)

    @pytest.fixture
    def sample_user_data(self, sample_datetime):
        """Sample user data for testing."""
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
            "last_usage_reset": sample_datetime,
            "billing_period_start": sample_datetime,
            "is_active": True,
            "email_verified": True,
            "email_verification_token": None,
            "password_reset_token": None,
            "password_reset_expires": None,
            "stripe_customer_id": None,
            "subscription_id": None,
            "subscription_status": None,
            "created_at": sample_datetime,
            "updated_at": sample_datetime
        }

    # Enum Tests
    def test_user_role_enum(self):
        """Test UserRole enum values."""
        assert UserRole.USER == "user"
        assert UserRole.ADMIN == "admin"
        
        # Test enum creation
        role = UserRole.USER
        assert role.value == "user"
        
        role = UserRole.ADMIN
        assert role.value == "admin"

    def test_subscription_tier_enum(self):
        """Test SubscriptionTier enum values."""
        assert SubscriptionTier.FREE == "free"
        assert SubscriptionTier.PRO == "pro"
        assert SubscriptionTier.BUSINESS == "business"
        assert SubscriptionTier.ENTERPRISE == "enterprise"
        
        # Test enum creation
        tier = SubscriptionTier.FREE
        assert tier.value == "free"
        
        tier = SubscriptionTier.PRO
        assert tier.value == "pro"

    # UserResponse Model Tests
    def test_user_response_creation(self, sample_datetime):
        """Test UserResponse model creation."""
        user_response = UserResponse(
            id="test-user-id",
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            company_name="Test Company",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            monthly_limit=5,
            usage_count=0,
            last_usage_reset=sample_datetime,
            billing_period_start=sample_datetime,
            is_active=True,
            email_verified=True,
            created_at=sample_datetime,
            updated_at=sample_datetime
        )
        
        assert user_response.id == "test-user-id"
        assert user_response.email == "test@example.com"
        assert user_response.first_name == "John"
        assert user_response.last_name == "Doe"
        assert user_response.company_name == "Test Company"
        assert user_response.role == UserRole.USER
        assert user_response.subscription_tier == SubscriptionTier.FREE
        assert user_response.monthly_limit == 5
        assert user_response.usage_count == 0
        assert user_response.is_active is True
        assert user_response.email_verified is True

    def test_user_response_optional_company_name(self, sample_datetime):
        """Test UserResponse with optional company name."""
        user_response = UserResponse(
            id="test-user-id",
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            company_name=None,  # Optional field
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            monthly_limit=5,
            usage_count=0,
            last_usage_reset=sample_datetime,
            billing_period_start=sample_datetime,
            is_active=True,
            email_verified=True,
            created_at=sample_datetime,
            updated_at=sample_datetime
        )
        
        assert user_response.company_name is None

    def test_user_response_invalid_email(self, sample_datetime):
        """Test UserResponse with invalid email."""
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            UserResponse(
                id="test-user-id",
                email="invalid-email",  # Invalid email format
                first_name="John",
                last_name="Doe",
                company_name="Test Company",
                role=UserRole.USER,
                subscription_tier=SubscriptionTier.FREE,
                monthly_limit=5,
                usage_count=0,
                last_usage_reset=sample_datetime,
                billing_period_start=sample_datetime,
                is_active=True,
                email_verified=True,
                created_at=sample_datetime,
                updated_at=sample_datetime
            )
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "value_error" for error in errors)

    # UserDB Model Tests
    def test_userdb_creation(self, sample_user_data):
        """Test UserDB model creation."""
        user_db = UserDB(**sample_user_data)
        
        assert user_db.id == "test-user-id"
        assert user_db.email == "test@example.com"
        assert user_db.password == "hashed_password"
        assert user_db.google_id is None
        assert user_db.first_name == "John"
        assert user_db.last_name == "Doe"
        assert user_db.company_name == "Test Company"
        assert user_db.role == "user"
        assert user_db.subscription_tier == "free"
        assert user_db.monthly_limit == 5
        assert user_db.usage_count == 0
        assert user_db.is_active is True
        assert user_db.email_verified is True

    def test_userdb_to_user_response(self, sample_user_data):
        """Test UserDB to UserResponse conversion."""
        user_db = UserDB(**sample_user_data)
        user_response = user_db.to_user_response()
        
        assert isinstance(user_response, UserResponse)
        assert user_response.id == user_db.id
        assert user_response.email == user_db.email
        assert user_response.first_name == user_db.first_name
        assert user_response.last_name == user_db.last_name
        assert user_response.company_name == user_db.company_name
        assert user_response.role == UserRole(user_db.role)
        assert user_response.subscription_tier == SubscriptionTier(user_db.subscription_tier)
        assert user_response.monthly_limit == user_db.monthly_limit
        assert user_response.usage_count == user_db.usage_count
        assert user_response.is_active == user_db.is_active
        assert user_response.email_verified == user_db.email_verified

    def test_userdb_to_user_internal(self, sample_user_data):
        """Test UserDB to UserInternal conversion."""
        user_db = UserDB(**sample_user_data)
        user_internal = user_db.to_user_internal()
        
        assert isinstance(user_internal, UserInternal)
        assert user_internal.id == user_db.id
        assert user_internal.email == user_db.email
        assert user_internal.password == user_db.password
        assert user_internal.google_id == user_db.google_id
        assert user_internal.first_name == user_db.first_name
        assert user_internal.last_name == user_db.last_name
        assert user_internal.company_name == user_db.company_name
        assert user_internal.role == UserRole(user_db.role)
        assert user_internal.subscription_tier == SubscriptionTier(user_db.subscription_tier)
        assert user_internal.monthly_limit == user_db.monthly_limit
        assert user_internal.usage_count == user_db.usage_count
        assert user_internal.is_active == user_db.is_active
        assert user_internal.email_verified == user_db.email_verified

    def test_userdb_role_enum_property(self, sample_user_data):
        """Test UserDB role_enum property."""
        user_db = UserDB(**sample_user_data)
        
        assert user_db.role_enum == UserRole.USER
        
        # Test with admin role
        sample_user_data["role"] = "admin"
        admin_user_db = UserDB(**sample_user_data)
        assert admin_user_db.role_enum == UserRole.ADMIN

    def test_userdb_subscription_tier_enum_property(self, sample_user_data):
        """Test UserDB subscription_tier_enum property."""
        user_db = UserDB(**sample_user_data)
        
        assert user_db.subscription_tier_enum == SubscriptionTier.FREE
        
        # Test with pro tier
        sample_user_data["subscription_tier"] = "pro"
        pro_user_db = UserDB(**sample_user_data)
        assert pro_user_db.subscription_tier_enum == SubscriptionTier.PRO

    # UserInternal Model Tests
    def test_user_internal_creation(self, sample_datetime):
        """Test UserInternal model creation."""
        user_internal = UserInternal(
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
            last_usage_reset=sample_datetime,
            billing_period_start=sample_datetime,
            is_active=True,
            email_verified=True,
            email_verification_token=None,
            password_reset_token=None,
            password_reset_expires=None,
            stripe_customer_id=None,
            subscription_id=None,
            subscription_status=None,
            created_at=sample_datetime,
            updated_at=sample_datetime
        )
        
        assert user_internal.id == "test-user-id"
        assert user_internal.email == "test@example.com"
        assert user_internal.password == "hashed_password"
        assert user_internal.google_id is None
        assert user_internal.first_name == "John"
        assert user_internal.last_name == "Doe"
        assert user_internal.company_name == "Test Company"
        assert user_internal.role == UserRole.USER
        assert user_internal.subscription_tier == SubscriptionTier.FREE
        assert user_internal.monthly_limit == 5
        assert user_internal.usage_count == 0
        assert user_internal.is_active is True
        assert user_internal.email_verified is True

    def test_user_internal_to_user_response(self, sample_datetime):
        """Test UserInternal to UserResponse conversion."""
        user_internal = UserInternal(
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
            last_usage_reset=sample_datetime,
            billing_period_start=sample_datetime,
            is_active=True,
            email_verified=True,
            email_verification_token=None,
            password_reset_token=None,
            password_reset_expires=None,
            stripe_customer_id=None,
            subscription_id=None,
            subscription_status=None,
            created_at=sample_datetime,
            updated_at=sample_datetime
        )
        
        user_response = user_internal.to_user_response()
        
        assert isinstance(user_response, UserResponse)
        assert user_response.id == user_internal.id
        assert user_response.email == user_internal.email
        assert user_response.first_name == user_internal.first_name
        assert user_response.last_name == user_internal.last_name
        assert user_response.company_name == user_internal.company_name
        assert user_response.role == user_internal.role
        assert user_response.subscription_tier == user_internal.subscription_tier
        assert user_response.monthly_limit == user_internal.monthly_limit
        assert user_response.usage_count == user_internal.usage_count
        assert user_response.is_active == user_internal.is_active
        assert user_response.email_verified == user_internal.email_verified

    # CreateUserData Model Tests
    def test_create_user_data_creation(self):
        """Test CreateUserData model creation."""
        create_data = CreateUserData(
            email="test@example.com",
            password="TestPassword123!",
            first_name="John",
            last_name="Doe",
            company_name="Test Company"
        )
        
        assert create_data.email == "test@example.com"
        assert create_data.password == "TestPassword123!"
        assert create_data.first_name == "John"
        assert create_data.last_name == "Doe"
        assert create_data.company_name == "Test Company"
        assert create_data.google_id is None

    def test_create_user_data_google_oauth(self):
        """Test CreateUserData for Google OAuth user."""
        create_data = CreateUserData(
            email="test@example.com",
            password=None,  # No password for Google OAuth
            google_id="google_123456789",
            first_name="John",
            last_name="Doe",
            company_name="Test Company"
        )
        
        assert create_data.email == "test@example.com"
        assert create_data.password is None
        assert create_data.google_id == "google_123456789"
        assert create_data.first_name == "John"
        assert create_data.last_name == "Doe"
        assert create_data.company_name == "Test Company"

    def test_create_user_data_minimal(self):
        """Test CreateUserData with minimal fields."""
        create_data = CreateUserData(
            email="test@example.com",
            password="TestPassword123!",
            first_name="John",
            last_name="Doe"
        )
        
        assert create_data.email == "test@example.com"
        assert create_data.password == "TestPassword123!"
        assert create_data.first_name == "John"
        assert create_data.last_name == "Doe"
        assert create_data.company_name is None
        assert create_data.google_id is None

    def test_create_user_data_invalid_email(self):
        """Test CreateUserData with invalid email."""
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            CreateUserData(
                email="invalid-email",
                password="TestPassword123!",
                first_name="John",
                last_name="Doe"
            )
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "value_error" for error in errors)

    # UpdateUserData Model Tests
    def test_update_user_data_creation(self):
        """Test UpdateUserData model creation."""
        update_data = UpdateUserData(
            first_name="Jane",
            last_name="Smith",
            company_name="Updated Company"
        )
        
        assert update_data.first_name == "Jane"
        assert update_data.last_name == "Smith"
        assert update_data.company_name == "Updated Company"
        assert update_data.google_id is None
        assert update_data.role is None
        assert update_data.is_active is None

    def test_update_user_data_all_fields(self, sample_datetime):
        """Test UpdateUserData with all fields."""
        update_data = UpdateUserData(
            first_name="Jane",
            last_name="Smith",
            company_name="Updated Company",
            google_id="google_123456789",
            role="admin",
            is_active=True,
            email_verified=True,
            subscription_tier="pro",
            monthly_limit=100,
            usage_count=10,
            last_usage_reset=sample_datetime,
            billing_period_start=sample_datetime
        )
        
        assert update_data.first_name == "Jane"
        assert update_data.last_name == "Smith"
        assert update_data.company_name == "Updated Company"
        assert update_data.google_id == "google_123456789"
        assert update_data.role == "admin"
        assert update_data.is_active is True
        assert update_data.email_verified is True
        assert update_data.subscription_tier == "pro"
        assert update_data.monthly_limit == 100
        assert update_data.usage_count == 10

    def test_update_user_data_empty(self):
        """Test UpdateUserData with no fields set."""
        update_data = UpdateUserData()
        
        assert update_data.first_name is None
        assert update_data.last_name is None
        assert update_data.company_name is None
        assert update_data.google_id is None
        assert update_data.role is None
        assert update_data.is_active is None

    def test_update_user_data_invalid_role(self):
        """Test UpdateUserData with invalid role."""
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            UpdateUserData(role="invalid_role")
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "literal_error" for error in errors)

    def test_update_user_data_invalid_subscription_tier(self):
        """Test UpdateUserData with invalid subscription tier."""
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            UpdateUserData(subscription_tier="invalid_tier")
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "literal_error" for error in errors)

    # LoginData Model Tests
    def test_login_data_creation(self):
        """Test LoginData model creation."""
        login_data = LoginData(
            email="test@example.com",
            password="TestPassword123!"
        )
        
        assert login_data.email == "test@example.com"
        assert login_data.password == "TestPassword123!"

    def test_login_data_invalid_email(self):
        """Test LoginData with invalid email."""
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            LoginData(
                email="invalid-email",
                password="TestPassword123!"
            )
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "value_error" for error in errors)

    def test_login_data_empty_password(self):
        """Test LoginData with empty password."""
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            LoginData(
                email="test@example.com",
                password=""
            )
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "string_too_short" for error in errors)

    # AuthTokens Model Tests
    def test_auth_tokens_creation(self):
        """Test AuthTokens model creation."""
        auth_tokens = AuthTokens(
            access_token="access_token_123",
            refresh_token="refresh_token_456"
        )
        
        assert auth_tokens.access_token == "access_token_123"
        assert auth_tokens.refresh_token == "refresh_token_456"

    # JWTPayload Model Tests
    def test_jwt_payload_creation(self, sample_datetime):
        """Test JWTPayload model creation."""
        jwt_payload = JWTPayload(
            id="test-user-id",
            email="test@example.com",
            role="user",
            subscription_tier="free",
            usage_count=0,
            monthly_limit=5,
            last_usage_reset=sample_datetime,
            billing_period_start=sample_datetime
        )
        
        assert jwt_payload.id == "test-user-id"
        assert jwt_payload.email == "test@example.com"
        assert jwt_payload.role == "user"
        assert jwt_payload.subscription_tier == "free"
        assert jwt_payload.usage_count == 0
        assert jwt_payload.monthly_limit == 5
        assert jwt_payload.last_usage_reset == sample_datetime
        assert jwt_payload.billing_period_start == sample_datetime

    # GoogleProfile Model Tests
    def test_google_profile_creation(self):
        """Test GoogleProfile model creation."""
        google_profile = GoogleProfile(
            id="google_123456789",
            email="test@example.com",
            verified_email=True,
            name="John Doe",
            given_name="John",
            family_name="Doe",
            picture="https://example.com/photo.jpg",
            locale="en"
        )
        
        assert google_profile.id == "google_123456789"
        assert google_profile.email == "test@example.com"
        assert google_profile.verified_email is True
        assert google_profile.name == "John Doe"
        assert google_profile.given_name == "John"
        assert google_profile.family_name == "Doe"
        assert google_profile.picture == "https://example.com/photo.jpg"
        assert google_profile.locale == "en"

    def test_google_profile_invalid_email(self):
        """Test GoogleProfile with invalid email."""
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            GoogleProfile(
                id="google_123456789",
                email="invalid-email",
                verified_email=True,
                name="John Doe",
                given_name="John",
                family_name="Doe",
                picture="https://example.com/photo.jpg",
                locale="en"
            )
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "value_error" for error in errors)

    # Utility Function Tests
    def test_dict_to_userdb(self, sample_user_data):
        """Test dict_to_userdb utility function."""
        user_db = dict_to_userdb(sample_user_data)
        
        assert isinstance(user_db, UserDB)
        assert user_db.id == sample_user_data["id"]
        assert user_db.email == sample_user_data["email"]
        assert user_db.password == sample_user_data["password"]
        assert user_db.google_id == sample_user_data["google_id"]
        assert user_db.first_name == sample_user_data["first_name"]
        assert user_db.last_name == sample_user_data["last_name"]
        assert user_db.company_name == sample_user_data["company_name"]
        assert user_db.role == sample_user_data["role"]
        assert user_db.subscription_tier == sample_user_data["subscription_tier"]
        assert user_db.monthly_limit == sample_user_data["monthly_limit"]
        assert user_db.usage_count == sample_user_data["usage_count"]
        assert user_db.is_active == sample_user_data["is_active"]
        assert user_db.email_verified == sample_user_data["email_verified"]

    def test_dict_to_userdb_with_defaults(self):
        """Test dict_to_userdb with minimal data and defaults."""
        minimal_data = {
            "id": "test-user-id",
            "email": "test@example.com",
            "first_name": "John",
            "last_name": "Doe"
        }
        
        user_db = dict_to_userdb(minimal_data)
        
        assert user_db.id == "test-user-id"
        assert user_db.email == "test@example.com"
        assert user_db.first_name == "John"
        assert user_db.last_name == "Doe"
        assert user_db.role == "user"  # Default value
        assert user_db.subscription_tier == "free"  # Default value
        assert user_db.monthly_limit == 1000  # Default value
        assert user_db.usage_count == 0  # Default value
        assert user_db.is_active is True  # Default value
        assert user_db.email_verified is False  # Default value

    def test_dict_to_userdb_with_none_values(self):
        """Test dict_to_userdb with None values."""
        data_with_nones = {
            "id": "test-user-id",
            "email": "test@example.com",
            "password": None,
            "google_id": None,
            "first_name": "John",
            "last_name": "Doe",
            "company_name": None,
            "role": "user",
            "subscription_tier": "free",
            "monthly_limit": 5,
            "usage_count": 0,
            "last_usage_reset": None,
            "billing_period_start": None,
            "is_active": True,
            "email_verified": True,
            "email_verification_token": None,
            "password_reset_token": None,
            "password_reset_expires": None,
            "stripe_customer_id": None,
            "subscription_id": None,
            "subscription_status": None,
            "created_at": None,
            "updated_at": None
        }
        
        user_db = dict_to_userdb(data_with_nones)
        
        assert user_db.password is None
        assert user_db.google_id is None
        assert user_db.company_name is None
        assert user_db.last_usage_reset is None
        assert user_db.billing_period_start is None
        assert user_db.email_verification_token is None
        assert user_db.password_reset_token is None
        assert user_db.password_reset_expires is None
        assert user_db.stripe_customer_id is None
        assert user_db.subscription_id is None
        assert user_db.subscription_status is None
        assert user_db.created_at is None
        assert user_db.updated_at is None

    # Edge Cases and Integration Tests
    def test_userdb_with_none_last_usage_reset(self, sample_user_data):
        """Test UserDB with None last_usage_reset."""
        sample_user_data["last_usage_reset"] = None
        user_db = UserDB(**sample_user_data)
        user_internal = user_db.to_user_internal()
        
        # Should set default value when None
        assert user_internal.last_usage_reset is not None
        assert isinstance(user_internal.last_usage_reset, datetime)

    def test_user_response_json_encoding(self, sample_datetime):
        """Test UserResponse JSON encoding with datetime."""
        user_response = UserResponse(
            id="test-user-id",
            email="test@example.com",
            first_name="John",
            last_name="Doe",
            company_name="Test Company",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            monthly_limit=5,
            usage_count=0,
            last_usage_reset=sample_datetime,
            billing_period_start=sample_datetime,
            is_active=True,
            email_verified=True,
            created_at=sample_datetime,
            updated_at=sample_datetime
        )
        
        # Test that datetime fields are properly encoded
        try:
            json_data = user_response.model_dump(mode='json')
            assert isinstance(json_data["last_usage_reset"], str)
            assert isinstance(json_data["billing_period_start"], str)
            assert isinstance(json_data["created_at"], str)
            assert isinstance(json_data["updated_at"], str)
        except Exception:
            # If model_dump() doesn't work, test dict() instead
            dict_data = user_response.dict()
            assert isinstance(dict_data["last_usage_reset"], str)
            assert isinstance(dict_data["billing_period_start"], str)
            assert isinstance(dict_data["created_at"], str)
            assert isinstance(dict_data["updated_at"], str)

    def test_user_internal_json_encoding(self, sample_datetime):
        """Test UserInternal JSON encoding with datetime."""
        user_internal = UserInternal(
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
            last_usage_reset=sample_datetime,
            billing_period_start=sample_datetime,
            is_active=True,
            email_verified=True,
            email_verification_token=None,
            password_reset_token=None,
            password_reset_expires=None,
            stripe_customer_id=None,
            subscription_id=None,
            subscription_status=None,
            created_at=sample_datetime,
            updated_at=sample_datetime
        )
        
        # Test that datetime fields are properly encoded
        try:
            json_data = user_internal.model_dump(mode='json')
            assert isinstance(json_data["last_usage_reset"], str)
            assert isinstance(json_data["billing_period_start"], str)
            assert isinstance(json_data["created_at"], str)
            assert isinstance(json_data["updated_at"], str)
        except Exception:
            # If model_dump() doesn't work, test dict() instead
            dict_data = user_internal.dict()
            assert isinstance(dict_data["last_usage_reset"], str)
            assert isinstance(dict_data["billing_period_start"], str)
            assert isinstance(dict_data["created_at"], str)
            assert isinstance(dict_data["updated_at"], str)

    def test_model_serialization_roundtrip(self, sample_user_data):
        """Test model serialization and deserialization roundtrip."""
        # Create UserDB from data
        user_db = UserDB(**sample_user_data)
        
        # Convert to UserInternal
        user_internal = user_db.to_user_internal()
        
        # Convert to UserResponse
        user_response = user_internal.to_user_response()
        
        # Verify data integrity
        assert user_response.id == user_db.id
        assert user_response.email == user_db.email
        assert user_response.first_name == user_db.first_name
        assert user_response.last_name == user_db.last_name
        assert user_response.company_name == user_db.company_name
        # Handle both enum objects and strings
        role_value = user_response.role.value if hasattr(user_response.role, 'value') else user_response.role
        tier_value = user_response.subscription_tier.value if hasattr(user_response.subscription_tier, 'value') else user_response.subscription_tier
        assert role_value == user_db.role
        assert tier_value == user_db.subscription_tier
        assert user_response.monthly_limit == user_db.monthly_limit
        assert user_response.usage_count == user_db.usage_count
        assert user_response.is_active == user_db.is_active
        assert user_response.email_verified == user_db.email_verified
