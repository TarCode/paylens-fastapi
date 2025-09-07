"""
Unit tests for AuthService.
"""
import pytest
import jwt
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import HTTPException, status

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'app'))

from services.auth_service import AuthService
from models.user import CreateUserData, UserInternal, UserRole, SubscriptionTier, GoogleProfile, AuthTokens, JWTPayload


class TestAuthService:
    """Test cases for AuthService."""

    @pytest.fixture
    def auth_service(self):
        """Create AuthService instance for testing."""
        return AuthService()

    @pytest.fixture
    def mock_user_service(self):
        """Mock user service."""
        return AsyncMock()

    @pytest.fixture
    def sample_user_internal(self):
        """Sample user internal for testing."""
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
            last_usage_reset=datetime.now(timezone.utc),
            billing_period_start=datetime.now(timezone.utc),
            is_active=True,
            email_verified=True,
            email_verification_token=None,
            password_reset_token=None,
            password_reset_expires=None,
            stripe_customer_id=None,
            subscription_id=None,
            subscription_status=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )

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
    def sample_google_profile(self):
        """Sample Google profile."""
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

    # Registration Tests
    @pytest.mark.asyncio
    async def test_register_success(self, auth_service, mock_user_service, sample_create_user_data, sample_user_internal):
        """Test successful user registration."""
        # Mock user service methods
        mock_user_service.find_by_email.return_value = None
        mock_user_service.create_user.return_value = sample_user_internal
        
        # Patch the user_service import
        with patch('services.auth_service.user_service', mock_user_service):
            result = await auth_service.register(sample_create_user_data)
            
            # Verify the result
            assert "user" in result
            assert "tokens" in result
            assert result["user"].email == sample_create_user_data.email
            assert result["tokens"].access_token is not None
            assert result["tokens"].refresh_token is not None
            
            # Verify user service was called correctly
            mock_user_service.find_by_email.assert_called_once_with(sample_create_user_data.email)
            mock_user_service.create_user.assert_called_once_with(sample_create_user_data)

    @pytest.mark.asyncio
    async def test_register_user_already_exists(self, auth_service, mock_user_service, sample_create_user_data, sample_user_internal):
        """Test registration when user already exists."""
        # Mock user service to return existing user
        mock_user_service.find_by_email.return_value = sample_user_internal
        
        with patch('services.auth_service.user_service', mock_user_service):
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.register(sample_create_user_data)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "User with this email already exists" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_register_token_generation_failure(self, auth_service, mock_user_service, sample_create_user_data, sample_user_internal):
        """Test registration when token generation fails."""
        # Mock user service methods
        mock_user_service.find_by_email.return_value = None
        mock_user_service.create_user.return_value = sample_user_internal
        
        # Mock generate_tokens to raise an exception
        with patch('app.services.auth_service.user_service', mock_user_service), \
             patch.object(auth_service, 'generate_tokens', side_effect=Exception("Token generation failed")):
            
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.register(sample_create_user_data)
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Failed to generate authentication tokens" in str(exc_info.value.detail)

    # Login Tests
    @pytest.mark.asyncio
    async def test_login_success(self, auth_service, mock_user_service, sample_user_internal):
        """Test successful login."""
        credentials = {"email": "test@example.com", "password": "TestPassword123!"}
        
        # Mock user service methods
        mock_user_service.find_by_email.return_value = sample_user_internal
        mock_user_service.validate_password.return_value = True
        
        with patch('services.auth_service.user_service', mock_user_service):
            result = await auth_service.login(credentials)
            
            # Verify the result
            assert "user" in result
            assert "tokens" in result
            assert result["user"].email == credentials["email"]
            
            # Verify user service was called correctly
            mock_user_service.find_by_email.assert_called_once_with(credentials["email"])
            mock_user_service.validate_password.assert_called_once_with(credentials["password"], sample_user_internal.password)

    @pytest.mark.asyncio
    async def test_login_user_not_found(self, auth_service, mock_user_service):
        """Test login when user is not found."""
        credentials = {"email": "nonexistent@example.com", "password": "TestPassword123!"}
        
        # Mock user service to return None
        mock_user_service.find_by_email.return_value = None
        
        with patch('services.auth_service.user_service', mock_user_service):
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.login(credentials)
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid email or password" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_login_invalid_password(self, auth_service, mock_user_service, sample_user_internal):
        """Test login with invalid password."""
        credentials = {"email": "test@example.com", "password": "WrongPassword"}
        
        # Mock user service methods
        mock_user_service.find_by_email.return_value = sample_user_internal
        mock_user_service.validate_password.return_value = False
        
        with patch('services.auth_service.user_service', mock_user_service):
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.login(credentials)
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid email or password" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_login_google_oauth_account(self, auth_service, mock_user_service):
        """Test login attempt on Google OAuth account."""
        # Create user with Google ID but no password
        google_user = UserInternal(
            id="test-user-id",
            email="test@example.com",
            password=None,  # No password
            google_id="google_123456789",  # Has Google ID
            first_name="John",
            last_name="Doe",
            company_name="Test Company",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.FREE,
            monthly_limit=5,
            usage_count=0,
            last_usage_reset=datetime.now(timezone.utc),
            billing_period_start=datetime.now(timezone.utc),
            is_active=True,
            email_verified=True,
            email_verification_token=None,
            password_reset_token=None,
            password_reset_expires=None,
            stripe_customer_id=None,
            subscription_id=None,
            subscription_status=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        credentials = {"email": "test@example.com", "password": "TestPassword123!"}
        
        # Mock user service
        mock_user_service.find_by_email.return_value = google_user
        
        with patch('services.auth_service.user_service', mock_user_service):
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.login(credentials)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "This account uses Google OAuth" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_login_inactive_account(self, auth_service, mock_user_service):
        """Test login with inactive account."""
        # Create inactive user
        inactive_user = UserInternal(
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
            last_usage_reset=datetime.now(timezone.utc),
            billing_period_start=datetime.now(timezone.utc),
            is_active=False,  # Inactive account
            email_verified=True,
            email_verification_token=None,
            password_reset_token=None,
            password_reset_expires=None,
            stripe_customer_id=None,
            subscription_id=None,
            subscription_status=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        credentials = {"email": "test@example.com", "password": "TestPassword123!"}
        
        # Mock user service methods
        mock_user_service.find_by_email.return_value = inactive_user
        mock_user_service.validate_password.return_value = True
        
        with patch('services.auth_service.user_service', mock_user_service):
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.login(credentials)
            
            assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
            assert "Account is deactivated" in str(exc_info.value.detail)

    # Token Generation Tests
    @pytest.mark.asyncio
    async def test_generate_tokens_success(self, auth_service, sample_user_internal):
        """Test successful token generation."""
        tokens = await auth_service.generate_tokens(sample_user_internal)
        
        # Verify token structure
        assert isinstance(tokens, AuthTokens)
        assert tokens.access_token is not None
        assert tokens.refresh_token is not None
        
        # Verify access token can be decoded
        decoded_access = jwt.decode(tokens.access_token, auth_service.jwt_secret, algorithms=["HS256"])
        assert decoded_access["id"] == sample_user_internal.id
        assert decoded_access["email"] == sample_user_internal.email
        assert decoded_access["role"] == sample_user_internal.role.value
        
        # Verify refresh token can be decoded
        decoded_refresh = jwt.decode(tokens.refresh_token, auth_service.refresh_token_secret, algorithms=["HS256"])
        assert decoded_refresh["id"] == sample_user_internal.id
        assert decoded_refresh["email"] == sample_user_internal.email

    @pytest.mark.asyncio
    async def test_generate_tokens_with_enum_values(self, auth_service):
        """Test token generation with enum values."""
        # Create user with enum values
        user_with_enums = UserInternal(
            id="test-user-id",
            email="test@example.com",
            password="hashed_password",
            google_id=None,
            first_name="John",
            last_name="Doe",
            company_name="Test Company",
            role=UserRole.ADMIN,  # Enum value
            subscription_tier=SubscriptionTier.PRO,  # Enum value
            monthly_limit=100,
            usage_count=0,
            last_usage_reset=datetime.now(timezone.utc),
            billing_period_start=datetime.now(timezone.utc),
            is_active=True,
            email_verified=True,
            email_verification_token=None,
            password_reset_token=None,
            password_reset_expires=None,
            stripe_customer_id=None,
            subscription_id=None,
            subscription_status=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        tokens = await auth_service.generate_tokens(user_with_enums)
        
        # Verify enum values are properly converted to strings
        decoded_access = jwt.decode(tokens.access_token, auth_service.jwt_secret, algorithms=["HS256"])
        assert decoded_access["role"] == "admin"
        assert decoded_access["subscription_tier"] == "pro"

    # Token Verification Tests
    @pytest.mark.asyncio
    async def test_verify_token_success(self, auth_service, sample_user_internal):
        """Test successful token verification."""
        # Generate a token first
        tokens = await auth_service.generate_tokens(sample_user_internal)
        
        # Verify the token
        payload = await auth_service.verify_token(tokens.access_token)
        
        # Verify payload structure
        assert isinstance(payload, JWTPayload)
        assert payload.id == sample_user_internal.id
        assert payload.email == sample_user_internal.email
        assert payload.role == sample_user_internal.role.value

    @pytest.mark.asyncio
    async def test_verify_token_expired(self, auth_service):
        """Test token verification with expired token."""
        # Create an expired token
        expired_payload = {
            "id": "test-user-id",
            "email": "test@example.com",
            "role": "user",
            "subscription_tier": "free",
            "usage_count": 0,
            "monthly_limit": 5,
            "last_usage_reset": datetime.now(timezone.utc).isoformat(),
            "billing_period_start": datetime.now(timezone.utc).isoformat(),
            "iat": int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp()),
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())  # Expired
        }
        
        expired_token = jwt.encode(expired_payload, auth_service.jwt_secret, algorithm="HS256")
        
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.verify_token(expired_token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Token has expired" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_verify_token_invalid(self, auth_service):
        """Test token verification with invalid token."""
        invalid_token = "invalid.token.here"
        
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.verify_token(invalid_token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid or expired token" in str(exc_info.value.detail)

    # Refresh Token Tests
    @pytest.mark.asyncio
    async def test_refresh_token_success(self, auth_service, mock_user_service, sample_user_internal):
        """Test successful token refresh."""
        # Generate tokens first
        tokens = await auth_service.generate_tokens(sample_user_internal)
        
        # Mock user service
        mock_user_service.find_by_id.return_value = sample_user_internal
        
        with patch('services.auth_service.user_service', mock_user_service):
            result = await auth_service.refresh_token(tokens.refresh_token)
            
            # Verify the result
            assert "user" in result
            assert "tokens" in result
            assert result["user"].id == sample_user_internal.id
            
            # Verify new tokens were generated
            assert result["tokens"].access_token != tokens.access_token
            assert result["tokens"].refresh_token != tokens.refresh_token

    @pytest.mark.asyncio
    async def test_refresh_token_expired(self, auth_service):
        """Test refresh token with expired token."""
        # Create an expired refresh token
        expired_payload = {
            "id": "test-user-id",
            "email": "test@example.com",
            "iat": int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp()),
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())  # Expired
        }
        
        expired_token = jwt.encode(expired_payload, auth_service.refresh_token_secret, algorithm="HS256")
        
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.refresh_token(expired_token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Refresh token has expired" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, auth_service):
        """Test refresh token with invalid token."""
        invalid_token = "invalid.refresh.token"
        
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.refresh_token(invalid_token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid refresh token" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_refresh_token_user_not_found(self, auth_service, mock_user_service):
        """Test refresh token when user is not found."""
        # Generate a valid refresh token
        valid_payload = {
            "id": "nonexistent-user-id",
            "email": "test@example.com",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp())
        }
        
        valid_token = jwt.encode(valid_payload, auth_service.refresh_token_secret, algorithm="HS256")
        
        # Mock user service to return None
        mock_user_service.find_by_id.return_value = None
        
        with patch('services.auth_service.user_service', mock_user_service):
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.refresh_token(valid_token)
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid refresh token" in str(exc_info.value.detail)

    # Password Validation Tests
    def test_validate_password_strong(self, auth_service):
        """Test password validation with strong password."""
        strong_password = "StrongPassword123!"
        result = auth_service.validate_password(strong_password)
        
        assert result["is_valid"] is True
        assert len(result["errors"]) == 0

    def test_validate_password_weak(self, auth_service):
        """Test password validation with weak password."""
        weak_password = "weak"
        result = auth_service.validate_password(weak_password)
        
        assert result["is_valid"] is False
        assert len(result["errors"]) > 0
        assert any("8 characters" in error for error in result["errors"])

    def test_validate_password_missing_requirements(self, auth_service):
        """Test password validation with missing requirements."""
        # Password missing uppercase, number, and special character
        weak_password = "weakpassword"
        result = auth_service.validate_password(weak_password)
        
        assert result["is_valid"] is False
        assert len(result["errors"]) >= 3  # At least 3 missing requirements

    # Email Validation Tests
    def test_validate_email_valid(self, auth_service):
        """Test email validation with valid email."""
        valid_emails = [
            "test@example.com",
            "user.name@domain.co.uk",
            "test+tag@example.org"
        ]
        
        for email in valid_emails:
            assert auth_service.validate_email(email) is True

    def test_validate_email_invalid(self, auth_service):
        """Test email validation with invalid email."""
        invalid_emails = [
            "invalid-email",
            "@example.com",
            "test@",
            "test.example.com",
            ""
        ]
        
        for email in invalid_emails:
            assert auth_service.validate_email(email) is False

    # Expiration Time Parsing Tests
    def test_parse_expiration_time_days(self, auth_service):
        """Test parsing expiration time in days."""
        exp_time = auth_service._parse_expiration_time("7d")
        expected = int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp())
        
        # Allow for small time differences
        assert abs(exp_time - expected) < 2

    def test_parse_expiration_time_hours(self, auth_service):
        """Test parsing expiration time in hours."""
        exp_time = auth_service._parse_expiration_time("24h")
        expected = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
        
        # Allow for small time differences
        assert abs(exp_time - expected) < 2

    def test_parse_expiration_time_minutes(self, auth_service):
        """Test parsing expiration time in minutes."""
        exp_time = auth_service._parse_expiration_time("60m")
        expected = int((datetime.now(timezone.utc) + timedelta(minutes=60)).timestamp())
        
        # Allow for small time differences
        assert abs(exp_time - expected) < 2

    def test_parse_expiration_time_invalid_format(self, auth_service):
        """Test parsing expiration time with invalid format."""
        exp_time = auth_service._parse_expiration_time("invalid")
        expected = int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp())  # Default to 7 days
        
        # Allow for small time differences
        assert abs(exp_time - expected) < 2

    def test_parse_expiration_time_empty(self, auth_service):
        """Test parsing expiration time with empty string."""
        exp_time = auth_service._parse_expiration_time("")
        expected = int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp())  # Default to 7 days
        
        # Allow for small time differences
        assert abs(exp_time - expected) < 2

    # Password Reset Tests
    @pytest.mark.asyncio
    async def test_generate_password_reset_token_success(self, auth_service, mock_user_service, sample_user_internal):
        """Test successful password reset token generation."""
        email = "test@example.com"
        
        # Mock user service
        mock_user_service.find_by_email.return_value = sample_user_internal
        
        with patch('services.auth_service.user_service', mock_user_service):
            token = await auth_service.generate_password_reset_token(email)
            
            # Verify token is generated (UUID format)
            assert token is not None
            assert len(token) == 36  # UUID length
            assert token.count('-') == 4  # UUID format
            
            # Verify user service was called
            mock_user_service.find_by_email.assert_called_once_with(email)

    @pytest.mark.asyncio
    async def test_generate_password_reset_token_user_not_found(self, auth_service, mock_user_service):
        """Test password reset token generation when user is not found."""
        email = "nonexistent@example.com"
        
        # Mock user service to return None
        mock_user_service.find_by_email.return_value = None
        
        with patch('services.auth_service.user_service', mock_user_service):
            with pytest.raises(HTTPException) as exc_info:
                await auth_service.generate_password_reset_token(email)
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert "User not found" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_reset_password_not_implemented(self, auth_service):
        """Test password reset (not implemented)."""
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.reset_password("token", "new_password")
        
        assert exc_info.value.status_code == status.HTTP_501_NOT_IMPLEMENTED
        assert "Password reset functionality needs to be implemented" in str(exc_info.value.detail)

    # Email Verification Tests
    @pytest.mark.asyncio
    async def test_generate_email_verification_token(self, auth_service):
        """Test email verification token generation."""
        user_id = "test-user-id"
        token = await auth_service.generate_email_verification_token(user_id)
        
        # Verify token is generated (UUID format)
        assert token is not None
        assert len(token) == 36  # UUID length
        assert token.count('-') == 4  # UUID format

    @pytest.mark.asyncio
    async def test_verify_email_not_implemented(self, auth_service):
        """Test email verification (not implemented)."""
        with pytest.raises(HTTPException) as exc_info:
            await auth_service.verify_email("token")
        
        assert exc_info.value.status_code == status.HTTP_501_NOT_IMPLEMENTED
        assert "Email verification functionality needs to be implemented" in str(exc_info.value.detail)
