"""
Unit tests for Auth Middleware.
"""
import pytest
import jwt
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'app'))

from middleware.auth_middleware import AuthMiddleware, get_current_user, User
from models.user import UserRole, SubscriptionTier


class TestAuthMiddleware:
    """Test cases for Auth Middleware."""

    @pytest.fixture
    def auth_middleware(self):
        """Create AuthMiddleware instance for testing."""
        return AuthMiddleware()

    @pytest.fixture
    def valid_jwt_payload(self):
        """Valid JWT payload for testing."""
        return {
            "id": "test-user-id",
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
    def expired_jwt_payload(self):
        """Expired JWT payload for testing."""
        return {
            "id": "test-user-id",
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
    def valid_token(self, auth_middleware, valid_jwt_payload):
        """Create a valid JWT token."""
        return jwt.encode(valid_jwt_payload, auth_middleware.jwt_secret, algorithm="HS256")

    @pytest.fixture
    def expired_token(self, auth_middleware, expired_jwt_payload):
        """Create an expired JWT token."""
        return jwt.encode(expired_jwt_payload, auth_middleware.jwt_secret, algorithm="HS256")

    @pytest.fixture
    def invalid_token(self):
        """Create an invalid JWT token."""
        return "invalid.token.here"

    # Authentication Tests
    @pytest.mark.asyncio
    async def test_authenticate_and_ensure_user_success(self, auth_middleware, valid_token):
        """Test successful authentication."""
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=valid_token)
        
        user = await auth_middleware.authenticate_and_ensure_user(credentials)
        
        assert isinstance(user, User)
        assert user.id == "test-user-id"
        assert user.email == "test@example.com"
        assert user.role == UserRole.USER
        assert user.subscription_tier == SubscriptionTier.FREE
        assert user.usage_count == 0
        assert user.monthly_limit == 5

    @pytest.mark.asyncio
    async def test_authenticate_and_ensure_user_no_credentials(self, auth_middleware):
        """Test authentication without credentials."""
        with pytest.raises(HTTPException) as exc_info:
            await auth_middleware.authenticate_and_ensure_user(None)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_401_UNAUTHORIZED
        assert "success" in exception.detail
        assert exception.detail["success"] is False
        assert "error" in exception.detail
        assert "Access token is required" in exception.detail["error"]["message"]

    @pytest.mark.asyncio
    async def test_authenticate_and_ensure_user_expired_token(self, auth_middleware, expired_token):
        """Test authentication with expired token."""
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired_token)
        
        with pytest.raises(HTTPException) as exc_info:
            await auth_middleware.authenticate_and_ensure_user(credentials)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_401_UNAUTHORIZED
        assert "success" in exception.detail
        assert exception.detail["success"] is False
        assert "error" in exception.detail
        assert "Token has expired" in exception.detail["error"]["message"]

    @pytest.mark.asyncio
    async def test_authenticate_and_ensure_user_invalid_token(self, auth_middleware, invalid_token):
        """Test authentication with invalid token."""
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=invalid_token)
        
        with pytest.raises(HTTPException) as exc_info:
            await auth_middleware.authenticate_and_ensure_user(credentials)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_401_UNAUTHORIZED
        assert "success" in exception.detail
        assert exception.detail["success"] is False
        assert "error" in exception.detail
        assert "Invalid or expired token" in exception.detail["error"]["message"]

    @pytest.mark.asyncio
    async def test_authenticate_and_ensure_user_wrong_secret(self, auth_middleware, valid_jwt_payload):
        """Test authentication with token signed with wrong secret."""
        wrong_secret = "wrong-secret"
        token_with_wrong_secret = jwt.encode(valid_jwt_payload, wrong_secret, algorithm="HS256")
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_with_wrong_secret)
        
        with pytest.raises(HTTPException) as exc_info:
            await auth_middleware.authenticate_and_ensure_user(credentials)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_401_UNAUTHORIZED
        assert "success" in exception.detail
        assert exception.detail["success"] is False
        assert "error" in exception.detail
        assert "Invalid or expired token" in exception.detail["error"]["message"]

    @pytest.mark.asyncio
    async def test_authenticate_and_ensure_user_missing_required_fields(self, auth_middleware):
        """Test authentication with token missing required fields."""
        incomplete_payload = {
            "id": "test-user-id",
            "email": "test@example.com"
            # Missing role, subscription_tier, etc.
        }
        
        incomplete_token = jwt.encode(incomplete_payload, auth_middleware.jwt_secret, algorithm="HS256")
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=incomplete_token)
        
        user = await auth_middleware.authenticate_and_ensure_user(credentials)
        
        # Should use default values for missing fields
        assert user.id == "test-user-id"
        assert user.email == "test@example.com"
        assert user.role == UserRole.USER  # Default value
        assert user.subscription_tier == SubscriptionTier.FREE  # Default value
        assert user.usage_count == 0  # Default value
        assert user.monthly_limit == 100  # Default value

    # Get Current User Tests
    @pytest.mark.asyncio
    async def test_get_current_user_success(self, auth_middleware, valid_token):
        """Test successful user extraction from request."""
        mock_request = MagicMock()
        mock_request.headers = {"authorization": f"Bearer {valid_token}"}
        
        user = await auth_middleware.get_current_user(mock_request)
        
        assert isinstance(user, User)
        assert user.id == "test-user-id"
        assert user.email == "test@example.com"
        assert user.role == UserRole.USER

    @pytest.mark.asyncio
    async def test_get_current_user_no_auth_header(self, auth_middleware):
        """Test user extraction without authorization header."""
        mock_request = MagicMock()
        mock_request.headers = {}
        
        user = await auth_middleware.get_current_user(mock_request)
        
        assert user is None

    @pytest.mark.asyncio
    async def test_get_current_user_invalid_auth_header(self, auth_middleware):
        """Test user extraction with invalid authorization header."""
        mock_request = MagicMock()
        mock_request.headers = {"authorization": "InvalidFormat token"}
        
        user = await auth_middleware.get_current_user(mock_request)
        
        assert user is None

    @pytest.mark.asyncio
    async def test_get_current_user_no_bearer_prefix(self, auth_middleware, valid_token):
        """Test user extraction without Bearer prefix."""
        mock_request = MagicMock()
        mock_request.headers = {"authorization": valid_token}
        
        user = await auth_middleware.get_current_user(mock_request)
        
        assert user is None

    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self, auth_middleware, invalid_token):
        """Test user extraction with invalid token."""
        mock_request = MagicMock()
        mock_request.headers = {"authorization": f"Bearer {invalid_token}"}
        
        user = await auth_middleware.get_current_user(mock_request)
        
        assert user is None

    @pytest.mark.asyncio
    async def test_get_current_user_expired_token(self, auth_middleware, expired_token):
        """Test user extraction with expired token."""
        mock_request = MagicMock()
        mock_request.headers = {"authorization": f"Bearer {expired_token}"}
        
        user = await auth_middleware.get_current_user(mock_request)
        
        assert user is None

    # User Model Tests
    def test_user_model_creation(self, valid_jwt_payload):
        """Test User model creation from JWT payload."""
        user = User(
            id=valid_jwt_payload["id"],
            email=valid_jwt_payload["email"],
            role=UserRole(valid_jwt_payload["role"]),
            subscription_tier=SubscriptionTier(valid_jwt_payload["subscription_tier"]),
            usage_count=valid_jwt_payload["usage_count"],
            monthly_limit=valid_jwt_payload["monthly_limit"],
            last_usage_reset=datetime.fromisoformat(valid_jwt_payload["last_usage_reset"]),
            billing_period_start=datetime.fromisoformat(valid_jwt_payload["billing_period_start"])
        )
        
        assert user.id == "test-user-id"
        assert user.email == "test@example.com"
        assert user.role == UserRole.USER
        assert user.subscription_tier == SubscriptionTier.FREE
        assert user.usage_count == 0
        assert user.monthly_limit == 5
        assert isinstance(user.last_usage_reset, datetime)
        assert isinstance(user.billing_period_start, datetime)

    def test_user_model_with_admin_role(self):
        """Test User model with admin role."""
        user = User(
            id="admin-user-id",
            email="admin@example.com",
            role=UserRole.ADMIN,
            subscription_tier=SubscriptionTier.ENTERPRISE,
            usage_count=100,
            monthly_limit=1000,
            last_usage_reset=datetime.now(timezone.utc),
            billing_period_start=datetime.now(timezone.utc)
        )
        
        assert user.role == UserRole.ADMIN
        assert user.subscription_tier == SubscriptionTier.ENTERPRISE
        assert user.usage_count == 100
        assert user.monthly_limit == 1000

    def test_user_model_with_pro_subscription(self):
        """Test User model with pro subscription."""
        user = User(
            id="pro-user-id",
            email="pro@example.com",
            role=UserRole.USER,
            subscription_tier=SubscriptionTier.PRO,
            usage_count=50,
            monthly_limit=100,
            last_usage_reset=datetime.now(timezone.utc),
            billing_period_start=datetime.now(timezone.utc)
        )
        
        assert user.subscription_tier == SubscriptionTier.PRO
        assert user.usage_count == 50
        assert user.monthly_limit == 100

    # Dependency Injection Tests
    @pytest.mark.asyncio
    async def test_get_current_user_dependency_success(self, valid_token):
        """Test get_current_user dependency function."""
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=valid_token)
        
        user = await get_current_user(credentials)
        
        assert isinstance(user, User)
        assert user.id == "test-user-id"
        assert user.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_get_current_user_dependency_no_credentials(self):
        """Test get_current_user dependency without credentials."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(None)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Access token is required" in exception.detail["error"]["message"]

    # Edge Cases and Error Handling
    @pytest.mark.asyncio
    async def test_authenticate_and_ensure_user_malformed_token(self, auth_middleware):
        """Test authentication with malformed token."""
        malformed_token = "not.a.valid.jwt"
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=malformed_token)
        
        with pytest.raises(HTTPException) as exc_info:
            await auth_middleware.authenticate_and_ensure_user(credentials)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid or expired token" in exception.detail["error"]["message"]

    @pytest.mark.asyncio
    async def test_authenticate_and_ensure_user_empty_token(self, auth_middleware):
        """Test authentication with empty token."""
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="")
        
        with pytest.raises(HTTPException) as exc_info:
            await auth_middleware.authenticate_and_ensure_user(credentials)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid or expired token" in exception.detail["error"]["message"]

    @pytest.mark.asyncio
    async def test_authenticate_and_ensure_user_none_token(self, auth_middleware):
        """Test authentication with None token."""
        with pytest.raises(HTTPException) as exc_info:
            await auth_middleware.authenticate_and_ensure_user(None)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Access token is required" in exception.detail["error"]["message"]

    @pytest.mark.asyncio
    async def test_get_current_user_exception_handling(self, auth_middleware):
        """Test get_current_user exception handling."""
        mock_request = MagicMock()
        mock_request.headers = {"authorization": "Bearer valid_token"}
        
        # Mock jwt.decode to raise an exception
        with patch('jwt.decode', side_effect=Exception("Unexpected error")):
            user = await auth_middleware.get_current_user(mock_request)
            
            assert user is None

    @pytest.mark.asyncio
    async def test_authenticate_and_ensure_user_exception_handling(self, auth_middleware):
        """Test authenticate_and_ensure_user exception handling."""
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="valid_token")
        
        # Mock jwt.decode to raise an exception
        with patch('jwt.decode', side_effect=Exception("Unexpected error")):
            with pytest.raises(HTTPException) as exc_info:
                await auth_middleware.authenticate_and_ensure_user(credentials)
            
            exception = exc_info.value
            assert exception.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid or expired token" in exception.detail["error"]["message"]

    # Environment Variable Tests
    def test_auth_middleware_initialization_with_custom_secret(self):
        """Test AuthMiddleware initialization with custom JWT secret."""
        with patch.dict('os.environ', {'JWT_SECRET': 'custom-secret'}):
            middleware = AuthMiddleware()
            assert middleware.jwt_secret == 'custom-secret'

    def test_auth_middleware_initialization_with_default_secret(self):
        """Test AuthMiddleware initialization with default JWT secret."""
        with patch.dict('os.environ', {}, clear=True):
            middleware = AuthMiddleware()
            assert middleware.jwt_secret == 'fallback-secret-change-in-production'

    # Token Validation Tests
    @pytest.mark.asyncio
    async def test_authenticate_and_ensure_user_with_different_roles(self, auth_middleware):
        """Test authentication with different user roles."""
        roles_to_test = ["user", "admin"]
        
        for role in roles_to_test:
            payload = {
                "id": f"test-{role}-id",
                "email": f"{role}@example.com",
                "role": role,
                "subscription_tier": "free",
                "usage_count": 0,
                "monthly_limit": 5,
                "last_usage_reset": datetime.now(timezone.utc).isoformat(),
                "billing_period_start": datetime.now(timezone.utc).isoformat(),
                "iat": int(datetime.now(timezone.utc).timestamp())
            }
            
            token = jwt.encode(payload, auth_middleware.jwt_secret, algorithm="HS256")
            credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
            
            user = await auth_middleware.authenticate_and_ensure_user(credentials)
            
            assert user.role.value == role
            assert user.email == f"{role}@example.com"

    @pytest.mark.asyncio
    async def test_authenticate_and_ensure_user_with_different_subscription_tiers(self, auth_middleware):
        """Test authentication with different subscription tiers."""
        tiers_to_test = ["free", "pro", "business", "enterprise"]
        
        for tier in tiers_to_test:
            payload = {
                "id": f"test-{tier}-id",
                "email": f"{tier}@example.com",
                "role": "user",
                "subscription_tier": tier,
                "usage_count": 0,
                "monthly_limit": 5,
                "last_usage_reset": datetime.now(timezone.utc).isoformat(),
                "billing_period_start": datetime.now(timezone.utc).isoformat(),
                "iat": int(datetime.now(timezone.utc).timestamp())
            }
            
            token = jwt.encode(payload, auth_middleware.jwt_secret, algorithm="HS256")
            credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
            
            user = await auth_middleware.authenticate_and_ensure_user(credentials)
            
            assert user.subscription_tier.value == tier
            assert user.email == f"{tier}@example.com"
