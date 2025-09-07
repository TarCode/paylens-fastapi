from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Union, Optional
import jwt
import uuid
import bcrypt
import re
import os
from fastapi import HTTPException, status

# Import your existing models and services
from models.user import User, AuthTokens, JWTPayload, GoogleProfile
from services.user_service import user_service


UserLike = Union[User, Dict[str, Any]]


class AuthService:
    def __init__(self):
        self.jwt_secret = os.getenv("JWT_SECRET", "fallback-secret-change-in-production")
        self.jwt_expires_in = os.getenv("JWT_EXPIRES_IN", "7d")
        self.refresh_token_secret = os.getenv("REFRESH_TOKEN_SECRET", "fallback-refresh-secret")
        self.refresh_token_expires_in = os.getenv("REFRESH_TOKEN_EXPIRES_IN", "30d")

    # small helper to access both dicts and objects
    def _get(self, user: UserLike, key: str, default: Optional[Any] = None) -> Any:
        if user is None:
            return default
        if isinstance(user, dict):
            return user.get(key, default)
        # fallback to attribute access for objects/SQLModel/Pydantic instances
        return getattr(user, key, default)

    async def register(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Register a new user
        user_data should contain: email, password (optional), google_id (optional), 
        first_name, last_name, company_name (optional)
        """
        # Check if user already exists
        existing_user = await user_service.find_by_email(user_data["email"])
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists"
            )

        # Create new user
        user = await user_service.create_user(user_data)

        # Generate tokens
        try:
            tokens = await self.generate_tokens(user)
            return {"user": self.sanitize_user(user), "tokens": tokens}
        except Exception as e:
            print(f"[ERROR] Token generation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate authentication tokens"
            )

    async def login(self, credentials: Dict[str, str]) -> Dict[str, Any]:
        """
        Login with email and password
        credentials should contain: email, password
        """
        # Find user by email
        user = await user_service.find_by_email(credentials["email"])
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )

        # read password and google_id via helper
        stored_password = self._get(user, "password")
        google_id = self._get(user, "google_id")

        # If no stored password but google_id exists -> google oauth account
        if not stored_password and google_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This account uses Google OAuth. Please sign in with Google."
            )

        if not stored_password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )

        # Validate password - ensure validate_password in user_service accepts (plain, hashed)
        is_valid_password = await user_service.validate_password(credentials["password"], stored_password)
        if not is_valid_password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )

        # Check if user is active
        is_active = bool(self._get(user, "is_active", True))

        if not is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is deactivated. Please contact support."
            )

        # Generate tokens
        tokens = await self.generate_tokens(user)

        return {"user": self.sanitize_user(user), "tokens": tokens}

    async def authenticate_with_google(self, profile: GoogleProfile) -> Dict[str, Any]:
        """
        Authenticate or register user with Google OAuth profile
        """
        # Check if user already exists by email
        user = await user_service.find_by_email(profile.email)

        is_new_user = False

        if not user:
            # Check if user exists by Google ID
            user = await user_service.find_by_google_id(profile.id)

            if not user:
                # Create new user from Google profile
                user_data = {
                    "email": profile.email,
                    "google_id": profile.id,
                    "first_name": profile.given_name,
                    "last_name": profile.family_name,
                    "email_verified": profile.verified_email,
                    "is_active": True,
                    "role": "user",
                    "subscription_tier": "free",
                    "monthly_limit": 100,
                    "usage_count": 0
                }

                user = await user_service.create_user(user_data)
                is_new_user = True

        elif not bool(self._get(user, "is_active", True)):
            # Existing user but deactivated - reactivate and link Google account
            uid = self._get(user, "id")
            try:
                update_result = await user_service.update_user(uid, {
                    "google_id": profile.id,
                    "is_active": True,
                    "email_verified": profile.verified_email
                })

                if not update_result:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to update user in database"
                    )

                user = await user_service.find_by_id(uid)

                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to retrieve updated user from database"
                    )

                is_new_user = False

            except Exception as error:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Account reactivation failed. Please contact support."
                )

        elif not self._get(user, "google_id"):
            # Existing active user, just link Google account
            uid = self._get(user, "id")
            await user_service.update_user(uid, {"google_id": profile.id})
            user = await user_service.find_by_id(uid)
            is_new_user = False

        if not user or not bool(self._get(user, "is_active", True)):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Account reactivation failed. Please contact support."
            )

        # Generate tokens
        tokens = await self.generate_tokens(user)

        return {"user": self.sanitize_user(user), "tokens": tokens, "is_new_user": is_new_user}

    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using refresh token
        """
        try:
            # Verify refresh token
            decoded = jwt.decode(refresh_token, self.refresh_token_secret, algorithms=["HS256"])

            # Find user
            user = await user_service.find_by_id(decoded.get("id"))
            if not user or not bool(self._get(user, "is_active", True)):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token"
                )

            # Generate new tokens
            tokens = await self.generate_tokens(user)

            return {"user": self.sanitize_user(user), "tokens": tokens}

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired"
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

    async def generate_tokens(self, user: UserLike) -> AuthTokens:
        """
        Generate access and refresh tokens for a user
        """
        uid = self._get(user, "id")
        email = self._get(user, "email")
        role = self._get(user, "role")
        subscription_tier = self._get(user, "subscription_tier")
        usage_count = self._get(user, "usage_count")
        monthly_limit = self._get(user, "monthly_limit")
        last_usage_reset = self._get(user, "last_usage_reset")
        billing_period_start = self._get(user, "billing_period_start")

        # Helper to convert datetime to ISO string, or return None
        def _iso_or_none(val):
            if val is None:
                return None
            if isinstance(val, str):
                return val
            if isinstance(val, datetime):
                if val.tzinfo is None:
                    val = val.replace(tzinfo=timezone.utc)
                return val.isoformat()
            return str(val)

        payload = {
            "id": uid,
            "email": email,
            "role": role,
            "subscription_tier": subscription_tier,
            "usage_count": usage_count,
            "monthly_limit": monthly_limit,
            "last_usage_reset": _iso_or_none(last_usage_reset),
            "billing_period_start": _iso_or_none(billing_period_start),
            "iat": int(datetime.now(timezone.utc).timestamp())  # issued at
        }

        # Generate expiration timestamps for access and refresh tokens
        access_exp = self._parse_expiration_time(self.jwt_expires_in)
        refresh_exp = self._parse_expiration_time(self.refresh_token_expires_in)

        # Generate JWTs using HS256
        access_token = jwt.encode(
            {**payload, "exp": access_exp},
            self.jwt_secret,
            algorithm="HS256"
        )

        refresh_token = jwt.encode(
            {"id": uid, "email": email, "exp": refresh_exp, "iat": payload["iat"]},
            self.refresh_token_secret,
            algorithm="HS256"
        )

        return AuthTokens(access_token=access_token, refresh_token=refresh_token)
    async def verify_token(self, token: str) -> JWTPayload:
        """
        Verify and decode JWT token
        """
        try:
            decoded = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            return JWTPayload(**decoded)
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )

    async def generate_password_reset_token(self, email: str) -> str:
        """
        Generate password reset token
        """
        user = await user_service.find_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        reset_token = str(uuid.uuid4())
        # In a real implementation, you'd store this in the database
        # For now, we'll just return the token
        return reset_token

    async def reset_password(self, token: str, new_password: str) -> None:
        """
        Reset user password using reset token
        """
        # In a real implementation, you'd validate the token against the database
        # For now, we'll just raise an error indicating it needs implementation
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Password reset functionality needs to be implemented with database storage"
        )

    async def generate_email_verification_token(self, user_id: str) -> str:
        """
        Generate email verification token
        """
        verification_token = str(uuid.uuid4())
        # In a real implementation, you'd store this in the database
        # For now, we'll just return the token
        return verification_token

    async def verify_email(self, token: str) -> None:
        """
        Verify user email using verification token
        """
        # In a real implementation, you'd validate the token and update the user's email_verified status
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Email verification functionality needs to be implemented with database storage"
        )

    def sanitize_user(self, user: UserLike) -> Dict[str, Any]:
        """
        Get user profile (without sensitive data)
        """
        # produce a mutable dict
        if user is None:
            return {}

        if isinstance(user, dict):
            user_dict = user.copy()
        else:
            # object -> convert to dict using .dict() if available, else __dict__
            if hasattr(user, "dict"):
                user_dict = user.dict()
            elif hasattr(user, "__dict__"):
                user_dict = dict(user.__dict__)
            else:
                # fallback: try to build dict from known attributes
                user_dict = {
                    "id": getattr(user, "id", None),
                    "email": getattr(user, "email", None),
                }

        # Remove sensitive fields
        sensitive_fields = [
            "password",
            "email_verification_token",
            "password_reset_token",
            "password_reset_expires"
        ]

        for field in sensitive_fields:
            user_dict.pop(field, None)

        return user_dict

    def validate_password(self, password: str) -> Dict[str, Any]:
        """
        Validate password strength
        """
        errors = []

        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")

        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")

        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")

        if not re.search(r"\d", password):
            errors.append("Password must contain at least one number")

        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
            errors.append("Password must contain at least one special character")

        return {
            "is_valid": len(errors) == 0,
            "errors": errors
        }

    def validate_email(self, email: str) -> bool:
        """
        Validate email format
        """
        email_regex = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
        return bool(re.match(email_regex, email))

    def _parse_expiration_time(self, time_str: str) -> int:
        """
        Parse expiration time string (e.g., "7d", "30d") to timestamp
        """
        now = datetime.now(tz=timezone.utc)

        if not time_str:
            time_str = "7d"

        if time_str.endswith('d'):
            days = int(time_str[:-1])
            exp_time = now + timedelta(days=days)
        elif time_str.endswith('h'):
            hours = int(time_str[:-1])
            exp_time = now + timedelta(hours=hours)
        elif time_str.endswith('m'):
            minutes = int(time_str[:-1])
            exp_time = now + timedelta(minutes=minutes)
        else:
            # Default to 7 days if format is not recognized
            exp_time = now + timedelta(days=7)

        # return unix timestamp (int)
        return int(exp_time.timestamp())


# Create singleton instance
auth_service = AuthService()
