from pyexpat import ParserCreate
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from datetime import datetime
from enum import Enum

# Enums for better type safety
class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"

class SubscriptionTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"

class User(BaseModel):
    """User model representing a complete user entity"""
    id: str
    email: EmailStr
    password: Optional[str] = None  # Optional for Google OAuth users
    google_id: Optional[str] = Field(None, alias="googleId")  # Google OAuth ID
    first_name: str = Field(..., alias="firstName")
    last_name: str = Field(..., alias="lastName")
    company_name: Optional[str] = Field(None, alias="companyName")
    role: UserRole = UserRole.USER
    subscription_tier: SubscriptionTier = Field(SubscriptionTier.FREE, alias="subscriptionTier")
    monthly_limit: int = Field(default=1000, alias="monthlyLimit")
    usage_count: int = Field(default=0, alias="usageCount")
    last_usage_reset: datetime = Field(default_factory=datetime.now(datetime.timezone.utc), alias="lastUsageReset")
    billing_period_start: datetime = Field(default_factory=datetime.now(datetime.timezone.utc), alias="billingPeriodStart")
    is_active: bool = Field(default=True, alias="isActive")
    email_verified: bool = Field(default=False, alias="emailVerified")
    email_verification_token: Optional[str] = Field(None, alias="emailVerificationToken")
    password_reset_token: Optional[str] = Field(None, alias="passwordResetToken")
    password_reset_expires: Optional[datetime] = Field(None, alias="passwordResetExpires")
    stripe_customer_id: Optional[str] = Field(None, alias="stripeCustomerId")
    subscription_id: Optional[str] = Field(None, alias="subscriptionId")
    subscription_status: Optional[str] = Field(None, alias="subscriptionStatus")
    created_at: datetime = Field(default_factory=datetime.now(datetime.timezone.utc), alias="createdAt")
    updated_at: datetime = Field(default_factory=datetime.now(datetime.timezone.utc), alias="updatedAt")

    class Config:
        allow_population_by_field_name = True
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

    @field_validator('password')
    def validate_password_or_google_id(cls, v, values):
        """Ensure user has either password or googleId"""
        if not v and not values.get('google_id'):
            raise ValueError('User must have either password or googleId')
        return v

class CreateUserData(BaseModel):
    """Data required to create a new user"""
    email: EmailStr
    password: Optional[str] = None  # Optional for Google OAuth users
    google_id: Optional[str] = Field(None, alias="googleId")  # Google OAuth ID
    first_name: str = Field(..., alias="firstName")
    last_name: str = Field(..., alias="lastName")
    company_name: Optional[str] = Field(None, alias="companyName")

    class Config:
        allow_population_by_field_name = True

    @field_validator('password')
    def validate_password_or_google_id(cls, v, values):
        """Ensure user has either password or googleId"""
        if not v and not values.get('google_id'):
            raise ValueError('User must have either password or googleId')
        return v

class UpdateUserData(BaseModel):
    """Data that can be updated for a user"""
    first_name: Optional[str] = Field(None, alias="firstName")
    last_name: Optional[str] = Field(None, alias="lastName")
    company_name: Optional[str] = Field(None, alias="companyName")
    google_id: Optional[str] = Field(None, alias="googleId")
    role: Optional[UserRole] = None
    is_active: Optional[bool] = Field(None, alias="isActive")
    email_verified: Optional[bool] = Field(None, alias="emailVerified")
    subscription_tier: Optional[SubscriptionTier] = Field(None, alias="subscriptionTier")
    monthly_limit: Optional[int] = Field(None, alias="monthlyLimit")
    usage_count: Optional[int] = Field(None, alias="usageCount")
    last_usage_reset: Optional[datetime] = Field(None, alias="lastUsageReset")
    billing_period_start: Optional[datetime] = Field(None, alias="billingPeriodStart")

    class Config:
        allow_population_by_field_name = True
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

class LoginData(BaseModel):
    """Data required for user login"""
    email: EmailStr
    password: str

class AuthTokens(BaseModel):
    """Authentication tokens returned after successful login/registration"""
    access_token: str = Field(..., alias="accessToken")
    refresh_token: str = Field(..., alias="refreshToken")

    class Config:
        allow_population_by_field_name = True

class JWTPayload(BaseModel):
    """JWT token payload structure"""
    id: str
    email: EmailStr
    role: UserRole
    subscription_tier: SubscriptionTier = Field(..., alias="subscriptionTier")
    usage_count: int = Field(..., alias="usageCount")
    monthly_limit: int = Field(..., alias="monthlyLimit")
    last_usage_reset: datetime = Field(..., alias="lastUsageReset")
    billing_period_start: datetime = Field(..., alias="billingPeriodStart")
    exp: Optional[int] = None  # Expiration timestamp
    iat: Optional[int] = None  # Issued at timestamp

    class Config:
        allow_population_by_field_name = True
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: int(v.timestamp()) if v else None
        }

class GoogleProfile(BaseModel):
    """Google OAuth profile data"""
    id: str
    email: EmailStr
    verified_email: bool
    name: str
    given_name: str
    family_name: str
    picture: str
    locale: str = "en"

# Database-specific models (for ORMs like SQLAlchemy)
class UserDB(BaseModel):
    """User model for database operations (without sensitive data)"""
    id: Optional[str] = None
    email: EmailStr
    password_hash: Optional[str] = None  # Hashed password
    google_id: Optional[str] = None
    first_name: str
    last_name: str
    company_name: Optional[str] = None
    role: UserRole = UserRole.USER
    subscription_tier: SubscriptionTier = SubscriptionTier.FREE
    monthly_limit: int = 1000
    usage_count: int = 0
    last_usage_reset: datetime = Field(default_factory=datetime.now(datetime.timezone.utc))
    billing_period_start: datetime = Field(default_factory=datetime.now(datetime.timezone.utc))
    is_active: bool = True
    email_verified: bool = False
    email_verification_token: Optional[str] = None
    password_reset_token: Optional[str] = None
    password_reset_expires: Optional[datetime] = None
    stripe_customer_id: Optional[str] = None
    subscription_id: Optional[str] = None
    subscription_status: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now(datetime.timezone.utc))
    updated_at: datetime = Field(default_factory=datetime.now(datetime.timezone.utc))

    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

# Response models for API endpoints
class UserResponse(BaseModel):
    """Sanitized user data for API responses (no sensitive information)"""
    id: str
    email: EmailStr
    first_name: str = Field(..., alias="firstName")
    last_name: str = Field(..., alias="lastName")
    company_name: Optional[str] = Field(None, alias="companyName")
    role: UserRole
    subscription_tier: SubscriptionTier = Field(..., alias="subscriptionTier")
    monthly_limit: int = Field(..., alias="monthlyLimit")
    usage_count: int = Field(..., alias="usageCount")
    last_usage_reset: datetime = Field(..., alias="lastUsageReset")
    billing_period_start: datetime = Field(..., alias="billingPeriodStart")
    is_active: bool = Field(..., alias="isActive")
    email_verified: bool = Field(..., alias="emailVerified")
    created_at: datetime = Field(..., alias="createdAt")
    updated_at: datetime = Field(..., alias="updatedAt")

    class Config:
        allow_population_by_field_name = True
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

# Utility functions for model conversion
def user_to_response(user: UserDB) -> UserResponse:
    """Convert UserDB model to UserResponse (sanitized)"""
    return user.to_user_response()

def create_jwt_payload(user: UserDB) -> JWTPayload:
    """Create JWT payload from user data"""
    return JWTPayload(
        id=user.id,
        email=user.email,
        role=UserRole(user.role),
        subscriptionTier=SubscriptionTier(user.subscription_tier),
        usageCount=user.usage_count,
        monthlyLimit=user.monthly_limit,
        lastUsageReset=user.last_usage_reset,
        billingPeriodStart=user.billing_period_start
    )

def create_user_from_data(user_data: CreateUserData, password_hash: Optional[str] = None) -> ParserCreate:
    """Convert CreateUserData to UserCreate model"""
    return ParserCreate(
        email=user_data.email,
        password_hash=password_hash,
        google_id=user_data.google_id,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        company_name=user_data.company_name
    )