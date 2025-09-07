from sqlmodel import SQLModel, Field, func
from pydantic import EmailStr, BaseModel
from typing import Optional, Literal
from datetime import datetime, timezone
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

# Response model for API endpoints (defined before UserDB)
class UserResponse(BaseModel):
    """Sanitized user data for API responses (no sensitive information)"""
    id: str
    email: EmailStr
    first_name: str
    last_name: str
    company_name: Optional[str] = None
    role: UserRole
    subscription_tier: SubscriptionTier
    monthly_limit: int
    usage_count: int
    last_usage_reset: datetime
    billing_period_start: datetime
    is_active: bool
    email_verified: bool
    created_at: datetime
    updated_at: datetime

    model_config = {
        "populate_by_name": True,
        "use_enum_values": True,
        "json_encoders": {
            datetime: lambda v: v.isoformat() if v else None
        }
    }

# Database-specific models (for ORMs like SQLAlchemy)
class UserDB(SQLModel, table=True):
    """User model for database operations"""
    __tablename__ = "users"
    
    id: Optional[str] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)  # EmailStr not supported in SQLModel table
    password: Optional[str] = Field(default=None)  # Hashed password
    google_id: Optional[str] = Field(default=None, unique=True)
    first_name: str
    last_name: str
    company_name: Optional[str] = Field(default=None)
    role: str = Field(default=UserRole.USER.value)  # Store as string
    subscription_tier: str = Field(default=SubscriptionTier.FREE.value)  # Store as string
    monthly_limit: int = Field(default=1000)
    usage_count: int = Field(default=0)
    last_usage_reset: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    billing_period_start: datetime = Field(
        sa_column_kwargs={"server_default": func.now()}  # <-- DB default
    )
    is_active: bool = Field(default=True)
    email_verified: bool = Field(default=False)
    email_verification_token: Optional[str] = Field(default=None)
    password_reset_token: Optional[str] = Field(default=None)
    password_reset_expires: Optional[datetime] = Field(default=None)
    stripe_customer_id: Optional[str] = Field(default=None)
    subscription_id: Optional[str] = Field(default=None)
    subscription_status: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_user_response(self) -> 'UserResponse':
        """Convert UserDB model to UserResponse (sanitized)"""
        
        return UserResponse(
            id=self.id,
            email=self.email,
            first_name=self.first_name,
            last_name=self.last_name,
            company_name=self.company_name,
            role=UserRole(self.role),
            subscription_tier=SubscriptionTier(self.subscription_tier),
            monthly_limit=self.monthly_limit,
            usage_count=self.usage_count,
            last_usage_reset=self.last_usage_reset,
            billing_period_start=self.billing_period_start,
            is_active=self.is_active,
            email_verified=self.email_verified,
            created_at=self.created_at,
            updated_at=self.updated_at
        )

    def to_user_internal(self) -> 'UserInternal':
        """Convert UserDB model to UserInternal (includes sensitive data)"""
        
        # Handle None values for datetime fields
        last_usage_reset = self.last_usage_reset
        if last_usage_reset is None:
            last_usage_reset = datetime.now(timezone.utc)
        
        return UserInternal(
            id=self.id,
            email=self.email,
            password=self.password,
            google_id=self.google_id,
            first_name=self.first_name,
            last_name=self.last_name,
            company_name=self.company_name,
            role=UserRole(self.role),
            subscription_tier=SubscriptionTier(self.subscription_tier),
            monthly_limit=self.monthly_limit,
            usage_count=self.usage_count,
            last_usage_reset=last_usage_reset,
            billing_period_start=self.billing_period_start,
            is_active=self.is_active,
            email_verified=self.email_verified,
            email_verification_token=self.email_verification_token,
            password_reset_token=self.password_reset_token,
            password_reset_expires=self.password_reset_expires,
            stripe_customer_id=self.stripe_customer_id,
            subscription_id=self.subscription_id,
            subscription_status=self.subscription_status,
            created_at=self.created_at,
            updated_at=self.updated_at
        )

    @property
    def role_enum(self) -> UserRole:
        """Get role as enum"""
        return UserRole(self.role)
    
    @property
    def subscription_tier_enum(self) -> SubscriptionTier:
        """Get subscription tier as enum"""
        return SubscriptionTier(self.subscription_tier)

# Internal User model for service layer operations (includes sensitive data)
class UserInternal(BaseModel):
    """Internal user model for service operations (includes sensitive fields)"""
    id: str
    email: EmailStr
    password: Optional[str] = None
    google_id: Optional[str] = None
    first_name: str
    last_name: str
    company_name: Optional[str] = None
    role: UserRole
    subscription_tier: SubscriptionTier
    monthly_limit: int
    usage_count: int
    last_usage_reset: datetime
    billing_period_start: datetime
    is_active: bool
    email_verified: bool
    email_verification_token: Optional[str] = None
    password_reset_token: Optional[str] = None
    password_reset_expires: Optional[datetime] = None
    stripe_customer_id: Optional[str] = None
    subscription_id: Optional[str] = None
    subscription_status: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {
        "populate_by_name": True,
        "use_enum_values": True,
        "json_encoders": {
            datetime: lambda v: v.isoformat() if v else None
        }
    }

    def to_user_response(self) -> 'UserResponse':
        """Convert UserInternal to UserResponse (sanitized)"""
        return UserResponse(
            id=self.id,
            email=self.email,
            first_name=self.first_name,
            last_name=self.last_name,
            company_name=self.company_name,
            role=self.role,
            subscription_tier=self.subscription_tier,
            monthly_limit=self.monthly_limit,
            usage_count=self.usage_count,
            last_usage_reset=self.last_usage_reset,
            billing_period_start=self.billing_period_start,
            is_active=self.is_active,
            email_verified=self.email_verified,
            created_at=self.created_at,
            updated_at=self.updated_at
        )


class CreateUserData(BaseModel):
    email: str
    password: Optional[str] = None  # Optional for Google OAuth users
    google_id: Optional[str] = None  # Google OAuth ID
    first_name: str
    last_name: str
    company_name: Optional[str] = None


class UpdateUserData(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    company_name: Optional[str] = None
    google_id: Optional[str] = None
    role: Optional[Literal['user', 'admin']] = None
    is_active: Optional[bool] = None
    email_verified: Optional[bool] = None
    subscription_tier: Optional[Literal['free', 'pro', 'business', 'enterprise']] = None
    monthly_limit: Optional[int] = None
    usage_count: Optional[int] = None
    last_usage_reset: Optional[datetime] = None
    billing_period_start: Optional[datetime] = None


class LoginData(BaseModel):
    email: str
    password: str


class AuthTokens(BaseModel):
    access_token: str
    refresh_token: str


class JWTPayload(BaseModel):
    id: str
    email: str
    role: str
    subscription_tier: str
    usage_count: int
    monthly_limit: int
    last_usage_reset: datetime
    billing_period_start: datetime


class GoogleProfile(BaseModel):
    id: str
    email: str
    verified_email: bool
    name: str
    given_name: str
    family_name: str
    picture: str
    locale: str


# Utility functions for model conversion
def dict_to_userdb(data: dict) -> UserDB:
    """Convert dictionary (from database) to UserDB model"""
    return UserDB(
        id=data.get('id'),
        email=data.get('email'),
        password=data.get('password'),
        google_id=data.get('google_id'),
        first_name=data.get('first_name'),
        last_name=data.get('last_name'),
        company_name=data.get('company_name'),
        role=data.get('role', UserRole.USER.value),
        subscription_tier=data.get('subscription_tier', SubscriptionTier.FREE.value),
        monthly_limit=data.get('monthly_limit', 1000),
        usage_count=data.get('usage_count', 0),
        last_usage_reset=data.get('last_usage_reset'),
        billing_period_start=data.get('billing_period_start'),
        is_active=data.get('is_active', True),
        email_verified=data.get('email_verified', False),
        email_verification_token=data.get('email_verification_token'),
        password_reset_token=data.get('password_reset_token'),
        password_reset_expires=data.get('password_reset_expires'),
        stripe_customer_id=data.get('stripe_customer_id'),
        subscription_id=data.get('subscription_id'),
        subscription_status=data.get('subscription_status'),
        created_at=data.get('created_at'),
        updated_at=data.get('updated_at')
    )