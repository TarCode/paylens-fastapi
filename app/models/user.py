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
    firstName: str = Field(..., alias="firstName")
    lastName: str = Field(..., alias="lastName")
    companyName: Optional[str] = Field(None, alias="companyName")
    role: UserRole
    subscriptionTier: SubscriptionTier = Field(..., alias="subscriptionTier")
    monthlyLimit: int = Field(..., alias="monthlyLimit")
    usageCount: int = Field(..., alias="usageCount")
    lastUsageReset: datetime = Field(..., alias="lastUsageReset")
    billingPeriodStart: datetime = Field(..., alias="billingPeriodStart")
    isActive: bool = Field(..., alias="isActive")
    emailVerified: bool = Field(..., alias="emailVerified")
    createdAt: datetime = Field(..., alias="createdAt")
    updatedAt: datetime = Field(..., alias="updatedAt")

    class Config:
        allow_population_by_field_name = True
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
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
            firstName=self.first_name,
            lastName=self.last_name,
            companyName=self.company_name,
            role=UserRole(self.role),
            subscriptionTier=SubscriptionTier(self.subscription_tier),
            monthlyLimit=self.monthly_limit,
            usageCount=self.usage_count,
            lastUsageReset=self.last_usage_reset,
            billingPeriodStart=self.billing_period_start,
            isActive=self.is_active,
            emailVerified=self.email_verified,
            createdAt=self.created_at,
            updatedAt=self.updated_at
        )

    @property
    def role_enum(self) -> UserRole:
        """Get role as enum"""
        return UserRole(self.role)
    
    @property
    def subscription_tier_enum(self) -> SubscriptionTier:
        """Get subscription tier as enum"""
        return SubscriptionTier(self.subscription_tier)

# Alternative UserDB model with better validation (non-table version for API operations)
class UserDBValidated(SQLModel):
    """User model with proper validation for API operations (not a table)"""
    id: Optional[str] = None
    email: EmailStr
    password: Optional[str] = None
    google_id: Optional[str] = None
    first_name: str
    last_name: str
    company_name: Optional[str] = None
    role: UserRole = UserRole.USER
    subscription_tier: SubscriptionTier = SubscriptionTier.FREE
    monthly_limit: int = 1000
    usage_count: int = 0
    last_usage_reset: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    billing_period_start: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True
    email_verified: bool = False
    email_verification_token: Optional[str] = None
    password_reset_token: Optional[str] = None
    password_reset_expires: Optional[datetime] = None
    stripe_customer_id: Optional[str] = None
    subscription_id: Optional[str] = None
    subscription_status: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

# Utility functions for conversion between models
def userdb_to_validated(user_db: UserDB) -> UserDBValidated:
    """Convert UserDB (table model) to UserDBValidated (validation model)"""
    return UserDBValidated(
        id=user_db.id,
        email=user_db.email,
        password=user_db.password,
        google_id=user_db.google_id,
        first_name=user_db.first_name,
        last_name=user_db.last_name,
        company_name=user_db.company_name,
        role=UserRole(user_db.role),
        subscription_tier=SubscriptionTier(user_db.subscription_tier),
        monthly_limit=user_db.monthly_limit,
        usage_count=user_db.usage_count,
        last_usage_reset=user_db.last_usage_reset,
        billing_period_start=user_db.billing_period_start,
        is_active=user_db.is_active,
        email_verified=user_db.email_verified,
        email_verification_token=user_db.email_verification_token,
        password_reset_token=user_db.password_reset_token,
        password_reset_expires=user_db.password_reset_expires,
        stripe_customer_id=user_db.stripe_customer_id,
        subscription_id=user_db.subscription_id,
        subscription_status=user_db.subscription_status,
        created_at=user_db.created_at,
        updated_at=user_db.updated_at
    )

def validated_to_userdb(user_validated: UserDBValidated) -> UserDB:
    """Convert UserDBValidated to UserDB (for database operations)"""
    return UserDB(
        id=user_validated.id,
        email=user_validated.email,
        password=user_validated.password,
        google_id=user_validated.google_id,
        first_name=user_validated.first_name,
        last_name=user_validated.last_name,
        company_name=user_validated.company_name,
        role=user_validated.role.value,
        subscription_tier=user_validated.subscription_tier.value,
        monthly_limit=user_validated.monthly_limit,
        usage_count=user_validated.usage_count,
        last_usage_reset=user_validated.last_usage_reset,
        billing_period_start=user_validated.billing_period_start,
        is_active=user_validated.is_active,
        email_verified=user_validated.email_verified,
        email_verification_token=user_validated.email_verification_token,
        password_reset_token=user_validated.password_reset_token,
        password_reset_expires=user_validated.password_reset_expires,
        stripe_customer_id=user_validated.stripe_customer_id,
        subscription_id=user_validated.subscription_id,
        subscription_status=user_validated.subscription_status,
        created_at=user_validated.created_at,
        updated_at=user_validated.updated_at
    )

class User(BaseModel):
    id: str
    email: str
    password: Optional[str] = None  # Optional for Google OAuth users
    googleId: Optional[str] = None  # Google OAuth ID
    firstName: str
    lastName: str
    companyName: Optional[str] = None
    role: Literal['user', 'admin']
    subscriptionTier: Literal['free', 'pro', 'business', 'enterprise']
    monthlyLimit: int
    usageCount: int
    lastUsageReset: datetime
    billingPeriodStart: datetime
    isActive: bool
    emailVerified: bool
    emailVerificationToken: Optional[str] = None
    passwordResetToken: Optional[str] = None
    passwordResetExpires: Optional[datetime] = None
    stripeCustomerId: Optional[str] = None
    subscriptionId: Optional[str] = None
    subscriptionStatus: Optional[str] = None
    createdAt: datetime
    updatedAt: datetime


class CreateUserData(BaseModel):
    email: str
    password: Optional[str] = None  # Optional for Google OAuth users
    googleId: Optional[str] = None  # Google OAuth ID
    firstName: str
    lastName: str
    companyName: Optional[str] = None


class UpdateUserData(BaseModel):
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    companyName: Optional[str] = None
    googleId: Optional[str] = None
    role: Optional[Literal['user', 'admin']] = None
    isActive: Optional[bool] = None
    emailVerified: Optional[bool] = None
    subscriptionTier: Optional[Literal['free', 'pro', 'business', 'enterprise']] = None
    monthlyLimit: Optional[int] = None
    usageCount: Optional[int] = None
    lastUsageReset: Optional[datetime] = None
    billingPeriodStart: Optional[datetime] = None


class LoginData(BaseModel):
    email: str
    password: str


class AuthTokens(BaseModel):
    accessToken: str
    refreshToken: str


class JWTPayload(BaseModel):
    id: str
    email: str
    role: str
    subscriptionTier: str
    usageCount: int
    monthlyLimit: int
    lastUsageReset: datetime
    billingPeriodStart: datetime


class GoogleProfile(BaseModel):
    id: str
    email: str
    verified_email: bool
    name: str
    given_name: str
    family_name: str
    picture: str
    locale: str