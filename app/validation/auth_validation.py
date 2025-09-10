from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, validator


# Validation Models
class RegisterData(BaseModel):
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long")
    first_name: str = Field(..., min_length=2, max_length=100, description="First name must be between 2 and 100 characters")
    last_name: str = Field(..., min_length=2, max_length=100, description="Last name must be between 2 and 100 characters")
    company_name: Optional[str] = Field(None, max_length=255, description="Company name must be less than 255 characters")

    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        """Trim whitespace and validate name fields"""
        if v:
            v = v.strip()
            if len(v) < 2:
                raise ValueError('Name must be at least 2 characters long')
            if len(v) > 100:
                raise ValueError('Name must be less than 100 characters')
        return v

    @validator('company_name')
    def validate_company_name(cls, v):
        """Trim whitespace and validate company name"""
        if v is not None:
            v = v.strip()
            if len(v) > 255:
                raise ValueError('Company name must be less than 255 characters')
            if len(v) == 0:
                return None
        return v

    @validator('password')
    def validate_password_strength(cls, v):
        """Basic password strength validation"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        # Optional: Add more password requirements
        # if not re.search(r'[A-Za-z]', v):
        #     raise ValueError('Password must contain at least one letter')
        # if not re.search(r'\d', v):
        #     raise ValueError('Password must contain at least one number')
        return v
    


class LoginData(BaseModel):
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=6, description="Password must be at least 6 characters long")

    @validator('password')
    def password_not_empty(cls, v):
        """Ensure password is not empty or whitespace only"""
        if not v or not v.strip():
            raise ValueError('Password cannot be empty or whitespace only')
        return v


# Custom validation decorator for route handlers
def validate_request_body(model_class):
    """
    Decorator to validate request body using Pydantic models.
    Usage:
    
    @app.post("/register")
    @validate_request_body(RegisterData)
    async def register(validated_data: RegisterData):
        # validated_data is already validated
        return ok({"message": "Registration successful"})
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # The FastAPI framework handles validation automatically
            # when you use Pydantic models as parameters
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# Error handler for validation errors
class ValidationError(Exception):
    """Custom validation error"""
    def __init__(self, message: str, details: Optional[List[str]] = None):
        self.message = message
        self.details = details or []
        super().__init__(self.message)