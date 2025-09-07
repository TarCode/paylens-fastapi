from typing import Any, Optional, Dict, List
from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, validator
import re


# Response Utilities
class SuccessResponse(BaseModel):
    success: bool = True
    data: Optional[Any] = None
    message: Optional[str] = None


class ErrorResponse(BaseModel):
    success: bool = False
    error: Dict[str, Any]


def ok(data: Optional[Any] = None) -> JSONResponse:
    """Return successful response with optional data"""
    response_data = {"success": True}
    if data is not None:
        response_data["data"] = data
    return JSONResponse(content=response_data)


def created(data: Optional[Any] = None, message: Optional[str] = None) -> JSONResponse:
    """Return created response with optional data and message"""
    response_data = {"success": True}
    if message:
        response_data["message"] = message
    if data is not None:
        response_data["data"] = data
    return JSONResponse(status_code=201, content=response_data)


def bad_request(error: Any, message: str = "Bad request") -> HTTPException:
    """Raise bad request exception with error details"""
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"success": False, "error": {"message": message, "details": error}}
    )


def unauthorized(message: str = "Unauthorized") -> HTTPException:
    """Raise unauthorized exception"""
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"success": False, "error": {"message": message}}
    )


def not_found(message: str = "Not found") -> HTTPException:
    """Raise not found exception"""
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"success": False, "error": {"message": message}}
    )


def server_error(message: str = "Internal server error") -> HTTPException:
    """Raise internal server error exception"""
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={"success": False, "error": {"message": message}}
    )


# Validation Models
class RegisterData(BaseModel):
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long")
    firstName: str = Field(..., min_length=2, max_length=100, description="First name must be between 2 and 100 characters")
    lastName: str = Field(..., min_length=2, max_length=100, description="Last name must be between 2 and 100 characters")
    companyName: Optional[str] = Field(None, max_length=255, description="Company name must be less than 255 characters")

    @validator('firstName', 'lastName')
    def validate_names(cls, v):
        """Trim whitespace and validate name fields"""
        if v:
            v = v.strip()
            if len(v) < 2:
                raise ValueError('Name must be at least 2 characters long')
            if len(v) > 100:
                raise ValueError('Name must be less than 100 characters')
        return v

    @validator('companyName')
    def validate_company_name(cls, v):
        """Trim whitespace and validate company name"""
        if v:
            v = v.strip()
            if len(v) > 255:
                raise ValueError('Company name must be less than 255 characters')
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
    password: str = Field(..., min_length=1, description="Password is required")

    @validator('password')
    def password_not_empty(cls, v):
        """Ensure password is not empty"""
        if not v or not v.strip():
            raise ValueError('Password is required')
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