from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, validator
from typing import Optional, Dict, Any
import json
import base64
from services.auth_service import auth_service
from services.user_service import user_service
from models.user import GoogleProfile
from middleware.auth_middleware import get_current_user
from validation.auth_validation import (
    BadRequestResponse, 
    CreatedResponse, 
    NotFoundResponse, 
    OkResponse, 
    ServerErrorResponse, 
    UnauthorizedResponse
)

# Pydantic Models
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    firstName: str
    lastName: str
    companyName: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RefreshTokenRequest(BaseModel):
    refreshToken: str

class UpdateProfileRequest(BaseModel):
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    companyName: Optional[str] = None

class ChangePasswordRequest(BaseModel):
    currentPassword: str
    newPassword: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    newPassword: str

class GoogleJWTRequest(BaseModel):
    credential: str

# Response Models
class UserResponse(BaseModel):
    user: Dict[str, Any]
    tokens: Dict[str, str]

class ProfileResponse(BaseModel):
    user: Dict[str, Any]

class PasswordResetResponse(BaseModel):
    success: bool
    message: str

class GoogleAuthResponse(BaseModel):
    user: Dict[str, Any]
    tokens: Dict[str, str]
    isNewUser: bool

# Router
router = APIRouter(prefix="/auth", tags=["authentication"])
security = HTTPBearer()

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(request: RegisterRequest):
    """Register a new user"""
    try:
        # Validate password strength
        password_validation = auth_service.validate_password(request.password)
        if not password_validation["is_valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=password_validation["errors"]
            )

        result = await auth_service.register({
            "email": request.email,
            "password": request.password,
            "firstName": request.firstName,
            "lastName": request.lastName,
            "companyName": request.companyName
        })

        sanitized_user = auth_service.sanitize_user(result["user"])

        return UserResponse(
            user=sanitized_user,
            tokens=result["tokens"]
        )

    except ValueError as e:
        if str(e) == "User with this email already exists":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/login", response_model=UserResponse)
async def login(request: LoginRequest):
    """Login user"""
    try:
        result = await auth_service.login({
            "email": request.email,
            "password": request.password
        })

        print(f"Login result user: {result['user']}")  # Debug logging
        print(f"isActive type: {type(result['user'].get('isActive'))}")  # Debug logging
        print(f"isActive value: {result['user'].get('isActive')}")  # Debug logging

        sanitized_user = auth_service.sanitize_user(result["user"])

        return UserResponse(
            user=sanitized_user,
            tokens=result["tokens"]
        )

    except ValueError as e:
        if str(e) in ["Invalid email or password", "Account is deactivated. Please contact support."]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e)
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/refresh-token", response_model=UserResponse)
async def refresh_token(request: RefreshTokenRequest):
    """Refresh access token"""
    try:
        if not request.refreshToken:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Refresh token is required"
            )

        result = await auth_service.refresh_token(request.refreshToken)
        sanitized_user = auth_service.sanitize_user(result["user"])

        return UserResponse(
            user=sanitized_user,
            tokens=result["tokens"]
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )

@router.get("/profile", response_model=ProfileResponse)
async def get_profile(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get user profile"""
    try:
        user = await user_service.find_by_id(current_user["id"])
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        sanitized_user = auth_service.sanitize_user(user)

        return ProfileResponse(user=sanitized_user)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.put("/profile", response_model=ProfileResponse)
async def update_profile(
    request: UpdateProfileRequest, 
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update user profile"""
    try:
        update_data = {}
        if request.firstName is not None:
            update_data["firstName"] = request.firstName
        if request.lastName is not None:
            update_data["lastName"] = request.lastName
        if request.companyName is not None:
            update_data["companyName"] = request.companyName

        updated_user = await user_service.update_user(current_user["id"], update_data)
        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        sanitized_user = auth_service.sanitize_user(updated_user)

        return ProfileResponse(user=sanitized_user)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/change-password", status_code=status.HTTP_201_CREATED)
async def change_password(
    request: ChangePasswordRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Change user password"""
    try:
        if not request.currentPassword or not request.newPassword:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password and new password are required"
            )

        # Validate new password strength
        password_validation = auth_service.validate_password(request.newPassword)
        if not password_validation["is_valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "errors": password_validation["errors"],
                    "message": "New password does not meet requirements"
                }
            )

        # Get user with password
        user = await user_service.find_by_id(current_user["id"])
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Check if user has a password (traditional login users)
        if not user.get("password"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This account uses Google OAuth and does not have a password to change"
            )

        # Validate current password
        is_valid_current_password = await user_service.validate_password(
            request.currentPassword, 
            user["password"]
        )
        if not is_valid_current_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )

        # Update password
        await user_service.update_password(current_user["id"], request.newPassword)

        return {"message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/forgot-password", status_code=status.HTTP_201_CREATED)
async def forgot_password(request: ForgotPasswordRequest):
    """Request password reset"""
    try:
        if not request.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is required"
            )

        # Always return success for security (don't reveal if email exists)
        try:
            await auth_service.generate_password_reset_token(request.email)
            # In a real implementation, send email here
        except Exception:
            # Silently ignore errors for security
            pass

        return {
            "message": "If an account with that email exists, a password reset link has been sent."
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/reset-password", response_model=PasswordResetResponse)
async def reset_password(request: ResetPasswordRequest):
    """Reset password with token"""
    try:
        if not request.token or not request.newPassword:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token and new password are required"
            )

        # Validate password strength
        password_validation = auth_service.validate_password(request.newPassword)
        if not password_validation["is_valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password does not meet requirements"
            )

        await auth_service.reset_password(request.token, request.newPassword)

        return PasswordResetResponse(
            success=True,
            message="Password reset successfully"
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/google/callback", response_model=GoogleAuthResponse)
async def google_auth_callback(request: Request):
    """Google OAuth callback"""
    try:
        # This would typically be handled by OAuth middleware
        # The user profile should be available in the request context
        user_profile = getattr(request.state, 'user', None)
        
        if not user_profile:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )

        # Convert to GoogleProfile format
        profile = GoogleProfile(**user_profile)

        result = await auth_service.authenticate_with_google(profile)
        sanitized_user = auth_service.sanitize_user(result["user"])

        return GoogleAuthResponse(
            user=sanitized_user,
            tokens=result["tokens"],
            isNewUser=result["isNewUser"]
        )

    except Exception as e:
        print(f"Google auth callback error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google authentication failed"
        )

@router.post("/google/jwt", response_model=GoogleAuthResponse, status_code=status.HTTP_201_CREATED)
async def google_jwt_auth(request: GoogleJWTRequest):
    """Google JWT authentication"""
    try:
        if not request.credential:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google JWT credential is required"
            )

        # Decode the JWT token to get user info
        try:
            payload_encoded = request.credential.split('.')[1]
            # Add padding if necessary
            payload_encoded += '=' * (4 - len(payload_encoded) % 4)
            payload = json.loads(base64.b64decode(payload_encoded).decode())
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JWT token format"
            )

        # Create a profile object similar to the Google Profile interface
        profile = GoogleProfile(
            id=payload.get('sub'),
            email=payload.get('email'),
            verified_email=payload.get('email_verified', False),
            name=payload.get('name'),
            given_name=payload.get('given_name'),
            family_name=payload.get('family_name'),
            picture=payload.get('picture'),
            locale=payload.get('locale', 'en')
        )

        result = await auth_service.authenticate_with_google(profile)
        sanitized_user = auth_service.sanitize_user(result["user"])

        return GoogleAuthResponse(
            user=sanitized_user,
            tokens=result["tokens"],
            isNewUser=result["isNewUser"]
        )

    except HTTPException:
        raise
    except Exception as e:
        print(f"Google JWT auth error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e) or "Google authentication failed"
        )

# Export the router to be included in the main app
auth_router = router