from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBearer
from pydantic import BaseModel, EmailStr
from typing import Optional
import json
import base64
from services.auth_service import auth_service
from services.user_service import user_service
from models.user import GoogleProfile, UserResponse, AuthTokens
from middleware.auth_middleware import get_current_user
from validation.auth_validation import (
    RegisterData,
    LoginData
)
from helpers.response import (
    bad_request,
    created, 
    not_found,
    ok,
    server_error,
    unauthorized,
)

# Additional Pydantic Models (beyond those in auth_validation)
class RefreshTokenRequest(BaseModel):
    refresh_token: str

class UpdateProfileRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    company_name: Optional[str] = None

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class GoogleJWTRequest(BaseModel):
    credential: str

# Response Models
class AuthResponse(BaseModel):
    user: UserResponse
    tokens: AuthTokens

class ProfileResponse(BaseModel):
    user: UserResponse

class PasswordResetResponse(BaseModel):
    success: bool
    message: str

class GoogleAuthResponse(BaseModel):
    user: UserResponse
    tokens: AuthTokens
    is_new_user: bool

# Router
router = APIRouter(prefix="/auth", tags=["authentication"])
security = HTTPBearer()

@router.post("/register", status_code=201)
async def register(request: RegisterData):
    """Register a new user"""
    try:
        # Validate password strength
        password_validation = auth_service.validate_password(request.password)
        if not password_validation["is_valid"]:
            return bad_request(password_validation["errors"], "Password validation failed")

        # Convert RegisterData to CreateUserData
        from models.user import CreateUserData
        create_data = CreateUserData(
            email=request.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name,
            company_name=request.company_name
        )
        result = await auth_service.register(create_data)

        return created({
            "user": result["user"],
            "tokens": result["tokens"]
        })

    except HTTPException as e:
        if e.status_code == 400:
            return bad_request(e.detail, "Registration failed")
        return server_error("Registration failed")
    except Exception as e:
        print(f"[ERROR] Registration failed: {e}")
        return server_error("Registration failed")

@router.post("/login")
async def login(request: LoginData):
    """Login user"""
    try:
        result = await auth_service.login({
            "email": request.email,
            "password": request.password
        })

        return ok({
            "user": result["user"],
            "tokens": result["tokens"]
        })

    except ValueError as e:
        if str(e) in ["Invalid email or password", "Account is deactivated. Please contact support."]:
            return unauthorized(str(e))
        return server_error("Login failed")

@router.post("/refresh-token")
async def refresh_token(request: RefreshTokenRequest):
    """Refresh access token"""
    try:
        if not request.refresh_token:
            return bad_request("Refresh token is required")

        result = await auth_service.refresh_token(request.refresh_token)

        return ok({
            "user": result["user"],
            "tokens": result["tokens"]
        })

    except HTTPException:
        # Re-raise HTTPExceptions (like bad_request) to preserve their status codes
        raise
    except Exception as e:
        return unauthorized(str(e))

@router.get("/profile")
async def get_profile(current_user = Depends(get_current_user)):
    """Get user profile"""
    try:
        user = await user_service.find_by_id(current_user.id)
        if not user:
            return not_found("User not found")

        return ok({"user": user.to_user_response()})

    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Profile retrieval error: {e}")
        return server_error("Failed to retrieve profile")

@router.put("/profile")
async def update_profile(
    request: UpdateProfileRequest, 
    current_user = Depends(get_current_user)
):
    """Update user profile"""
    try:
        updated_user = await user_service.update_user(current_user.id, request)
        if not updated_user:
            return not_found("User not found")

        return ok({"user": updated_user.to_user_response()})

    except HTTPException as e:
        raise e
    except Exception as e:
        return server_error("Failed to update profile")

@router.post("/change-password", status_code=201)
async def change_password(
    request: ChangePasswordRequest,
    current_user = Depends(get_current_user)
):
    """Change user password"""
    try:
        if not request.current_password or not request.new_password:
            return bad_request("Current password and new password are required")

        # Validate new password strength
        password_validation = auth_service.validate_password(request.new_password)
        if not password_validation["is_valid"]:
            return bad_request({
                "errors": password_validation["errors"],
                "message": "New password does not meet requirements"
            })

        # Get user with password
        user = await user_service.find_by_id(current_user.id)
        if not user:
            return not_found("User not found")

        # Check if user has a password (traditional login users)
        if not user.password:
            return bad_request("This account uses Google OAuth and does not have a password to change")

        # Validate current password
        is_valid_current_password = await user_service.validate_password(
            request.current_password, 
            user.password
        )
        if not is_valid_current_password:
            return bad_request("Current password is incorrect")

        # Update password
        await user_service.update_password(current_user.id, request.new_password)

        return created("Password changed successfully")

    except HTTPException as e:
        raise e
    except Exception as e:
        return server_error("Failed to change password")

@router.post("/forgot-password", status_code=201)
async def forgot_password(request: ForgotPasswordRequest):
    """Request password reset"""
    try:
        if not request.email:
            return bad_request("Email is required")

        # Always return success for security (don't reveal if email exists)
        try:
            await auth_service.generate_password_reset_token(request.email)
            # In a real implementation, send email here
        except Exception:
            # Silently ignore errors for security
            pass

        return created("If an account with that email exists, a password reset link has been sent.")

    except Exception as e:
        return server_error("Failed to process password reset request")

@router.post("/reset-password")
async def reset_password(request: ResetPasswordRequest):
    """Reset password with token"""
    try:
        if not request.token or not request.new_password:
            return bad_request("Token and new password are required")

        # Validate password strength
        password_validation = auth_service.validate_password(request.new_password)
        if not password_validation["is_valid"]:
            return bad_request("Password does not meet requirements")

        await auth_service.reset_password(request.token, request.new_password)

        return ok({
            "success": True,
            "message": "Password reset successfully"
        })

    except HTTPException:
        # Re-raise HTTPExceptions (like bad_request) to preserve their status codes
        raise
    except Exception as e:
        return bad_request(str(e))

@router.get("/google/callback")
async def google_auth_callback(request: Request):
    """Google OAuth callback"""
    try:
        # This would typically be handled by OAuth middleware
        # The user profile should be available in the request context
        user_profile = getattr(request.state, 'user', None)
        
        if not user_profile:
            return unauthorized("User not found")

        # Convert to GoogleProfile format
        profile = GoogleProfile(**user_profile)

        result = await auth_service.authenticate_with_google(profile)

        return ok({
            "user": result["user"],
            "tokens": result["tokens"],
            "is_new_user": result["is_new_user"]
        })

    except Exception as e:
        print(f"Google auth callback error: {e}")
        return unauthorized("Google authentication failed")

@router.post("/google/jwt", status_code=201)
async def google_jwt_auth(request: GoogleJWTRequest):
    """Google JWT authentication"""
    try:
        if not request.credential:
            return bad_request("Google JWT credential is required")

        # Decode the JWT token to get user info
        try:
            payload_encoded = request.credential.split('.')[1]
            # Add padding if necessary
            payload_encoded += '=' * (4 - len(payload_encoded) % 4)
            payload = json.loads(base64.b64decode(payload_encoded).decode())
        except Exception as e:
            return bad_request("Invalid JWT token format")

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

        return created({
            "user": result["user"],
            "tokens": result["tokens"],
            "is_new_user": result["is_new_user"]
        })

    except HTTPException:
        # Re-raise HTTPExceptions (like bad_request) to preserve their status codes
        raise
    except Exception as e:
        print(f"Google JWT auth error: {e}")
        return server_error(str(e) or "Google authentication failed")

# Export the router to be included in the main app
auth_router = router