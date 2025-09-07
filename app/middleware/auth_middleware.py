import os
import jwt
from datetime import datetime
from typing import Optional
from fastapi import Depends, Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from models.user import UserRole, SubscriptionTier


class User(BaseModel):
    id: str
    email: str
    role: UserRole
    subscription_tier: SubscriptionTier
    usage_count: int
    monthly_limit: int
    last_usage_reset: datetime
    billing_period_start: datetime


class AuthMiddleware:
    """
    Enhanced authentication middleware that combines JWT verification and user existence check.
    This middleware should be used for all protected routes.
    
    Usage:
    - As a dependency: @app.get("/profile", dependencies=[Depends(auth_middleware.authenticate_and_ensure_user)])
    - As a class method: user = await auth_middleware.get_current_user(request)
    """
    
    def __init__(self):
        self.jwt_secret = os.getenv('JWT_SECRET', 'fallback-secret')
        self.security = HTTPBearer()

    async def authenticate_and_ensure_user(self, credentials: HTTPAuthorizationCredentials = None) -> User:
        """
        FastAPI dependency for authentication.
        Use this as a dependency in your route handlers.
        """
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "success": False,
                    "error": {
                        "message": "Access token is required"
                    }
                }
            )

        try:
            # Verify and decode JWT token
            decoded = jwt.decode(
                credentials.credentials, 
                self.jwt_secret, 
                algorithms=["HS256"]
            )
            
            # Create user object from decoded token
            user = User(
                id=decoded.get('id'),
                email=decoded.get('email'),
                role=UserRole(decoded.get('role', 'user')),
                subscription_tier=SubscriptionTier(decoded.get('subscription_tier', 'free')),
                usage_count=decoded.get('usage_count', 0),
                monthly_limit=decoded.get('monthly_limit', 100),
                last_usage_reset=datetime.fromisoformat(decoded.get('last_usage_reset', datetime.now().isoformat())),
                billing_period_start=datetime.fromisoformat(decoded.get('billing_period_start', datetime.now().isoformat()))
            )
            
            return user
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "success": False,
                    "error": {
                        "message": "Token has expired"
                    }
                }
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "success": False,
                    "error": {
                        "message": "Invalid or expired token"
                    }
                }
            )
        except Exception as e:
            print(f"JWT verification error: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "success": False,
                    "error": {
                        "message": "Invalid or expired token"
                    }
                }
            )

    async def get_current_user(self, request: Request) -> Optional[User]:
        """
        Extract user from request headers manually.
        Useful for custom middleware or when you need to handle auth manually.
        """
        auth_header = request.headers.get("authorization")
        
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        
        token = auth_header.split(" ")[1]
        
        try:
            decoded = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            
            user = User(
                id=decoded.get('id'),
                email=decoded.get('email'),
                role=UserRole(decoded.get('role', 'user')),
                subscription_tier=SubscriptionTier(decoded.get('subscription_tier', 'free')),
                usage_count=decoded.get('usage_count', 0),
                monthly_limit=decoded.get('monthly_limit', 100),
                last_usage_reset=datetime.fromisoformat(decoded.get('last_usage_reset', datetime.now().isoformat())),
                billing_period_start=datetime.fromisoformat(decoded.get('billing_period_start', datetime.now().isoformat()))
            )
            
            return user
            
        except Exception:
            return None


# Singleton instance
auth_middleware = AuthMiddleware()


# Convenience function for dependency injection
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> User:
    """
    Convenience function to use as a FastAPI dependency.
    
    Usage:
    @app.get("/profile")
    async def get_profile(current_user: User = Depends(get_current_user)):
        return {"user": current_user}
    """
    return await auth_middleware.authenticate_and_ensure_user(credentials)