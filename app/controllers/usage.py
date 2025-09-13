import time
from typing import Dict, Any
from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel
from services.auth_service import auth_service
from services.user_service import user_service
from middleware.auth_middleware import get_current_user, User
from validation.usage_validation import (
    UsageResponse,
    UsageStatsResponse,
    ErrorDetailsResponse,
    bad_request,
    not_found,
    ok,
    server_error,
    too_many_requests
)
from helpers.response import ErrorResponse

# In-memory request deduplication cache (use Redis in production)
recent_requests: Dict[str, float] = {}
REQUEST_DEDUPE_WINDOW = 5.0  # 5 seconds

# Response Models
class IncrementUsageResponse(BaseModel):
    user: Dict[str, Any]
    tokens: Dict[str, Any]
    usage_count: int
    monthly_limit: int
    was_reset: bool = False

class GetUsageResponse(BaseModel):
    usage_count: int
    monthly_limit: int
    subscription_tier: str
    usage_percentage: int

# Router
router = APIRouter(prefix="/usage", tags=["usage"])

@router.post("/increment",
    response_model=IncrementUsageResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Bad request or increment failed"},
        404: {"model": ErrorResponse, "description": "User not found"},
        429: {"model": ErrorResponse, "description": "Request too frequent or usage limit exceeded"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    }
)
async def increment_usage(request: Request, current_user: User = Depends(get_current_user)):
    """Increment user's usage count with rate limiting and atomic limit checking"""
    try:
        user_id = current_user.id
        now = time.time()

        # Request deduplication - prevent rapid duplicate requests
        if user_id in recent_requests:
            last_request_time = recent_requests[user_id]
            if now - last_request_time < REQUEST_DEDUPE_WINDOW:
                print(f"🚨 Rapid usage request blocked for user {user_id} from {request.client.host if request.client else 'unknown'}")
                raise too_many_requests(ErrorDetailsResponse(
                    message="Request too frequent. Please wait before trying again.",
                    code="REQUEST_TOO_FREQUENT"
                ))
        
        recent_requests[user_id] = now

        # Clean up old entries from deduplication cache
        keys_to_remove = []
        for key, timestamp in recent_requests.items():
            if now - timestamp > REQUEST_DEDUPE_WINDOW * 2:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            recent_requests.pop(key, None)

        # Increment usage count with atomic limit checking
        result = await user_service.increment_usage_count(user_id)

        if not result["can_increment"]:
            # Log usage limit violations for monitoring
            if result.get("error", "").find("limit exceeded") != -1:
                subscription_tier_value = None
                if result["user"]:
                    subscription_tier_value = result["user"].subscription_tier.value if hasattr(result["user"].subscription_tier, 'value') else str(result["user"].subscription_tier)
                
                print(f"🚨 Usage limit exceeded for user {user_id} from {request.client.host if request.client else 'unknown'}:", {
                    "current_usage": result["user"].usage_count if result["user"] else None,
                    "monthly_limit": result["user"].monthly_limit if result["user"] else None,
                    "subscription_tier": subscription_tier_value
                })

            # Determine appropriate status code based on error
            error_msg = result.get("error", "Unknown error")
            if "not found" in error_msg:
                raise not_found(error_msg)
            elif "limit exceeded" in error_msg:
                raise too_many_requests(ErrorDetailsResponse(
                    message=error_msg,
                    code="USAGE_LIMIT_EXCEEDED",
                    current_usage=result["user"].usage_count if result["user"] else None,
                    limit=result["user"].monthly_limit if result["user"] else None,
                    was_reset=result.get("was_reset", False)
                ))
            else:
                raise bad_request(error_msg, "INCREMENT_FAILED")

        # Generate new tokens with updated usage count
        tokens = await auth_service.generate_tokens(result["user"])

        return IncrementUsageResponse(
            user=result["user"].to_user_response().model_dump(),
            tokens=tokens.model_dump(),
            usage_count=result["user"].usage_count,
            monthly_limit=result["user"].monthly_limit,
            was_reset=result.get("was_reset", False)
        )

    except HTTPException:
        # Re-raise HTTPExceptions (like too_many_requests) to preserve their status codes
        raise
    except Exception as error:
        print(f"Increment usage error: {error}")
        raise server_error("Failed to increment usage")

@router.get("/",
    response_model=GetUsageResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Authentication required"},
        404: {"model": ErrorResponse, "description": "User not found"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    }
)
async def get_usage(current_user: User = Depends(get_current_user)):
    """Get user's current usage statistics"""
    try:
        user_id = current_user.id
        user = await user_service.find_by_id(user_id)

        if not user:
            raise not_found("User not found")

        usage_percentage = 0
        if user.monthly_limit > 0:
            usage_percentage = round((user.usage_count / user.monthly_limit) * 100)

        # Handle both enum and string values for subscription_tier
        subscription_tier_value = user.subscription_tier.value if hasattr(user.subscription_tier, 'value') else str(user.subscription_tier)
        
        return GetUsageResponse(
            usage_count=user.usage_count,
            monthly_limit=user.monthly_limit,
            subscription_tier=subscription_tier_value,
            usage_percentage=usage_percentage
        )

    except HTTPException:
        # Re-raise HTTPExceptions (like not_found) to preserve their status codes
        raise
    except Exception as error:
        print(f"Get usage error: {error}")
        raise server_error("Failed to get usage data")

# Export the router to be included in the main app
usage_router = router
