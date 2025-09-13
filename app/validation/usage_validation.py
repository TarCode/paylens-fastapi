from typing import Any, Optional, Dict
from fastapi import HTTPException, status
from pydantic import BaseModel

# Response Models
class UsageResponse(BaseModel):
    user: Optional[Dict[str, Any]] = None
    tokens: Optional[Dict[str, Any]] = None
    usage_count: int
    monthly_limit: int
    was_reset: bool = False

class UsageStatsResponse(BaseModel):
    usage_count: int
    monthly_limit: int
    subscription_tier: str
    usage_percentage: int

class ErrorDetailsResponse(BaseModel):
    message: str
    code: Optional[str] = None
    current_usage: Optional[int] = None
    limit: Optional[int] = None
    was_reset: Optional[bool] = None

# Response Utilities for Usage Controller
def bad_request(error: Any, code: Optional[str] = None) -> HTTPException:
    """Raise bad request exception with error details"""
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"success": False, "error": {"message": str(error), "code": code}}
    )

def not_found(message: str = "Not found") -> HTTPException:
    """Raise not found exception"""
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"success": False, "error": {"message": message}}
    )

def ok(data: Any) -> Dict[str, Any]:
    """Return success response with data"""
    return {"success": True, "data": data}

def server_error(message: str = "Internal server error") -> HTTPException:
    """Raise internal server error exception"""
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={"success": False, "error": {"message": message}}
    )

def too_many_requests(error_details: ErrorDetailsResponse) -> HTTPException:
    """Raise too many requests exception with detailed error"""
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={
            "success": False, 
            "error": {
                "message": error_details.message,
                "code": error_details.code,
                "current_usage": error_details.current_usage,
                "limit": error_details.limit,
                "was_reset": error_details.was_reset
            }
        }
    )
