from typing import Any, Optional, Dict
from fastapi import HTTPException, status
from pydantic import BaseModel

# Response Utilities
class SuccessResponse(BaseModel):
    success: bool = True
    data: Optional[Any] = None
    message: Optional[str] = None


class ErrorResponse(BaseModel):
    success: bool = False
    error: Dict[str, Any]


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
