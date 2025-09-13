"""
Unit tests for Auth Validation utilities.
"""
import pytest
from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'app'))

from helpers.response import (
    bad_request, unauthorized, not_found, server_error, ErrorResponse, SuccessResponse
)


class TestAuthValidation:
    """Test cases for Auth Validation utilities."""

    # Response Helper Tests
    # Note: ok() and created() functions are no longer used in controllers
    # as we now return Pydantic models directly for better OpenAPI documentation

    def test_bad_request_exception(self):
        """Test bad request exception."""
        error_details = ["Email is required", "Password is too short"]
        message = "Validation failed"
        
        with pytest.raises(HTTPException) as exc_info:
            bad_request(error_details, message)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_400_BAD_REQUEST
        assert "success" in exception.detail
        assert exception.detail["success"] is False
        assert "error" in exception.detail
        assert exception.detail["error"]["message"] == message
        assert exception.detail["error"]["details"] == error_details

    def test_unauthorized_exception(self):
        """Test unauthorized exception."""
        message = "Access denied"
        
        with pytest.raises(HTTPException) as exc_info:
            unauthorized(message)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_401_UNAUTHORIZED
        assert "success" in exception.detail
        assert exception.detail["success"] is False
        assert "error" in exception.detail
        assert exception.detail["error"]["message"] == message

    def test_not_found_exception(self):
        """Test not found exception."""
        message = "Resource not found"
        
        with pytest.raises(HTTPException) as exc_info:
            not_found(message)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_404_NOT_FOUND
        assert "success" in exception.detail
        assert exception.detail["success"] is False
        assert "error" in exception.detail
        assert exception.detail["error"]["message"] == message

    def test_server_error_exception(self):
        """Test server error exception."""
        message = "Internal server error"
        
        with pytest.raises(HTTPException) as exc_info:
            server_error(message)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "success" in exception.detail
        assert exception.detail["success"] is False
        assert "error" in exception.detail
        assert exception.detail["error"]["message"] == message


 # SuccessResponse Model Tests
    def test_success_response_default(self):
        """Test SuccessResponse with default values."""
        response = SuccessResponse()
        
        assert response.success is True
        assert response.data is None
        assert response.message is None

    def test_success_response_with_data(self):
        """Test SuccessResponse with data."""
        data = {"user": "test_user"}
        response = SuccessResponse(data=data)
        
        assert response.success is True
        assert response.data == data
        assert response.message is None

    def test_success_response_with_message(self):
        """Test SuccessResponse with message."""
        message = "Operation successful"
        response = SuccessResponse(message=message)
        
        assert response.success is True
        assert response.data is None
        assert response.message == message

    def test_success_response_with_data_and_message(self):
        """Test SuccessResponse with data and message."""
        data = {"user": "test_user"}
        message = "Operation successful"
        response = SuccessResponse(data=data, message=message)
        
        assert response.success is True
        assert response.data == data
        assert response.message == message

    # ErrorResponse Model Tests
    def test_error_response_default(self):
        """Test ErrorResponse with default values."""
        response = ErrorResponse(error={})
        
        assert response.success is False
        assert response.error == {}

    def test_error_response_with_error_details(self):
        """Test ErrorResponse with error details."""
        error_details = {"message": "Something went wrong", "code": "ERROR_001"}
        response = ErrorResponse(error=error_details)
        
        assert response.success is False
        assert response.error == error_details

    # Edge Cases and Integration Tests
    # Complex data and datetime tests removed as ok() function is no longer used
    # Controllers now return Pydantic models directly
