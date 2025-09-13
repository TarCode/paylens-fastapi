"""
Unit tests for Usage Validation utilities.
"""
import pytest
from fastapi import HTTPException, status

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'app'))

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


class TestUsageValidationModels:
    """Test cases for Usage Validation Pydantic models."""

    def test_usage_response_model(self):
        """Test UsageResponse model creation and validation."""
        # Test with all fields
        response_data = {
            "user": {"id": "test-id", "email": "test@example.com"},
            "tokens": {"access_token": "token", "refresh_token": "refresh"},
            "usage_count": 5,
            "monthly_limit": 10,
            "was_reset": True
        }
        
        response = UsageResponse(**response_data)
        
        assert response.user == response_data["user"]
        assert response.tokens == response_data["tokens"]
        assert response.usage_count == 5
        assert response.monthly_limit == 10
        assert response.was_reset is True

    def test_usage_response_model_minimal(self):
        """Test UsageResponse model with minimal required fields."""
        response_data = {
            "usage_count": 3,
            "monthly_limit": 5
        }
        
        response = UsageResponse(**response_data)
        
        assert response.user is None
        assert response.tokens is None
        assert response.usage_count == 3
        assert response.monthly_limit == 5
        assert response.was_reset is False  # Default value

    def test_usage_stats_response_model(self):
        """Test UsageStatsResponse model creation and validation."""
        stats_data = {
            "usage_count": 25,
            "monthly_limit": 100,
            "subscription_tier": "pro",
            "usage_percentage": 25
        }
        
        response = UsageStatsResponse(**stats_data)
        
        assert response.usage_count == 25
        assert response.monthly_limit == 100
        assert response.subscription_tier == "pro"
        assert response.usage_percentage == 25

    def test_error_details_response_model(self):
        """Test ErrorDetailsResponse model creation and validation."""
        # Test with all fields
        error_data = {
            "message": "Usage limit exceeded",
            "code": "USAGE_LIMIT_EXCEEDED",
            "current_usage": 5,
            "limit": 5,
            "was_reset": False
        }
        
        response = ErrorDetailsResponse(**error_data)
        
        assert response.message == "Usage limit exceeded"
        assert response.code == "USAGE_LIMIT_EXCEEDED"
        assert response.current_usage == 5
        assert response.limit == 5
        assert response.was_reset is False

    def test_error_details_response_model_minimal(self):
        """Test ErrorDetailsResponse model with minimal required fields."""
        error_data = {
            "message": "Something went wrong"
        }
        
        response = ErrorDetailsResponse(**error_data)
        
        assert response.message == "Something went wrong"
        assert response.code is None
        assert response.current_usage is None
        assert response.limit is None
        assert response.was_reset is None


class TestUsageValidationHelpers:
    """Test cases for Usage Validation helper functions."""

    def test_bad_request_with_message_only(self):
        """Test bad_request helper with message only."""
        error_message = "Invalid input"
        
        with pytest.raises(HTTPException) as exc_info:
            bad_request(error_message)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_400_BAD_REQUEST
        assert exception.detail["success"] is False
        assert exception.detail["error"]["message"] == "Invalid input"
        assert exception.detail["error"]["code"] is None

    def test_bad_request_with_code(self):
        """Test bad_request helper with message and code."""
        error_message = "Validation failed"
        error_code = "VALIDATION_ERROR"
        
        with pytest.raises(HTTPException) as exc_info:
            bad_request(error_message, error_code)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_400_BAD_REQUEST
        assert exception.detail["success"] is False
        assert exception.detail["error"]["message"] == "Validation failed"
        assert exception.detail["error"]["code"] == "VALIDATION_ERROR"

    def test_bad_request_with_complex_error(self):
        """Test bad_request helper with complex error object."""
        error_dict = {"field": "email", "issue": "invalid format"}
        
        with pytest.raises(HTTPException) as exc_info:
            bad_request(error_dict)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_400_BAD_REQUEST
        assert exception.detail["success"] is False
        assert "field" in str(exception.detail["error"]["message"])

    def test_not_found_default_message(self):
        """Test not_found helper with default message."""
        with pytest.raises(HTTPException) as exc_info:
            not_found()
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_404_NOT_FOUND
        assert exception.detail["success"] is False
        assert exception.detail["error"]["message"] == "Not found"

    def test_not_found_custom_message(self):
        """Test not_found helper with custom message."""
        custom_message = "User not found"
        
        with pytest.raises(HTTPException) as exc_info:
            not_found(custom_message)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_404_NOT_FOUND
        assert exception.detail["success"] is False
        assert exception.detail["error"]["message"] == "User not found"

    def test_ok_with_data(self):
        """Test ok helper with data."""
        test_data = {"message": "Success", "count": 5}
        
        result = ok(test_data)
        
        assert result["success"] is True
        assert result["data"] == test_data

    def test_ok_with_none_data(self):
        """Test ok helper with None data."""
        result = ok(None)
        
        assert result["success"] is True
        assert result["data"] is None

    def test_ok_with_string_data(self):
        """Test ok helper with string data."""
        test_data = "Operation completed successfully"
        
        result = ok(test_data)
        
        assert result["success"] is True
        assert result["data"] == test_data

    def test_server_error_default_message(self):
        """Test server_error helper with default message."""
        with pytest.raises(HTTPException) as exc_info:
            server_error()
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exception.detail["success"] is False
        assert exception.detail["error"]["message"] == "Internal server error"

    def test_server_error_custom_message(self):
        """Test server_error helper with custom message."""
        custom_message = "Database connection failed"
        
        with pytest.raises(HTTPException) as exc_info:
            server_error(custom_message)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exception.detail["success"] is False
        assert exception.detail["error"]["message"] == "Database connection failed"

    def test_too_many_requests_with_error_details(self):
        """Test too_many_requests helper with ErrorDetailsResponse."""
        error_details = ErrorDetailsResponse(
            message="Usage limit exceeded",
            code="USAGE_LIMIT_EXCEEDED",
            current_usage=10,
            limit=10,
            was_reset=False
        )
        
        with pytest.raises(HTTPException) as exc_info:
            too_many_requests(error_details)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert exception.detail["success"] is False
        assert exception.detail["error"]["message"] == "Usage limit exceeded"
        assert exception.detail["error"]["code"] == "USAGE_LIMIT_EXCEEDED"
        assert exception.detail["error"]["current_usage"] == 10
        assert exception.detail["error"]["limit"] == 10
        assert exception.detail["error"]["was_reset"] is False

    def test_too_many_requests_with_minimal_error_details(self):
        """Test too_many_requests helper with minimal ErrorDetailsResponse."""
        error_details = ErrorDetailsResponse(
            message="Request too frequent"
        )
        
        with pytest.raises(HTTPException) as exc_info:
            too_many_requests(error_details)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert exception.detail["success"] is False
        assert exception.detail["error"]["message"] == "Request too frequent"
        assert exception.detail["error"]["code"] is None
        assert exception.detail["error"]["current_usage"] is None
        assert exception.detail["error"]["limit"] is None
        assert exception.detail["error"]["was_reset"] is None


class TestUsageValidationIntegration:
    """Integration tests for Usage Validation components."""

    def test_error_details_with_too_many_requests_flow(self):
        """Test complete flow from ErrorDetailsResponse to too_many_requests exception."""
        # Simulate a usage limit exceeded scenario
        error_details = ErrorDetailsResponse(
            message="Monthly usage limit of 100 requests exceeded",
            code="USAGE_LIMIT_EXCEEDED",
            current_usage=100,
            limit=100,
            was_reset=False
        )
        
        # Verify the error details are correctly structured
        assert error_details.message == "Monthly usage limit of 100 requests exceeded"
        assert error_details.code == "USAGE_LIMIT_EXCEEDED"
        assert error_details.current_usage == 100
        assert error_details.limit == 100
        assert error_details.was_reset is False
        
        # Test that it properly raises HTTPException with correct structure
        with pytest.raises(HTTPException) as exc_info:
            too_many_requests(error_details)
        
        exception = exc_info.value
        
        # Verify all details are preserved in the exception
        assert exception.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        error_detail = exception.detail["error"]
        assert error_detail["message"] == error_details.message
        assert error_detail["code"] == error_details.code
        assert error_detail["current_usage"] == error_details.current_usage
        assert error_detail["limit"] == error_details.limit
        assert error_detail["was_reset"] == error_details.was_reset

    def test_rate_limiting_error_flow(self):
        """Test complete flow for rate limiting error."""
        error_details = ErrorDetailsResponse(
            message="Request too frequent. Please wait before trying again.",
            code="REQUEST_TOO_FREQUENT"
        )
        
        with pytest.raises(HTTPException) as exc_info:
            too_many_requests(error_details)
        
        exception = exc_info.value
        assert exception.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert exception.detail["error"]["code"] == "REQUEST_TOO_FREQUENT"
        assert "Request too frequent" in exception.detail["error"]["message"]

    def test_success_response_structure(self):
        """Test that success responses have consistent structure."""
        test_cases = [
            {"data": {"usage": 5, "limit": 10}},
            {"data": "Simple string message"},
            {"data": None},
            {"data": [1, 2, 3, 4, 5]},
            {"data": {"nested": {"deeply": {"structured": "data"}}}}
        ]
        
        for test_case in test_cases:
            result = ok(test_case["data"])
            
            # Verify consistent structure
            assert "success" in result
            assert "data" in result
            assert result["success"] is True
            assert result["data"] == test_case["data"]

    def test_error_response_consistency(self):
        """Test that all error helpers produce consistent response structures."""
        error_helpers = [
            (bad_request, ("Test error",), status.HTTP_400_BAD_REQUEST),
            (not_found, ("Resource not found",), status.HTTP_404_NOT_FOUND),
            (server_error, ("Server failed",), status.HTTP_500_INTERNAL_SERVER_ERROR),
        ]
        
        for helper_func, args, expected_status in error_helpers:
            with pytest.raises(HTTPException) as exc_info:
                helper_func(*args)
            
            exception = exc_info.value
            
            # Verify consistent error structure
            assert exception.status_code == expected_status
            assert "detail" in exception.__dict__
            assert exception.detail["success"] is False
            assert "error" in exception.detail
            assert "message" in exception.detail["error"]

    def test_model_serialization_compatibility(self):
        """Test that models can be serialized properly for JSON responses."""
        import json
        
        # Test UsageStatsResponse
        stats = UsageStatsResponse(
            usage_count=50,
            monthly_limit=100,
            subscription_tier="pro",
            usage_percentage=50
        )
        
        # Should be serializable to JSON
        stats_json = json.dumps(stats.model_dump())
        stats_loaded = json.loads(stats_json)
        
        assert stats_loaded["usage_count"] == 50
        assert stats_loaded["monthly_limit"] == 100
        assert stats_loaded["subscription_tier"] == "pro"
        assert stats_loaded["usage_percentage"] == 50
        
        # Test ErrorDetailsResponse
        error = ErrorDetailsResponse(
            message="Test error",
            code="TEST_ERROR",
            current_usage=75,
            limit=100,
            was_reset=True
        )
        
        error_json = json.dumps(error.model_dump())
        error_loaded = json.loads(error_json)
        
        assert error_loaded["message"] == "Test error"
        assert error_loaded["code"] == "TEST_ERROR"
        assert error_loaded["current_usage"] == 75
        assert error_loaded["limit"] == 100
        assert error_loaded["was_reset"] is True
