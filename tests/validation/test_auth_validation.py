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

from validation.auth_validation import (
    ok, created, bad_request, unauthorized, not_found, server_error,
    RegisterData, LoginData, SuccessResponse, ErrorResponse
)


class TestAuthValidation:
    """Test cases for Auth Validation utilities."""

    # Response Helper Tests
    def test_ok_response_with_data(self):
        """Test ok response with data."""
        test_data = {"user": "test_user", "id": 123}
        response = ok(test_data)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 200
        
        content = response.body.decode()
        assert '"success":true' in content
        assert '"user":"test_user"' in content
        assert '"id":123' in content

    def test_ok_response_without_data(self):
        """Test ok response without data."""
        response = ok()
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 200
        
        content = response.body.decode()
        assert '"success":true' in content
        assert '"data"' not in content

    def test_created_response_with_data_and_message(self):
        """Test created response with data and message."""
        test_data = {"user": "test_user", "id": 123}
        message = "User created successfully"
        response = created(test_data, message)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 201
        
        content = response.body.decode()
        assert '"success":true' in content
        assert '"message":"User created successfully"' in content
        assert '"data":{"user":"test_user","id":123}' in content

    def test_created_response_without_data(self):
        """Test created response without data."""
        message = "Resource created"
        response = created(message=message)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 201
        
        content = response.body.decode()
        assert '"success":true' in content
        assert '"message":"Resource created"' in content
        assert '"data"' not in content

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

    # RegisterData Model Tests
    def test_register_data_valid(self):
        """Test valid RegisterData."""
        data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "John",
            "last_name": "Doe",
            "company_name": "Test Company"
        }
        
        register_data = RegisterData(**data)
        
        assert register_data.email == "test@example.com"
        assert register_data.password == "TestPassword123!"
        assert register_data.first_name == "John"
        assert register_data.last_name == "Doe"
        assert register_data.company_name == "Test Company"

    def test_register_data_minimal(self):
        """Test RegisterData with minimal required fields."""
        data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "John",
            "last_name": "Doe"
        }
        
        register_data = RegisterData(**data)
        
        assert register_data.email == "test@example.com"
        assert register_data.password == "TestPassword123!"
        assert register_data.first_name == "John"
        assert register_data.last_name == "Doe"
        assert register_data.company_name is None

    def test_register_data_invalid_email(self):
        """Test RegisterData with invalid email."""
        data = {
            "email": "invalid-email",
            "password": "TestPassword123!",
            "first_name": "John",
            "last_name": "Doe"
        }

        with pytest.raises(ValidationError) as exc_info:
            RegisterData(**data)

        errors = exc_info.value.errors()
        assert any(error["type"] == "value_error" for error in errors)

    def test_register_data_short_password(self):
        """Test RegisterData with short password."""
        data = {
            "email": "test@example.com",
            "password": "short",
            "first_name": "John",
            "last_name": "Doe"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            RegisterData(**data)
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "string_too_short" for error in errors)

    def test_register_data_short_first_name(self):
        """Test RegisterData with short first name."""
        data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "J",
            "last_name": "Doe"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            RegisterData(**data)
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "string_too_short" for error in errors)

    def test_register_data_long_first_name(self):
        """Test RegisterData with long first name."""
        data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "A" * 101,  # Too long
            "last_name": "Doe"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            RegisterData(**data)
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "string_too_long" for error in errors)

    def test_register_data_short_last_name(self):
        """Test RegisterData with short last name."""
        data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "John",
            "last_name": "D"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            RegisterData(**data)
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "string_too_short" for error in errors)

    def test_register_data_long_company_name(self):
        """Test RegisterData with long company name."""
        data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "John",
            "last_name": "Doe",
            "company_name": "A" * 256  # Too long
        }
        
        with pytest.raises(ValidationError) as exc_info:
            RegisterData(**data)
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "string_too_long" for error in errors)

    def test_register_data_name_trimming(self):
        """Test that names are properly trimmed."""
        data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "  John  ",
            "last_name": "  Doe  ",
            "company_name": "  Test Company  "
        }
        
        register_data = RegisterData(**data)
        
        assert register_data.first_name == "John"
        assert register_data.last_name == "Doe"
        assert register_data.company_name == "Test Company"

    def test_register_data_empty_company_name(self):
        """Test RegisterData with empty company name."""
        data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "John",
            "last_name": "Doe",
            "company_name": ""
        }
        
        register_data = RegisterData(**data)
        
        assert register_data.company_name is None

    # LoginData Model Tests
    def test_login_data_valid(self):
        """Test valid LoginData."""
        data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        login_data = LoginData(**data)
        
        assert login_data.email == "test@example.com"
        assert login_data.password == "TestPassword123!"

    def test_login_data_invalid_email(self):
        """Test LoginData with invalid email."""
        data = {
            "email": "invalid-email",
            "password": "TestPassword123!"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            LoginData(**data)
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "value_error" for error in errors)

    def test_login_data_empty_password(self):
        """Test LoginData with empty password."""
        data = {
            "email": "test@example.com",
            "password": ""
        }
        
        with pytest.raises(ValidationError) as exc_info:
            LoginData(**data)
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "string_too_short" for error in errors)

    def test_login_data_whitespace_password(self):
        """Test LoginData with whitespace-only password."""
        data = {
            "email": "test@example.com",
            "password": "   "
        }

        with pytest.raises(ValidationError) as exc_info:
            LoginData(**data)

        errors = exc_info.value.errors()
        assert any(error["type"] == "string_too_short" for error in errors)

    def test_login_data_short_password(self):
        """Test LoginData with short password."""
        data = {
            "email": "test@example.com",
            "password": "short"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            LoginData(**data)
        
        errors = exc_info.value.errors()
        assert any(error["type"] == "string_too_short" for error in errors)

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
    def test_response_helpers_with_complex_data(self):
        """Test response helpers with complex data structures."""
        complex_data = {
            "user": {
                "id": 123,
                "email": "test@example.com",
                "profile": {
                    "first_name": "John",
                    "last_name": "Doe",
                    "preferences": ["email", "sms"]
                }
            },
            "tokens": {
                "access_token": "abc123",
                "refresh_token": "def456"
            }
        }
        
        response = ok(complex_data)
        
        assert isinstance(response, JSONResponse)
        content = response.body.decode()
        assert '"id":123' in content
        assert '"first_name":"John"' in content
        assert '"preferences":["email","sms"]' in content

    def test_response_helpers_with_datetime_data(self):
        """Test response helpers with datetime data."""
        from datetime import datetime, timezone
        
        data_with_datetime = {
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        
        response = ok(data_with_datetime)
        
        assert isinstance(response, JSONResponse)
        content = response.body.decode()
        assert '"created_at"' in content
        assert '"updated_at"' in content

    def test_register_data_with_special_characters(self):
        """Test RegisterData with special characters in names."""
        data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "José",
            "last_name": "O'Connor",
            "company_name": "Test & Co. Ltd."
        }
        
        register_data = RegisterData(**data)
        
        assert register_data.first_name == "José"
        assert register_data.last_name == "O'Connor"
        assert register_data.company_name == "Test & Co. Ltd."

    def test_register_data_with_unicode_characters(self):
        """Test RegisterData with unicode characters."""
        data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "李明",
            "last_name": "王华",
            "company_name": "测试公司"
        }
        
        register_data = RegisterData(**data)
        
        assert register_data.first_name == "李明"
        assert register_data.last_name == "王华"
        assert register_data.company_name == "测试公司"
