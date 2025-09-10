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
    RegisterData, LoginData
)

class TestAuthValidation:
    """Test cases for Auth Validation utilities."""
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
