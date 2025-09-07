# Paylens API Test Suite

This directory contains comprehensive unit tests for the Paylens FastAPI application. The test suite covers all major components including services, controllers, models, validation, and middleware.

## Test Structure

```
tests/
├── conftest.py                 # Test configuration and fixtures
├── services/                   # Service layer tests
│   ├── test_auth_service.py   # AuthService unit tests
│   └── test_user_service.py   # UserService unit tests
├── controllers/                # Controller/API endpoint tests
│   └── test_auth_controller.py # Auth controller tests
├── models/                     # Model tests
│   └── test_user.py           # User model tests
├── validation/                 # Validation utility tests
│   └── test_auth_validation.py # Auth validation tests
├── middleware/                 # Middleware tests
│   └── test_auth_middleware.py # Auth middleware tests
└── README.md                  # This file
```

## Test Coverage

### Services (Unit Tests)
- **AuthService**: Registration, login, token generation/verification, password reset, email verification
- **UserService**: User CRUD operations, password hashing, email verification, usage tracking

### Controllers (Integration Tests)
- **Auth Controller**: All authentication endpoints with FastAPI TestClient
  - `/auth/register` - User registration
  - `/auth/login` - User login
  - `/auth/refresh-token` - Token refresh
  - `/auth/profile` - Profile management
  - `/auth/change-password` - Password change
  - `/auth/forgot-password` - Password reset request
  - `/auth/reset-password` - Password reset
  - `/auth/google/jwt` - Google OAuth JWT authentication

### Models
- **User Models**: UserResponse, UserDB, UserInternal, CreateUserData, UpdateUserData
- **Auth Models**: AuthTokens, JWTPayload, GoogleProfile
- **Validation Models**: RegisterData, LoginData
- **Model Conversions**: dict_to_userdb utility function

### Validation
- **Response Helpers**: ok(), created(), bad_request(), unauthorized(), not_found(), server_error()
- **Validation Models**: RegisterData, LoginData with field validation
- **Error Handling**: Custom validation errors and HTTP exceptions

### Middleware
- **Auth Middleware**: JWT token verification, user extraction, authentication dependency injection
- **Token Validation**: Expired tokens, invalid tokens, malformed tokens
- **User Model**: User model creation and validation

## Running Tests

### Prerequisites
1. Install test dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set up test environment variables (already configured in conftest.py):
   ```bash
   export JWT_SECRET="test-jwt-secret"
   export REFRESH_TOKEN_SECRET="test-refresh-secret"
   export JWT_EXPIRES_IN="1h"
   export REFRESH_TOKEN_EXPIRES_IN="7d"
   export BCRYPT_ROUNDS="4"
   ```

### Running All Tests
```bash
# Run all tests with coverage
python -m pytest tests/ -v --cov=app --cov-report=term-missing --cov-report=html:htmlcov

# Or use the test runner script
python run_tests.py
```

### Running Specific Test Categories
```bash
# Run only service tests
python -m pytest tests/services/ -v

# Run only controller tests
python -m pytest tests/controllers/ -v

# Run only model tests
python -m pytest tests/models/ -v

# Run only validation tests
python -m pytest tests/validation/ -v

# Run only middleware tests
python -m pytest tests/middleware/ -v
```

### Running Individual Test Files
```bash
# Run specific test file
python -m pytest tests/services/test_auth_service.py -v

# Run specific test class
python -m pytest tests/services/test_auth_service.py::TestAuthService -v

# Run specific test method
python -m pytest tests/services/test_auth_service.py::TestAuthService::test_register_success -v
```

### Running Tests with Markers
```bash
# Run only unit tests
python -m pytest tests/ -v -m unit

# Run only integration tests
python -m pytest tests/ -v -m integration

# Run only slow tests
python -m pytest tests/ -v -m slow
```

## Test Configuration

### pytest.ini
The test configuration is defined in `pytest.ini`:
- Test discovery patterns
- Coverage settings (80% minimum)
- Async test support
- Test markers

### conftest.py
Contains shared fixtures and test configuration:
- Database service mocks
- Sample user data
- Auth service mocks
- Test client setup
- Environment variable configuration

## Mocking Strategy

### Database Mocking
- All database operations are mocked using `AsyncMock`
- Database queries return predictable test data
- No actual database connections during tests

### Service Mocking
- External services (auth, user) are mocked when testing controllers
- Service dependencies are mocked when testing individual services
- JWT operations use test secrets

### External Dependencies
- Google OAuth is mocked
- Email services are mocked
- File system operations are mocked

## Test Data

### Fixtures
- `sample_user_data`: Complete user data dictionary
- `sample_user_internal`: UserInternal model instance
- `sample_user_response`: UserResponse model instance
- `sample_create_user_data`: CreateUserData for registration
- `sample_google_profile`: Google OAuth profile data
- `sample_auth_tokens`: JWT tokens for testing

### Test Data Generation
- Uses `faker` library for generating realistic test data
- Consistent test data across test runs
- Edge cases and boundary conditions covered

## Coverage Goals

- **Target**: 80% code coverage minimum
- **Current Coverage**: Comprehensive coverage of all critical paths
- **Coverage Reports**: Generated in HTML format in `htmlcov/` directory

## Best Practices

### Test Organization
- One test file per module/class
- Descriptive test method names
- Grouped by functionality
- Clear test data setup

### Assertions
- Specific assertions for expected behavior
- Error message validation
- Type checking
- State verification

### Async Testing
- Proper async/await usage
- AsyncMock for async functions
- Event loop management

### Mocking
- Mock external dependencies
- Verify mock interactions
- Use realistic mock data
- Clean up after tests

## Continuous Integration

The test suite is designed to run in CI/CD environments:
- No external dependencies
- Deterministic test results
- Fast execution
- Clear failure reporting

## Debugging Tests

### Verbose Output
```bash
python -m pytest tests/ -v -s
```

### Debug Mode
```bash
python -m pytest tests/ --pdb
```

### Coverage Debugging
```bash
# Generate detailed coverage report
python -m pytest tests/ --cov=app --cov-report=html:htmlcov
# Open htmlcov/index.html in browser
```

## Adding New Tests

### For New Services
1. Create test file in `tests/services/`
2. Follow naming convention: `test_<service_name>.py`
3. Create test class: `Test<ServiceName>`
4. Add fixtures for test data
5. Mock dependencies
6. Test all public methods

### For New Controllers
1. Create test file in `tests/controllers/`
2. Use FastAPI TestClient
3. Mock service dependencies
4. Test all endpoints
5. Verify response codes and data

### For New Models
1. Create test file in `tests/models/`
2. Test model creation
3. Test validation rules
4. Test serialization/deserialization
5. Test edge cases

## Troubleshooting

### Common Issues
1. **Import Errors**: Ensure PYTHONPATH includes project root
2. **Async Issues**: Use `pytest-asyncio` and proper async/await
3. **Mock Issues**: Verify mock setup and cleanup
4. **Database Issues**: Ensure all database operations are mocked

### Test Failures
1. Check test data setup
2. Verify mock configurations
3. Review assertion expectations
4. Check for timing issues in async tests

## Performance

- Tests run in parallel where possible
- Fast execution with mocked dependencies
- Minimal setup/teardown overhead
- Efficient test data generation

## Security Testing

- JWT token validation
- Password hashing verification
- Input validation testing
- Authentication flow testing
- Authorization boundary testing
