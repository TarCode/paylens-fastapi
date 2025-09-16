# Paylens FastAPI Backend

[![codecov](https://codecov.io/gh/TarCode/paylens-fastapi/branch/main/graph/badge.svg)](https://codecov.io/gh/TarCode/paylens-fastapi)
[![Tests](https://github.com/TarCode/paylens-fastapi/actions/workflows/test.yml/badge.svg)](https://github.com/TarCode/paylens-fastapi/actions/workflows/test.yml)

A secure FastAPI backend for user authentication with JWT tokens and Google OAuth support.

## Features

- User authentication (email/password + Google OAuth)
- JWT token management with refresh tokens
- Password reset functionality
- User profile management

## Quick Start

### Requirements
- Python 3.10+
- PostgreSQL 15+

### Setup

1. **Clone and setup**
```bash
git clone <repository-url>
cd paylens/api
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate
pip install -r requirements.txt
```

2. **Environment configuration**
Create `.env` file:
```bash
DATABASE_URL=postgresql://username:password@localhost:5432/paylens_db
JWT_SECRET=your-jwt-secret-change-in-production
JWT_EXPIRES_IN=7d
REFRESH_TOKEN_SECRET=your-refresh-secret
ENV=development
```

3. **Database setup**
```bash
# With Docker (recommended)
docker-compose -f docker-compose.dev.yml up db -d
make migrate

# Or with local PostgreSQL
python app/scripts/migrate.py up
```

4. **Run the application**
```bash
uvicorn app.main:app --reload --port 8000
```

Access at http://localhost:8000 (docs at http://localhost:8000/docs)

## API Endpoints

### Authentication
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/register` | POST | Register new user |
| `/auth/login` | POST | User login |
| `/auth/refresh-token` | POST | Refresh access token |
| `/auth/profile` | GET/PUT | Get/update user profile |
| `/auth/change-password` | POST | Change password |
| `/auth/forgot-password` | POST | Request password reset |
| `/auth/reset-password` | POST | Reset password |
| `/auth/google/callback` | GET | Google OAuth callback |

### Example Usage

**Register:**
```bash
POST /auth/register
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Login:**
```bash
POST /auth/login
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user": { "id": "uuid", "email": "user@example.com", ... },
    "tokens": { "access_token": "...", "refresh_token": "..." }
  }
}
```

## Testing

```bash
# Run all tests
make test

# Quick tests
make test-quick

# Specific test types
make test-unit
make test-integration
```

## Docker Development

```bash
# Start all services
make up

# Stop services
make down

# Reset database
make resetdb
```

## Deployment

### Docker
```bash
docker build -t paylens-api .
docker run -p 8000:80 -e DATABASE_URL=... -e JWT_SECRET=... paylens-api
```

### Environment Variables
```bash
DATABASE_URL=postgresql://user:pass@host:5432/dbname
JWT_SECRET=your-production-jwt-secret
REFRESH_TOKEN_SECRET=your-refresh-token-secret
ENV=production
```

## Project Structure

```
app/
├── controllers/     # API routes
├── services/        # Business logic
├── models/          # Data models
├── middleware/      # Auth middleware
├── validation/      # Request validation
└── main.py         # App entry point

tests/              # Test suite
.github/workflows/  # CI/CD
```

### Code Standards
- Follow PEP 8
- Use snake_case naming
- Add type hints
- Write tests for new features
- Maintain test coverage

## Available Commands

```bash
make test          # Run tests
make migrate       # Database migrations
make up/down       # Docker services
make help          # Show all commands
```
