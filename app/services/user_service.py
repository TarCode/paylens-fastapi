import bcrypt
import uuid
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from services.db_service import db_service
from models.user import UserDB, UserInternal, CreateUserData, UpdateUserData, dict_to_userdb


class UserService:
    async def create_user(self, user_data: CreateUserData) -> UserInternal:
        """Create a new user in the database"""
        email = user_data.email
        password = user_data.password
        google_id = user_data.google_id
        first_name = user_data.first_name
        last_name = user_data.last_name
        company_name = user_data.company_name

        # Hash password if provided (for traditional registration)
        hashed_password = None
        if password:
            salt_rounds = int(os.getenv("BCRYPT_ROUNDS", "12"))
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=salt_rounds)).decode('utf-8')

        user_id = str(uuid.uuid4())
        now = datetime.now()

        # Determine subscription tier based on company name (for now, default to free)
        subscription_tier = "free" if company_name else "free"
        monthly_limit = self._get_monthly_limit(subscription_tier)

        query = """
            INSERT INTO users (
                id, email, password, google_id, first_name, last_name, company_name,
                role, subscription_tier, monthly_limit, usage_count,
                is_active, email_verified, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING *
        """

        values = [
            user_id,
            email,
            hashed_password,
            google_id,
            first_name,
            last_name,
            company_name,
            "user",
            subscription_tier,
            monthly_limit,
            0,  # usage_count
            True,  # is_active (activate user immediately)
            True,  # email_verified (for development - in production use email verification)
            now,
            now
        ]

        result = await db_service.query(query, values)
        if result["rows"]:
            return dict_to_userdb(result["rows"][0]).to_user_internal()
        raise Exception("Failed to create user")

    async def find_by_email(self, email: str) -> Optional[UserInternal]:
        """Find user by email address"""
        query = "SELECT * FROM users WHERE email = $1"
        result = await db_service.query(query, [email])
        if result["rows"]:
            return dict_to_userdb(result["rows"][0]).to_user_internal()
        return None

    async def find_by_id(self, user_id: str) -> Optional[UserInternal]:
        """Find user by ID"""
        query = "SELECT * FROM users WHERE id = $1"
        result = await db_service.query(query, [user_id])
        if result["rows"]:
            return dict_to_userdb(result["rows"][0]).to_user_internal()
        return None

    async def find_by_google_id(self, google_id: str) -> Optional[UserInternal]:
        """Find user by Google ID"""
        query = "SELECT * FROM users WHERE google_id = $1"
        result = await db_service.query(query, [google_id])
        if result["rows"]:
            return dict_to_userdb(result["rows"][0]).to_user_internal()
        return None

    async def update_user(self, user_id: str, update_data: UpdateUserData) -> Optional[UserInternal]:
        """Update user data"""
        fields = []
        values = []
        param_count = 1

        # Convert Pydantic model to dict and filter None values
        update_dict = update_data.model_dump(exclude_unset=True)
        for key, value in update_dict.items():
            if value is not None:
                # Convert camelCase to snake_case
                db_key = self._camel_to_snake(key)
                fields.append(f"{db_key} = ${param_count}")
                values.append(value)
                param_count += 1

        if not fields:
            return await self.find_by_id(user_id)

        values.append(user_id)  # Add ID for WHERE clause
        values.append(datetime.now())  # Add updated_at timestamp

        query = f"""
            UPDATE users
            SET {', '.join(fields)}, updated_at = ${param_count + 1}
            WHERE id = ${param_count}
            RETURNING *
        """

        result = await db_service.query(query, values)
        if result["rows"]:
            return dict_to_userdb(result["rows"][0]).to_user_internal()
        return None

    async def increment_usage_count(self, user_id: str) -> Dict[str, Any]:
        """Increment user's usage count with proper validation"""
        # First, check if user needs monthly reset
        reset_check = await self.check_and_reset_monthly_usage(user_id)
        user = reset_check["user"]

        if not user:
            return {"user": None, "can_increment": False, "error": "User not found"}

        # Use a database transaction with row-level locking to prevent race conditions
        query = """
            UPDATE users
            SET usage_count = usage_count + 1, updated_at = NOW()
            WHERE id = $1
            AND (
                subscription_tier = 'enterprise'
                OR usage_count < monthly_limit
            )
            RETURNING *
        """
        result = await db_service.query(query, [user_id])

        if not result["rows"]:
            # Check current user status after potential reset
            user_check = await self.find_by_id(user_id)
            if not user_check:
                return {"user": None, "can_increment": False, "error": "User not found"}

            if user_check.subscription_tier == "enterprise":
                # This shouldn't happen, but handle edge case
                return {"user": None, "can_increment": False, "error": "Enterprise user increment failed"}

            return {
                "user": user_check,
                "can_increment": False,
                "error": f"Usage limit exceeded. Current: {user_check.usage_count}, Limit: {user_check.monthly_limit}",
                "was_reset": reset_check["was_reset"]
            }

        updated_user = dict_to_userdb(result["rows"][0]).to_user_internal()
        return {
            "user": updated_user,
            "can_increment": True,
            "was_reset": reset_check["was_reset"]
        }

    async def reset_monthly_usage(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Reset monthly usage for one user or all users"""
        result = {"reset_count": 0, "errors": []}

        try:
            if user_id:
                # Reset specific user
                query = """
                    UPDATE users
                    SET usage_count = 0,
                        last_usage_reset = NOW(),
                        billing_period_start = DATE_TRUNC('month', NOW()),
                        updated_at = NOW()
                    WHERE id = $1
                    RETURNING *
                """
                params = [user_id]
            else:
                # Reset all users whose billing period has ended
                query = """
                    UPDATE users
                    SET usage_count = 0,
                        last_usage_reset = NOW(),
                        billing_period_start = DATE_TRUNC('month', NOW()),
                        updated_at = NOW()
                    WHERE billing_period_start < DATE_TRUNC('month', NOW())
                    RETURNING *
                """
                params = []

            db_result = await db_service.query(query, params)
            result["reset_count"] = len(db_result["rows"])

            if result["reset_count"] > 0:
                print(f"✅ Reset usage for {result['reset_count']} user(s)")

        except Exception as error:
            error_msg = f"Failed to reset monthly usage: {str(error)}"
            print(f"❌ {error_msg}")
            result["errors"].append(error_msg)

        return result

    async def check_and_reset_monthly_usage(self, user_id: str) -> Dict[str, Any]:
        """Check if user needs monthly reset"""
        try:
            user = await self.find_by_id(user_id)
            if not user:
                return {"was_reset": False, "user": None}

            # Check if current date is in a new month compared to billing_period_start
            current_month = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            last_reset_month = user.billing_period_start.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

            if current_month > last_reset_month:
                # Reset usage for this user
                reset_result = await self.reset_monthly_usage(user_id)
                if reset_result["reset_count"] > 0:
                    # Fetch updated user data
                    updated_user = await self.find_by_id(user_id)
                    return {"was_reset": True, "user": updated_user}

            return {"was_reset": False, "user": user}
        except Exception as error:
            print(f"Error checking monthly reset: {error}")
            return {"was_reset": False, "user": None}

    async def validate_password(self, plain_password: str, hashed_password: str) -> bool:
        """Validate password against hash"""
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

    async def update_password(self, user_id: str, new_password: str) -> None:
        """Update user password"""
        salt_rounds = int(os.getenv("BCRYPT_ROUNDS", "12"))
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(rounds=salt_rounds)).decode('utf-8')

        query = """
            UPDATE users
            SET password = $1, updated_at = NOW()
            WHERE id = $2
        """
        await db_service.query(query, [hashed_password, user_id])

    async def deactivate_user(self, user_id: str) -> None:
        """Deactivate a user"""
        query = """
            UPDATE users
            SET is_active = false, updated_at = NOW()
            WHERE id = $1
        """
        await db_service.query(query, [user_id])

    def _get_monthly_limit(self, tier: str) -> int:
        """Get monthly usage limit based on subscription tier"""
        limits = {
            "free": 5,
            "pro": 100,
            "business": 1000,
            "enterprise": -1  # unlimited
        }
        return limits.get(tier, 5)

    async def get_all_users(self, limit: int = 50, offset: int = 0) -> List[UserInternal]:
        """Get all users (admin function)"""
        query = """
            SELECT * FROM users
            WHERE is_active = true
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        """
        result = await db_service.query(query, [limit, offset])
        return [dict_to_userdb(row).to_user_internal() for row in result["rows"]]

    async def get_user_stats(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user statistics"""
        query = """
            SELECT
                u.usage_count,
                u.monthly_limit,
                u.subscription_tier,
                u.created_at as registration_date,
                u.updated_at as last_updated
            FROM users u
            WHERE u.id = $1
        """
        result = await db_service.query(query, [user_id])
        return result["rows"][0] if result["rows"] else None

    def _camel_to_snake(self, name: str) -> str:
        """Convert camelCase to snake_case"""
        import re
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


# Create singleton instance
user_service = UserService()