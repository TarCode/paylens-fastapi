"""Database migration script using SQLModel and Alembic

This script provides both programmatic migration capabilities and Alembic integration.
Run with: python migrate.py [up|down|init]
"""

import asyncio
import sys
from typing import Optional
from sqlmodel import SQLModel, create_engine, Session, text
from sqlalchemy import inspect
from models.user import UserDB
import logging
from pathlib import Path
from config.db import DATABASE_URL

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseMigrator:
    def __init__(self, database_url: str):
        self.engine = create_engine(database_url, echo=False)
        
    async def safe_execute(self, sql: str, description: Optional[str] = None) -> Optional[any]:
        """Execute SQL safely with error handling"""
        try:
            with Session(self.engine) as session:
                result = session.exec(text(sql))
                session.commit()
                
                # Get row count if available
                row_count = getattr(result, 'rowcount', None)
                logger.info(f"Query successful{f': {description}' if description else ''}")
                if row_count is not None:
                    logger.info(f"Affected rows: {row_count}")
                return result
                
        except Exception as e:
            logger.error(f"Query failed{f': {description}' if description else ''}: {str(e)}")
            return None

    async def create_tables(self):
        """Create all tables and run migrations"""
        logger.info("Starting database migration...")
        
        # Create all tables from SQLModel models
        logger.info("Creating tables from SQLModel models...")
        SQLModel.metadata.create_all(self.engine)
        
        # Apply additional constraints and indexes
        await self._create_indexes()
        await self._create_triggers()
        await self._fix_data_issues()
        
        logger.info("✅ Database migration completed successfully!")

    async def _create_indexes(self):
        """Create additional indexes"""
        indexes = [
            ("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);", "Index email"),
            ("CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);", "Index is_active"),
            ("CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);", "Index google_id"),
            ("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);", "Index role"),
            ("CREATE INDEX IF NOT EXISTS idx_users_subscription_tier ON users(subscription_tier);", "Index subscription_tier"),
            ("CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);", "Index created_at"),
        ]
        
        for sql, description in indexes:
            await self.safe_execute(sql, description)

    async def _create_triggers(self):
        """Create database triggers"""
        # Updated_at trigger function
        await self.safe_execute("""
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = NOW();
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        """, "Create trigger function")

        # Drop existing trigger and create new one
        await self.safe_execute("""
            DROP TRIGGER IF EXISTS update_users_updated_at ON users;
            CREATE TRIGGER update_users_updated_at
                BEFORE UPDATE ON users
                FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        """, "Create updated_at trigger")

    async def _fix_data_issues(self):
        """Fix any data consistency issues"""
        # Fix NULL is_active values
        result = await self.safe_execute("""
            UPDATE users
            SET is_active = true
            WHERE is_active IS NULL
        """, "Fix NULL is_active")
        
        if result and hasattr(result, 'rowcount') and result.rowcount > 0:
            logger.info(f"Fixed {result.rowcount} users with NULL is_active values")

        # Update default monthly_limit for existing users
        result = await self.safe_execute("""
            UPDATE users 
            SET monthly_limit = 1000 
            WHERE monthly_limit < 100 OR monthly_limit IS NULL
        """, "Update monthly_limit to new default")
        
        if result and hasattr(result, 'rowcount') and result.rowcount > 0:
            logger.info(f"Updated {result.rowcount} users with low monthly_limit")

        # Fix any users with both password and google_id as NULL
        result = await self.safe_execute("""
            UPDATE users 
            SET is_active = false 
            WHERE password IS NULL AND google_id IS NULL AND is_active = true
        """, "Deactivate invalid users")
        
        if result and hasattr(result, 'rowcount') and result.rowcount > 0:
            logger.warning(f"Deactivated {result.rowcount} invalid users (no password or google_id)")

    async def drop_tables(self):
        """Drop all tables"""
        logger.info("Dropping all tables...")
        
        # Drop triggers first
        await self.safe_execute("DROP TRIGGER IF EXISTS update_users_updated_at ON users;", "Drop trigger")
        await self.safe_execute("DROP FUNCTION IF EXISTS update_updated_at_column();", "Drop trigger function")
        
        # Drop tables
        SQLModel.metadata.drop_all(self.engine)
        
        logger.info("✅ All tables dropped successfully!")

    def check_table_exists(self, table_name: str) -> bool:
        """Check if a table exists"""
        inspector = inspect(self.engine)
        return table_name in inspector.get_table_names()

    async def get_table_info(self):
        """Get information about existing tables"""
        inspector = inspect(self.engine)
        tables = inspector.get_table_names()
        
        logger.info("Existing tables:")
        for table in tables:
            columns = inspector.get_columns(table)
            logger.info(f"  {table}: {len(columns)} columns")
            for col in columns:
                logger.info(f"    - {col['name']}: {col['type']}")

    async def validate_schema(self):
        """Validate that the database schema matches our models"""
        logger.info("Validating database schema...")
        
        table_name = UserDB.__tablename__
        if not self.check_table_exists(table_name):
            logger.error(f"{table_name.title()} table does not exist!")
            return False
            
        inspector = inspect(self.engine)
        columns = {col['name']: col for col in inspector.get_columns(table_name)}
        
        # Get required columns from UserDB model
        model_fields = UserDB.__fields__.keys()
        required_columns = [
            field for field in model_fields 
            if not UserDB.__fields__[field].default and 
               UserDB.__fields__[field].default_factory is None
        ]
        
        missing_columns = [col for col in required_columns if col not in columns]
        if missing_columns:
            logger.error(f"Missing required columns: {missing_columns}")
            return False
            
        logger.info("✅ Database schema validation passed!")
        return True


# Alembic integration
def create_alembic_migration():
    """Generate Alembic migration files"""
    try:
        from alembic.config import Config
        from alembic import command
        
        # Create alembic.ini if it doesn't exist
        alembic_ini_content = """
[alembic]
script_location = migrations
prepend_sys_path = .
version_path_separator = os
sqlalchemy.url = postgresql://user:password@localhost/dbname

[post_write_hooks]
hooks = black
black.type = console_scripts
black.entrypoint = black
black.options = -l 79 REVISION_SCRIPT_FILENAME

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
"""
        
        if not Path("alembic.ini").exists():
            with open("alembic.ini", "w") as f:
                f.write(alembic_ini_content.strip())
                
        # Initialize Alembic if migrations directory doesn't exist
        if not Path("migrations").exists():
            alembic_cfg = Config("alembic.ini")
            command.init(alembic_cfg, "migrations")
            logger.info("Initialized Alembic migrations directory")
            
        # Generate migration
        alembic_cfg = Config("alembic.ini")
        command.revision(alembic_cfg, autogenerate=True, message="Initial migration")
        logger.info("Generated Alembic migration")
        
    except ImportError:
        logger.warning("Alembic not installed. Install with: pip install alembic")
    except Exception as e:
        logger.error(f"Failed to create Alembic migration: {e}")


async def main():
    """Main function to handle command line arguments"""
    
    # Get database URL from environment/config
    database_url = DATABASE_URL
    logger.info(f"Using database: {database_url.split('@')[-1] if '@' in database_url else 'local'}")  # Don't log full URL with credentials
    
    migrator = DatabaseMigrator(database_url)
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "down":
            await migrator.drop_tables()
        elif command == "info":
            await migrator.get_table_info()
        elif command == "validate":
            await migrator.validate_schema()
        elif command == "alembic":
            create_alembic_migration()
        elif command == "up" or command == "migrate":
            await migrator.create_tables()
        else:
            logger.error(f"Unknown command: {command}")
            logger.info("Available commands: up, down, info, validate, alembic")
            sys.exit(1)
    else:
        # Default to creating tables
        await migrator.create_tables()


if __name__ == "__main__":
    print("Starting migration script...")
    try:
        print("Testing database configuration...")
        db_url = DATABASE_URL
        print(f"Database URL loaded successfully: {db_url.split('@')[-1] if '@' in db_url else 'configured'}")
        print("Running main function...")
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nMigration interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Migration failed with error: {e}")
        logger.exception("Full error details:")
        sys.exit(1)