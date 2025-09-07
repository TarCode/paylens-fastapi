import os
import asyncio
from typing import Any, Dict, List, Optional, Callable, TypeVar, Awaitable
import asyncpg
from contextlib import asynccontextmanager
import logging

# Set up logging
logger = logging.getLogger(__name__)

T = TypeVar('T')

def transform_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Transform database row - keep snake_case as is"""
    if not row or not isinstance(row, dict):
        return row
    
    # Return row as-is since we want snake_case
    return row

class DatabaseService:
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
        self.database_url = os.getenv('DATABASE_URL')
        
        if not self.database_url:
            raise ValueError("DATABASE_URL environment variable is required")

    async def initialize(self):
        """Initialize the database connection pool"""
        if self.pool is None:
            self.pool = await asyncpg.create_pool(
                self.database_url,
                min_size=1,
                max_size=20,
                command_timeout=2,
                server_settings={
                    'application_name': 'fastapi_app'
                }
            )
            logger.info("Database pool initialized")

    async def query(self, text: str, params: Optional[List[Any]] = None) -> List[Dict[str, Any]]:
        """Execute a query and return transformed results"""
        if not self.pool:
            await self.initialize()
        
        async with self.pool.acquire() as connection:
            try:
                if params:
                    rows = await connection.fetch(text, *params)
                else:
                    rows = await connection.fetch(text)
                
                # Transform each row (keeping snake_case)
                transformed_rows = [transform_row(dict(row)) for row in rows]
                return {"rows": transformed_rows}
            except Exception as e:
                logger.error(f"Query execution failed: {e}")
                raise

    async def fetchrow(self, text: str, params: Optional[List[Any]] = None) -> Optional[Dict[str, Any]]:
        """Execute a query and return a single transformed row"""
        if not self.pool:
            await self.initialize()
        
        async with self.pool.acquire() as connection:
            try:
                if params:
                    row = await connection.fetchrow(text, *params)
                else:
                    row = await connection.fetchrow(text)
                
                if row:
                    return transform_row(dict(row))
                return None
            except Exception as e:
                logger.error(f"Fetchrow execution failed: {e}")
                raise

    async def execute(self, text: str, params: Optional[List[Any]] = None) -> str:
        """Execute a command and return the status"""
        if not self.pool:
            await self.initialize()
        
        async with self.pool.acquire() as connection:
            try:
                if params:
                    result = await connection.execute(text, *params)
                else:
                    result = await connection.execute(text)
                return result
            except Exception as e:
                logger.error(f"Execute command failed: {e}")
                raise

    @asynccontextmanager
    async def get_connection(self):
        """Get a database connection from the pool"""
        if not self.pool:
            await self.initialize()
        
        async with self.pool.acquire() as connection:
            yield connection

    async def transaction(self, callback: Callable[[asyncpg.Connection], Awaitable[T]]) -> T:
        """Execute a transaction"""
        if not self.pool:
            await self.initialize()
        
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                try:
                    result = await callback(connection)
                    return result
                except Exception as e:
                    logger.error(f"Transaction failed: {e}")
                    raise

    async def close(self):
        """Close the database pool"""
        if self.pool:
            await self.pool.close()
            self.pool = None
            logger.info("Database pool closed")

    async def health_check(self) -> bool:
        """Check database connectivity"""
        try:
            result = await self.query('SELECT NOW() as current_time')
            return len(result) > 0
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

# Singleton instance
db_service = DatabaseService()