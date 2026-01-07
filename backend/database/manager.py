"""
Database operations module for SQLite with migrations and integrity management
Migrated from api/database.py with backend integration.
"""
import sqlite3
import json
import os
import shutil
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from pathlib import Path

from ..config.settings import settings

logger = logging.getLogger(__name__)


class DatabaseMigration:
    """Database migration management"""
    
    # Migration scripts in order
    MIGRATIONS = [
        {
            "version": 1,
            "description": "Initial schema creation",
            "sql": """
                CREATE TABLE IF NOT EXISTS repositories (
                    id TEXT PRIMARY KEY,
                    url TEXT,
                    local_path TEXT,
                    primary_languages TEXT,
                    structure_summary TEXT,
                    analysis_status TEXT,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS threat_documents (
                    id TEXT PRIMARY KEY,
                    repo_id TEXT,
                    doc_type TEXT,
                    title TEXT,
                    content TEXT,
                    metadata TEXT,
                    version INTEGER DEFAULT 1,
                    is_current BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP,
                    FOREIGN KEY (repo_id) REFERENCES repositories (id)
                );
                
                CREATE TABLE IF NOT EXISTS code_references (
                    id TEXT PRIMARY KEY,
                    doc_id TEXT,
                    file_path TEXT,
                    line_start INTEGER,
                    line_end INTEGER,
                    function_name TEXT,
                    class_name TEXT,
                    code_snippet TEXT,
                    FOREIGN KEY (doc_id) REFERENCES threat_documents (id)
                );
                
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    description TEXT,
                    applied_at TIMESTAMP,
                    checksum TEXT
                );
            """
        },
        {
            "version": 2,
            "description": "Add indexes for performance",
            "sql": """
                CREATE INDEX IF NOT EXISTS idx_repositories_status ON repositories(analysis_status);
                CREATE INDEX IF NOT EXISTS idx_repositories_created ON repositories(created_at);
                CREATE INDEX IF NOT EXISTS idx_threat_docs_repo ON threat_documents(repo_id);
                CREATE INDEX IF NOT EXISTS idx_threat_docs_type ON threat_documents(doc_type);
                CREATE INDEX IF NOT EXISTS idx_threat_docs_current ON threat_documents(is_current);
                CREATE INDEX IF NOT EXISTS idx_code_refs_doc ON code_references(doc_id);
            """
        },
        {
            "version": 3,
            "description": "Add analysis tracking tables",
            "sql": """
                CREATE TABLE IF NOT EXISTS analysis_sessions (
                    id TEXT PRIMARY KEY,
                    repo_id TEXT,
                    status TEXT,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    error_message TEXT,
                    metadata TEXT,
                    FOREIGN KEY (repo_id) REFERENCES repositories (id)
                );
                
                CREATE TABLE IF NOT EXISTS pr_analyses (
                    id TEXT PRIMARY KEY,
                    pr_url TEXT,
                    repo_id TEXT,
                    status TEXT,
                    analysis_result TEXT,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP,
                    FOREIGN KEY (repo_id) REFERENCES repositories (id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_analysis_sessions_repo ON analysis_sessions(repo_id);
                CREATE INDEX IF NOT EXISTS idx_analysis_sessions_status ON analysis_sessions(status);
                CREATE INDEX IF NOT EXISTS idx_pr_analyses_repo ON pr_analyses(repo_id);
                CREATE INDEX IF NOT EXISTS idx_pr_analyses_url ON pr_analyses(pr_url);
            """
        }
    ]


class DatabaseManager:
    """Enhanced database manager with connection pooling and migrations"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.database_path
        self.migration_manager = DatabaseMigration()
        self._ensure_database_directory()
        self._initialize_database()
    
    def _ensure_database_directory(self):
        """Ensure database directory exists"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
    
    def _initialize_database(self):
        """Initialize database with migrations"""
        try:
            self._run_migrations()
            logger.info(f"Database initialized at {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def _run_migrations(self):
        """Run database migrations"""
        with self.get_connection() as conn:
            # Get current schema version
            current_version = self._get_schema_version(conn)
            
            # Apply migrations
            for migration in self.migration_manager.MIGRATIONS:
                if migration["version"] > current_version:
                    logger.info(f"Applying migration {migration['version']}: {migration['description']}")
                    
                    # Execute migration SQL
                    conn.executescript(migration["sql"])
                    
                    # Record migration
                    conn.execute(
                        "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
                        (migration["version"], migration["description"], datetime.utcnow())
                    )
                    
                    conn.commit()
                    logger.info(f"Migration {migration['version']} completed")
    
    def _get_schema_version(self, conn: sqlite3.Connection) -> int:
        """Get current schema version"""
        try:
            cursor = conn.execute("SELECT MAX(version) FROM schema_migrations")
            result = cursor.fetchone()
            return result[0] if result[0] is not None else 0
        except sqlite3.OperationalError:
            # Table doesn't exist yet
            return 0
    
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection with proper configuration"""
        conn = sqlite3.connect(
            self.db_path,
            timeout=30.0,
            check_same_thread=False
        )
        
        # Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON")
        
        # Set row factory for dict-like access
        conn.row_factory = sqlite3.Row
        
        return conn
    
    def execute_query(self, query: str, params: Optional[Tuple] = None) -> List[sqlite3.Row]:
        """Execute a SELECT query and return results"""
        with self.get_connection() as conn:
            cursor = conn.execute(query, params or ())
            return cursor.fetchall()
    
    def execute_update(self, query: str, params: Optional[Tuple] = None) -> int:
        """Execute an INSERT/UPDATE/DELETE query and return affected rows"""
        with self.get_connection() as conn:
            cursor = conn.execute(query, params or ())
            conn.commit()
            return cursor.rowcount
    
    def backup_database(self, backup_path: Optional[str] = None) -> str:
        """Create database backup"""
        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{self.db_path}.backup_{timestamp}"
        
        try:
            shutil.copy2(self.db_path, backup_path)
            logger.info(f"Database backed up to {backup_path}")
            return backup_path
        except Exception as e:
            logger.error(f"Database backup failed: {e}")
            raise
    
    def restore_database(self, backup_path: str):
        """Restore database from backup"""
        try:
            if not os.path.exists(backup_path):
                raise FileNotFoundError(f"Backup file not found: {backup_path}")
            
            # Create backup of current database
            current_backup = self.backup_database()
            
            try:
                shutil.copy2(backup_path, self.db_path)
                logger.info(f"Database restored from {backup_path}")
            except Exception as e:
                # Restore original if restore failed
                shutil.copy2(current_backup, self.db_path)
                raise e
            
        except Exception as e:
            logger.error(f"Database restore failed: {e}")
            raise
    
    def vacuum_database(self):
        """Vacuum database to reclaim space"""
        try:
            with self.get_connection() as conn:
                conn.execute("VACUUM")
                conn.commit()
            logger.info("Database vacuumed successfully")
        except Exception as e:
            logger.error(f"Database vacuum failed: {e}")
            raise
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            with self.get_connection() as conn:
                # Get table counts
                tables = ["repositories", "threat_documents", "code_references", "analysis_sessions", "pr_analyses"]
                stats = {}
                
                for table in tables:
                    try:
                        cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                        stats[f"{table}_count"] = cursor.fetchone()[0]
                    except sqlite3.OperationalError:
                        stats[f"{table}_count"] = 0
                
                # Get database size
                stats["database_size_bytes"] = os.path.getsize(self.db_path)
                stats["database_path"] = self.db_path
                
                # Get schema version
                stats["schema_version"] = self._get_schema_version(conn)
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {"error": str(e)}
    
    def close(self):
        """Close database connections and cleanup"""
        # SQLite connections are closed automatically when context managers exit
        # This method is here for interface compatibility
        logger.info("Database manager closed")


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_database_manager() -> DatabaseManager:
    """Get the global database manager instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager