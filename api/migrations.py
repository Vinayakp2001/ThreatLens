"""
Database Migration System for Security Wiki Generator

This module provides comprehensive database migration management with
backward compatibility, data preservation, and rollback capabilities.
"""
import sqlite3
import json
import logging
import hashlib
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from pathlib import Path

from api.config import settings

logger = logging.getLogger(__name__)


class MigrationError(Exception):
    """Migration-specific error"""
    pass


class Migration:
    """Individual migration definition"""
    
    def __init__(self, version: int, description: str, 
                 up_sql: str = None, down_sql: str = None,
                 up_func: Callable = None, down_func: Callable = None):
        self.version = version
        self.description = description
        self.up_sql = up_sql
        self.down_sql = down_sql
        self.up_func = up_func
        self.down_func = down_func
        
        if not (up_sql or up_func):
            raise ValueError("Migration must have either up_sql or up_func")
    
    def get_checksum(self) -> str:
        """Calculate migration checksum"""
        content = f"{self.version}{self.description}{self.up_sql or ''}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def apply(self, conn: sqlite3.Connection) -> bool:
        """Apply migration"""
        try:
            if self.up_func:
                self.up_func(conn)
            elif self.up_sql:
                conn.executescript(self.up_sql)
            return True
        except Exception as e:
            logger.error(f"Failed to apply migration {self.version}: {e}")
            raise MigrationError(f"Migration {self.version} failed: {e}")
    
    def rollback(self, conn: sqlite3.Connection) -> bool:
        """Rollback migration"""
        try:
            if self.down_func:
                self.down_func(conn)
            elif self.down_sql:
                conn.executescript(self.down_sql)
            return True
        except Exception as e:
            logger.error(f"Failed to rollback migration {self.version}: {e}")
            raise MigrationError(f"Migration {self.version} rollback failed: {e}")


class MigrationManager:
    """Comprehensive migration management system"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or settings.database_path
        self.migrations = self._get_all_migrations()
    
    def _get_all_migrations(self) -> List[Migration]:
        """Get all available migrations in order"""
        return [
            # Migration 1: Initial schema
            Migration(
                version=1,
                description="Initial schema creation",
                up_sql="""
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
                """,
                down_sql="""
                    DROP TABLE IF EXISTS code_references;
                    DROP TABLE IF EXISTS threat_documents;
                    DROP TABLE IF EXISTS repositories;
                    DROP TABLE IF EXISTS schema_migrations;
                """
            ),
            
            # Migration 2: Performance indexes
            Migration(
                version=2,
                description="Add indexes for performance",
                up_sql="""
                    CREATE INDEX IF NOT EXISTS idx_repositories_status ON repositories(analysis_status);
                    CREATE INDEX IF NOT EXISTS idx_repositories_created ON repositories(created_at);
                    CREATE INDEX IF NOT EXISTS idx_threat_docs_repo ON threat_documents(repo_id);
                    CREATE INDEX IF NOT EXISTS idx_threat_docs_type ON threat_documents(doc_type);
                    CREATE INDEX IF NOT EXISTS idx_threat_docs_current ON threat_documents(is_current);
                    CREATE INDEX IF NOT EXISTS idx_code_refs_doc ON code_references(doc_id);
                """,
                down_sql="""
                    DROP INDEX IF EXISTS idx_repositories_status;
                    DROP INDEX IF EXISTS idx_repositories_created;
                    DROP INDEX IF EXISTS idx_threat_docs_repo;
                    DROP INDEX IF EXISTS idx_threat_docs_type;
                    DROP INDEX IF EXISTS idx_threat_docs_current;
                    DROP INDEX IF EXISTS idx_code_refs_doc;
                """
            ),
            
            # Migration 3: Analysis tracking
            Migration(
                version=3,
                description="Add analysis tracking tables",
                up_sql="""
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
                    
                    CREATE TABLE IF NOT EXISTS system_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_name TEXT,
                        metric_value REAL,
                        metric_unit TEXT,
                        recorded_at TIMESTAMP,
                        metadata TEXT
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_analysis_sessions_repo ON analysis_sessions(repo_id);
                    CREATE INDEX IF NOT EXISTS idx_analysis_sessions_status ON analysis_sessions(status);
                    CREATE INDEX IF NOT EXISTS idx_system_metrics_name ON system_metrics(metric_name);
                    CREATE INDEX IF NOT EXISTS idx_system_metrics_recorded ON system_metrics(recorded_at);
                """,
                down_sql="""
                    DROP INDEX IF EXISTS idx_analysis_sessions_repo;
                    DROP INDEX IF EXISTS idx_analysis_sessions_status;
                    DROP INDEX IF EXISTS idx_system_metrics_name;
                    DROP INDEX IF EXISTS idx_system_metrics_recorded;
                    DROP TABLE IF EXISTS analysis_sessions;
                    DROP TABLE IF EXISTS system_metrics;
                """
            ),
            
            # Migration 4: Flexible security documentation and PR analysis
            Migration(
                version=4,
                description="Add flexible security documentation and PR analysis support",
                up_sql="""
                    CREATE TABLE IF NOT EXISTS security_documents (
                        id TEXT PRIMARY KEY,
                        repo_id TEXT,
                        title TEXT,
                        content TEXT,
                        scope TEXT,
                        metadata TEXT,
                        version INTEGER DEFAULT 1,
                        is_current BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP,
                        updated_at TIMESTAMP,
                        FOREIGN KEY (repo_id) REFERENCES repositories (id)
                    );
                    
                    CREATE TABLE IF NOT EXISTS pr_analyses (
                        id TEXT PRIMARY KEY,
                        pr_id TEXT,
                        repo_id TEXT,
                        pr_url TEXT,
                        changed_files TEXT,
                        security_issues TEXT,
                        recommendations TEXT,
                        risk_level TEXT,
                        has_repo_context BOOLEAN DEFAULT FALSE,
                        context_used TEXT,
                        created_at TIMESTAMP,
                        FOREIGN KEY (repo_id) REFERENCES repositories (id)
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_security_docs_repo ON security_documents(repo_id);
                    CREATE INDEX IF NOT EXISTS idx_security_docs_scope ON security_documents(scope);
                    CREATE INDEX IF NOT EXISTS idx_security_docs_current ON security_documents(is_current);
                    CREATE INDEX IF NOT EXISTS idx_pr_analyses_repo ON pr_analyses(repo_id);
                    CREATE INDEX IF NOT EXISTS idx_pr_analyses_pr_id ON pr_analyses(pr_id);
                    CREATE INDEX IF NOT EXISTS idx_pr_analyses_risk ON pr_analyses(risk_level);
                """,
                down_sql="""
                    DROP INDEX IF EXISTS idx_security_docs_repo;
                    DROP INDEX IF EXISTS idx_security_docs_scope;
                    DROP INDEX IF EXISTS idx_security_docs_current;
                    DROP INDEX IF EXISTS idx_pr_analyses_repo;
                    DROP INDEX IF EXISTS idx_pr_analyses_pr_id;
                    DROP INDEX IF EXISTS idx_pr_analyses_risk;
                    DROP TABLE IF EXISTS security_documents;
                    DROP TABLE IF EXISTS pr_analyses;
                """
            ),
            
            # Migration 5: Enhanced security document code references
            Migration(
                version=5,
                description="Add code references support for security documents",
                up_sql="""
                    CREATE TABLE IF NOT EXISTS security_document_references (
                        id TEXT PRIMARY KEY,
                        security_doc_id TEXT,
                        file_path TEXT,
                        line_start INTEGER,
                        line_end INTEGER,
                        function_name TEXT,
                        class_name TEXT,
                        code_snippet TEXT,
                        FOREIGN KEY (security_doc_id) REFERENCES security_documents (id)
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_security_doc_refs_doc ON security_document_references(security_doc_id);
                    CREATE INDEX IF NOT EXISTS idx_security_doc_refs_file ON security_document_references(file_path);
                """,
                down_sql="""
                    DROP INDEX IF EXISTS idx_security_doc_refs_doc;
                    DROP INDEX IF EXISTS idx_security_doc_refs_file;
                    DROP TABLE IF EXISTS security_document_references;
                """
            ),
            
            # Migration 6: Analysis workflow tracking
            Migration(
                version=6,
                description="Add analysis workflow and routing tracking",
                up_sql="""
                    CREATE TABLE IF NOT EXISTS analysis_workflows (
                        id TEXT PRIMARY KEY,
                        repo_id TEXT,
                        workflow_type TEXT,  -- 'repository', 'pr', 'context_aware_pr'
                        routing_decision TEXT,  -- JSON with routing information
                        execution_mode TEXT,
                        context_quality REAL,
                        fallback_used BOOLEAN DEFAULT FALSE,
                        started_at TIMESTAMP,
                        completed_at TIMESTAMP,
                        status TEXT,
                        error_message TEXT,
                        metadata TEXT,
                        FOREIGN KEY (repo_id) REFERENCES repositories (id)
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_workflows_repo ON analysis_workflows(repo_id);
                    CREATE INDEX IF NOT EXISTS idx_workflows_type ON analysis_workflows(workflow_type);
                    CREATE INDEX IF NOT EXISTS idx_workflows_status ON analysis_workflows(status);
                    CREATE INDEX IF NOT EXISTS idx_workflows_started ON analysis_workflows(started_at);
                """,
                down_sql="""
                    DROP INDEX IF EXISTS idx_workflows_repo;
                    DROP INDEX IF EXISTS idx_workflows_type;
                    DROP INDEX IF EXISTS idx_workflows_status;
                    DROP INDEX IF EXISTS idx_workflows_started;
                    DROP TABLE IF EXISTS analysis_workflows;
                """
            ),
            
            # Migration 7: GitHub API usage tracking
            Migration(
                version=7,
                description="Add GitHub API usage and rate limit tracking",
                up_sql="""
                    CREATE TABLE IF NOT EXISTS github_api_usage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        endpoint TEXT,
                        method TEXT,
                        status_code INTEGER,
                        rate_limit_remaining INTEGER,
                        rate_limit_reset TIMESTAMP,
                        response_time_ms INTEGER,
                        error_message TEXT,
                        requested_at TIMESTAMP,
                        metadata TEXT
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_github_usage_endpoint ON github_api_usage(endpoint);
                    CREATE INDEX IF NOT EXISTS idx_github_usage_status ON github_api_usage(status_code);
                    CREATE INDEX IF NOT EXISTS idx_github_usage_requested ON github_api_usage(requested_at);
                """,
                down_sql="""
                    DROP INDEX IF EXISTS idx_github_usage_endpoint;
                    DROP INDEX IF EXISTS idx_github_usage_status;
                    DROP INDEX IF EXISTS idx_github_usage_requested;
                    DROP TABLE IF EXISTS github_api_usage;
                """
            ),
            
            # Migration 8: Data migration for backward compatibility
            Migration(
                version=8,
                description="Migrate legacy threat documents to security documents",
                up_func=self._migrate_threat_docs_to_security_docs,
                down_func=self._rollback_threat_docs_migration
            ),
            
            # Migration 9: Enhanced metadata and configuration tracking
            Migration(
                version=9,
                description="Add configuration and system state tracking",
                up_sql="""
                    CREATE TABLE IF NOT EXISTS system_configuration (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        config_key TEXT UNIQUE,
                        config_value TEXT,
                        config_type TEXT,  -- 'string', 'integer', 'boolean', 'json'
                        description TEXT,
                        updated_at TIMESTAMP,
                        updated_by TEXT
                    );
                    
                    CREATE TABLE IF NOT EXISTS migration_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        migration_version INTEGER,
                        operation TEXT,  -- 'apply', 'rollback'
                        started_at TIMESTAMP,
                        completed_at TIMESTAMP,
                        success BOOLEAN,
                        error_message TEXT,
                        checksum TEXT
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_system_config_key ON system_configuration(config_key);
                    CREATE INDEX IF NOT EXISTS idx_migration_history_version ON migration_history(migration_version);
                    CREATE INDEX IF NOT EXISTS idx_migration_history_operation ON migration_history(operation);
                """,
                down_sql="""
                    DROP INDEX IF EXISTS idx_system_config_key;
                    DROP INDEX IF EXISTS idx_migration_history_version;
                    DROP INDEX IF EXISTS idx_migration_history_operation;
                    DROP TABLE IF EXISTS system_configuration;
                    DROP TABLE IF EXISTS migration_history;
                """
            ),
            
            # Migration 10: Data validation and cleanup
            Migration(
                version=10,
                description="Data validation and cleanup for security documents",
                up_func=self._validate_and_cleanup_data,
                down_func=self._rollback_data_cleanup
            ),
            
            # Migration 11: Enhanced backward compatibility
            Migration(
                version=11,
                description="Enhanced backward compatibility and data integrity",
                up_sql="""
                    -- Add triggers to maintain data consistency between legacy and new tables
                    CREATE TRIGGER IF NOT EXISTS sync_threat_to_security_insert
                    AFTER INSERT ON threat_documents
                    WHEN NEW.is_current = 1
                    BEGIN
                        INSERT OR IGNORE INTO security_documents 
                        (id, repo_id, title, content, scope, metadata, version, is_current, created_at, updated_at)
                        VALUES (NEW.id, NEW.repo_id, NEW.title, NEW.content, 'full_repo', NEW.metadata, NEW.version, NEW.is_current, NEW.created_at, NEW.updated_at);
                    END;
                    
                    CREATE TRIGGER IF NOT EXISTS sync_threat_to_security_update
                    AFTER UPDATE ON threat_documents
                    WHEN NEW.is_current = 1
                    BEGIN
                        UPDATE security_documents 
                        SET title = NEW.title, content = NEW.content, metadata = NEW.metadata, 
                            version = NEW.version, is_current = NEW.is_current, updated_at = NEW.updated_at
                        WHERE id = NEW.id;
                    END;
                    
                    -- Add data validation constraints
                    CREATE TABLE IF NOT EXISTS data_validation_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        table_name TEXT,
                        column_name TEXT,
                        rule_type TEXT,
                        rule_value TEXT,
                        description TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    
                    -- Insert validation rules
                    INSERT OR IGNORE INTO data_validation_rules 
                    (table_name, column_name, rule_type, rule_value, description)
                    VALUES 
                    ('security_documents', 'scope', 'enum', 'full_repo,pr_only', 'Valid scope values'),
                    ('pr_analyses', 'risk_level', 'enum', 'low,medium,high,critical', 'Valid risk levels'),
                    ('repositories', 'analysis_status', 'enum', 'pending,in_progress,completed,failed', 'Valid analysis statuses');
                """,
                down_sql="""
                    DROP TRIGGER IF EXISTS sync_threat_to_security_insert;
                    DROP TRIGGER IF EXISTS sync_threat_to_security_update;
                    DROP TABLE IF EXISTS data_validation_rules;
                """
            ),
            
            # Migration 12: Security Wiki Storage
            Migration(
                version=12,
                description="Add security wiki storage tables for consolidated documentation",
                up_sql="""
                    CREATE TABLE IF NOT EXISTS security_wikis (
                        id TEXT PRIMARY KEY,
                        repo_id TEXT,
                        title TEXT,
                        sections TEXT,  -- JSON serialized wiki sections
                        cross_references TEXT,  -- JSON serialized cross-references
                        search_index TEXT,  -- JSON serialized search index
                        metadata TEXT,  -- JSON serialized metadata
                        created_at TIMESTAMP,
                        updated_at TIMESTAMP,
                        FOREIGN KEY (repo_id) REFERENCES repositories (id)
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_security_wikis_repo ON security_wikis(repo_id);
                    CREATE INDEX IF NOT EXISTS idx_security_wikis_created ON security_wikis(created_at);
                    CREATE INDEX IF NOT EXISTS idx_security_wikis_updated ON security_wikis(updated_at);
                """,
                down_sql="""
                    DROP INDEX IF EXISTS idx_security_wikis_repo;
                    DROP INDEX IF EXISTS idx_security_wikis_created;
                    DROP INDEX IF EXISTS idx_security_wikis_updated;
                    DROP TABLE IF EXISTS security_wikis;
                """
            ),
            
            # Migration 13: User Wiki Collection (Phase 1 MVP)
            Migration(
                version=13,
                description="Add user wiki collection for personal dashboard",
                up_sql="""
                    CREATE TABLE IF NOT EXISTS user_wikis (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        repo_id TEXT NOT NULL,
                        repository_url TEXT NOT NULL,
                        repository_name TEXT NOT NULL,
                        wiki_id TEXT,  -- Reference to security_wikis.id
                        analysis_status TEXT DEFAULT 'pending',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP,
                        metadata TEXT,  -- JSON for additional data
                        FOREIGN KEY (repo_id) REFERENCES repositories (id),
                        FOREIGN KEY (wiki_id) REFERENCES security_wikis (id),
                        UNIQUE(user_id, repository_url)
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_user_wikis_user_id ON user_wikis(user_id);
                    CREATE INDEX IF NOT EXISTS idx_user_wikis_repo_id ON user_wikis(repo_id);
                    CREATE INDEX IF NOT EXISTS idx_user_wikis_status ON user_wikis(analysis_status);
                    CREATE INDEX IF NOT EXISTS idx_user_wikis_created ON user_wikis(created_at);
                """,
                down_sql="""
                    DROP INDEX IF EXISTS idx_user_wikis_user_id;
                    DROP INDEX IF EXISTS idx_user_wikis_repo_id;
                    DROP INDEX IF EXISTS idx_user_wikis_status;
                    DROP INDEX IF EXISTS idx_user_wikis_created;
                    DROP TABLE IF EXISTS user_wikis;
                """
            )
        ]
    
    def get_current_version(self) -> int:
        """Get current database schema version"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT MAX(version) FROM schema_migrations")
                result = cursor.fetchone()
                return result[0] if result and result[0] is not None else 0
        except sqlite3.OperationalError:
            return 0
    
    def get_pending_migrations(self) -> List[Migration]:
        """Get list of pending migrations"""
        current_version = self.get_current_version()
        return [m for m in self.migrations if m.version > current_version]
    
    def apply_migrations(self, target_version: Optional[int] = None) -> Dict[str, Any]:
        """Apply migrations up to target version"""
        result = {
            "started_at": datetime.now().isoformat(),
            "migrations_applied": [],
            "success": True,
            "errors": []
        }
        
        current_version = self.get_current_version()
        target_version = target_version or max(m.version for m in self.migrations)
        
        pending_migrations = [m for m in self.migrations 
                            if current_version < m.version <= target_version]
        
        if not pending_migrations:
            result["message"] = "No migrations to apply"
            result["completed_at"] = datetime.now().isoformat()
            return result
        
        logger.info(f"Applying {len(pending_migrations)} migrations from version {current_version} to {target_version}")
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            
            for migration in pending_migrations:
                migration_start = datetime.now()
                
                try:
                    logger.info(f"Applying migration {migration.version}: {migration.description}")
                    
                    # Record migration start
                    self._record_migration_history(conn, migration, "apply", migration_start)
                    
                    # Apply migration
                    migration.apply(conn)
                    
                    # Record successful migration
                    conn.execute("""
                        INSERT OR REPLACE INTO schema_migrations 
                        (version, description, applied_at, checksum)
                        VALUES (?, ?, ?, ?)
                    """, (
                        migration.version,
                        migration.description,
                        migration_start.isoformat(),
                        migration.get_checksum()
                    ))
                    
                    # Update migration history
                    self._record_migration_history(conn, migration, "apply", 
                                                 migration_start, datetime.now(), True)
                    
                    conn.commit()
                    
                    result["migrations_applied"].append({
                        "version": migration.version,
                        "description": migration.description,
                        "applied_at": migration_start.isoformat()
                    })
                    
                    logger.info(f"Successfully applied migration {migration.version}")
                    
                except Exception as e:
                    error_msg = f"Migration {migration.version} failed: {str(e)}"
                    logger.error(error_msg)
                    
                    # Record failed migration
                    self._record_migration_history(conn, migration, "apply", 
                                                 migration_start, datetime.now(), False, str(e))
                    
                    result["success"] = False
                    result["errors"].append(error_msg)
                    
                    conn.rollback()
                    break
        
        result["completed_at"] = datetime.now().isoformat()
        return result
    
    def rollback_migration(self, target_version: int) -> Dict[str, Any]:
        """Rollback migrations to target version"""
        result = {
            "started_at": datetime.now().isoformat(),
            "migrations_rolled_back": [],
            "success": True,
            "errors": []
        }
        
        current_version = self.get_current_version()
        
        if target_version >= current_version:
            result["message"] = "Target version is not lower than current version"
            result["completed_at"] = datetime.now().isoformat()
            return result
        
        migrations_to_rollback = [m for m in reversed(self.migrations) 
                                if target_version < m.version <= current_version]
        
        logger.info(f"Rolling back {len(migrations_to_rollback)} migrations from version {current_version} to {target_version}")
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            
            for migration in migrations_to_rollback:
                rollback_start = datetime.now()
                
                try:
                    logger.info(f"Rolling back migration {migration.version}: {migration.description}")
                    
                    # Record rollback start
                    self._record_migration_history(conn, migration, "rollback", rollback_start)
                    
                    # Rollback migration
                    migration.rollback(conn)
                    
                    # Remove from schema_migrations
                    conn.execute("DELETE FROM schema_migrations WHERE version = ?", (migration.version,))
                    
                    # Update migration history
                    self._record_migration_history(conn, migration, "rollback", 
                                                 rollback_start, datetime.now(), True)
                    
                    conn.commit()
                    
                    result["migrations_rolled_back"].append({
                        "version": migration.version,
                        "description": migration.description,
                        "rolled_back_at": rollback_start.isoformat()
                    })
                    
                    logger.info(f"Successfully rolled back migration {migration.version}")
                    
                except Exception as e:
                    error_msg = f"Migration {migration.version} rollback failed: {str(e)}"
                    logger.error(error_msg)
                    
                    # Record failed rollback
                    self._record_migration_history(conn, migration, "rollback", 
                                                 rollback_start, datetime.now(), False, str(e))
                    
                    result["success"] = False
                    result["errors"].append(error_msg)
                    
                    conn.rollback()
                    break
        
        result["completed_at"] = datetime.now().isoformat()
        return result
    
    def validate_migrations(self) -> Dict[str, Any]:
        """Validate migration integrity"""
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "migration_count": len(self.migrations),
            "current_version": self.get_current_version()
        }
        
        # Check for version gaps
        versions = [m.version for m in self.migrations]
        for i in range(1, max(versions) + 1):
            if i not in versions:
                validation_result["errors"].append(f"Missing migration version {i}")
                validation_result["valid"] = False
        
        # Check for duplicate versions
        if len(versions) != len(set(versions)):
            validation_result["errors"].append("Duplicate migration versions found")
            validation_result["valid"] = False
        
        # Validate checksums
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT version, checksum FROM schema_migrations")
                applied_migrations = dict(cursor.fetchall())
                
                for migration in self.migrations:
                    if migration.version in applied_migrations:
                        stored_checksum = applied_migrations[migration.version]
                        current_checksum = migration.get_checksum()
                        
                        if stored_checksum != current_checksum:
                            validation_result["warnings"].append(
                                f"Migration {migration.version} checksum mismatch - migration may have been modified"
                            )
        
        except Exception as e:
            validation_result["errors"].append(f"Error validating checksums: {e}")
            validation_result["valid"] = False
        
        return validation_result
    
    def get_migration_status(self) -> Dict[str, Any]:
        """Get comprehensive migration status"""
        current_version = self.get_current_version()
        pending_migrations = self.get_pending_migrations()
        
        status = {
            "current_version": current_version,
            "latest_version": max(m.version for m in self.migrations),
            "pending_migrations": len(pending_migrations),
            "up_to_date": len(pending_migrations) == 0,
            "migrations": []
        }
        
        for migration in self.migrations:
            migration_info = {
                "version": migration.version,
                "description": migration.description,
                "applied": migration.version <= current_version,
                "checksum": migration.get_checksum()
            }
            status["migrations"].append(migration_info)
        
        return status
    
    def create_migration_script(self, output_path: str = "migrate_database.py") -> str:
        """Create a standalone migration script"""
        script_content = '''#!/usr/bin/env python3
"""
Standalone Database Migration Script for Security Wiki Generator

This script can be run independently to migrate the database to the latest schema.
It includes all necessary migration logic and can be used for deployment automation.
"""
import sys
import os
import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path

# Add the api directory to the path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'api'))

try:
    from migrations import MigrationManager
    from config import settings
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Make sure you're running this script from the project root directory.")
    sys.exit(1)

def setup_logging():
    """Setup logging for migration script"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('migration.log')
        ]
    )

def main():
    """Main migration function"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    print("Security Wiki Generator Database Migration")
    print("=" * 50)
    
    try:
        # Initialize migration manager
        manager = MigrationManager()
        
        # Check current status
        status = manager.get_migration_status()
        print(f"Current database version: {status['current_version']}")
        print(f"Latest available version: {status['latest_version']}")
        print(f"Pending migrations: {status['pending_migrations']}")
        
        if status['up_to_date']:
            print("Database is already up to date!")
            return 0
        
        # Validate migrations
        validation = manager.validate_migrations()
        if not validation['valid']:
            print("Migration validation failed:")
            for error in validation['errors']:
                print(f"  ERROR: {error}")
            return 1
        
        if validation['warnings']:
            print("Migration warnings:")
            for warning in validation['warnings']:
                print(f"  WARNING: {warning}")
        
        # Create backup before migration
        print("\\nCreating database backup...")
        backup_info = manager.create_backup()
        if backup_info['success']:
            print(f"Backup created: {backup_info['backup_name']}")
        else:
            print(f"Backup failed: {backup_info['error']}")
            return 1
        
        # Apply migrations
        print("\\nApplying migrations...")
        result = manager.apply_migrations()
        
        if result['success']:
            print(f"Successfully applied {len(result['migrations_applied'])} migrations")
            for migration in result['migrations_applied']:
                print(f"  ✓ Migration {migration['version']}: {migration['description']}")
        else:
            print("Migration failed:")
            for error in result['errors']:
                print(f"  ERROR: {error}")
            return 1
        
        # Final validation
        print("\\nPerforming final validation...")
        final_status = manager.get_migration_status()
        if final_status['up_to_date']:
            print("✓ Database migration completed successfully!")
        else:
            print("⚠ Migration completed but database is not up to date")
            return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"Migration script failed: {e}")
        print(f"Migration failed with error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
'''
        
        with open(output_path, 'w') as f:
            f.write(script_content)
        
        # Make script executable on Unix systems
        try:
            os.chmod(output_path, 0o755)
        except:
            pass  # Windows doesn't support chmod
        
        logger.info(f"Migration script created: {output_path}")
        return output_path
    
    def export_migration_sql(self, output_path: str = "migrations.sql") -> str:
        """Export all migrations as SQL file"""
        with open(output_path, 'w') as f:
            f.write("-- Security Wiki Generator Database Migrations\n")
            f.write(f"-- Generated at: {datetime.now().isoformat()}\n")
            f.write("-- This file contains all database migrations in order\n\n")
            
            for migration in self.migrations:
                f.write(f"-- Migration {migration.version}: {migration.description}\n")
                f.write("-- " + "=" * 60 + "\n")
                
                if migration.up_sql:
                    f.write(migration.up_sql)
                    f.write("\n\n")
                else:
                    f.write("-- This migration uses Python functions and cannot be exported as SQL\n\n")
        
        logger.info(f"Migration SQL exported: {output_path}")
        return output_path
    
    def _record_migration_history(self, conn: sqlite3.Connection, migration: Migration, 
                                operation: str, started_at: datetime, 
                                completed_at: Optional[datetime] = None,
                                success: Optional[bool] = None, 
                                error_message: Optional[str] = None):
        """Record migration operation in history"""
        try:
            conn.execute("""
                INSERT INTO migration_history 
                (migration_version, operation, started_at, completed_at, success, error_message, checksum)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                migration.version,
                operation,
                started_at.isoformat(),
                completed_at.isoformat() if completed_at else None,
                success,
                error_message,
                migration.get_checksum()
            ))
        except sqlite3.OperationalError:
            # migration_history table might not exist yet
            pass
    
    def _migrate_threat_docs_to_security_docs(self, conn: sqlite3.Connection):
        """Migrate legacy threat documents to new security documents format"""
        logger.info("Migrating legacy threat documents to security documents")
        
        try:
            # Check if security_documents table exists
            cursor = conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='security_documents'
            """)
            if not cursor.fetchone():
                logger.warning("security_documents table not found, skipping migration")
                return
            
            # Check if threat_documents table exists and has data
            cursor = conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='threat_documents'
            """)
            if not cursor.fetchone():
                logger.info("threat_documents table not found, no data to migrate")
                return
            
            # Count existing threat documents
            cursor = conn.execute("SELECT COUNT(*) FROM threat_documents")
            threat_doc_count = cursor.fetchone()[0]
            
            if threat_doc_count == 0:
                logger.info("No threat documents to migrate")
                return
            
            logger.info(f"Migrating {threat_doc_count} threat documents to security documents")
            
            # Migrate threat documents to security documents
            cursor = conn.execute("""
                INSERT OR IGNORE INTO security_documents 
                (id, repo_id, title, content, scope, metadata, version, is_current, created_at, updated_at)
                SELECT 
                    id,
                    repo_id,
                    title,
                    content,
                    'full_repo' as scope,  -- Legacy docs are full repo analysis
                    metadata,
                    version,
                    is_current,
                    created_at,
                    updated_at
                FROM threat_documents
                WHERE is_current = 1
            """)
            migrated_docs = cursor.rowcount
            
            # Migrate code references for security documents
            cursor = conn.execute("""
                INSERT OR IGNORE INTO security_document_references
                (id, security_doc_id, file_path, line_start, line_end, function_name, class_name, code_snippet)
                SELECT 
                    cr.id,
                    cr.doc_id as security_doc_id,
                    cr.file_path,
                    cr.line_start,
                    cr.line_end,
                    cr.function_name,
                    cr.class_name,
                    cr.code_snippet
                FROM code_references cr
                INNER JOIN threat_documents td ON cr.doc_id = td.id
                WHERE td.is_current = 1
            """)
            migrated_refs = cursor.rowcount
            
            logger.info(f"Successfully migrated {migrated_docs} documents and {migrated_refs} code references")
            
        except Exception as e:
            logger.error(f"Error during threat documents migration: {e}")
            raise MigrationError(f"Failed to migrate threat documents: {e}")
    
    def _rollback_threat_docs_migration(self, conn: sqlite3.Connection):
        """Rollback threat documents migration"""
        logger.info("Rolling back threat documents migration")
        
        try:
            # Remove migrated security documents (only those that came from threat_documents)
            cursor = conn.execute("""
                DELETE FROM security_documents 
                WHERE id IN (
                    SELECT id FROM threat_documents WHERE is_current = 1
                )
            """)
            removed_docs = cursor.rowcount
            
            # Remove migrated security document references
            cursor = conn.execute("""
                DELETE FROM security_document_references 
                WHERE security_doc_id IN (
                    SELECT id FROM threat_documents WHERE is_current = 1
                )
            """)
            removed_refs = cursor.rowcount
            
            logger.info(f"Rollback removed {removed_docs} security documents and {removed_refs} references")
            
        except Exception as e:
            logger.error(f"Error during migration rollback: {e}")
            raise MigrationError(f"Failed to rollback threat documents migration: {e}")
    
    def _validate_and_cleanup_data(self, conn: sqlite3.Connection):
        """Validate and cleanup data for security documents"""
        logger.info("Validating and cleaning up security document data")
        
        try:
            # Clean up invalid scope values
            cursor = conn.execute("""
                UPDATE security_documents 
                SET scope = 'full_repo' 
                WHERE scope IS NULL OR scope NOT IN ('full_repo', 'pr_only')
            """)
            updated_scopes = cursor.rowcount
            
            # Clean up invalid risk levels in PR analyses
            cursor = conn.execute("""
                UPDATE pr_analyses 
                SET risk_level = 'medium' 
                WHERE risk_level IS NULL OR risk_level NOT IN ('low', 'medium', 'high', 'critical')
            """)
            updated_risks = cursor.rowcount
            
            # Remove orphaned security document references
            cursor = conn.execute("""
                DELETE FROM security_document_references 
                WHERE security_doc_id NOT IN (SELECT id FROM security_documents)
            """)
            removed_orphaned_refs = cursor.rowcount
            
            # Update metadata format for consistency
            cursor = conn.execute("""
                UPDATE security_documents 
                SET metadata = '{}' 
                WHERE metadata IS NULL OR metadata = ''
            """)
            updated_metadata = cursor.rowcount
            
            logger.info(f"Data cleanup: {updated_scopes} scopes, {updated_risks} risk levels, "
                       f"{removed_orphaned_refs} orphaned refs, {updated_metadata} metadata fields")
            
        except Exception as e:
            logger.error(f"Error during data validation and cleanup: {e}")
            raise MigrationError(f"Failed to validate and cleanup data: {e}")
    
    def _rollback_data_cleanup(self, conn: sqlite3.Connection):
        """Rollback data cleanup (no-op since cleanup is beneficial)"""
        logger.info("Data cleanup rollback - no action needed (cleanup is beneficial)")
        pass
        
        # Get all current threat documents
        cursor = conn.execute("""
            SELECT id, repo_id, title, content, doc_type, metadata, created_at, updated_at
            FROM threat_documents 
            WHERE is_current = 1
        """)
        
        threat_docs = cursor.fetchall()
        migrated_count = 0
        
        for doc in threat_docs:
            doc_id, repo_id, title, content, doc_type, metadata, created_at, updated_at = doc
            
            # Create corresponding security document
            security_doc_id = f"sec_{doc_id}"
            
            # Determine scope based on doc_type
            scope = "full_repo"  # Most legacy docs are full repository analysis
            
            # Enhance metadata with migration info
            try:
                metadata_dict = json.loads(metadata) if metadata else {}
            except:
                metadata_dict = {}
            
            metadata_dict.update({
                "migrated_from_threat_doc": True,
                "original_doc_type": doc_type,
                "original_doc_id": doc_id,
                "migration_date": datetime.now().isoformat()
            })
            
            # Insert security document
            conn.execute("""
                INSERT OR IGNORE INTO security_documents
                (id, repo_id, title, content, scope, metadata, version, is_current, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                security_doc_id,
                repo_id,
                title,
                content,
                scope,
                json.dumps(metadata_dict),
                1,
                True,
                created_at,
                updated_at or created_at
            ))
            
            # Migrate code references
            ref_cursor = conn.execute("""
                SELECT id, file_path, line_start, line_end, function_name, class_name, code_snippet
                FROM code_references 
                WHERE doc_id = ?
            """, (doc_id,))
            
            for ref in ref_cursor.fetchall():
                ref_id, file_path, line_start, line_end, function_name, class_name, code_snippet = ref
                
                # Create new reference for security document
                new_ref_id = f"sec_ref_{ref_id}"
                
                conn.execute("""
                    INSERT OR IGNORE INTO security_document_references
                    (id, security_doc_id, file_path, line_start, line_end, function_name, class_name, code_snippet)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    new_ref_id,
                    security_doc_id,
                    file_path,
                    line_start,
                    line_end,
                    function_name,
                    class_name,
                    code_snippet
                ))
            
            migrated_count += 1
        
        logger.info(f"Successfully migrated {migrated_count} threat documents to security documents")
    
    def _rollback_threat_docs_migration(self, conn: sqlite3.Connection):
        """Rollback threat document migration"""
        logger.info("Rolling back threat document migration")
        
        # Remove migrated security documents
        cursor = conn.execute("""
            DELETE FROM security_documents 
            WHERE json_extract(metadata, '$.migrated_from_threat_doc') = 1
        """)
        
        deleted_count = cursor.rowcount
        logger.info(f"Removed {deleted_count} migrated security documents")


def create_migration_manager(db_path: str = None) -> MigrationManager:
    """Create and return a migration manager instance"""
    return MigrationManager(db_path)


def run_migrations(db_path: str = None, target_version: int = None) -> Dict[str, Any]:
    """Convenience function to run migrations"""
    manager = create_migration_manager(db_path)
    return manager.apply_migrations(target_version)


def get_migration_status(db_path: str = None) -> Dict[str, Any]:
    """Convenience function to get migration status"""
    manager = create_migration_manager(db_path)
    return manager.get_migration_status()


def validate_migrations(db_path: str = None) -> Dict[str, Any]:
    """Convenience function to validate migrations"""
    manager = create_migration_manager(db_path)
    return manager.validate_migrations()