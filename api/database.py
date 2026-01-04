"""
Database operations module for SQLite with migrations and integrity management
"""
import sqlite3
import json
import os
import shutil
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from pathlib import Path

from api.config import settings
from api.models import RepoContext, ThreatDoc, CodeReference, SecurityDocument, PRAnalysis
from api.migrations import MigrationManager


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
            """
        },
        {
            "version": 4,
            "description": "Add flexible security documentation and PR analysis support",
            "sql": """
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
            """
        }
    ]
    
    @classmethod
    def get_migration_checksum(cls, migration: Dict[str, Any]) -> str:
        """Calculate checksum for migration"""
        import hashlib
        content = f"{migration['version']}{migration['description']}{migration['sql']}"
        return hashlib.md5(content.encode()).hexdigest()


class DatabaseManager:
    """Enhanced SQLite database manager with migrations and integrity checks"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.database_path
        self.backup_dir = Path(settings.storage_base_path) / "db_backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self.initialize_database()
    
    def initialize_database(self):
        """Initialize database with migrations"""
        logger.info(f"Initializing database at {self.db_path}")
        
        # Ensure database directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Use the new migration manager
        migration_manager = MigrationManager(self.db_path)
        
        # Apply all pending migrations
        result = migration_manager.apply_migrations()
        
        if not result['success']:
            logger.error(f"Database migration failed: {result['errors']}")
            raise Exception(f"Database initialization failed: {result['errors']}")
        
        logger.info(f"Database initialized successfully with {len(result['migrations_applied'])} migrations applied")
        
        # Perform integrity check
        if not self.check_integrity():
            logger.warning("Database integrity check failed after initialization")
    
    def _run_migrations(self):
        """Run database migrations"""
        with sqlite3.connect(self.db_path) as conn:
            # Enable foreign key constraints
            conn.execute("PRAGMA foreign_keys = ON")
            
            # Get current schema version
            current_version = self._get_schema_version(conn)
            logger.info(f"Current database schema version: {current_version}")
            
            # Apply migrations
            for migration in DatabaseMigration.MIGRATIONS:
                if migration["version"] > current_version:
                    logger.info(f"Applying migration {migration['version']}: {migration['description']}")
                    
                    try:
                        # Execute migration SQL
                        conn.executescript(migration["sql"])
                        
                        # Record migration
                        checksum = DatabaseMigration.get_migration_checksum(migration)
                        conn.execute("""
                            INSERT OR REPLACE INTO schema_migrations 
                            (version, description, applied_at, checksum)
                            VALUES (?, ?, ?, ?)
                        """, (
                            migration["version"],
                            migration["description"],
                            datetime.now().isoformat(),
                            checksum
                        ))
                        
                        conn.commit()
                        logger.info(f"Successfully applied migration {migration['version']}")
                        
                    except Exception as e:
                        logger.error(f"Failed to apply migration {migration['version']}: {e}")
                        conn.rollback()
                        raise
    
    def _get_schema_version(self, conn: sqlite3.Connection) -> int:
        """Get current schema version"""
        try:
            cursor = conn.execute("SELECT MAX(version) FROM schema_migrations")
            result = cursor.fetchone()
            return result[0] if result and result[0] is not None else 0
        except sqlite3.OperationalError:
            # Table doesn't exist yet
            return 0
    
    def health_check(self) -> bool:
        """Check database health and connectivity"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT 1")
                result = cursor.fetchone()
                return result is not None and result[0] == 1
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    def check_integrity(self) -> bool:
        """Perform comprehensive database integrity check"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # SQLite integrity check
                cursor = conn.execute("PRAGMA integrity_check")
                integrity_result = cursor.fetchone()
                
                if integrity_result[0] != "ok":
                    logger.error(f"Database integrity check failed: {integrity_result[0]}")
                    return False
                
                # Foreign key check
                cursor = conn.execute("PRAGMA foreign_key_check")
                fk_violations = cursor.fetchall()
                
                if fk_violations:
                    logger.error(f"Foreign key violations found: {fk_violations}")
                    return False
                
                # Check for orphaned records
                orphaned_docs = self._check_orphaned_documents(conn)
                orphaned_refs = self._check_orphaned_references(conn)
                
                if orphaned_docs or orphaned_refs:
                    logger.warning(f"Found {orphaned_docs} orphaned documents and {orphaned_refs} orphaned references")
                
                logger.info("Database integrity check passed")
                return True
                
        except Exception as e:
            logger.error(f"Database integrity check failed: {e}")
            return False
    
    def _check_orphaned_documents(self, conn: sqlite3.Connection) -> int:
        """Check for orphaned threat documents"""
        cursor = conn.execute("""
            SELECT COUNT(*) FROM threat_documents td
            LEFT JOIN repositories r ON td.repo_id = r.id
            WHERE r.id IS NULL
        """)
        return cursor.fetchone()[0]
    
    def _check_orphaned_references(self, conn: sqlite3.Connection) -> int:
        """Check for orphaned code references"""
        cursor = conn.execute("""
            SELECT COUNT(*) FROM code_references cr
            LEFT JOIN threat_documents td ON cr.doc_id = td.id
            WHERE td.id IS NULL
        """)
        return cursor.fetchone()[0]
    
    def repair_database(self) -> Dict[str, Any]:
        """Attempt to repair database issues"""
        repair_result = {
            "started_at": datetime.now().isoformat(),
            "operations": [],
            "success": True,
            "errors": []
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Clean up orphaned documents
                cursor = conn.execute("""
                    DELETE FROM threat_documents 
                    WHERE repo_id NOT IN (SELECT id FROM repositories)
                """)
                orphaned_docs_removed = cursor.rowcount
                
                if orphaned_docs_removed > 0:
                    repair_result["operations"].append(f"Removed {orphaned_docs_removed} orphaned documents")
                
                # Clean up orphaned code references
                cursor = conn.execute("""
                    DELETE FROM code_references 
                    WHERE doc_id NOT IN (SELECT id FROM threat_documents)
                """)
                orphaned_refs_removed = cursor.rowcount
                
                if orphaned_refs_removed > 0:
                    repair_result["operations"].append(f"Removed {orphaned_refs_removed} orphaned code references")
                
                # Vacuum database to reclaim space
                conn.execute("VACUUM")
                repair_result["operations"].append("Database vacuumed")
                
                # Analyze tables for query optimization
                conn.execute("ANALYZE")
                repair_result["operations"].append("Database statistics updated")
                
                conn.commit()
                
        except Exception as e:
            repair_result["success"] = False
            repair_result["errors"].append(str(e))
            logger.error(f"Database repair failed: {e}")
        
        repair_result["completed_at"] = datetime.now().isoformat()
        return repair_result
    
    def create_backup(self, backup_name: Optional[str] = None) -> Dict[str, Any]:
        """Create database backup"""
        if backup_name is None:
            backup_name = f"db_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        
        backup_path = self.backup_dir / backup_name
        
        backup_info = {
            "backup_name": backup_name,
            "backup_path": str(backup_path),
            "created_at": datetime.now().isoformat(),
            "success": True,
            "error": None,
            "size_bytes": 0
        }
        
        try:
            # Create backup using SQLite backup API
            with sqlite3.connect(self.db_path) as source_conn:
                with sqlite3.connect(backup_path) as backup_conn:
                    source_conn.backup(backup_conn)
            
            # Get backup file size
            backup_info["size_bytes"] = backup_path.stat().st_size
            backup_info["size_mb"] = backup_info["size_bytes"] / 1024 / 1024
            
            logger.info(f"Database backup created: {backup_path} ({backup_info['size_mb']:.1f}MB)")
            
        except Exception as e:
            backup_info["success"] = False
            backup_info["error"] = str(e)
            logger.error(f"Database backup failed: {e}")
        
        return backup_info
    
    def restore_backup(self, backup_name: str) -> Dict[str, Any]:
        """Restore database from backup"""
        backup_path = self.backup_dir / backup_name
        
        if not backup_path.exists():
            raise ValueError(f"Backup file not found: {backup_name}")
        
        restore_info = {
            "backup_name": backup_name,
            "restored_at": datetime.now().isoformat(),
            "success": True,
            "error": None
        }
        
        try:
            # Create backup of current database
            current_backup = self.create_backup(f"pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
            
            # Close any existing connections
            self.close()
            
            # Replace current database with backup
            shutil.copy2(backup_path, self.db_path)
            
            # Verify restored database
            if not self.health_check():
                raise Exception("Restored database failed health check")
            
            logger.info(f"Database restored from backup: {backup_name}")
            
        except Exception as e:
            restore_info["success"] = False
            restore_info["error"] = str(e)
            logger.error(f"Database restore failed: {e}")
        
        return restore_info
    
    def export_data(self, export_path: str, format: str = "json") -> Dict[str, Any]:
        """Export database data to file"""
        export_info = {
            "export_path": export_path,
            "format": format,
            "exported_at": datetime.now().isoformat(),
            "success": True,
            "error": None,
            "records_exported": 0
        }
        
        try:
            if format.lower() == "json":
                export_info.update(self._export_to_json(export_path))
            elif format.lower() == "sql":
                export_info.update(self._export_to_sql(export_path))
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
        except Exception as e:
            export_info["success"] = False
            export_info["error"] = str(e)
            logger.error(f"Data export failed: {e}")
        
        return export_info
    
    def _export_to_json(self, export_path: str) -> Dict[str, Any]:
        """Export data to JSON format"""
        export_data = {
            "exported_at": datetime.now().isoformat(),
            "schema_version": self._get_schema_version(sqlite3.connect(self.db_path)),
            "repositories": [],
            "threat_documents": [],
            "code_references": []
        }
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Export repositories
            cursor = conn.execute("SELECT * FROM repositories")
            for row in cursor:
                export_data["repositories"].append(dict(row))
            
            # Export threat documents
            cursor = conn.execute("SELECT * FROM threat_documents WHERE is_current = 1")
            for row in cursor:
                export_data["threat_documents"].append(dict(row))
            
            # Export code references
            cursor = conn.execute("SELECT * FROM code_references")
            for row in cursor:
                export_data["code_references"].append(dict(row))
        
        # Write to file
        with open(export_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        total_records = (len(export_data["repositories"]) + 
                        len(export_data["threat_documents"]) + 
                        len(export_data["code_references"]))
        
        return {"records_exported": total_records}
    
    def _export_to_sql(self, export_path: str) -> Dict[str, Any]:
        """Export data to SQL format"""
        with sqlite3.connect(self.db_path) as conn:
            with open(export_path, 'w') as f:
                # Write schema
                f.write("-- Database Schema Export\n")
                f.write(f"-- Exported at: {datetime.now().isoformat()}\n\n")
                
                # Get schema
                cursor = conn.execute("SELECT sql FROM sqlite_master WHERE type='table'")
                for row in cursor:
                    if row[0]:
                        f.write(f"{row[0]};\n\n")
                
                # Export data
                f.write("-- Data Export\n\n")
                
                for line in conn.iterdump():
                    if line.startswith('INSERT'):
                        f.write(f"{line}\n")
        
        # Count records
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    (SELECT COUNT(*) FROM repositories) +
                    (SELECT COUNT(*) FROM threat_documents) +
                    (SELECT COUNT(*) FROM code_references) as total
            """)
            total_records = cursor.fetchone()[0]
        
        return {"records_exported": total_records}
    
    def import_data(self, import_path: str, format: str = "json") -> Dict[str, Any]:
        """Import data from file"""
        import_info = {
            "import_path": import_path,
            "format": format,
            "imported_at": datetime.now().isoformat(),
            "success": True,
            "error": None,
            "records_imported": 0
        }
        
        try:
            if format.lower() == "json":
                import_info.update(self._import_from_json(import_path))
            elif format.lower() == "sql":
                import_info.update(self._import_from_sql(import_path))
            else:
                raise ValueError(f"Unsupported import format: {format}")
            
        except Exception as e:
            import_info["success"] = False
            import_info["error"] = str(e)
            logger.error(f"Data import failed: {e}")
        
        return import_info
    
    def _import_from_json(self, import_path: str) -> Dict[str, Any]:
        """Import data from JSON format"""
        with open(import_path, 'r') as f:
            import_data = json.load(f)
        
        records_imported = 0
        
        with sqlite3.connect(self.db_path) as conn:
            # Import repositories
            for repo in import_data.get("repositories", []):
                conn.execute("""
                    INSERT OR REPLACE INTO repositories 
                    (id, url, local_path, primary_languages, structure_summary, 
                     analysis_status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    repo["id"], repo["url"], repo["local_path"],
                    repo["primary_languages"], repo["structure_summary"],
                    repo["analysis_status"], repo["created_at"], repo["updated_at"]
                ))
                records_imported += 1
            
            # Import threat documents
            for doc in import_data.get("threat_documents", []):
                conn.execute("""
                    INSERT OR REPLACE INTO threat_documents
                    (id, repo_id, doc_type, title, content, metadata, version, 
                     is_current, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    doc["id"], doc["repo_id"], doc["doc_type"], doc["title"],
                    doc["content"], doc["metadata"], doc["version"],
                    doc["is_current"], doc["created_at"], doc["updated_at"]
                ))
                records_imported += 1
            
            # Import code references
            for ref in import_data.get("code_references", []):
                conn.execute("""
                    INSERT OR REPLACE INTO code_references
                    (id, doc_id, file_path, line_start, line_end, 
                     function_name, class_name, code_snippet)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ref["id"], ref["doc_id"], ref["file_path"],
                    ref["line_start"], ref["line_end"], ref["function_name"],
                    ref["class_name"], ref["code_snippet"]
                ))
                records_imported += 1
            
            conn.commit()
        
        return {"records_imported": records_imported}
    
    def _import_from_sql(self, import_path: str) -> Dict[str, Any]:
        """Import data from SQL format"""
        with open(import_path, 'r') as f:
            sql_content = f.read()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(sql_content)
            conn.commit()
        
        # Count imported records
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    (SELECT COUNT(*) FROM repositories) +
                    (SELECT COUNT(*) FROM threat_documents) +
                    (SELECT COUNT(*) FROM code_references) as total
            """)
            total_records = cursor.fetchone()[0]
        
        return {"records_imported": total_records}
    
    def get_database_statistics(self) -> Dict[str, Any]:
        """Get comprehensive database statistics"""
        stats = {
            "timestamp": datetime.now().isoformat(),
            "database_path": self.db_path,
            "file_size_bytes": 0,
            "file_size_mb": 0,
            "schema_version": 0,
            "table_stats": {},
            "index_stats": {},
            "integrity_status": "unknown"
        }
        
        try:
            # File size
            if os.path.exists(self.db_path):
                stats["file_size_bytes"] = os.path.getsize(self.db_path)
                stats["file_size_mb"] = stats["file_size_bytes"] / 1024 / 1024
            
            with sqlite3.connect(self.db_path) as conn:
                # Schema version
                stats["schema_version"] = self._get_schema_version(conn)
                
                # Table statistics
                tables = ["repositories", "threat_documents", "code_references", "analysis_sessions"]
                for table in tables:
                    try:
                        cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                        count = cursor.fetchone()[0]
                        stats["table_stats"][table] = {"row_count": count}
                    except sqlite3.OperationalError:
                        stats["table_stats"][table] = {"row_count": 0, "error": "Table not found"}
                
                # Index information
                cursor = conn.execute("SELECT name, tbl_name FROM sqlite_master WHERE type='index'")
                for name, table in cursor.fetchall():
                    if not name.startswith("sqlite_"):  # Skip system indexes
                        stats["index_stats"][name] = {"table": table}
                
                # Integrity check
                stats["integrity_status"] = "ok" if self.check_integrity() else "failed"
        
        except Exception as e:
            stats["error"] = str(e)
            logger.error(f"Failed to get database statistics: {e}")
        
        return stats
    
    def save_security_document(self, security_doc: SecurityDocument) -> bool:
        """Save security document to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Mark previous versions as not current
                conn.execute("""
                    UPDATE security_documents 
                    SET is_current = FALSE 
                    WHERE repo_id = ? AND title = ? AND is_current = TRUE
                """, (security_doc.repo_id, security_doc.title))
                
                # Insert new security document
                conn.execute("""
                    INSERT OR REPLACE INTO security_documents 
                    (id, repo_id, title, content, scope, metadata, version, is_current, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    security_doc.id,
                    security_doc.repo_id,
                    security_doc.title,
                    security_doc.content,
                    security_doc.scope,
                    json.dumps(security_doc.metadata),
                    1,  # version
                    True,  # is_current
                    security_doc.created_at.isoformat(),
                    security_doc.updated_at.isoformat() if security_doc.updated_at else None
                ))
                
                # Save code references
                for ref in security_doc.code_references:
                    conn.execute("""
                        INSERT OR REPLACE INTO security_document_references
                        (id, security_doc_id, file_path, line_start, line_end, function_name, class_name, code_snippet)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ref.id,
                        security_doc.id,
                        ref.file_path,
                        ref.line_start,
                        ref.line_end,
                        ref.function_name,
                        ref.class_name,
                        ref.code_snippet
                    ))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error saving security document: {e}")
            return False
    
    def get_security_document(self, doc_id: str) -> Optional[SecurityDocument]:
        """Get security document by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT id, repo_id, title, content, scope, metadata, created_at, updated_at
                    FROM security_documents 
                    WHERE id = ? AND is_current = TRUE
                """, (doc_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Get code references
                ref_cursor = conn.execute("""
                    SELECT id, file_path, line_start, line_end, function_name, class_name, code_snippet
                    FROM security_document_references
                    WHERE security_doc_id = ?
                """, (doc_id,))
                
                code_references = []
                for ref_row in ref_cursor:
                    code_references.append(CodeReference(
                        id=ref_row[0],
                        file_path=ref_row[1],
                        line_start=ref_row[2],
                        line_end=ref_row[3],
                        function_name=ref_row[4],
                        class_name=ref_row[5],
                        code_snippet=ref_row[6]
                    ))
                
                return SecurityDocument(
                    id=row[0],
                    repo_id=row[1],
                    title=row[2],
                    content=row[3],
                    scope=row[4],
                    metadata=json.loads(row[5]) if row[5] else {},
                    code_references=code_references,
                    created_at=datetime.fromisoformat(row[6]),
                    updated_at=datetime.fromisoformat(row[7]) if row[7] else None
                )
        except Exception as e:
            logger.error(f"Error getting security document: {e}")
            return None
    
    def get_security_documents_by_repo(self, repo_id: str, scope: Optional[str] = None) -> List[SecurityDocument]:
        """Get all security documents for a repository"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                query = """
                    SELECT id, repo_id, title, content, scope, metadata, created_at, updated_at
                    FROM security_documents 
                    WHERE repo_id = ? AND is_current = TRUE
                """
                params = [repo_id]
                
                if scope:
                    query += " AND scope = ?"
                    params.append(scope)
                
                cursor = conn.execute(query, params)
                documents = []
                
                for row in cursor:
                    # Get code references for this document
                    ref_cursor = conn.execute("""
                        SELECT id, file_path, line_start, line_end, function_name, class_name, code_snippet
                        FROM security_document_references
                        WHERE security_doc_id = ?
                    """, (row[0],))
                    
                    code_references = []
                    for ref_row in ref_cursor:
                        code_references.append(CodeReference(
                            id=ref_row[0],
                            file_path=ref_row[1],
                            line_start=ref_row[2],
                            line_end=ref_row[3],
                            function_name=ref_row[4],
                            class_name=ref_row[5],
                            code_snippet=ref_row[6]
                        ))
                    
                    documents.append(SecurityDocument(
                        id=row[0],
                        repo_id=row[1],
                        title=row[2],
                        content=row[3],
                        scope=row[4],
                        metadata=json.loads(row[5]) if row[5] else {},
                        code_references=code_references,
                        created_at=datetime.fromisoformat(row[6]),
                        updated_at=datetime.fromisoformat(row[7]) if row[7] else None
                    ))
                
                return documents
        except Exception as e:
            logger.error(f"Error getting security documents by repo: {e}")
            return []
    
    def save_pr_analysis(self, pr_analysis: PRAnalysis) -> bool:
        """Save PR analysis to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO pr_analyses 
                    (id, pr_id, repo_id, pr_url, changed_files, security_issues, 
                     recommendations, risk_level, has_repo_context, context_used, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    pr_analysis.id,
                    pr_analysis.pr_id,
                    pr_analysis.repo_id,
                    pr_analysis.pr_url,
                    json.dumps(pr_analysis.changed_files),
                    json.dumps(pr_analysis.security_issues),
                    json.dumps(pr_analysis.recommendations),
                    pr_analysis.risk_level,
                    pr_analysis.has_repo_context,
                    json.dumps(pr_analysis.context_used),
                    pr_analysis.created_at.isoformat()
                ))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error saving PR analysis: {e}")
            return False
    
    def get_pr_analysis(self, pr_id: str) -> Optional[PRAnalysis]:
        """Get PR analysis by PR ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT id, pr_id, repo_id, pr_url, changed_files, security_issues,
                           recommendations, risk_level, has_repo_context, context_used, created_at
                    FROM pr_analyses 
                    WHERE pr_id = ?
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (pr_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                return PRAnalysis(
                    id=row[0],
                    pr_id=row[1],
                    repo_id=row[2],
                    pr_url=row[3],
                    changed_files=json.loads(row[4]) if row[4] else [],
                    security_issues=json.loads(row[5]) if row[5] else [],
                    recommendations=json.loads(row[6]) if row[6] else [],
                    risk_level=row[7],
                    has_repo_context=bool(row[8]),
                    context_used=json.loads(row[9]) if row[9] else {},
                    created_at=datetime.fromisoformat(row[10])
                )
        except Exception as e:
            logger.error(f"Error getting PR analysis: {e}")
            return None
    
    def get_pr_analyses_by_repo(self, repo_id: str) -> List[PRAnalysis]:
        """Get all PR analyses for a repository"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT id, pr_id, repo_id, pr_url, changed_files, security_issues,
                           recommendations, risk_level, has_repo_context, context_used, created_at
                    FROM pr_analyses 
                    WHERE repo_id = ?
                    ORDER BY created_at DESC
                """, (repo_id,))
                
                analyses = []
                for row in cursor:
                    analyses.append(PRAnalysis(
                        id=row[0],
                        pr_id=row[1],
                        repo_id=row[2],
                        pr_url=row[3],
                        changed_files=json.loads(row[4]) if row[4] else [],
                        security_issues=json.loads(row[5]) if row[5] else [],
                        recommendations=json.loads(row[6]) if row[6] else [],
                        risk_level=row[7],
                        has_repo_context=bool(row[8]),
                        context_used=json.loads(row[9]) if row[9] else {},
                        created_at=datetime.fromisoformat(row[10])
                    ))
                
                return analyses
        except Exception as e:
            logger.error(f"Error getting PR analyses by repo: {e}")
            return []
    
    def close(self):
        """Close database connections (placeholder for cleanup)"""
        # SQLite connections are closed automatically with context managers
        # This method is here for interface consistency
        pass
    
    def save_repo_context(self, repo_context: RepoContext) -> bool:
        """Save repository context to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO repositories 
                    (id, url, local_path, primary_languages, structure_summary, 
                     analysis_status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    repo_context.repo_id,
                    repo_context.repo_url,
                    repo_context.local_path,
                    json.dumps(repo_context.primary_languages),
                    json.dumps(repo_context.structure_summary),
                    repo_context.analysis_status,
                    repo_context.created_at.isoformat(),
                    datetime.now().isoformat()
                ))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error saving repo context: {e}")
            return False
    
    def get_repo_context(self, repo_id: str) -> Optional[RepoContext]:
        """Get repository context by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT id, url, local_path, primary_languages, structure_summary,
                           analysis_status, created_at
                    FROM repositories WHERE id = ?
                """, (repo_id,))
                
                row = cursor.fetchone()
                if row:
                    return RepoContext(
                        repo_id=row[0],
                        repo_url=row[1],
                        local_path=row[2],
                        primary_languages=json.loads(row[3]) if row[3] else [],
                        structure_summary=json.loads(row[4]) if row[4] else {},
                        analysis_status=row[5],
                        created_at=datetime.fromisoformat(row[6])
                    )
        except Exception as e:
            print(f"Error getting repo context: {e}")
        return None
    
    def save_threat_doc(self, threat_doc: ThreatDoc) -> bool:
        """Save threat document to database with versioning support"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Check if document already exists
                cursor = conn.execute("""
                    SELECT version FROM threat_documents 
                    WHERE id = ? AND is_current = TRUE
                """, (threat_doc.id,))
                
                existing_version = cursor.fetchone()
                version = 1 if not existing_version else existing_version[0] + 1
                
                # If updating existing document, mark old version as not current
                if existing_version:
                    conn.execute("""
                        UPDATE threat_documents 
                        SET is_current = FALSE 
                        WHERE id = ? AND is_current = TRUE
                    """, (threat_doc.id,))
                
                # Insert new version
                conn.execute("""
                    INSERT INTO threat_documents
                    (id, repo_id, doc_type, title, content, metadata, version, 
                     is_current, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    threat_doc.id,
                    threat_doc.repo_id,
                    threat_doc.doc_type.value,
                    threat_doc.title,
                    threat_doc.content,
                    json.dumps(threat_doc.metadata),
                    version,
                    True,
                    threat_doc.created_at.isoformat(),
                    (threat_doc.updated_at or datetime.now()).isoformat()
                ))
                
                # Delete old code references for this document
                conn.execute("DELETE FROM code_references WHERE doc_id = ?", (threat_doc.id,))
                
                # Save new code references
                for ref in threat_doc.code_references:
                    conn.execute("""
                        INSERT INTO code_references
                        (id, doc_id, file_path, line_start, line_end, 
                         function_name, class_name, code_snippet)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ref.id,
                        threat_doc.id,
                        ref.file_path,
                        ref.line_start,
                        ref.line_end,
                        ref.function_name,
                        ref.class_name,
                        ref.code_snippet
                    ))
                
                conn.commit()
                return True
        except Exception as e:
            print(f"Error saving threat document: {e}")
            return False
    
    def save_security_document(self, security_doc: SecurityDocument) -> bool:
        """Save security document to database with versioning support"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Check if document already exists
                cursor = conn.execute("""
                    SELECT version FROM security_documents 
                    WHERE id = ? AND is_current = TRUE
                """, (security_doc.id,))
                
                existing_version = cursor.fetchone()
                version = 1 if not existing_version else existing_version[0] + 1
                
                # If updating existing document, mark old version as not current
                if existing_version:
                    conn.execute("""
                        UPDATE security_documents 
                        SET is_current = FALSE 
                        WHERE id = ? AND is_current = TRUE
                    """, (security_doc.id,))
                
                # Insert new version
                conn.execute("""
                    INSERT INTO security_documents
                    (id, repo_id, title, content, scope, metadata, version, 
                     is_current, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    security_doc.id,
                    security_doc.repo_id,
                    security_doc.title,
                    security_doc.content,
                    security_doc.scope,
                    json.dumps(security_doc.metadata),
                    version,
                    True,
                    security_doc.created_at.isoformat(),
                    (security_doc.updated_at or datetime.now()).isoformat()
                ))
                
                # Delete old code references for this document
                conn.execute("DELETE FROM code_references WHERE doc_id = ?", (security_doc.id,))
                
                # Save new code references
                for ref in security_doc.code_references:
                    conn.execute("""
                        INSERT INTO code_references
                        (id, doc_id, file_path, line_start, line_end, 
                         function_name, class_name, code_snippet)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ref.id,
                        security_doc.id,
                        ref.file_path,
                        ref.line_start,
                        ref.line_end,
                        ref.function_name,
                        ref.class_name,
                        ref.code_snippet
                    ))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error saving security document: {e}")
            return False
    
    def get_threat_docs_by_repo(self, repo_id: str, include_all_versions: bool = False) -> List[ThreatDoc]:
        """Get threat documents for a repository (current versions by default)"""
        docs = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                query = """
                    SELECT id, repo_id, doc_type, title, content, metadata, 
                           version, created_at, updated_at
                    FROM threat_documents WHERE repo_id = ?
                """
                params = [repo_id]
                
                if not include_all_versions:
                    query += " AND is_current = TRUE"
                
                query += " ORDER BY created_at DESC"
                
                cursor = conn.execute(query, params)
                
                for row in cursor.fetchall():
                    # Get code references for this document
                    ref_cursor = conn.execute("""
                        SELECT id, file_path, line_start, line_end, 
                               function_name, class_name, code_snippet
                        FROM code_references WHERE doc_id = ?
                    """, (row[0],))
                    
                    code_refs = [
                        CodeReference(
                            id=ref_row[0],
                            file_path=ref_row[1],
                            line_start=ref_row[2],
                            line_end=ref_row[3],
                            function_name=ref_row[4],
                            class_name=ref_row[5],
                            code_snippet=ref_row[6]
                        )
                        for ref_row in ref_cursor.fetchall()
                    ]
                    
                    # Add version info to metadata
                    metadata = json.loads(row[5]) if row[5] else {}
                    metadata['version'] = row[6]
                    
                    docs.append(ThreatDoc(
                        id=row[0],
                        repo_id=row[1],
                        doc_type=row[2],
                        title=row[3],
                        content=row[4],
                        metadata=metadata,
                        code_references=code_refs,
                        created_at=datetime.fromisoformat(row[7]),
                        updated_at=datetime.fromisoformat(row[8]) if row[8] else None
                    ))
        except Exception as e:
            print(f"Error getting threat documents: {e}")
        
        return docs
    
    def get_threat_doc_by_id(self, doc_id: str, version: Optional[int] = None) -> Optional[ThreatDoc]:
        """Get a specific threat document by ID and optionally by version"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                query = """
                    SELECT id, repo_id, doc_type, title, content, metadata, 
                           version, created_at, updated_at
                    FROM threat_documents WHERE id = ?
                """
                params = [doc_id]
                
                if version:
                    query += " AND version = ?"
                    params.append(version)
                else:
                    query += " AND is_current = TRUE"
                
                cursor = conn.execute(query, params)
                row = cursor.fetchone()
                
                if row:
                    # Get code references
                    ref_cursor = conn.execute("""
                        SELECT id, file_path, line_start, line_end, 
                               function_name, class_name, code_snippet
                        FROM code_references WHERE doc_id = ?
                    """, (row[0],))
                    
                    code_refs = [
                        CodeReference(
                            id=ref_row[0],
                            file_path=ref_row[1],
                            line_start=ref_row[2],
                            line_end=ref_row[3],
                            function_name=ref_row[4],
                            class_name=ref_row[5],
                            code_snippet=ref_row[6]
                        )
                        for ref_row in ref_cursor.fetchall()
                    ]
                    
                    # Add version info to metadata
                    metadata = json.loads(row[5]) if row[5] else {}
                    metadata['version'] = row[6]
                    
                    return ThreatDoc(
                        id=row[0],
                        repo_id=row[1],
                        doc_type=row[2],
                        title=row[3],
                        content=row[4],
                        metadata=metadata,
                        code_references=code_refs,
                        created_at=datetime.fromisoformat(row[7]),
                        updated_at=datetime.fromisoformat(row[8]) if row[8] else None
                    )
        except Exception as e:
            print(f"Error getting threat document: {e}")
        
        return None
    
    def get_document_versions(self, doc_id: str) -> List[Dict[str, Any]]:
        """Get all versions of a document with metadata"""
        versions = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT version, title, is_current, created_at, updated_at
                    FROM threat_documents 
                    WHERE id = ? 
                    ORDER BY version DESC
                """, (doc_id,))
                
                for row in cursor.fetchall():
                    versions.append({
                        'version': row[0],
                        'title': row[1],
                        'is_current': bool(row[2]),
                        'created_at': row[3],
                        'updated_at': row[4]
                    })
        except Exception as e:
            print(f"Error getting document versions: {e}")
        
        return versions
    
    def get_documents_by_type(self, repo_id: str, doc_type: str) -> List[ThreatDoc]:
        """Get documents by type for a repository"""
        docs = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT id, repo_id, doc_type, title, content, metadata, 
                           version, created_at, updated_at
                    FROM threat_documents 
                    WHERE repo_id = ? AND doc_type = ? AND is_current = TRUE
                    ORDER BY created_at DESC
                """, (repo_id, doc_type))
                
                for row in cursor.fetchall():
                    # Get code references
                    ref_cursor = conn.execute("""
                        SELECT id, file_path, line_start, line_end, 
                               function_name, class_name, code_snippet
                        FROM code_references WHERE doc_id = ?
                    """, (row[0],))
                    
                    code_refs = [
                        CodeReference(
                            id=ref_row[0],
                            file_path=ref_row[1],
                            line_start=ref_row[2],
                            line_end=ref_row[3],
                            function_name=ref_row[4],
                            class_name=ref_row[5],
                            code_snippet=ref_row[6]
                        )
                        for ref_row in ref_cursor.fetchall()
                    ]
                    
                    # Add version info to metadata
                    metadata = json.loads(row[5]) if row[5] else {}
                    metadata['version'] = row[6]
                    
                    docs.append(ThreatDoc(
                        id=row[0],
                        repo_id=row[1],
                        doc_type=row[2],
                        title=row[3],
                        content=row[4],
                        metadata=metadata,
                        code_references=code_refs,
                        created_at=datetime.fromisoformat(row[7]),
                        updated_at=datetime.fromisoformat(row[8]) if row[8] else None
                    ))
        except Exception as e:
            print(f"Error getting documents by type: {e}")
        
        return docs
    
    def update_repo_analysis_status(self, repo_id: str, status: str) -> bool:
        """Update repository analysis status"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE repositories 
                    SET analysis_status = ?, updated_at = ?
                    WHERE id = ?
                """, (status, datetime.now().isoformat(), repo_id))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error updating repo status: {e}")
            return False
    
    def get_repo_statistics(self, repo_id: str) -> Dict[str, Any]:
        """Get statistics for a repository"""
        stats = {}
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Count documents by type
                cursor = conn.execute("""
                    SELECT doc_type, COUNT(*) 
                    FROM threat_documents 
                    WHERE repo_id = ? AND is_current = TRUE
                    GROUP BY doc_type
                """, (repo_id,))
                
                doc_counts = dict(cursor.fetchall())
                
                # Get total code references
                cursor = conn.execute("""
                    SELECT COUNT(DISTINCT cr.id)
                    FROM code_references cr
                    JOIN threat_documents td ON cr.doc_id = td.id
                    WHERE td.repo_id = ? AND td.is_current = TRUE
                """, (repo_id,))
                
                code_ref_count = cursor.fetchone()[0]
                
                # Get last update time
                cursor = conn.execute("""
                    SELECT MAX(updated_at)
                    FROM threat_documents
                    WHERE repo_id = ? AND is_current = TRUE
                """, (repo_id,))
                
                last_updated = cursor.fetchone()[0]
                
                stats = {
                    'document_counts': doc_counts,
                    'total_documents': sum(doc_counts.values()),
                    'code_references': code_ref_count,
                    'last_updated': last_updated
                }
                
        except Exception as e:
            print(f"Error getting repo statistics: {e}")
        
        return stats
    
    def cleanup_old_versions(self, repo_id: str, keep_versions: int = 5) -> bool:
        """Clean up old document versions, keeping only the specified number"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get documents with more than keep_versions versions
                cursor = conn.execute("""
                    SELECT id, COUNT(*) as version_count
                    FROM threat_documents 
                    WHERE repo_id = ?
                    GROUP BY id
                    HAVING version_count > ?
                """, (repo_id, keep_versions))
                
                for doc_id, version_count in cursor.fetchall():
                    # Delete oldest versions, keeping the most recent ones
                    conn.execute("""
                        DELETE FROM threat_documents 
                        WHERE id = ? AND version NOT IN (
                            SELECT version FROM threat_documents 
                            WHERE id = ? 
                            ORDER BY version DESC 
                            LIMIT ?
                        )
                    """, (doc_id, doc_id, keep_versions))
                
                conn.commit()
                return True
        except Exception as e:
            print(f"Error cleaning up old versions: {e}")
            return False
    
    def save_security_document(self, security_doc: SecurityDocument) -> bool:
        """Save security document to database with versioning support"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Check if document already exists
                cursor = conn.execute("""
                    SELECT version FROM security_documents 
                    WHERE id = ? AND is_current = TRUE
                """, (security_doc.id,))
                
                existing_version = cursor.fetchone()
                version = 1 if not existing_version else existing_version[0] + 1
                
                # If updating existing document, mark old version as not current
                if existing_version:
                    conn.execute("""
                        UPDATE security_documents 
                        SET is_current = FALSE 
                        WHERE id = ? AND is_current = TRUE
                    """, (security_doc.id,))
                
                # Insert new version
                conn.execute("""
                    INSERT INTO security_documents
                    (id, repo_id, title, content, scope, metadata, version, 
                     is_current, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    security_doc.id,
                    security_doc.repo_id,
                    security_doc.title,
                    security_doc.content,
                    security_doc.scope,
                    json.dumps(security_doc.metadata),
                    version,
                    True,
                    security_doc.created_at.isoformat(),
                    security_doc.updated_at.isoformat() if security_doc.updated_at else None
                ))
                
                # Save code references
                for ref in security_doc.code_references:
                    conn.execute("""
                        INSERT OR REPLACE INTO code_references
                        (id, doc_id, file_path, line_start, line_end, 
                         function_name, class_name, code_snippet)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ref.id, security_doc.id, ref.file_path,
                        ref.line_start, ref.line_end, ref.function_name,
                        ref.class_name, ref.code_snippet
                    ))
                
                conn.commit()
                return True
        except Exception as e:
            print(f"Error saving security document: {e}")
            return False
    
    def get_security_document(self, doc_id: str) -> Optional[SecurityDocument]:
        """Get security document by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT id, repo_id, title, content, scope, metadata, created_at, updated_at
                    FROM security_documents 
                    WHERE id = ? AND is_current = TRUE
                """, (doc_id,))
                
                row = cursor.fetchone()
                if row:
                    # Get code references
                    ref_cursor = conn.execute("""
                        SELECT id, file_path, line_start, line_end, 
                               function_name, class_name, code_snippet
                        FROM code_references WHERE doc_id = ?
                    """, (doc_id,))
                    
                    code_refs = []
                    for ref_row in ref_cursor.fetchall():
                        code_refs.append(CodeReference(
                            id=ref_row[0],
                            file_path=ref_row[1],
                            line_start=ref_row[2],
                            line_end=ref_row[3],
                            function_name=ref_row[4],
                            class_name=ref_row[5],
                            code_snippet=ref_row[6]
                        ))
                    
                    return SecurityDocument(
                        id=row[0],
                        repo_id=row[1],
                        title=row[2],
                        content=row[3],
                        scope=row[4],
                        metadata=json.loads(row[5]) if row[5] else {},
                        code_references=code_refs,
                        created_at=datetime.fromisoformat(row[6]),
                        updated_at=datetime.fromisoformat(row[7]) if row[7] else None
                    )
        except Exception as e:
            print(f"Error getting security document: {e}")
        return None
    
    def get_security_documents_by_repo(self, repo_id: str, scope: Optional[str] = None) -> List[SecurityDocument]:
        """Get all security documents for a repository, optionally filtered by scope"""
        documents = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                query = """
                    SELECT id, repo_id, title, content, scope, metadata, created_at, updated_at
                    FROM security_documents 
                    WHERE repo_id = ? AND is_current = TRUE
                """
                params = [repo_id]
                
                if scope:
                    query += " AND scope = ?"
                    params.append(scope)
                
                query += " ORDER BY created_at DESC"
                
                cursor = conn.execute(query, params)
                
                for row in cursor.fetchall():
                    # Get code references for each document
                    ref_cursor = conn.execute("""
                        SELECT id, file_path, line_start, line_end, 
                               function_name, class_name, code_snippet
                        FROM code_references WHERE doc_id = ?
                    """, (row[0],))
                    
                    code_refs = []
                    for ref_row in ref_cursor.fetchall():
                        code_refs.append(CodeReference(
                            id=ref_row[0],
                            file_path=ref_row[1],
                            line_start=ref_row[2],
                            line_end=ref_row[3],
                            function_name=ref_row[4],
                            class_name=ref_row[5],
                            code_snippet=ref_row[6]
                        ))
                    
                    documents.append(SecurityDocument(
                        id=row[0],
                        repo_id=row[1],
                        title=row[2],
                        content=row[3],
                        scope=row[4],
                        metadata=json.loads(row[5]) if row[5] else {},
                        code_references=code_refs,
                        created_at=datetime.fromisoformat(row[6]),
                        updated_at=datetime.fromisoformat(row[7]) if row[7] else None
                    ))
        except Exception as e:
            print(f"Error getting security documents: {e}")
        return documents
    
    def save_pr_analysis(self, pr_analysis: PRAnalysis) -> bool:
        """Save PR analysis to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO pr_analyses
                    (id, pr_id, repo_id, pr_url, changed_files, security_issues, 
                     recommendations, risk_level, has_repo_context, context_used, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    pr_analysis.id,
                    pr_analysis.pr_id,
                    pr_analysis.repo_id,
                    pr_analysis.pr_url,
                    json.dumps(pr_analysis.changed_files),
                    json.dumps(pr_analysis.security_issues),
                    json.dumps(pr_analysis.recommendations),
                    pr_analysis.risk_level,
                    pr_analysis.has_repo_context,
                    json.dumps(pr_analysis.context_used),
                    pr_analysis.created_at.isoformat()
                ))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error saving PR analysis: {e}")
            return False
    
    def get_pr_analysis(self, pr_id: str) -> Optional[PRAnalysis]:
        """Get PR analysis by PR ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT id, pr_id, repo_id, pr_url, changed_files, security_issues,
                           recommendations, risk_level, has_repo_context, context_used, created_at
                    FROM pr_analyses WHERE pr_id = ?
                    ORDER BY created_at DESC LIMIT 1
                """, (pr_id,))
                
                row = cursor.fetchone()
                if row:
                    return PRAnalysis(
                        id=row[0],
                        pr_id=row[1],
                        repo_id=row[2],
                        pr_url=row[3],
                        changed_files=json.loads(row[4]) if row[4] else [],
                        security_issues=json.loads(row[5]) if row[5] else [],
                        recommendations=json.loads(row[6]) if row[6] else [],
                        risk_level=row[7],
                        has_repo_context=bool(row[8]),
                        context_used=json.loads(row[9]) if row[9] else {},
                        created_at=datetime.fromisoformat(row[10])
                    )
        except Exception as e:
            print(f"Error getting PR analysis: {e}")
        return None
    
    def get_pr_analyses_by_repo(self, repo_id: str) -> List[PRAnalysis]:
        """Get all PR analyses for a repository"""
        analyses = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT id, pr_id, repo_id, pr_url, changed_files, security_issues,
                           recommendations, risk_level, has_repo_context, context_used, created_at
                    FROM pr_analyses WHERE repo_id = ?
                    ORDER BY created_at DESC
                """, (repo_id,))
                
                for row in cursor.fetchall():
                    analyses.append(PRAnalysis(
                        id=row[0],
                        pr_id=row[1],
                        repo_id=row[2],
                        pr_url=row[3],
                        changed_files=json.loads(row[4]) if row[4] else [],
                        security_issues=json.loads(row[5]) if row[5] else [],
                        recommendations=json.loads(row[6]) if row[6] else [],
                        risk_level=row[7],
                        has_repo_context=bool(row[8]),
                        context_used=json.loads(row[9]) if row[9] else {},
                        created_at=datetime.fromisoformat(row[10])
                    ))
        except Exception as e:
            print(f"Error getting PR analyses: {e}")
        return analyses
    
    def has_repo_analysis(self, repo_id: str) -> bool:
        """Check if repository has existing security analysis (knowledge base)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM security_documents 
                    WHERE repo_id = ? AND scope = 'full_repo' AND is_current = TRUE
                """, (repo_id,))
                
                count = cursor.fetchone()[0]
                return count > 0
        except Exception as e:
            print(f"Error checking repo analysis: {e}")
            return False


# Global database manager instance
db_manager = DatabaseManager()


# Additional utility functions for backward compatibility
def has_repo_analysis(repo_id: str) -> bool:
    """Check if repository has existing security analysis (knowledge base)"""
    return db_manager.has_repo_analysis(repo_id)


def save_security_document(security_doc: SecurityDocument) -> bool:
    """Save security document to database"""
    return db_manager.save_security_document(security_doc)


def get_security_document(doc_id: str) -> Optional[SecurityDocument]:
    """Get security document by ID"""
    return db_manager.get_security_document(doc_id)


def get_security_documents_by_repo(repo_id: str) -> List[SecurityDocument]:
    """Get all security documents for a repository"""
    return db_manager.get_security_documents_by_repo(repo_id)


def save_pr_analysis(pr_analysis: PRAnalysis) -> bool:
    """Save PR analysis to database"""
    return db_manager.save_pr_analysis(pr_analysis)


def get_pr_analysis(pr_id: str) -> Optional[PRAnalysis]:
    """Get PR analysis by PR ID"""
    return db_manager.get_pr_analysis(pr_id)