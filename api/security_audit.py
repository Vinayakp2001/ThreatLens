"""
Comprehensive audit logging system for security operations
"""
import json
import logging
import sqlite3
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum

from pydantic import BaseModel, Field

from api.config import settings
from api.security_encryption import data_encryption

logger = logging.getLogger(__name__)


class AuditEventType(str, Enum):
    """Types of audit events"""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_FAILED = "mfa_failed"
    PASSWORD_CHANGED = "password_changed"
    ACCOUNT_LOCKED = "account_locked"
    
    # Authorization events
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PERMISSION_CHANGED = "permission_changed"
    ROLE_CHANGED = "role_changed"
    
    # Data access events
    DATA_READ = "data_read"
    DATA_CREATED = "data_created"
    DATA_UPDATED = "data_updated"
    DATA_DELETED = "data_deleted"
    DATA_EXPORTED = "data_exported"
    DATA_IMPORTED = "data_imported"
    
    # Security events
    ENCRYPTION_KEY_ROTATED = "encryption_key_rotated"
    SECURITY_POLICY_CHANGED = "security_policy_changed"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    SECURITY_SCAN_COMPLETED = "security_scan_completed"
    
    # System events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIGURATION_CHANGED = "configuration_changed"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"
    
    # Analysis events
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETED = "analysis_completed"
    ANALYSIS_FAILED = "analysis_failed"
    WIKI_GENERATED = "wiki_generated"
    WIKI_UPDATED = "wiki_updated"


class AuditSeverity(str, Enum):
    """Audit event severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditEvent(BaseModel):
    """Audit event model"""
    id: str
    event_type: AuditEventType
    severity: AuditSeverity
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    action: str
    success: bool
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)
    
    class Config:
        use_enum_values = True


class AuditLogger:
    """Comprehensive audit logging system"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or str(Path(settings.storage_base_path) / "security" / "audit.db")
        self.log_retention_days = 365  # Keep audit logs for 1 year
        
        # Ensure audit directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize audit database
        self._initialize_audit_db()
    
    def _initialize_audit_db(self):
        """Initialize audit database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        user_id TEXT,
                        session_id TEXT,
                        resource_type TEXT,
                        resource_id TEXT,
                        action TEXT NOT NULL,
                        success BOOLEAN NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        details TEXT,  -- Encrypted JSON
                        timestamp TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                """)
                
                # Create indexes for performance
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_events(severity)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_success ON audit_events(success)")
                
                conn.commit()
                
            logger.info("Audit database initialized successfully")
        
        except Exception as e:
            logger.error(f"Failed to initialize audit database: {e}")
            raise
    
    def log_event(self, event_type: AuditEventType, action: str, success: bool,
                  user_id: Optional[str] = None, session_id: Optional[str] = None,
                  resource_type: Optional[str] = None, resource_id: Optional[str] = None,
                  severity: AuditSeverity = AuditSeverity.MEDIUM,
                  ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                  details: Optional[Dict[str, Any]] = None) -> str:
        """Log an audit event"""
        try:
            from api.security_encryption import secure_hasher
            
            event_id = secure_hasher.generate_secure_token(16)
            
            event = AuditEvent(
                id=event_id,
                event_type=event_type,
                severity=severity,
                user_id=user_id,
                session_id=session_id,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                success=success,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details or {}
            )
            
            # Encrypt sensitive details
            encrypted_details = None
            if event.details:
                encrypted_package = data_encryption.encrypt_security_data(
                    event.details, "audit_details"
                )
                encrypted_details = json.dumps(encrypted_package)
            
            # Store in database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO audit_events 
                    (id, event_type, severity, user_id, session_id, resource_type, 
                     resource_id, action, success, ip_address, user_agent, details, 
                     timestamp, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.id, event.event_type.value, event.severity.value,
                    event.user_id, event.session_id, event.resource_type,
                    event.resource_id, event.action, event.success,
                    event.ip_address, event.user_agent, encrypted_details,
                    event.timestamp.isoformat(), datetime.now().isoformat()
                ))
                
                conn.commit()
            
            # Log to application logger based on severity
            log_message = f"AUDIT: {event.action} - User: {user_id or 'system'} - Success: {success}"
            
            if severity == AuditSeverity.CRITICAL:
                logger.critical(log_message)
            elif severity == AuditSeverity.HIGH:
                logger.error(log_message)
            elif severity == AuditSeverity.MEDIUM:
                logger.warning(log_message)
            else:
                logger.info(log_message)
            
            return event_id
        
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            # Don't raise exception to avoid breaking the main operation
            return ""
    
    def get_audit_events(self, start_date: Optional[datetime] = None,
                        end_date: Optional[datetime] = None,
                        user_id: Optional[str] = None,
                        event_type: Optional[AuditEventType] = None,
                        severity: Optional[AuditSeverity] = None,
                        success: Optional[bool] = None,
                        limit: int = 1000) -> List[AuditEvent]:
        """Retrieve audit events with filtering"""
        try:
            query = "SELECT * FROM audit_events WHERE 1=1"
            params = []
            
            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date.isoformat())
            
            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date.isoformat())
            
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            
            if event_type:
                query += " AND event_type = ?"
                params.append(event_type.value)
            
            if severity:
                query += " AND severity = ?"
                params.append(severity.value)
            
            if success is not None:
                query += " AND success = ?"
                params.append(success)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            events = []
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)
                
                for row in cursor:
                    # Decrypt details if present
                    details = {}
                    if row['details']:
                        try:
                            encrypted_package = json.loads(row['details'])
                            details = data_encryption.decrypt_security_data(encrypted_package)
                        except Exception as e:
                            logger.error(f"Failed to decrypt audit details: {e}")
                            details = {"error": "Failed to decrypt details"}
                    
                    event = AuditEvent(
                        id=row['id'],
                        event_type=AuditEventType(row['event_type']),
                        severity=AuditSeverity(row['severity']),
                        user_id=row['user_id'],
                        session_id=row['session_id'],
                        resource_type=row['resource_type'],
                        resource_id=row['resource_id'],
                        action=row['action'],
                        success=bool(row['success']),
                        ip_address=row['ip_address'],
                        user_agent=row['user_agent'],
                        details=details,
                        timestamp=datetime.fromisoformat(row['timestamp'])
                    )
                    
                    events.append(event)
            
            return events
        
        except Exception as e:
            logger.error(f"Failed to retrieve audit events: {e}")
            return []
    
    def get_audit_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get audit statistics for the specified period"""
        try:
            start_date = datetime.now() - timedelta(days=days)
            
            stats = {
                "period_days": days,
                "start_date": start_date.isoformat(),
                "end_date": datetime.now().isoformat(),
                "total_events": 0,
                "events_by_type": {},
                "events_by_severity": {},
                "success_rate": 0.0,
                "failed_events": 0,
                "unique_users": 0,
                "top_users": [],
                "security_events": 0
            }
            
            with sqlite3.connect(self.db_path) as conn:
                # Total events
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM audit_events WHERE timestamp >= ?",
                    (start_date.isoformat(),)
                )
                stats["total_events"] = cursor.fetchone()[0]
                
                # Events by type
                cursor = conn.execute("""
                    SELECT event_type, COUNT(*) 
                    FROM audit_events 
                    WHERE timestamp >= ? 
                    GROUP BY event_type
                """, (start_date.isoformat(),))
                
                for event_type, count in cursor.fetchall():
                    stats["events_by_type"][event_type] = count
                
                # Events by severity
                cursor = conn.execute("""
                    SELECT severity, COUNT(*) 
                    FROM audit_events 
                    WHERE timestamp >= ? 
                    GROUP BY severity
                """, (start_date.isoformat(),))
                
                for severity, count in cursor.fetchall():
                    stats["events_by_severity"][severity] = count
                
                # Success rate
                cursor = conn.execute("""
                    SELECT 
                        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                        SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed,
                        COUNT(*) as total
                    FROM audit_events 
                    WHERE timestamp >= ?
                """, (start_date.isoformat(),))
                
                result = cursor.fetchone()
                if result and result[2] > 0:
                    stats["success_rate"] = (result[0] / result[2]) * 100
                    stats["failed_events"] = result[1]
                
                # Unique users
                cursor = conn.execute("""
                    SELECT COUNT(DISTINCT user_id) 
                    FROM audit_events 
                    WHERE timestamp >= ? AND user_id IS NOT NULL
                """, (start_date.isoformat(),))
                stats["unique_users"] = cursor.fetchone()[0]
                
                # Top users by activity
                cursor = conn.execute("""
                    SELECT user_id, COUNT(*) as event_count
                    FROM audit_events 
                    WHERE timestamp >= ? AND user_id IS NOT NULL
                    GROUP BY user_id 
                    ORDER BY event_count DESC 
                    LIMIT 10
                """, (start_date.isoformat(),))
                
                stats["top_users"] = [
                    {"user_id": row[0], "event_count": row[1]}
                    for row in cursor.fetchall()
                ]
                
                # Security-related events
                security_event_types = [
                    AuditEventType.LOGIN_FAILED.value,
                    AuditEventType.MFA_FAILED.value,
                    AuditEventType.ACCESS_DENIED.value,
                    AuditEventType.ACCOUNT_LOCKED.value,
                    AuditEventType.VULNERABILITY_DETECTED.value
                ]
                
                placeholders = ','.join(['?' for _ in security_event_types])
                cursor = conn.execute(f"""
                    SELECT COUNT(*) 
                    FROM audit_events 
                    WHERE timestamp >= ? AND event_type IN ({placeholders})
                """, [start_date.isoformat()] + security_event_types)
                
                stats["security_events"] = cursor.fetchone()[0]
            
            return stats
        
        except Exception as e:
            logger.error(f"Failed to get audit statistics: {e}")
            return {}
    
    def cleanup_old_events(self) -> Dict[str, Any]:
        """Clean up old audit events based on retention policy"""
        try:
            cutoff_date = datetime.now() - timedelta(days=self.log_retention_days)
            
            with sqlite3.connect(self.db_path) as conn:
                # Count events to be deleted
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM audit_events WHERE timestamp < ?",
                    (cutoff_date.isoformat(),)
                )
                events_to_delete = cursor.fetchone()[0]
                
                # Delete old events
                cursor = conn.execute(
                    "DELETE FROM audit_events WHERE timestamp < ?",
                    (cutoff_date.isoformat(),)
                )
                deleted_count = cursor.rowcount
                
                # Vacuum database to reclaim space
                conn.execute("VACUUM")
                conn.commit()
            
            cleanup_result = {
                "cleanup_date": datetime.now().isoformat(),
                "cutoff_date": cutoff_date.isoformat(),
                "events_deleted": deleted_count,
                "retention_days": self.log_retention_days
            }
            
            logger.info(f"Audit cleanup completed: {deleted_count} events deleted")
            return cleanup_result
        
        except Exception as e:
            logger.error(f"Audit cleanup failed: {e}")
            return {"error": str(e)}
    
    def export_audit_logs(self, start_date: datetime, end_date: datetime,
                         export_path: str, format: str = "json") -> Dict[str, Any]:
        """Export audit logs to file"""
        try:
            events = self.get_audit_events(
                start_date=start_date,
                end_date=end_date,
                limit=100000  # Large limit for export
            )
            
            export_data = {
                "export_info": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "exported_at": datetime.now().isoformat(),
                    "total_events": len(events)
                },
                "events": [event.dict() for event in events]
            }
            
            if format.lower() == "json":
                with open(export_path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
            return {
                "success": True,
                "export_path": export_path,
                "events_exported": len(events),
                "file_size": Path(export_path).stat().st_size
            }
        
        except Exception as e:
            logger.error(f"Audit export failed: {e}")
            return {"success": False, "error": str(e)}


# Global audit logger instance
audit_logger = AuditLogger()


# Convenience functions for common audit events
def log_authentication_event(event_type: AuditEventType, user_id: str, success: bool,
                           ip_address: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
    """Log authentication-related audit event"""
    severity = AuditSeverity.HIGH if not success else AuditSeverity.MEDIUM
    
    audit_logger.log_event(
        event_type=event_type,
        action=f"User authentication: {event_type.value}",
        success=success,
        user_id=user_id,
        severity=severity,
        ip_address=ip_address,
        details=details
    )


def log_data_access_event(event_type: AuditEventType, user_id: str, resource_type: str,
                         resource_id: str, success: bool, details: Optional[Dict[str, Any]] = None):
    """Log data access audit event"""
    audit_logger.log_event(
        event_type=event_type,
        action=f"Data access: {event_type.value}",
        success=success,
        user_id=user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        severity=AuditSeverity.MEDIUM,
        details=details
    )


def log_security_event(event_type: AuditEventType, action: str, success: bool,
                      user_id: Optional[str] = None, severity: AuditSeverity = AuditSeverity.HIGH,
                      details: Optional[Dict[str, Any]] = None):
    """Log security-related audit event"""
    audit_logger.log_event(
        event_type=event_type,
        action=action,
        success=success,
        user_id=user_id,
        severity=severity,
        details=details
    )