"""
Security Error Handler - Comprehensive error classification and handling for security operations.

This module provides detailed error classification, contextual error messages with recovery actions,
and error tracking and pattern analysis for security operations.
"""

import logging
import traceback
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
import json
import sqlite3
from pathlib import Path

# Configure security error logger
security_logger = logging.getLogger('security_errors')
security_logger.setLevel(logging.INFO)

class SecurityErrorCategory(Enum):
    """Security error categories for classification."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_VALIDATION = "data_validation"
    ENCRYPTION = "encryption"
    ANALYSIS_FAILURE = "analysis_failure"
    OWASP_COMPLIANCE = "owasp_compliance"
    THREAT_DETECTION = "threat_detection"
    MITIGATION_FAILURE = "mitigation_failure"
    PERFORMANCE = "performance"
    EXTERNAL_SERVICE = "external_service"
    DATA_CORRUPTION = "data_corruption"
    CONFIGURATION = "configuration"

class SecurityErrorSeverity(Enum):
    """Security error severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class SecurityErrorContext:
    """Context information for security errors."""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    operation: Optional[str] = None
    resource: Optional[str] = None
    request_id: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RecoveryAction:
    """Recovery action for security errors."""
    action_type: str
    description: str
    automated: bool
    parameters: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SecurityError:
    """Comprehensive security error representation."""
    error_id: str
    category: SecurityErrorCategory
    severity: SecurityErrorSeverity
    message: str
    technical_details: str
    context: SecurityErrorContext
    recovery_actions: List[RecoveryAction]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False
    resolution_notes: Optional[str] = None

class SecurityErrorClassifier:
    """Classifies and categorizes security errors."""
    
    def __init__(self):
        self.classification_rules = self._initialize_classification_rules()
        self.error_patterns = {}
        self._load_error_patterns()
    
    def _initialize_classification_rules(self) -> Dict[str, Dict]:
        """Initialize error classification rules."""
        return {
            "authentication": {
                "keywords": ["login", "password", "token", "session", "auth"],
                "severity_mapping": {
                    "invalid_credentials": SecurityErrorSeverity.MEDIUM,
                    "session_expired": SecurityErrorSeverity.LOW,
                    "token_invalid": SecurityErrorSeverity.MEDIUM,
                    "mfa_required": SecurityErrorSeverity.HIGH
                }
            },
            "authorization": {
                "keywords": ["permission", "access", "role", "privilege", "forbidden"],
                "severity_mapping": {
                    "insufficient_permissions": SecurityErrorSeverity.HIGH,
                    "role_not_found": SecurityErrorSeverity.MEDIUM,
                    "access_denied": SecurityErrorSeverity.HIGH
                }
            },
            "data_validation": {
                "keywords": ["validation", "sanitization", "injection", "xss", "sql"],
                "severity_mapping": {
                    "sql_injection_attempt": SecurityErrorSeverity.CRITICAL,
                    "xss_attempt": SecurityErrorSeverity.HIGH,
                    "invalid_input": SecurityErrorSeverity.MEDIUM
                }
            },
            "encryption": {
                "keywords": ["encryption", "decryption", "key", "cipher", "tls"],
                "severity_mapping": {
                    "encryption_failure": SecurityErrorSeverity.CRITICAL,
                    "key_rotation_failed": SecurityErrorSeverity.HIGH,
                    "tls_handshake_failed": SecurityErrorSeverity.HIGH
                }
            },
            "analysis_failure": {
                "keywords": ["analysis", "threat", "vulnerability", "scan"],
                "severity_mapping": {
                    "analysis_timeout": SecurityErrorSeverity.MEDIUM,
                    "analysis_corrupted": SecurityErrorSeverity.HIGH,
                    "scanner_failure": SecurityErrorSeverity.MEDIUM
                }
            }
        }
    
    def _load_error_patterns(self):
        """Load historical error patterns for analysis."""
        try:
            pattern_file = Path("storage/logs/error_patterns.json")
            if pattern_file.exists():
                with open(pattern_file, 'r') as f:
                    self.error_patterns = json.load(f)
        except Exception as e:
            security_logger.warning(f"Could not load error patterns: {e}")
    
    def classify_error(self, error_message: str, exception: Exception, 
                      context: SecurityErrorContext) -> SecurityError:
        """Classify an error and create a SecurityError object."""
        category = self._determine_category(error_message, exception)
        severity = self._determine_severity(error_message, exception, category)
        recovery_actions = self._generate_recovery_actions(category, exception, context)
        
        error_id = self._generate_error_id(category, severity)
        
        return SecurityError(
            error_id=error_id,
            category=category,
            severity=severity,
            message=self._generate_user_message(category, exception),
            technical_details=self._generate_technical_details(exception),
            context=context,
            recovery_actions=recovery_actions
        )
    
    def _determine_category(self, error_message: str, exception: Exception) -> SecurityErrorCategory:
        """Determine the error category based on message and exception type."""
        error_text = f"{error_message} {str(exception)}".lower()
        
        # Check for specific exception types first
        if isinstance(exception, PermissionError):
            return SecurityErrorCategory.AUTHORIZATION
        elif isinstance(exception, ValueError) and "validation" in error_text:
            return SecurityErrorCategory.DATA_VALIDATION
        elif isinstance(exception, ConnectionError):
            return SecurityErrorCategory.EXTERNAL_SERVICE
        
        # Check classification rules
        for category_name, rules in self.classification_rules.items():
            if any(keyword in error_text for keyword in rules["keywords"]):
                return SecurityErrorCategory(category_name)
        
        # Default to analysis failure for unclassified errors
        return SecurityErrorCategory.ANALYSIS_FAILURE
    
    def _determine_severity(self, error_message: str, exception: Exception, 
                          category: SecurityErrorCategory) -> SecurityErrorSeverity:
        """Determine error severity based on category and content."""
        error_text = error_message.lower()
        
        # Critical severity indicators
        if any(indicator in error_text for indicator in 
               ["critical", "security breach", "data leak", "unauthorized access"]):
            return SecurityErrorSeverity.CRITICAL
        
        # High severity indicators
        if any(indicator in error_text for indicator in 
               ["injection", "privilege escalation", "authentication bypass"]):
            return SecurityErrorSeverity.HIGH
        
        # Use category-specific severity mapping
        category_rules = self.classification_rules.get(category.value, {})
        severity_mapping = category_rules.get("severity_mapping", {})
        
        for error_type, severity in severity_mapping.items():
            if error_type in error_text:
                return severity
        
        # Default severity based on category
        severity_defaults = {
            SecurityErrorCategory.AUTHENTICATION: SecurityErrorSeverity.MEDIUM,
            SecurityErrorCategory.AUTHORIZATION: SecurityErrorSeverity.HIGH,
            SecurityErrorCategory.DATA_VALIDATION: SecurityErrorSeverity.HIGH,
            SecurityErrorCategory.ENCRYPTION: SecurityErrorSeverity.CRITICAL,
            SecurityErrorCategory.ANALYSIS_FAILURE: SecurityErrorSeverity.MEDIUM,
            SecurityErrorCategory.EXTERNAL_SERVICE: SecurityErrorSeverity.LOW
        }
        
        return severity_defaults.get(category, SecurityErrorSeverity.MEDIUM)
    
    def _generate_recovery_actions(self, category: SecurityErrorCategory, 
                                 exception: Exception, 
                                 context: SecurityErrorContext) -> List[RecoveryAction]:
        """Generate contextual recovery actions based on error category."""
        actions = []
        
        if category == SecurityErrorCategory.AUTHENTICATION:
            actions.extend([
                RecoveryAction(
                    action_type="retry_authentication",
                    description="Retry authentication with valid credentials",
                    automated=False
                ),
                RecoveryAction(
                    action_type="session_refresh",
                    description="Refresh user session",
                    automated=True,
                    parameters={"session_id": context.session_id}
                )
            ])
        
        elif category == SecurityErrorCategory.AUTHORIZATION:
            actions.extend([
                RecoveryAction(
                    action_type="check_permissions",
                    description="Verify user permissions for the requested resource",
                    automated=True,
                    parameters={"user_id": context.user_id, "resource": context.resource}
                ),
                RecoveryAction(
                    action_type="request_access",
                    description="Request additional permissions from administrator",
                    automated=False
                )
            ])
        
        elif category == SecurityErrorCategory.DATA_VALIDATION:
            actions.extend([
                RecoveryAction(
                    action_type="sanitize_input",
                    description="Re-validate and sanitize input data",
                    automated=True
                ),
                RecoveryAction(
                    action_type="security_scan",
                    description="Perform security scan on input data",
                    automated=True
                )
            ])
        
        elif category == SecurityErrorCategory.EXTERNAL_SERVICE:
            actions.extend([
                RecoveryAction(
                    action_type="retry_request",
                    description="Retry the external service request",
                    automated=True,
                    parameters={"max_retries": 3, "backoff": "exponential"}
                ),
                RecoveryAction(
                    action_type="fallback_service",
                    description="Use fallback service if available",
                    automated=True
                )
            ])
        
        elif category == SecurityErrorCategory.ANALYSIS_FAILURE:
            actions.extend([
                RecoveryAction(
                    action_type="restart_analysis",
                    description="Restart the security analysis process",
                    automated=True
                ),
                RecoveryAction(
                    action_type="use_cached_results",
                    description="Use previously cached analysis results",
                    automated=True
                )
            ])
        
        # Add common recovery actions
        actions.append(
            RecoveryAction(
                action_type="log_incident",
                description="Log security incident for review",
                automated=True,
                parameters={"severity": "high" if category in [
                    SecurityErrorCategory.AUTHORIZATION,
                    SecurityErrorCategory.DATA_VALIDATION,
                    SecurityErrorCategory.ENCRYPTION
                ] else "medium"}
            )
        )
        
        return actions
    
    def _generate_user_message(self, category: SecurityErrorCategory, 
                             exception: Exception) -> str:
        """Generate user-friendly error message."""
        messages = {
            SecurityErrorCategory.AUTHENTICATION: "Authentication failed. Please check your credentials and try again.",
            SecurityErrorCategory.AUTHORIZATION: "You don't have permission to access this resource. Please contact your administrator.",
            SecurityErrorCategory.DATA_VALIDATION: "The provided data contains security issues. Please review and correct your input.",
            SecurityErrorCategory.ENCRYPTION: "A security encryption error occurred. Please try again or contact support.",
            SecurityErrorCategory.ANALYSIS_FAILURE: "Security analysis could not be completed. The system will retry automatically.",
            SecurityErrorCategory.EXTERNAL_SERVICE: "An external service is temporarily unavailable. Please try again later.",
            SecurityErrorCategory.DATA_CORRUPTION: "Data integrity issue detected. Recovery procedures have been initiated.",
            SecurityErrorCategory.OWASP_COMPLIANCE: "OWASP compliance validation failed. Please review security requirements."
        }
        
        return messages.get(category, "A security error occurred. Please try again or contact support.")
    
    def _generate_technical_details(self, exception: Exception) -> str:
        """Generate technical error details for logging."""
        return f"{type(exception).__name__}: {str(exception)}\n{traceback.format_exc()}"
    
    def _generate_error_id(self, category: SecurityErrorCategory, 
                          severity: SecurityErrorSeverity) -> str:
        """Generate unique error ID."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"SEC_{category.value.upper()}_{severity.value.upper()}_{timestamp}"

class SecurityErrorTracker:
    """Tracks and analyzes security error patterns."""
    
    def __init__(self, db_path: str = "storage/logs/security_errors.db"):
        self.db_path = db_path
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize the error tracking database."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_errors (
                    error_id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    technical_details TEXT,
                    context TEXT,
                    recovery_actions TEXT,
                    timestamp TEXT NOT NULL,
                    resolved BOOLEAN DEFAULT FALSE,
                    resolution_notes TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS error_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    pattern_description TEXT NOT NULL,
                    occurrence_count INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    severity_trend TEXT
                )
            """)
    
    def track_error(self, error: SecurityError):
        """Track a security error in the database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO security_errors 
                (error_id, category, severity, message, technical_details, 
                 context, recovery_actions, timestamp, resolved, resolution_notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                error.error_id,
                error.category.value,
                error.severity.value,
                error.message,
                error.technical_details,
                json.dumps(error.context.__dict__),
                json.dumps([action.__dict__ for action in error.recovery_actions]),
                error.timestamp.isoformat(),
                error.resolved,
                error.resolution_notes
            ))
        
        self._update_error_patterns(error)
        security_logger.info(f"Tracked security error: {error.error_id}")
    
    def _update_error_patterns(self, error: SecurityError):
        """Update error pattern analysis."""
        pattern_key = f"{error.category.value}_{error.severity.value}"
        
        with sqlite3.connect(self.db_path) as conn:
            # Check if pattern exists
            cursor = conn.execute(
                "SELECT occurrence_count, first_seen FROM error_patterns WHERE pattern_id = ?",
                (pattern_key,)
            )
            result = cursor.fetchone()
            
            if result:
                # Update existing pattern
                conn.execute("""
                    UPDATE error_patterns 
                    SET occurrence_count = occurrence_count + 1, 
                        last_seen = ?
                    WHERE pattern_id = ?
                """, (error.timestamp.isoformat(), pattern_key))
            else:
                # Create new pattern
                conn.execute("""
                    INSERT INTO error_patterns 
                    (pattern_id, category, pattern_description, occurrence_count, 
                     first_seen, last_seen, severity_trend)
                    VALUES (?, ?, ?, 1, ?, ?, ?)
                """, (
                    pattern_key,
                    error.category.value,
                    f"{error.category.value} errors with {error.severity.value} severity",
                    error.timestamp.isoformat(),
                    error.timestamp.isoformat(),
                    error.severity.value
                ))
    
    def get_error_patterns(self, days: int = 30) -> List[Dict]:
        """Get error patterns from the last N days."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT pattern_id, category, pattern_description, 
                       occurrence_count, first_seen, last_seen, severity_trend
                FROM error_patterns 
                WHERE last_seen >= ?
                ORDER BY occurrence_count DESC
            """, (cutoff_date.isoformat(),))
            
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_error_statistics(self, days: int = 7) -> Dict:
        """Get error statistics for the last N days."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        with sqlite3.connect(self.db_path) as conn:
            # Total errors by category
            cursor = conn.execute("""
                SELECT category, COUNT(*) as count
                FROM security_errors 
                WHERE timestamp >= ?
                GROUP BY category
            """, (cutoff_date.isoformat(),))
            category_stats = dict(cursor.fetchall())
            
            # Total errors by severity
            cursor = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM security_errors 
                WHERE timestamp >= ?
                GROUP BY severity
            """, (cutoff_date.isoformat(),))
            severity_stats = dict(cursor.fetchall())
            
            # Resolution rate
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN resolved THEN 1 ELSE 0 END) as resolved
                FROM security_errors 
                WHERE timestamp >= ?
            """, (cutoff_date.isoformat(),))
            total, resolved = cursor.fetchone()
            resolution_rate = (resolved / total * 100) if total > 0 else 0
            
            return {
                "category_distribution": category_stats,
                "severity_distribution": severity_stats,
                "resolution_rate": resolution_rate,
                "total_errors": total,
                "resolved_errors": resolved
            }

# Global instances
error_classifier = SecurityErrorClassifier()
error_tracker = SecurityErrorTracker()

def handle_security_error(exception: Exception, context: SecurityErrorContext, 
                         custom_message: Optional[str] = None) -> SecurityError:
    """Main function to handle security errors."""
    error_message = custom_message or str(exception)
    
    # Classify the error
    security_error = error_classifier.classify_error(error_message, exception, context)
    
    # Track the error
    error_tracker.track_error(security_error)
    
    # Log the error
    security_logger.error(
        f"Security Error [{security_error.error_id}]: {security_error.message}",
        extra={
            "error_id": security_error.error_id,
            "category": security_error.category.value,
            "severity": security_error.severity.value,
            "context": security_error.context.__dict__
        }
    )
    
    return security_error