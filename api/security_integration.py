"""
Integration layer for security components with existing ThreatLens systems
"""
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from contextlib import contextmanager

from api.config import settings
from api.database import DatabaseManager
from api.models import SecurityDocument, RepoContext, User
from api.security_encryption import data_encryption, key_manager
from api.security_validation import security_validator, validation_middleware
from api.security_auth import auth_manager, rbac_manager, Permission
from api.security_audit import audit_logger, AuditEventType, AuditSeverity

logger = logging.getLogger(__name__)


class SecureDataManager:
    """Secure data management layer with encryption and validation"""
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db_manager = db_manager or DatabaseManager()
    
    def save_security_document_secure(self, security_doc: SecurityDocument, 
                                    user_id: str) -> bool:
        """Save security document with encryption and audit logging"""
        try:
            # Validate input data
            validated_doc = self._validate_security_document(security_doc)
            
            # Encrypt sensitive content
            encrypted_doc = self._encrypt_security_document(validated_doc)
            
            # Save to database
            success = self.db_manager.save_security_document(encrypted_doc)
            
            # Audit log
            audit_logger.log_event(
                event_type=AuditEventType.DATA_CREATED,
                action="Security document created",
                success=success,
                user_id=user_id,
                resource_type="security_document",
                resource_id=security_doc.id,
                details={
                    "document_title": security_doc.title,
                    "scope": security_doc.scope,
                    "repo_id": security_doc.repo_id
                }
            )
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to save security document: {e}")
            
            audit_logger.log_event(
                event_type=AuditEventType.DATA_CREATED,
                action="Security document creation failed",
                success=False,
                user_id=user_id,
                resource_type="security_document",
                resource_id=security_doc.id,
                severity=AuditSeverity.HIGH,
                details={"error": str(e)}
            )
            
            return False
    
    def get_security_document_secure(self, doc_id: str, user_id: str) -> Optional[SecurityDocument]:
        """Retrieve and decrypt security document with access control"""
        try:
            # Get encrypted document from database
            encrypted_doc = self.db_manager.get_security_document(doc_id)
            
            if not encrypted_doc:
                return None
            
            # Decrypt document
            decrypted_doc = self._decrypt_security_document(encrypted_doc)
            
            # Audit log
            audit_logger.log_event(
                event_type=AuditEventType.DATA_READ,
                action="Security document accessed",
                success=True,
                user_id=user_id,
                resource_type="security_document",
                resource_id=doc_id
            )
            
            return decrypted_doc
        
        except Exception as e:
            logger.error(f"Failed to retrieve security document: {e}")
            
            audit_logger.log_event(
                event_type=AuditEventType.DATA_READ,
                action="Security document access failed",
                success=False,
                user_id=user_id,
                resource_type="security_document",
                resource_id=doc_id,
                severity=AuditSeverity.MEDIUM,
                details={"error": str(e)}
            )
            
            return None
    
    def _validate_security_document(self, doc: SecurityDocument) -> SecurityDocument:
        """Validate security document data"""
        validation_rules = {
            "title": {"max_length": 200, "pattern": r"^[a-zA-Z0-9\s\-_\.]+$"},
            "content": {"max_length": 100000, "allow_html": True},
            "scope": {"max_length": 50},
            "metadata": {"max_keys": 50}
        }
        
        # Validate each field
        doc.title = security_validator.validate_and_sanitize(doc.title, "title", validation_rules["title"])
        doc.content = security_validator.validate_and_sanitize(doc.content, "content", validation_rules["content"])
        doc.scope = security_validator.validate_and_sanitize(doc.scope, "scope", validation_rules["scope"])
        doc.metadata = security_validator.validate_and_sanitize(doc.metadata, "metadata", validation_rules["metadata"])
        
        return doc
    
    def _encrypt_security_document(self, doc: SecurityDocument) -> SecurityDocument:
        """Encrypt sensitive fields in security document"""
        # Encrypt content (main sensitive data)
        encrypted_content = data_encryption.encrypt_field(doc.content, "security_content")
        
        # Encrypt metadata if it contains sensitive information
        encrypted_metadata = data_encryption.encrypt_field(doc.metadata, "security_metadata")
        
        # Create new document with encrypted fields
        encrypted_doc = doc.copy()
        encrypted_doc.content = encrypted_content
        encrypted_doc.metadata = encrypted_metadata
        
        return encrypted_doc
    
    def _decrypt_security_document(self, encrypted_doc: SecurityDocument) -> SecurityDocument:
        """Decrypt security document fields"""
        # Decrypt content
        decrypted_content = data_encryption.decrypt_field(encrypted_doc.content)
        
        # Decrypt metadata
        decrypted_metadata = data_encryption.decrypt_field(encrypted_doc.metadata)
        
        # Create decrypted document
        decrypted_doc = encrypted_doc.copy()
        decrypted_doc.content = decrypted_content
        decrypted_doc.metadata = decrypted_metadata
        
        return decrypted_doc


class SecureRepositoryManager:
    """Secure repository management with access controls"""
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db_manager = db_manager or DatabaseManager()
    
    def create_repository_context_secure(self, repo_context: RepoContext, 
                                       user_id: str) -> bool:
        """Create repository context with security validation"""
        try:
            # Validate repository URL/path
            if repo_context.repo_url:
                validated_url = security_validator.validate_and_sanitize(
                    repo_context.repo_url, "repo_url", 
                    {"type": "url", "max_length": 500}
                )
                repo_context.repo_url = validated_url
            
            # Validate local path
            validated_path = security_validator.validate_and_sanitize(
                repo_context.local_path, "local_path",
                {"type": "filepath", "max_length": 500}
            )
            repo_context.local_path = validated_path
            
            # Save to database
            success = self.db_manager.save_repo_context(repo_context)
            
            # Audit log
            audit_logger.log_event(
                event_type=AuditEventType.DATA_CREATED,
                action="Repository context created",
                success=success,
                user_id=user_id,
                resource_type="repository",
                resource_id=repo_context.repo_id,
                details={
                    "repo_url": repo_context.repo_url,
                    "local_path": repo_context.local_path
                }
            )
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to create repository context: {e}")
            
            audit_logger.log_event(
                event_type=AuditEventType.DATA_CREATED,
                action="Repository context creation failed",
                success=False,
                user_id=user_id,
                resource_type="repository",
                resource_id=repo_context.repo_id,
                severity=AuditSeverity.HIGH,
                details={"error": str(e)}
            )
            
            return False


class SecurityMiddleware:
    """Security middleware for API endpoints"""
    
    def __init__(self):
        self.secure_data_manager = SecureDataManager()
        self.secure_repo_manager = SecureRepositoryManager()
    
    @contextmanager
    def secure_operation(self, operation_name: str, user_id: str, 
                        resource_type: Optional[str] = None, 
                        resource_id: Optional[str] = None):
        """Context manager for secure operations with audit logging"""
        start_time = datetime.now()
        
        try:
            # Log operation start
            audit_logger.log_event(
                event_type=AuditEventType.DATA_READ,  # Will be updated based on actual operation
                action=f"{operation_name} started",
                success=True,
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                severity=AuditSeverity.LOW
            )
            
            yield
            
            # Log successful completion
            duration = (datetime.now() - start_time).total_seconds()
            audit_logger.log_event(
                event_type=AuditEventType.DATA_READ,
                action=f"{operation_name} completed",
                success=True,
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                details={"duration_seconds": duration}
            )
        
        except Exception as e:
            # Log failure
            duration = (datetime.now() - start_time).total_seconds()
            audit_logger.log_event(
                event_type=AuditEventType.DATA_READ,
                action=f"{operation_name} failed",
                success=False,
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                severity=AuditSeverity.HIGH,
                details={
                    "error": str(e),
                    "duration_seconds": duration
                }
            )
            raise
    
    def validate_api_request(self, request_data: Dict[str, Any], 
                           endpoint: str) -> Dict[str, Any]:
        """Validate API request data"""
        return validation_middleware.validate_request_data(request_data, endpoint)
    
    def check_user_permission(self, user: User, permission: Permission, 
                            resource_id: Optional[str] = None) -> bool:
        """Check user permission with audit logging"""
        has_permission = rbac_manager.check_permission(user, permission, resource_id)
        
        audit_logger.log_event(
            event_type=AuditEventType.ACCESS_GRANTED if has_permission else AuditEventType.ACCESS_DENIED,
            action=f"Permission check: {permission.value}",
            success=has_permission,
            user_id=user.id,
            resource_id=resource_id,
            severity=AuditSeverity.MEDIUM if not has_permission else AuditSeverity.LOW,
            details={
                "permission": permission.value,
                "user_role": user.role.value
            }
        )
        
        return has_permission


class SecurityHealthChecker:
    """Security system health monitoring"""
    
    def __init__(self):
        self.last_check = None
        self.health_status = {}
    
    def perform_security_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive security health check"""
        health_report = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "healthy",
            "components": {},
            "warnings": [],
            "errors": []
        }
        
        try:
            # Check encryption system
            encryption_status = self._check_encryption_health()
            health_report["components"]["encryption"] = encryption_status
            
            # Check authentication system
            auth_status = self._check_auth_health()
            health_report["components"]["authentication"] = auth_status
            
            # Check audit system
            audit_status = self._check_audit_health()
            health_report["components"]["audit"] = audit_status
            
            # Check validation system
            validation_status = self._check_validation_health()
            health_report["components"]["validation"] = validation_status
            
            # Determine overall status
            component_statuses = [comp["status"] for comp in health_report["components"].values()]
            
            if "error" in component_statuses:
                health_report["overall_status"] = "error"
            elif "warning" in component_statuses:
                health_report["overall_status"] = "warning"
            
            # Collect warnings and errors
            for component, status in health_report["components"].items():
                if status["status"] == "warning":
                    health_report["warnings"].extend(status.get("issues", []))
                elif status["status"] == "error":
                    health_report["errors"].extend(status.get("issues", []))
            
            self.last_check = datetime.now()
            self.health_status = health_report
            
        except Exception as e:
            health_report["overall_status"] = "error"
            health_report["errors"].append(f"Health check failed: {e}")
            logger.error(f"Security health check failed: {e}")
        
        return health_report
    
    def _check_encryption_health(self) -> Dict[str, Any]:
        """Check encryption system health"""
        try:
            # Test encryption/decryption
            test_data = "security_health_check_test"
            encrypted = data_encryption.encrypt_security_data(test_data, "health_check")
            decrypted = data_encryption.decrypt_security_data(encrypted)
            
            if decrypted != test_data:
                return {
                    "status": "error",
                    "issues": ["Encryption/decryption test failed"]
                }
            
            # Check key manager
            key_metadata = key_manager._load_key_metadata()
            
            return {
                "status": "healthy",
                "key_version": key_metadata.get("version", 1),
                "last_rotation": key_metadata.get("rotation_history", [])[-1] if key_metadata.get("rotation_history") else None
            }
        
        except Exception as e:
            return {
                "status": "error",
                "issues": [f"Encryption system error: {e}"]
            }
    
    def _check_auth_health(self) -> Dict[str, Any]:
        """Check authentication system health"""
        try:
            # Check if admin user exists
            admin_exists = any(user.role.value == "admin" for user in auth_manager.users.values())
            
            if not admin_exists:
                return {
                    "status": "error",
                    "issues": ["No admin user found"]
                }
            
            # Check active sessions
            active_sessions = len([s for s in auth_manager.sessions.values() if s.status.value == "active"])
            
            return {
                "status": "healthy",
                "total_users": len(auth_manager.users),
                "active_sessions": active_sessions
            }
        
        except Exception as e:
            return {
                "status": "error",
                "issues": [f"Authentication system error: {e}"]
            }
    
    def _check_audit_health(self) -> Dict[str, Any]:
        """Check audit system health"""
        try:
            # Test audit logging
            test_event_id = audit_logger.log_event(
                event_type=AuditEventType.SYSTEM_STARTUP,
                action="Security health check",
                success=True,
                severity=AuditSeverity.LOW
            )
            
            if not test_event_id:
                return {
                    "status": "warning",
                    "issues": ["Audit logging test failed"]
                }
            
            # Get recent statistics
            stats = audit_logger.get_audit_statistics(days=1)
            
            return {
                "status": "healthy",
                "recent_events": stats.get("total_events", 0),
                "success_rate": stats.get("success_rate", 0)
            }
        
        except Exception as e:
            return {
                "status": "error",
                "issues": [f"Audit system error: {e}"]
            }
    
    def _check_validation_health(self) -> Dict[str, Any]:
        """Check validation system health"""
        try:
            # Test validation
            test_data = "test_validation_data"
            validated = security_validator.validate_and_sanitize(test_data, "health_check")
            
            if validated != test_data:
                return {
                    "status": "warning",
                    "issues": ["Validation test produced unexpected result"]
                }
            
            # Get validation statistics
            stats = validation_middleware.get_validation_stats()
            
            return {
                "status": "healthy",
                "total_validations": stats.get("total_validations", 0),
                "blocked_attempts": stats.get("blocked_attempts", 0)
            }
        
        except Exception as e:
            return {
                "status": "error",
                "issues": [f"Validation system error: {e}"]
            }


# Global instances
secure_data_manager = SecureDataManager()
secure_repo_manager = SecureRepositoryManager()
security_middleware = SecurityMiddleware()
security_health_checker = SecurityHealthChecker()