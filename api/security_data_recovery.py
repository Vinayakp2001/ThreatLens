"""
Security Data Recovery - Automatic backup and recovery mechanisms for security data.

This module provides automatic backup and recovery for security data, data validation
and corruption detection, and rollback capabilities for security data operations.
"""

import os
import json
import sqlite3
import hashlib
import shutil
import gzip
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import threading
import time

# Configure recovery logger
recovery_logger = logging.getLogger('security_recovery')
recovery_logger.setLevel(logging.INFO)

class BackupType(Enum):
    """Types of security data backups."""
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"
    SNAPSHOT = "snapshot"

class RecoveryStatus(Enum):
    """Recovery operation status."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    IN_PROGRESS = "in_progress"

@dataclass
class BackupMetadata:
    """Metadata for security data backups."""
    backup_id: str
    backup_type: BackupType
    timestamp: datetime
    file_path: str
    checksum: str
    size_bytes: int
    data_sources: List[str]
    compression: bool = True
    encrypted: bool = True
    retention_days: int = 30

@dataclass
class ValidationResult:
    """Result of data validation check."""
    is_valid: bool
    corruption_detected: bool
    missing_files: List[str]
    checksum_mismatches: List[str]
    validation_errors: List[str]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class RecoveryOperation:
    """Recovery operation tracking."""
    operation_id: str
    operation_type: str
    status: RecoveryStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    recovered_files: List[str] = field(default_factory=list)
    failed_files: List[str] = field(default_factory=list)
    error_messages: List[str] = field(default_factory=list)

class SecurityDataValidator:
    """Validates security data integrity and detects corruption."""
    
    def __init__(self):
        self.validation_rules = self._initialize_validation_rules()
    
    def _initialize_validation_rules(self) -> Dict[str, Dict]:
        """Initialize data validation rules for different data types."""
        return {
            "security_wiki": {
                "required_fields": ["id", "title", "threats", "mitigations", "owasp_mappings"],
                "field_types": {
                    "id": str,
                    "title": str,
                    "threats": list,
                    "mitigations": list,
                    "owasp_mappings": list
                },
                "constraints": {
                    "title": {"min_length": 1, "max_length": 500},
                    "threats": {"min_items": 0, "max_items": 100},
                    "mitigations": {"min_items": 0, "max_items": 100}
                }
            },
            "security_analysis": {
                "required_fields": ["analysis_id", "repository", "timestamp", "results"],
                "field_types": {
                    "analysis_id": str,
                    "repository": str,
                    "timestamp": str,
                    "results": dict
                }
            },
            "owasp_mapping": {
                "required_fields": ["category", "subcategory", "description"],
                "field_types": {
                    "category": str,
                    "subcategory": str,
                    "description": str
                }
            }
        }
    
    def validate_file(self, file_path: str, data_type: str) -> ValidationResult:
        """Validate a single data file."""
        validation_errors = []
        missing_files = []
        checksum_mismatches = []
        
        try:
            # Check if file exists
            if not Path(file_path).exists():
                missing_files.append(file_path)
                return ValidationResult(
                    is_valid=False,
                    corruption_detected=True,
                    missing_files=missing_files,
                    checksum_mismatches=checksum_mismatches,
                    validation_errors=["File does not exist"]
                )
            
            # Validate file content based on type
            if file_path.endswith('.json'):
                validation_errors.extend(self._validate_json_file(file_path, data_type))
            elif file_path.endswith('.db'):
                validation_errors.extend(self._validate_database_file(file_path))
            
            # Check file integrity
            if not self._verify_file_integrity(file_path):
                checksum_mismatches.append(file_path)
                validation_errors.append(f"Checksum mismatch for {file_path}")
            
        except Exception as e:
            validation_errors.append(f"Validation error for {file_path}: {str(e)}")
        
        is_valid = len(validation_errors) == 0 and len(missing_files) == 0 and len(checksum_mismatches) == 0
        corruption_detected = len(checksum_mismatches) > 0 or any("corruption" in error.lower() for error in validation_errors)
        
        return ValidationResult(
            is_valid=is_valid,
            corruption_detected=corruption_detected,
            missing_files=missing_files,
            checksum_mismatches=checksum_mismatches,
            validation_errors=validation_errors
        )
    
    def _validate_json_file(self, file_path: str, data_type: str) -> List[str]:
        """Validate JSON file structure and content."""
        errors = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Get validation rules for data type
            rules = self.validation_rules.get(data_type, {})
            
            # Check required fields
            required_fields = rules.get("required_fields", [])
            for field in required_fields:
                if field not in data:
                    errors.append(f"Missing required field: {field}")
            
            # Check field types
            field_types = rules.get("field_types", {})
            for field, expected_type in field_types.items():
                if field in data and not isinstance(data[field], expected_type):
                    errors.append(f"Invalid type for field {field}: expected {expected_type.__name__}")
            
            # Check constraints
            constraints = rules.get("constraints", {})
            for field, constraint_rules in constraints.items():
                if field in data:
                    errors.extend(self._validate_field_constraints(field, data[field], constraint_rules))
            
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON format: {str(e)}")
        except Exception as e:
            errors.append(f"JSON validation error: {str(e)}")
        
        return errors
    
    def _validate_database_file(self, file_path: str) -> List[str]:
        """Validate database file integrity."""
        errors = []
        
        try:
            with sqlite3.connect(file_path) as conn:
                # Check database integrity
                cursor = conn.execute("PRAGMA integrity_check")
                result = cursor.fetchone()
                if result[0] != "ok":
                    errors.append(f"Database integrity check failed: {result[0]}")
                
                # Check if critical tables exist
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                
                expected_tables = ["security_wikis", "security_analyses", "owasp_mappings"]
                for table in expected_tables:
                    if table not in tables:
                        errors.append(f"Missing critical table: {table}")
        
        except sqlite3.DatabaseError as e:
            errors.append(f"Database validation error: {str(e)}")
        except Exception as e:
            errors.append(f"Database file error: {str(e)}")
        
        return errors
    
    def _validate_field_constraints(self, field_name: str, value: Any, constraints: Dict) -> List[str]:
        """Validate field constraints."""
        errors = []
        
        if isinstance(value, str):
            min_length = constraints.get("min_length")
            max_length = constraints.get("max_length")
            
            if min_length is not None and len(value) < min_length:
                errors.append(f"Field {field_name} too short: minimum {min_length} characters")
            
            if max_length is not None and len(value) > max_length:
                errors.append(f"Field {field_name} too long: maximum {max_length} characters")
        
        elif isinstance(value, list):
            min_items = constraints.get("min_items")
            max_items = constraints.get("max_items")
            
            if min_items is not None and len(value) < min_items:
                errors.append(f"Field {field_name} has too few items: minimum {min_items}")
            
            if max_items is not None and len(value) > max_items:
                errors.append(f"Field {field_name} has too many items: maximum {max_items}")
        
        return errors
    
    def _verify_file_integrity(self, file_path: str) -> bool:
        """Verify file integrity using checksums."""
        try:
            # Calculate current checksum
            current_checksum = self._calculate_checksum(file_path)
            
            # Check if stored checksum exists
            checksum_file = f"{file_path}.checksum"
            if Path(checksum_file).exists():
                with open(checksum_file, 'r') as f:
                    stored_checksum = f.read().strip()
                return current_checksum == stored_checksum
            
            # If no stored checksum, create one
            with open(checksum_file, 'w') as f:
                f.write(current_checksum)
            return True
            
        except Exception as e:
            recovery_logger.warning(f"Could not verify integrity for {file_path}: {e}")
            return False
    
    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA-256 checksum for a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

class SecurityBackupManager:
    """Manages automatic backups of security data."""
    
    def __init__(self, backup_dir: str = "storage/backups/security"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.backup_dir / "backup_metadata.json"
        self.validator = SecurityDataValidator()
        self._load_metadata()
    
    def _load_metadata(self):
        """Load backup metadata."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    self.backups = {
                        backup_id: BackupMetadata(**backup_data) 
                        for backup_id, backup_data in data.items()
                    }
            except Exception as e:
                recovery_logger.warning(f"Could not load backup metadata: {e}")
                self.backups = {}
        else:
            self.backups = {}
    
    def _save_metadata(self):
        """Save backup metadata."""
        try:
            data = {
                backup_id: {
                    "backup_id": backup.backup_id,
                    "backup_type": backup.backup_type.value,
                    "timestamp": backup.timestamp.isoformat(),
                    "file_path": backup.file_path,
                    "checksum": backup.checksum,
                    "size_bytes": backup.size_bytes,
                    "data_sources": backup.data_sources,
                    "compression": backup.compression,
                    "encrypted": backup.encrypted,
                    "retention_days": backup.retention_days
                }
                for backup_id, backup in self.backups.items()
            }
            
            with open(self.metadata_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            recovery_logger.error(f"Could not save backup metadata: {e}")
    
    def create_backup(self, data_sources: List[str], backup_type: BackupType = BackupType.FULL) -> str:
        """Create a backup of security data."""
        timestamp = datetime.now(timezone.utc)
        # Use microseconds to avoid conflicts in rapid succession
        backup_id = f"security_backup_{timestamp.strftime('%Y%m%d_%H%M%S_%f')}"
        
        try:
            # Create backup directory
            backup_path = self.backup_dir / backup_id
            backup_path.mkdir(exist_ok=True)
            
            # Copy data files
            copied_files = []
            total_size = 0
            
            for source in data_sources:
                source_path = Path(source)
                if source_path.exists():
                    if source_path.is_file():
                        dest_path = backup_path / source_path.name
                        shutil.copy2(source_path, dest_path)
                        copied_files.append(str(dest_path))
                        total_size += dest_path.stat().st_size
                    elif source_path.is_dir():
                        dest_dir = backup_path / source_path.name
                        # Handle existing directories
                        if dest_dir.exists():
                            shutil.rmtree(dest_dir)
                        shutil.copytree(source_path, dest_dir)
                        for file_path in dest_dir.rglob('*'):
                            if file_path.is_file():
                                copied_files.append(str(file_path))
                                total_size += file_path.stat().st_size
            
            # Create compressed archive
            archive_path = self.backup_dir / f"{backup_id}.tar.gz"
            shutil.make_archive(str(archive_path.with_suffix('')), 'gztar', backup_path)
            
            # Calculate checksum
            checksum = self.validator._calculate_checksum(str(archive_path))
            
            # Clean up temporary directory
            shutil.rmtree(backup_path)
            
            # Create backup metadata
            backup_metadata = BackupMetadata(
                backup_id=backup_id,
                backup_type=backup_type,
                timestamp=timestamp,
                file_path=str(archive_path),
                checksum=checksum,
                size_bytes=archive_path.stat().st_size,
                data_sources=data_sources,
                compression=True,
                encrypted=False,  # TODO: Implement encryption
                retention_days=30
            )
            
            self.backups[backup_id] = backup_metadata
            self._save_metadata()
            
            recovery_logger.info(f"Created security backup: {backup_id}")
            return backup_id
            
        except Exception as e:
            recovery_logger.error(f"Failed to create backup: {e}")
            raise
    
    def restore_backup(self, backup_id: str, restore_path: Optional[str] = None) -> RecoveryOperation:
        """Restore data from a backup."""
        operation_id = f"restore_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        operation = RecoveryOperation(
            operation_id=operation_id,
            operation_type="restore_backup",
            status=RecoveryStatus.IN_PROGRESS,
            start_time=datetime.now(timezone.utc)
        )
        
        try:
            if backup_id not in self.backups:
                operation.status = RecoveryStatus.FAILED
                operation.error_messages.append(f"Backup {backup_id} not found")
                return operation
            
            backup = self.backups[backup_id]
            backup_file = Path(backup.file_path)
            
            if not backup_file.exists():
                operation.status = RecoveryStatus.FAILED
                operation.error_messages.append(f"Backup file {backup.file_path} not found")
                return operation
            
            # Verify backup integrity
            current_checksum = self.validator._calculate_checksum(str(backup_file))
            if current_checksum != backup.checksum:
                operation.status = RecoveryStatus.FAILED
                operation.error_messages.append("Backup file integrity check failed")
                return operation
            
            # Extract backup
            extract_path = Path(restore_path) if restore_path else Path("storage/temp/restore")
            extract_path.mkdir(parents=True, exist_ok=True)
            
            shutil.unpack_archive(str(backup_file), str(extract_path))
            
            # List restored files
            for file_path in extract_path.rglob('*'):
                if file_path.is_file():
                    operation.recovered_files.append(str(file_path))
            
            operation.status = RecoveryStatus.SUCCESS
            operation.end_time = datetime.now(timezone.utc)
            
            recovery_logger.info(f"Successfully restored backup {backup_id}")
            
        except Exception as e:
            operation.status = RecoveryStatus.FAILED
            operation.error_messages.append(str(e))
            operation.end_time = datetime.now(timezone.utc)
            recovery_logger.error(f"Failed to restore backup {backup_id}: {e}")
        
        return operation
    
    def cleanup_old_backups(self):
        """Clean up expired backups based on retention policy."""
        current_time = datetime.now(timezone.utc)
        expired_backups = []
        
        for backup_id, backup in self.backups.items():
            retention_cutoff = backup.timestamp + timedelta(days=backup.retention_days)
            if current_time > retention_cutoff:
                expired_backups.append(backup_id)
        
        for backup_id in expired_backups:
            try:
                backup = self.backups[backup_id]
                backup_file = Path(backup.file_path)
                if backup_file.exists():
                    backup_file.unlink()
                
                del self.backups[backup_id]
                recovery_logger.info(f"Cleaned up expired backup: {backup_id}")
                
            except Exception as e:
                recovery_logger.error(f"Failed to cleanup backup {backup_id}: {e}")
        
        if expired_backups:
            self._save_metadata()

class SecurityDataRecoveryManager:
    """Main manager for security data recovery operations."""
    
    def __init__(self):
        self.backup_manager = SecurityBackupManager()
        self.validator = SecurityDataValidator()
        self.recovery_operations = {}
        self._start_monitoring()
    
    def _start_monitoring(self):
        """Start background monitoring for data integrity."""
        def monitor_loop():
            while True:
                try:
                    self.perform_integrity_check()
                    time.sleep(3600)  # Check every hour
                except Exception as e:
                    recovery_logger.error(f"Monitoring error: {e}")
                    time.sleep(300)  # Wait 5 minutes on error
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    
    def perform_integrity_check(self) -> ValidationResult:
        """Perform comprehensive integrity check on security data."""
        recovery_logger.info("Starting security data integrity check")
        
        # Define critical data files to check
        critical_files = [
            "data/threatlens.db",
            "data/security_patterns.db",
            "storage/knowledge_bases",
            "storage/docs"
        ]
        
        all_errors = []
        all_missing = []
        all_checksums = []
        corruption_detected = False
        
        for file_path in critical_files:
            if Path(file_path).exists():
                if Path(file_path).is_file():
                    result = self.validator.validate_file(file_path, "security_analysis")
                    all_errors.extend(result.validation_errors)
                    all_missing.extend(result.missing_files)
                    all_checksums.extend(result.checksum_mismatches)
                    if result.corruption_detected:
                        corruption_detected = True
                elif Path(file_path).is_dir():
                    for sub_file in Path(file_path).rglob('*.json'):
                        result = self.validator.validate_file(str(sub_file), "security_wiki")
                        all_errors.extend(result.validation_errors)
                        all_missing.extend(result.missing_files)
                        all_checksums.extend(result.checksum_mismatches)
                        if result.corruption_detected:
                            corruption_detected = True
            else:
                all_missing.append(file_path)
        
        overall_result = ValidationResult(
            is_valid=len(all_errors) == 0 and len(all_missing) == 0 and len(all_checksums) == 0,
            corruption_detected=corruption_detected,
            missing_files=all_missing,
            checksum_mismatches=all_checksums,
            validation_errors=all_errors
        )
        
        if not overall_result.is_valid:
            recovery_logger.warning(f"Integrity check found issues: {len(all_errors)} errors, {len(all_missing)} missing files")
            self.handle_data_corruption(overall_result)
        
        return overall_result
    
    def handle_data_corruption(self, validation_result: ValidationResult):
        """Handle detected data corruption."""
        recovery_logger.error("Data corruption detected, initiating recovery procedures")
        
        # Create emergency backup of current state
        try:
            emergency_backup_id = self.backup_manager.create_backup(
                ["data", "storage/knowledge_bases", "storage/docs"],
                BackupType.SNAPSHOT
            )
            recovery_logger.info(f"Created emergency backup: {emergency_backup_id}")
        except Exception as e:
            recovery_logger.error(f"Failed to create emergency backup: {e}")
        
        # Attempt automatic recovery
        recovery_operation = self.attempt_automatic_recovery(validation_result)
        self.recovery_operations[recovery_operation.operation_id] = recovery_operation
        
        return recovery_operation
    
    def attempt_automatic_recovery(self, validation_result: ValidationResult) -> RecoveryOperation:
        """Attempt automatic recovery from the most recent valid backup."""
        operation_id = f"auto_recovery_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        operation = RecoveryOperation(
            operation_id=operation_id,
            operation_type="automatic_recovery",
            status=RecoveryStatus.IN_PROGRESS,
            start_time=datetime.now(timezone.utc)
        )
        
        try:
            # Find the most recent valid backup
            valid_backups = []
            for backup_id, backup in self.backup_manager.backups.items():
                backup_file = Path(backup.file_path)
                if backup_file.exists():
                    # Verify backup integrity
                    current_checksum = self.validator._calculate_checksum(str(backup_file))
                    if current_checksum == backup.checksum:
                        valid_backups.append((backup.timestamp, backup_id))
            
            if not valid_backups:
                operation.status = RecoveryStatus.FAILED
                operation.error_messages.append("No valid backups found for recovery")
                return operation
            
            # Use the most recent valid backup
            valid_backups.sort(reverse=True)
            latest_backup_id = valid_backups[0][1]
            
            # Restore from backup
            restore_operation = self.backup_manager.restore_backup(
                latest_backup_id, 
                "storage/temp/recovery"
            )
            
            if restore_operation.status == RecoveryStatus.SUCCESS:
                # Copy recovered files to their original locations
                # This is a simplified implementation - in production, you'd want more sophisticated logic
                operation.recovered_files = restore_operation.recovered_files
                operation.status = RecoveryStatus.SUCCESS
                recovery_logger.info(f"Automatic recovery completed using backup {latest_backup_id}")
            else:
                operation.status = RecoveryStatus.FAILED
                operation.error_messages.extend(restore_operation.error_messages)
            
        except Exception as e:
            operation.status = RecoveryStatus.FAILED
            operation.error_messages.append(str(e))
            recovery_logger.error(f"Automatic recovery failed: {e}")
        
        operation.end_time = datetime.now(timezone.utc)
        return operation
    
    def create_rollback_point(self, operation_name: str) -> str:
        """Create a rollback point before performing risky operations."""
        rollback_id = f"rollback_{operation_name}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}"
        
        try:
            backup_id = self.backup_manager.create_backup(
                ["data", "storage/knowledge_bases", "storage/docs"],
                BackupType.SNAPSHOT
            )
            
            # Store rollback mapping
            rollback_file = Path("storage/rollback_points.json")
            rollback_data = {}
            
            if rollback_file.exists():
                with open(rollback_file, 'r') as f:
                    rollback_data = json.load(f)
            
            rollback_data[rollback_id] = {
                "backup_id": backup_id,
                "operation_name": operation_name,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            rollback_file.parent.mkdir(parents=True, exist_ok=True)
            with open(rollback_file, 'w') as f:
                json.dump(rollback_data, f, indent=2)
            
            recovery_logger.info(f"Created rollback point: {rollback_id}")
            return rollback_id
            
        except Exception as e:
            recovery_logger.error(f"Failed to create rollback point: {e}")
            raise
    
    def rollback_to_point(self, rollback_id: str) -> RecoveryOperation:
        """Rollback to a specific rollback point."""
        operation_id = f"rollback_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        operation = RecoveryOperation(
            operation_id=operation_id,
            operation_type="rollback",
            status=RecoveryStatus.IN_PROGRESS,
            start_time=datetime.now(timezone.utc)
        )
        
        try:
            # Load rollback data
            rollback_file = Path("storage/rollback_points.json")
            if not rollback_file.exists():
                operation.status = RecoveryStatus.FAILED
                operation.error_messages.append("No rollback points found")
                return operation
            
            with open(rollback_file, 'r') as f:
                rollback_data = json.load(f)
            
            if rollback_id not in rollback_data:
                operation.status = RecoveryStatus.FAILED
                operation.error_messages.append(f"Rollback point {rollback_id} not found")
                return operation
            
            # Get backup ID for rollback
            backup_id = rollback_data[rollback_id]["backup_id"]
            
            # Restore from backup
            restore_operation = self.backup_manager.restore_backup(backup_id)
            
            if restore_operation.status == RecoveryStatus.SUCCESS:
                operation.recovered_files = restore_operation.recovered_files
                operation.status = RecoveryStatus.SUCCESS
                recovery_logger.info(f"Successfully rolled back to point: {rollback_id}")
            else:
                operation.status = RecoveryStatus.FAILED
                operation.error_messages.extend(restore_operation.error_messages)
            
        except Exception as e:
            operation.status = RecoveryStatus.FAILED
            operation.error_messages.append(str(e))
            recovery_logger.error(f"Rollback failed: {e}")
        
        operation.end_time = datetime.now(timezone.utc)
        return operation

# Global instance
security_recovery_manager = SecurityDataRecoveryManager()

def create_security_backup(data_sources: List[str]) -> str:
    """Create a security data backup."""
    return security_recovery_manager.backup_manager.create_backup(data_sources)

def validate_security_data(file_path: str, data_type: str) -> ValidationResult:
    """Validate security data file."""
    return security_recovery_manager.validator.validate_file(file_path, data_type)

def create_rollback_point(operation_name: str) -> str:
    """Create a rollback point for an operation."""
    return security_recovery_manager.create_rollback_point(operation_name)

def rollback_operation(rollback_id: str) -> RecoveryOperation:
    """Rollback to a specific point."""
    return security_recovery_manager.rollback_to_point(rollback_id)