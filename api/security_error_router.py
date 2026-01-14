"""
Security Error System Router - API endpoints for security error handling system.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import logging

from security_error_system import (
    security_error_system, get_security_system_status,
    SecurityErrorContext, handle_security_operation_error
)
from security_data_recovery import (
    security_recovery_manager, create_security_backup, 
    validate_security_data, create_rollback_point, rollback_operation
)
from security_error_handler import error_tracker
from security_auth import get_current_user, require_admin

router = APIRouter(prefix="/api/security/errors", tags=["Security Error Handling"])
logger = logging.getLogger(__name__)

@router.get("/status")
async def get_error_system_status(current_user: dict = Depends(get_current_user)):
    """Get current security error system status."""
    try:
        return get_security_system_status()
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system status")

@router.get("/statistics")
async def get_error_statistics(
    days: int = 7,
    current_user: dict = Depends(get_current_user)
):
    """Get error statistics for the specified number of days."""
    try:
        stats = error_tracker.get_error_statistics(days)
        return {
            "period_days": days,
            "statistics": stats,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get error statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve error statistics")

@router.get("/patterns")
async def get_error_patterns(
    days: int = 30,
    current_user: dict = Depends(get_current_user)
):
    """Get error patterns from the last N days."""
    try:
        patterns = error_tracker.get_error_patterns(days)
        return {
            "period_days": days,
            "patterns": patterns,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get error patterns: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve error patterns")

@router.post("/validate-data")
async def validate_security_data_endpoint(
    file_path: str,
    data_type: str,
    current_user: dict = Depends(require_admin)
):
    """Validate security data file integrity."""
    try:
        validation_result = validate_security_data(file_path, data_type)
        return {
            "file_path": file_path,
            "data_type": data_type,
            "validation_result": {
                "is_valid": validation_result.is_valid,
                "corruption_detected": validation_result.corruption_detected,
                "missing_files": validation_result.missing_files,
                "checksum_mismatches": validation_result.checksum_mismatches,
                "validation_errors": validation_result.validation_errors,
                "timestamp": validation_result.timestamp.isoformat()
            }
        }
    except Exception as e:
        logger.error(f"Data validation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Data validation failed: {str(e)}")

@router.post("/backup")
async def create_backup_endpoint(
    data_sources: List[str],
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_admin)
):
    """Create a backup of security data."""
    try:
        def create_backup_task():
            try:
                backup_id = create_security_backup(data_sources)
                logger.info(f"Backup created successfully: {backup_id}")
            except Exception as e:
                logger.error(f"Background backup failed: {e}")
        
        background_tasks.add_task(create_backup_task)
        
        return {
            "message": "Backup creation started",
            "data_sources": data_sources,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to start backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start backup: {str(e)}")

@router.get("/backups")
async def list_backups(current_user: dict = Depends(require_admin)):
    """List available security data backups."""
    try:
        backups = []
        for backup_id, backup in security_recovery_manager.backup_manager.backups.items():
            backups.append({
                "backup_id": backup.backup_id,
                "backup_type": backup.backup_type.value,
                "timestamp": backup.timestamp.isoformat(),
                "size_bytes": backup.size_bytes,
                "data_sources": backup.data_sources,
                "retention_days": backup.retention_days
            })
        
        return {
            "backups": sorted(backups, key=lambda x: x["timestamp"], reverse=True),
            "total_count": len(backups)
        }
    except Exception as e:
        logger.error(f"Failed to list backups: {e}")
        raise HTTPException(status_code=500, detail="Failed to list backups")

@router.post("/rollback-point")
async def create_rollback_point_endpoint(
    operation_name: str,
    current_user: dict = Depends(require_admin)
):
    """Create a rollback point for an operation."""
    try:
        rollback_id = create_rollback_point(operation_name)
        return {
            "rollback_id": rollback_id,
            "operation_name": operation_name,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to create rollback point: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create rollback point: {str(e)}")

@router.post("/rollback/{rollback_id}")
async def rollback_to_point_endpoint(
    rollback_id: str,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_admin)
):
    """Rollback to a specific rollback point."""
    try:
        def rollback_task():
            try:
                recovery_op = rollback_operation(rollback_id)
                logger.info(f"Rollback operation completed: {recovery_op.operation_id}, Status: {recovery_op.status.value}")
            except Exception as e:
                logger.error(f"Background rollback failed: {e}")
        
        background_tasks.add_task(rollback_task)
        
        return {
            "message": "Rollback operation started",
            "rollback_id": rollback_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to start rollback: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start rollback: {str(e)}")

@router.post("/integrity-check")
async def perform_integrity_check(
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_admin)
):
    """Perform comprehensive security data integrity check."""
    try:
        def integrity_check_task():
            try:
                validation_result = security_recovery_manager.perform_integrity_check()
                logger.info(f"Integrity check completed. Valid: {validation_result.is_valid}")
                if not validation_result.is_valid:
                    logger.warning(f"Integrity issues found: {len(validation_result.validation_errors)} errors")
            except Exception as e:
                logger.error(f"Background integrity check failed: {e}")
        
        background_tasks.add_task(integrity_check_task)
        
        return {
            "message": "Integrity check started",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to start integrity check: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start integrity check: {str(e)}")

@router.get("/recovery-operations")
async def list_recovery_operations(current_user: dict = Depends(require_admin)):
    """List recent recovery operations."""
    try:
        operations = []
        for op_id, operation in security_recovery_manager.recovery_operations.items():
            operations.append({
                "operation_id": operation.operation_id,
                "operation_type": operation.operation_type,
                "status": operation.status.value,
                "start_time": operation.start_time.isoformat(),
                "end_time": operation.end_time.isoformat() if operation.end_time else None,
                "recovered_files_count": len(operation.recovered_files),
                "failed_files_count": len(operation.failed_files),
                "error_count": len(operation.error_messages)
            })
        
        return {
            "operations": sorted(operations, key=lambda x: x["start_time"], reverse=True),
            "total_count": len(operations)
        }
    except Exception as e:
        logger.error(f"Failed to list recovery operations: {e}")
        raise HTTPException(status_code=500, detail="Failed to list recovery operations")

@router.get("/alerts/history")
async def get_alert_history(
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get recent security alert history."""
    try:
        alerts = security_error_system.alert_history[-limit:]
        return {
            "alerts": alerts,
            "total_count": len(security_error_system.alert_history),
            "returned_count": len(alerts)
        }
    except Exception as e:
        logger.error(f"Failed to get alert history: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alert history")

@router.post("/test-error")
async def test_error_handling(
    error_type: str = "test",
    severity: str = "medium",
    current_user: dict = Depends(require_admin)
):
    """Test the error handling system (admin only)."""
    try:
        # Create a test error context
        context = SecurityErrorContext(
            user_id=current_user.get("user_id"),
            session_id="test_session",
            operation="test_error_handling",
            resource="error_system_test"
        )
        
        # Create a test exception
        test_exception = Exception(f"Test {error_type} error for system validation")
        
        # Handle the error through the system
        security_error = handle_security_operation_error(
            "test_error_handling",
            test_exception,
            context,
            auto_recover=False
        )
        
        return {
            "message": "Test error handled successfully",
            "error_id": security_error.error_id,
            "category": security_error.category.value,
            "severity": security_error.severity.value,
            "recovery_actions_count": len(security_error.recovery_actions)
        }
    except Exception as e:
        logger.error(f"Test error handling failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test error handling failed: {str(e)}")

@router.put("/config")
async def update_error_config(
    config_updates: Dict[str, Any],
    current_user: dict = Depends(require_admin)
):
    """Update security error system configuration."""
    try:
        # This would update the configuration
        # For now, just return the current config
        current_config = security_error_system.alert_config.__dict__
        
        return {
            "message": "Configuration update requested",
            "current_config": current_config,
            "requested_updates": config_updates,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to update config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {str(e)}")

@router.get("/health")
async def health_check():
    """Health check endpoint for the security error system."""
    try:
        status = get_security_system_status()
        
        # Determine overall health
        all_services_operational = all(
            service_status == "operational" 
            for service_status in status["service_status"].values()
        )
        
        health_status = "healthy" if all_services_operational else "degraded"
        
        return {
            "status": health_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": status["service_status"],
            "recent_errors": len(status.get("recent_error_counts", {}))
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }