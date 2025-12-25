"""
Storage management system for file organization, cleanup, and quota management
"""
import os
import shutil
import time
import json
import logging
import hashlib
import tarfile
import gzip
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum

from .config import settings

logger = logging.getLogger(__name__)


class StorageType(Enum):
    """Types of storage areas"""
    REPOSITORIES = "repositories"
    DOCUMENTS = "documents"
    EMBEDDINGS = "embeddings"
    CACHE = "cache"
    BACKUPS = "backups"
    TEMP = "temp"
    LOGS = "logs"


@dataclass
class StorageQuota:
    """Storage quota configuration"""
    max_size_gb: float
    warning_threshold_percent: float = 80.0
    cleanup_threshold_percent: float = 90.0
    retention_days: int = 30


@dataclass
class StorageStats:
    """Storage usage statistics"""
    total_size_bytes: int
    used_size_bytes: int
    available_size_bytes: int
    file_count: int
    directory_count: int
    oldest_file_date: Optional[datetime] = None
    newest_file_date: Optional[datetime] = None


@dataclass
class CleanupResult:
    """Result of cleanup operation"""
    files_removed: int
    directories_removed: int
    bytes_freed: int
    errors: List[str]


class StorageManager:
    """Comprehensive storage management system"""
    
    def __init__(self):
        self.base_path = Path(settings.storage_base_path)
        self.quotas = self._initialize_quotas()
        self.storage_paths = self._initialize_storage_structure()
        
        # Ensure all directories exist
        self._create_storage_directories()
        
        # Initialize storage metadata
        self.metadata_file = self.base_path / "storage_metadata.json"
        self._load_metadata()
    
    def _initialize_quotas(self) -> Dict[StorageType, StorageQuota]:
        """Initialize storage quotas for different areas"""
        return {
            StorageType.REPOSITORIES: StorageQuota(
                max_size_gb=10.0,  # 10GB for repositories
                retention_days=30
            ),
            StorageType.DOCUMENTS: StorageQuota(
                max_size_gb=5.0,   # 5GB for documents
                retention_days=90
            ),
            StorageType.EMBEDDINGS: StorageQuota(
                max_size_gb=2.0,   # 2GB for embeddings
                retention_days=60
            ),
            StorageType.CACHE: StorageQuota(
                max_size_gb=1.0,   # 1GB for cache
                retention_days=7
            ),
            StorageType.BACKUPS: StorageQuota(
                max_size_gb=20.0,  # 20GB for backups
                retention_days=180
            ),
            StorageType.TEMP: StorageQuota(
                max_size_gb=2.0,   # 2GB for temp files
                retention_days=1
            ),
            StorageType.LOGS: StorageQuota(
                max_size_gb=1.0,   # 1GB for logs
                retention_days=30
            )
        }
    
    def _initialize_storage_structure(self) -> Dict[StorageType, Path]:
        """Initialize storage directory structure"""
        return {
            StorageType.REPOSITORIES: self.base_path / "repos",
            StorageType.DOCUMENTS: self.base_path / "docs",
            StorageType.EMBEDDINGS: self.base_path / "embeddings",
            StorageType.CACHE: self.base_path / "cache",
            StorageType.BACKUPS: self.base_path / "backups",
            StorageType.TEMP: self.base_path / "temp",
            StorageType.LOGS: self.base_path / "logs"
        }
    
    def _create_storage_directories(self):
        """Create all storage directories with proper permissions"""
        for storage_type, path in self.storage_paths.items():
            try:
                path.mkdir(parents=True, exist_ok=True)
                
                # Set appropriate permissions (readable/writable by owner only)
                if os.name != 'nt':  # Unix-like systems
                    os.chmod(path, 0o750)
                
                logger.debug(f"Created storage directory: {path}")
                
            except Exception as e:
                logger.error(f"Failed to create storage directory {path}: {e}")
                raise
    
    def _load_metadata(self):
        """Load storage metadata"""
        self.metadata = {
            "created_at": datetime.now().isoformat(),
            "last_cleanup": None,
            "last_backup": None,
            "storage_version": "1.0",
            "quotas": {st.value: asdict(quota) for st, quota in self.quotas.items()}
        }
        
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    stored_metadata = json.load(f)
                    self.metadata.update(stored_metadata)
            except Exception as e:
                logger.warning(f"Failed to load storage metadata: {e}")
        
        self._save_metadata()
    
    def _save_metadata(self):
        """Save storage metadata"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save storage metadata: {e}")
    
    def get_storage_path(self, storage_type: StorageType) -> Path:
        """Get path for specific storage type"""
        return self.storage_paths[storage_type]
    
    def create_isolated_repo_directory(self, repo_id: str) -> Path:
        """Create isolated directory for repository with proper naming"""
        repo_dir = self.storage_paths[StorageType.REPOSITORIES] / f"repo_{repo_id}"
        
        # Ensure unique directory name
        counter = 1
        while repo_dir.exists():
            repo_dir = self.storage_paths[StorageType.REPOSITORIES] / f"repo_{repo_id}_{counter}"
            counter += 1
        
        repo_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories for organization
        (repo_dir / "source").mkdir(exist_ok=True)
        (repo_dir / "analysis").mkdir(exist_ok=True)
        (repo_dir / "metadata").mkdir(exist_ok=True)
        
        logger.info(f"Created isolated repository directory: {repo_dir}")
        return repo_dir
    
    def get_storage_stats(self, storage_type: Optional[StorageType] = None) -> Dict[str, StorageStats]:
        """Get storage statistics for one or all storage types"""
        stats = {}
        
        storage_types = [storage_type] if storage_type else list(StorageType)
        
        for st in storage_types:
            path = self.storage_paths[st]
            stats[st.value] = self._calculate_directory_stats(path)
        
        return stats
    
    def _calculate_directory_stats(self, path: Path) -> StorageStats:
        """Calculate statistics for a directory"""
        total_size = 0
        file_count = 0
        directory_count = 0
        oldest_date = None
        newest_date = None
        
        try:
            if not path.exists():
                return StorageStats(0, 0, 0, 0, 0)
            
            for root, dirs, files in os.walk(path):
                directory_count += len(dirs)
                
                for file in files:
                    file_path = Path(root) / file
                    try:
                        stat = file_path.stat()
                        total_size += stat.st_size
                        file_count += 1
                        
                        file_date = datetime.fromtimestamp(stat.st_mtime)
                        if oldest_date is None or file_date < oldest_date:
                            oldest_date = file_date
                        if newest_date is None or file_date > newest_date:
                            newest_date = file_date
                            
                    except (OSError, IOError):
                        continue
            
            # Get available space
            disk_usage = shutil.disk_usage(path)
            available_size = disk_usage.free
            
        except Exception as e:
            logger.error(f"Error calculating stats for {path}: {e}")
            return StorageStats(0, 0, 0, 0, 0)
        
        return StorageStats(
            total_size_bytes=disk_usage.total,
            used_size_bytes=total_size,
            available_size_bytes=available_size,
            file_count=file_count,
            directory_count=directory_count,
            oldest_file_date=oldest_date,
            newest_file_date=newest_date
        )
    
    def check_quota_usage(self, storage_type: StorageType) -> Dict[str, Any]:
        """Check quota usage for a storage type"""
        stats = self._calculate_directory_stats(self.storage_paths[storage_type])
        quota = self.quotas[storage_type]
        
        max_bytes = quota.max_size_gb * 1024 * 1024 * 1024
        usage_percent = (stats.used_size_bytes / max_bytes) * 100 if max_bytes > 0 else 0
        
        status = "ok"
        if usage_percent >= quota.cleanup_threshold_percent:
            status = "critical"
        elif usage_percent >= quota.warning_threshold_percent:
            status = "warning"
        
        return {
            "storage_type": storage_type.value,
            "used_bytes": stats.used_size_bytes,
            "max_bytes": max_bytes,
            "usage_percent": usage_percent,
            "status": status,
            "warning_threshold": quota.warning_threshold_percent,
            "cleanup_threshold": quota.cleanup_threshold_percent,
            "needs_cleanup": usage_percent >= quota.cleanup_threshold_percent
        }
    
    def cleanup_old_files(
        self, 
        storage_type: StorageType, 
        max_age_days: Optional[int] = None,
        dry_run: bool = False
    ) -> CleanupResult:
        """Clean up old files in a storage area"""
        
        max_age_days = max_age_days or self.quotas[storage_type].retention_days
        cutoff_time = time.time() - (max_age_days * 24 * 60 * 60)
        
        path = self.storage_paths[storage_type]
        result = CleanupResult(0, 0, 0, [])
        
        try:
            for root, dirs, files in os.walk(path, topdown=False):
                # Clean up files
                for file in files:
                    file_path = Path(root) / file
                    try:
                        if file_path.stat().st_mtime < cutoff_time:
                            file_size = file_path.stat().st_size
                            
                            if not dry_run:
                                file_path.unlink()
                            
                            result.files_removed += 1
                            result.bytes_freed += file_size
                            
                            logger.debug(f"{'Would remove' if dry_run else 'Removed'} old file: {file_path}")
                            
                    except Exception as e:
                        error_msg = f"Failed to remove file {file_path}: {e}"
                        result.errors.append(error_msg)
                        logger.warning(error_msg)
                
                # Clean up empty directories
                for dir_name in dirs:
                    dir_path = Path(root) / dir_name
                    try:
                        if not any(dir_path.iterdir()):  # Directory is empty
                            if not dry_run:
                                dir_path.rmdir()
                            
                            result.directories_removed += 1
                            logger.debug(f"{'Would remove' if dry_run else 'Removed'} empty directory: {dir_path}")
                            
                    except Exception as e:
                        error_msg = f"Failed to remove directory {dir_path}: {e}"
                        result.errors.append(error_msg)
                        logger.warning(error_msg)
        
        except Exception as e:
            error_msg = f"Error during cleanup of {storage_type.value}: {e}"
            result.errors.append(error_msg)
            logger.error(error_msg)
        
        if not dry_run:
            self.metadata["last_cleanup"] = datetime.now().isoformat()
            self._save_metadata()
        
        logger.info(
            f"Cleanup {'simulation' if dry_run else 'completed'} for {storage_type.value}: "
            f"{result.files_removed} files, {result.directories_removed} dirs, "
            f"{result.bytes_freed / 1024 / 1024:.1f}MB freed"
        )
        
        return result
    
    def cleanup_failed_analyses(self, max_age_hours: int = 24) -> CleanupResult:
        """Clean up temporary files from failed analyses"""
        cutoff_time = time.time() - (max_age_hours * 60 * 60)
        result = CleanupResult(0, 0, 0, [])
        
        # Clean up temp directory
        temp_path = self.storage_paths[StorageType.TEMP]
        
        try:
            for item in temp_path.iterdir():
                try:
                    if item.stat().st_mtime < cutoff_time:
                        if item.is_file():
                            size = item.stat().st_size
                            item.unlink()
                            result.files_removed += 1
                            result.bytes_freed += size
                        elif item.is_dir():
                            shutil.rmtree(item)
                            result.directories_removed += 1
                        
                        logger.debug(f"Cleaned up failed analysis artifact: {item}")
                        
                except Exception as e:
                    error_msg = f"Failed to clean up {item}: {e}"
                    result.errors.append(error_msg)
                    logger.warning(error_msg)
        
        except Exception as e:
            error_msg = f"Error cleaning up failed analyses: {e}"
            result.errors.append(error_msg)
            logger.error(error_msg)
        
        return result
    
    def create_backup(self, storage_types: Optional[List[StorageType]] = None) -> Dict[str, Any]:
        """Create backup of specified storage areas"""
        storage_types = storage_types or [StorageType.DOCUMENTS, StorageType.EMBEDDINGS]
        
        backup_id = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        backup_dir = self.storage_paths[StorageType.BACKUPS] / backup_id
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        backup_info = {
            "backup_id": backup_id,
            "created_at": datetime.now().isoformat(),
            "storage_types": [st.value for st in storage_types],
            "files": [],
            "total_size": 0,
            "success": True,
            "errors": []
        }
        
        try:
            for storage_type in storage_types:
                source_path = self.storage_paths[storage_type]
                
                if not source_path.exists() or not any(source_path.iterdir()):
                    continue
                
                # Create compressed archive
                archive_name = f"{storage_type.value}.tar.gz"
                archive_path = backup_dir / archive_name
                
                try:
                    with tarfile.open(archive_path, 'w:gz') as tar:
                        tar.add(source_path, arcname=storage_type.value)
                    
                    archive_size = archive_path.stat().st_size
                    backup_info["files"].append({
                        "storage_type": storage_type.value,
                        "archive_name": archive_name,
                        "size_bytes": archive_size
                    })
                    backup_info["total_size"] += archive_size
                    
                    logger.info(f"Created backup archive: {archive_path} ({archive_size / 1024 / 1024:.1f}MB)")
                    
                except Exception as e:
                    error_msg = f"Failed to backup {storage_type.value}: {e}"
                    backup_info["errors"].append(error_msg)
                    logger.error(error_msg)
            
            # Save backup metadata
            metadata_file = backup_dir / "backup_info.json"
            with open(metadata_file, 'w') as f:
                json.dump(backup_info, f, indent=2)
            
            # Update global metadata
            self.metadata["last_backup"] = datetime.now().isoformat()
            self._save_metadata()
            
        except Exception as e:
            backup_info["success"] = False
            backup_info["errors"].append(f"Backup failed: {e}")
            logger.error(f"Backup creation failed: {e}")
        
        return backup_info
    
    def restore_backup(self, backup_id: str) -> Dict[str, Any]:
        """Restore from a backup"""
        backup_dir = self.storage_paths[StorageType.BACKUPS] / backup_id
        
        if not backup_dir.exists():
            raise ValueError(f"Backup {backup_id} not found")
        
        # Load backup metadata
        metadata_file = backup_dir / "backup_info.json"
        if not metadata_file.exists():
            raise ValueError(f"Backup metadata not found for {backup_id}")
        
        with open(metadata_file, 'r') as f:
            backup_info = json.load(f)
        
        restore_info = {
            "backup_id": backup_id,
            "restored_at": datetime.now().isoformat(),
            "restored_files": [],
            "success": True,
            "errors": []
        }
        
        try:
            for file_info in backup_info["files"]:
                storage_type = StorageType(file_info["storage_type"])
                archive_path = backup_dir / file_info["archive_name"]
                target_path = self.storage_paths[storage_type]
                
                # Backup existing data
                if target_path.exists():
                    backup_existing = target_path.parent / f"{target_path.name}_backup_{int(time.time())}"
                    shutil.move(target_path, backup_existing)
                
                # Extract archive
                try:
                    with tarfile.open(archive_path, 'r:gz') as tar:
                        tar.extractall(target_path.parent)
                    
                    restore_info["restored_files"].append(file_info["storage_type"])
                    logger.info(f"Restored {storage_type.value} from backup")
                    
                except Exception as e:
                    error_msg = f"Failed to restore {storage_type.value}: {e}"
                    restore_info["errors"].append(error_msg)
                    logger.error(error_msg)
        
        except Exception as e:
            restore_info["success"] = False
            restore_info["errors"].append(f"Restore failed: {e}")
            logger.error(f"Backup restore failed: {e}")
        
        return restore_info
    
    def get_backup_list(self) -> List[Dict[str, Any]]:
        """Get list of available backups"""
        backups = []
        backup_dir = self.storage_paths[StorageType.BACKUPS]
        
        try:
            for item in backup_dir.iterdir():
                if item.is_dir() and item.name.startswith("backup_"):
                    metadata_file = item / "backup_info.json"
                    
                    if metadata_file.exists():
                        try:
                            with open(metadata_file, 'r') as f:
                                backup_info = json.load(f)
                                backups.append(backup_info)
                        except Exception as e:
                            logger.warning(f"Failed to read backup metadata {metadata_file}: {e}")
        
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
        
        return sorted(backups, key=lambda x: x["created_at"], reverse=True)
    
    def perform_maintenance(self) -> Dict[str, Any]:
        """Perform comprehensive storage maintenance"""
        maintenance_result = {
            "started_at": datetime.now().isoformat(),
            "operations": {},
            "overall_success": True
        }
        
        try:
            # Check quotas and perform cleanup if needed
            for storage_type in StorageType:
                if storage_type == StorageType.BACKUPS:
                    continue  # Don't auto-cleanup backups
                
                quota_check = self.check_quota_usage(storage_type)
                maintenance_result["operations"][f"{storage_type.value}_quota"] = quota_check
                
                if quota_check["needs_cleanup"]:
                    cleanup_result = self.cleanup_old_files(storage_type)
                    maintenance_result["operations"][f"{storage_type.value}_cleanup"] = {
                        "files_removed": cleanup_result.files_removed,
                        "directories_removed": cleanup_result.directories_removed,
                        "bytes_freed": cleanup_result.bytes_freed,
                        "errors": cleanup_result.errors
                    }
            
            # Clean up failed analyses
            failed_cleanup = self.cleanup_failed_analyses()
            maintenance_result["operations"]["failed_analyses_cleanup"] = {
                "files_removed": failed_cleanup.files_removed,
                "directories_removed": failed_cleanup.directories_removed,
                "bytes_freed": failed_cleanup.bytes_freed,
                "errors": failed_cleanup.errors
            }
            
            # Create backup if it's been more than a week
            last_backup = self.metadata.get("last_backup")
            if (not last_backup or 
                datetime.now() - datetime.fromisoformat(last_backup) > timedelta(days=7)):
                
                backup_result = self.create_backup()
                maintenance_result["operations"]["backup"] = backup_result
            
        except Exception as e:
            maintenance_result["overall_success"] = False
            maintenance_result["error"] = str(e)
            logger.error(f"Maintenance operation failed: {e}")
        
        maintenance_result["completed_at"] = datetime.now().isoformat()
        return maintenance_result
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall storage system health"""
        health = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "storage_areas": {},
            "warnings": [],
            "errors": []
        }
        
        try:
            for storage_type in StorageType:
                quota_check = self.check_quota_usage(storage_type)
                stats = self._calculate_directory_stats(self.storage_paths[storage_type])
                
                area_health = {
                    "quota_status": quota_check["status"],
                    "usage_percent": quota_check["usage_percent"],
                    "file_count": stats.file_count,
                    "used_mb": stats.used_size_bytes / 1024 / 1024,
                    "available_mb": stats.available_size_bytes / 1024 / 1024
                }
                
                health["storage_areas"][storage_type.value] = area_health
                
                # Collect warnings and errors
                if quota_check["status"] == "warning":
                    health["warnings"].append(f"{storage_type.value} storage usage is high ({quota_check['usage_percent']:.1f}%)")
                elif quota_check["status"] == "critical":
                    health["errors"].append(f"{storage_type.value} storage is critically full ({quota_check['usage_percent']:.1f}%)")
            
            # Determine overall status
            if health["errors"]:
                health["status"] = "critical"
            elif health["warnings"]:
                health["status"] = "warning"
        
        except Exception as e:
            health["status"] = "error"
            health["errors"].append(f"Health check failed: {e}")
            logger.error(f"Storage health check failed: {e}")
        
        return health


# Global storage manager instance
storage_manager = StorageManager()