"""
Storage management system for file organization, cleanup, and quota management
Migrated from api/storage_manager.py with backend integration.
"""
import os
import shutil
import time
import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum

from ..config.settings import settings

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
            StorageType.REPOSITORIES: StorageQuota(max_size_gb=10.0, retention_days=90),
            StorageType.DOCUMENTS: StorageQuota(max_size_gb=5.0, retention_days=180),
            StorageType.EMBEDDINGS: StorageQuota(max_size_gb=2.0, retention_days=30),
            StorageType.CACHE: StorageQuota(max_size_gb=1.0, retention_days=7),
            StorageType.BACKUPS: StorageQuota(max_size_gb=20.0, retention_days=365),
            StorageType.TEMP: StorageQuota(max_size_gb=1.0, retention_days=1),
            StorageType.LOGS: StorageQuota(max_size_gb=1.0, retention_days=30)
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
        """Create all storage directories"""
        for storage_type, path in self.storage_paths.items():
            try:
                path.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Created storage directory: {path}")
            except Exception as e:
                logger.error(f"Failed to create storage directory {path}: {e}")
                raise
    
    def _load_metadata(self):
        """Load storage metadata"""
        try:
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r') as f:
                    self.metadata = json.load(f)
            else:
                self.metadata = {
                    "created_at": datetime.utcnow().isoformat(),
                    "last_cleanup": None,
                    "total_cleanups": 0
                }
                self._save_metadata()
        except Exception as e:
            logger.error(f"Failed to load storage metadata: {e}")
            self.metadata = {}
    
    def _save_metadata(self):
        """Save storage metadata"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save storage metadata: {e}")
    
    def get_storage_path(self, storage_type: StorageType) -> Path:
        """Get path for storage type"""
        return self.storage_paths[storage_type]
    
    def get_storage_stats(self, storage_type: Optional[StorageType] = None) -> Dict[StorageType, StorageStats]:
        """Get storage statistics"""
        stats = {}
        
        storage_types = [storage_type] if storage_type else list(StorageType)
        
        for stype in storage_types:
            path = self.storage_paths[stype]
            if path.exists():
                stats[stype] = self._calculate_directory_stats(path)
            else:
                stats[stype] = StorageStats(
                    total_size_bytes=0,
                    used_size_bytes=0,
                    available_size_bytes=0,
                    file_count=0,
                    directory_count=0
                )
        
        return stats
    
    def _calculate_directory_stats(self, path: Path) -> StorageStats:
        """Calculate statistics for a directory"""
        total_size = 0
        file_count = 0
        directory_count = 0
        oldest_date = None
        newest_date = None
        
        try:
            for item in path.rglob("*"):
                if item.is_file():
                    file_count += 1
                    size = item.stat().st_size
                    total_size += size
                    
                    # Track dates
                    mtime = datetime.fromtimestamp(item.stat().st_mtime)
                    if oldest_date is None or mtime < oldest_date:
                        oldest_date = mtime
                    if newest_date is None or mtime > newest_date:
                        newest_date = mtime
                        
                elif item.is_dir():
                    directory_count += 1
        
        except Exception as e:
            logger.error(f"Error calculating stats for {path}: {e}")
        
        return StorageStats(
            total_size_bytes=total_size,
            used_size_bytes=total_size,
            available_size_bytes=0,  # Would need disk space calculation
            file_count=file_count,
            directory_count=directory_count,
            oldest_file_date=oldest_date,
            newest_file_date=newest_date
        )
    
    def cleanup_storage(self, storage_type: Optional[StorageType] = None, force: bool = False) -> Dict[StorageType, CleanupResult]:
        """Clean up storage areas"""
        results = {}
        
        storage_types = [storage_type] if storage_type else list(StorageType)
        
        for stype in storage_types:
            try:
                result = self._cleanup_storage_type(stype, force)
                results[stype] = result
                logger.info(f"Cleanup completed for {stype.value}: {result.files_removed} files, {result.bytes_freed} bytes freed")
            except Exception as e:
                logger.error(f"Cleanup failed for {stype.value}: {e}")
                results[stype] = CleanupResult(0, 0, 0, [str(e)])
        
        # Update metadata
        self.metadata["last_cleanup"] = datetime.utcnow().isoformat()
        self.metadata["total_cleanups"] = self.metadata.get("total_cleanups", 0) + 1
        self._save_metadata()
        
        return results
    
    def _cleanup_storage_type(self, storage_type: StorageType, force: bool) -> CleanupResult:
        """Clean up a specific storage type"""
        path = self.storage_paths[storage_type]
        quota = self.quotas[storage_type]
        
        files_removed = 0
        directories_removed = 0
        bytes_freed = 0
        errors = []
        
        if not path.exists():
            return CleanupResult(0, 0, 0, [])
        
        # Calculate cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=quota.retention_days)
        
        try:
            for item in path.rglob("*"):
                if item.is_file():
                    try:
                        mtime = datetime.fromtimestamp(item.stat().st_mtime)
                        if force or mtime < cutoff_date:
                            size = item.stat().st_size
                            item.unlink()
                            files_removed += 1
                            bytes_freed += size
                    except Exception as e:
                        errors.append(f"Failed to remove file {item}: {e}")
            
            # Remove empty directories
            for item in sorted(path.rglob("*"), key=lambda p: len(p.parts), reverse=True):
                if item.is_dir() and not any(item.iterdir()):
                    try:
                        item.rmdir()
                        directories_removed += 1
                    except Exception as e:
                        errors.append(f"Failed to remove directory {item}: {e}")
        
        except Exception as e:
            errors.append(f"General cleanup error: {e}")
        
        return CleanupResult(files_removed, directories_removed, bytes_freed, errors)
    
    def create_backup(self, storage_type: StorageType, backup_name: Optional[str] = None) -> str:
        """Create backup of storage area"""
        if not backup_name:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{storage_type.value}_{timestamp}.tar.gz"
        
        source_path = self.storage_paths[storage_type]
        backup_path = self.storage_paths[StorageType.BACKUPS] / backup_name
        
        try:
            with tarfile.open(backup_path, "w:gz") as tar:
                tar.add(source_path, arcname=storage_type.value)
            
            logger.info(f"Created backup: {backup_path}")
            return str(backup_path)
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            raise
    
    def restore_backup(self, backup_path: str, storage_type: StorageType):
        """Restore from backup"""
        backup_file = Path(backup_path)
        if not backup_file.exists():
            raise FileNotFoundError(f"Backup file not found: {backup_path}")
        
        target_path = self.storage_paths[storage_type]
        
        try:
            # Create backup of current state
            current_backup = self.create_backup(storage_type, f"pre_restore_{int(time.time())}")
            
            # Clear target directory
            if target_path.exists():
                shutil.rmtree(target_path)
            
            # Extract backup
            with tarfile.open(backup_file, "r:gz") as tar:
                tar.extractall(target_path.parent)
            
            logger.info(f"Restored backup from {backup_path}")
            
        except Exception as e:
            logger.error(f"Backup restore failed: {e}")
            raise


# Global storage manager instance
_storage_manager: Optional[StorageManager] = None


def get_storage_manager() -> StorageManager:
    """Get the global storage manager instance"""
    global _storage_manager
    if _storage_manager is None:
        _storage_manager = StorageManager()
    return _storage_manager


# Backward compatibility
storage_manager = get_storage_manager()