"""
Concurrency control and file locking for analysis pipeline
"""
import fcntl
import os
import time
import logging
import threading
from pathlib import Path
from typing import Optional, Dict, Any, Set
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta

from .config import settings

logger = logging.getLogger(__name__)


@dataclass
class LockInfo:
    """Information about an active lock"""
    lock_id: str
    repo_id: str
    analysis_id: str
    process_id: int
    thread_id: int
    created_at: datetime
    lock_type: str


class ConcurrencyError(Exception):
    """Base exception for concurrency-related errors"""
    pass


class LockAcquisitionError(ConcurrencyError):
    """Raised when lock cannot be acquired"""
    pass


class LockTimeoutError(ConcurrencyError):
    """Raised when lock acquisition times out"""
    pass


class FileLockManager:
    """File-based locking system for repository analysis"""
    
    def __init__(self):
        self.locks_dir = Path(settings.storage_base_path) / "locks"
        self.locks_dir.mkdir(parents=True, exist_ok=True)
        self.active_locks: Dict[str, LockInfo] = {}
        self.lock_timeout = 3600  # 1 hour default timeout
        self._local_locks: Set[str] = set()
        self._lock = threading.Lock()
    
    @contextmanager
    def acquire_repo_lock(
        self, 
        repo_id: str, 
        analysis_id: str, 
        lock_type: str = "analysis",
        timeout: Optional[int] = None
    ):
        """
        Acquire exclusive lock for repository analysis
        
        Args:
            repo_id: Repository identifier
            analysis_id: Analysis identifier
            lock_type: Type of lock (analysis, cleanup, etc.)
            timeout: Lock acquisition timeout in seconds
        """
        lock_id = f"{repo_id}_{lock_type}"
        lock_file = self.locks_dir / f"{lock_id}.lock"
        
        timeout = timeout or self.lock_timeout
        start_time = time.time()
        
        try:
            # Check for existing locks
            self._check_existing_locks(repo_id, analysis_id, lock_type)
            
            # Try to acquire file lock
            lock_fd = None
            while time.time() - start_time < timeout:
                try:
                    lock_fd = os.open(lock_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except (OSError, IOError) as e:
                    if lock_fd:
                        os.close(lock_fd)
                        lock_fd = None
                    
                    if e.errno in (11, 35):  # EAGAIN or EWOULDBLOCK
                        time.sleep(0.1)
                        continue
                    else:
                        raise LockAcquisitionError(f"Failed to acquire lock: {e}")
            
            if lock_fd is None:
                raise LockTimeoutError(f"Lock acquisition timed out after {timeout}s")
            
            # Write lock information
            lock_info = LockInfo(
                lock_id=lock_id,
                repo_id=repo_id,
                analysis_id=analysis_id,
                process_id=os.getpid(),
                thread_id=threading.get_ident(),
                created_at=datetime.now(),
                lock_type=lock_type
            )
            
            lock_content = f"{lock_info.process_id}|{lock_info.thread_id}|{lock_info.analysis_id}|{lock_info.created_at.isoformat()}"
            os.write(lock_fd, lock_content.encode())
            os.fsync(lock_fd)
            
            # Register lock
            with self._lock:
                self.active_locks[lock_id] = lock_info
                self._local_locks.add(lock_id)
            
            logger.info(f"Acquired lock {lock_id} for analysis {analysis_id}")
            
            try:
                yield lock_info
            finally:
                # Release lock
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    os.close(lock_fd)
                    lock_file.unlink(missing_ok=True)
                    
                    with self._lock:
                        self.active_locks.pop(lock_id, None)
                        self._local_locks.discard(lock_id)
                    
                    logger.info(f"Released lock {lock_id} for analysis {analysis_id}")
                    
                except Exception as e:
                    logger.error(f"Error releasing lock {lock_id}: {e}")
                
        except Exception as e:
            logger.error(f"Lock operation failed for {lock_id}: {e}")
            raise
    
    def _check_existing_locks(self, repo_id: str, analysis_id: str, lock_type: str):
        """Check for conflicting existing locks"""
        
        # Check for same repository locks
        conflicting_locks = []
        for lock_id, lock_info in self.active_locks.items():
            if (lock_info.repo_id == repo_id and 
                lock_info.analysis_id != analysis_id and
                self._is_lock_active(lock_info)):
                conflicting_locks.append(lock_info)
        
        if conflicting_locks:
            conflict_info = [f"{lock.analysis_id} ({lock.lock_type})" for lock in conflicting_locks]
            raise LockAcquisitionError(
                f"Repository {repo_id} is locked by other analyses: {', '.join(conflict_info)}"
            )
    
    def _is_lock_active(self, lock_info: LockInfo) -> bool:
        """Check if a lock is still active"""
        
        # Check if lock file exists
        lock_file = self.locks_dir / f"{lock_info.lock_id}.lock"
        if not lock_file.exists():
            return False
        
        # Check if lock is too old
        if datetime.now() - lock_info.created_at > timedelta(seconds=self.lock_timeout):
            logger.warning(f"Lock {lock_info.lock_id} is stale, considering inactive")
            return False
        
        # Check if process is still running (basic check)
        try:
            os.kill(lock_info.process_id, 0)
        except OSError:
            logger.warning(f"Process {lock_info.process_id} for lock {lock_info.lock_id} is not running")
            return False
        
        return True
    
    def cleanup_stale_locks(self):
        """Clean up stale locks"""
        try:
            current_time = datetime.now()
            stale_locks = []
            
            # Check file-based locks
            for lock_file in self.locks_dir.glob("*.lock"):
                try:
                    # Try to read lock info
                    with open(lock_file, 'r') as f:
                        content = f.read().strip()
                    
                    if '|' in content:
                        parts = content.split('|')
                        if len(parts) >= 4:
                            process_id = int(parts[0])
                            created_at = datetime.fromisoformat(parts[3])
                            
                            # Check if stale
                            if (current_time - created_at > timedelta(seconds=self.lock_timeout) or
                                not self._is_process_running(process_id)):
                                stale_locks.append(lock_file)
                
                except Exception as e:
                    logger.warning(f"Error checking lock file {lock_file}: {e}")
                    stale_locks.append(lock_file)
            
            # Remove stale locks
            for lock_file in stale_locks:
                try:
                    lock_file.unlink()
                    logger.info(f"Removed stale lock: {lock_file.name}")
                except Exception as e:
                    logger.error(f"Failed to remove stale lock {lock_file}: {e}")
            
            # Clean up in-memory locks
            with self._lock:
                stale_lock_ids = []
                for lock_id, lock_info in self.active_locks.items():
                    if not self._is_lock_active(lock_info):
                        stale_lock_ids.append(lock_id)
                
                for lock_id in stale_lock_ids:
                    self.active_locks.pop(lock_id, None)
                    self._local_locks.discard(lock_id)
        
        except Exception as e:
            logger.error(f"Error during lock cleanup: {e}")
    
    def _is_process_running(self, pid: int) -> bool:
        """Check if a process is running"""
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    
    def get_active_locks(self) -> Dict[str, LockInfo]:
        """Get all active locks"""
        with self._lock:
            return self.active_locks.copy()
    
    def is_repo_locked(self, repo_id: str) -> bool:
        """Check if repository is currently locked"""
        for lock_info in self.active_locks.values():
            if lock_info.repo_id == repo_id and self._is_lock_active(lock_info):
                return True
        return False
    
    def get_repo_locks(self, repo_id: str) -> List[LockInfo]:
        """Get all locks for a specific repository"""
        return [
            lock_info for lock_info in self.active_locks.values()
            if lock_info.repo_id == repo_id and self._is_lock_active(lock_info)
        ]


class AnalysisQueue:
    """Queue system for managing concurrent analyses"""
    
    def __init__(self, max_concurrent: Optional[int] = None):
        self.max_concurrent = max_concurrent or settings.max_concurrent_analyses
        self.active_analyses: Dict[str, Dict[str, Any]] = {}
        self.queued_analyses: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
    
    def can_start_analysis(self, repo_id: str) -> bool:
        """Check if analysis can be started"""
        with self._lock:
            # Check concurrent limit
            if len(self.active_analyses) >= self.max_concurrent:
                return False
            
            # Check if same repository is already being analyzed
            for analysis_info in self.active_analyses.values():
                if analysis_info.get('repo_id') == repo_id:
                    return False
            
            return True
    
    def start_analysis(self, analysis_id: str, repo_id: str, analysis_type: str = "full") -> bool:
        """Start an analysis if possible"""
        with self._lock:
            if not self.can_start_analysis(repo_id):
                # Add to queue
                self.queued_analyses.append({
                    'analysis_id': analysis_id,
                    'repo_id': repo_id,
                    'analysis_type': analysis_type,
                    'queued_at': datetime.now()
                })
                return False
            
            # Start analysis
            self.active_analyses[analysis_id] = {
                'analysis_id': analysis_id,
                'repo_id': repo_id,
                'analysis_type': analysis_type,
                'started_at': datetime.now()
            }
            
            return True
    
    def complete_analysis(self, analysis_id: str):
        """Mark analysis as completed and start queued analyses"""
        with self._lock:
            # Remove from active
            completed_analysis = self.active_analyses.pop(analysis_id, None)
            
            if completed_analysis:
                logger.info(f"Completed analysis {analysis_id} for repo {completed_analysis['repo_id']}")
            
            # Try to start queued analyses
            self._start_queued_analyses()
    
    def fail_analysis(self, analysis_id: str, error_message: str):
        """Mark analysis as failed"""
        with self._lock:
            failed_analysis = self.active_analyses.pop(analysis_id, None)
            
            if failed_analysis:
                logger.error(f"Failed analysis {analysis_id} for repo {failed_analysis['repo_id']}: {error_message}")
            
            # Try to start queued analyses
            self._start_queued_analyses()
    
    def _start_queued_analyses(self):
        """Start queued analyses if possible"""
        started_analyses = []
        
        for i, queued_analysis in enumerate(self.queued_analyses):
            if self.can_start_analysis(queued_analysis['repo_id']):
                # Move from queue to active
                analysis_id = queued_analysis['analysis_id']
                self.active_analyses[analysis_id] = {
                    **queued_analysis,
                    'started_at': datetime.now()
                }
                started_analyses.append(i)
                
                logger.info(f"Started queued analysis {analysis_id} for repo {queued_analysis['repo_id']}")
        
        # Remove started analyses from queue (in reverse order to maintain indices)
        for i in reversed(started_analyses):
            self.queued_analyses.pop(i)
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status"""
        with self._lock:
            return {
                'active_count': len(self.active_analyses),
                'queued_count': len(self.queued_analyses),
                'max_concurrent': self.max_concurrent,
                'active_analyses': list(self.active_analyses.keys()),
                'queued_analyses': [q['analysis_id'] for q in self.queued_analyses]
            }
    
    def get_analysis_position(self, analysis_id: str) -> Optional[int]:
        """Get position of analysis in queue (0-based, None if not queued)"""
        with self._lock:
            for i, queued_analysis in enumerate(self.queued_analyses):
                if queued_analysis['analysis_id'] == analysis_id:
                    return i
            return None


# Global instances
lock_manager = FileLockManager()
analysis_queue = AnalysisQueue()