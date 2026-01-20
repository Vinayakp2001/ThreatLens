"""
Repository ingestion and structure analysis module
"""
import os
import shutil
import subprocess
import uuid
import re
import time
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse
import logging

# Handle both relative and absolute imports
try:
    from .models import RepoContext, StructureAnalysis
    from .config import settings
    from .storage_manager import storage_manager
except ImportError:
    from models import RepoContext, StructureAnalysis
    from config import settings
    from storage_manager import storage_manager

logger = logging.getLogger(__name__)
DEBUG_ANALYSIS = logging.getLogger('DEBUG_ANALYSIS')


class RepoIngestorError(Exception):
    """Base exception for repository ingestion errors"""
    def __init__(self, message: str, error_code: str = "REPO_ERROR", details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}


class InvalidRepositoryError(RepoIngestorError):
    """Raised when repository URL or path is invalid"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "INVALID_REPOSITORY", details)


class AccessDeniedError(RepoIngestorError):
    """Raised when repository access is denied"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "ACCESS_DENIED", details)


class RepositoryTooLargeError(RepoIngestorError):
    """Raised when repository exceeds size limits"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "REPOSITORY_TOO_LARGE", details)


class RepositoryTimeoutError(RepoIngestorError):
    """Raised when repository operations timeout"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "REPOSITORY_TIMEOUT", details)


class UnsupportedRepositoryError(RepoIngestorError):
    """Raised when repository type is not supported"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "UNSUPPORTED_REPOSITORY", details)


class NetworkError(RepoIngestorError):
    """Raised when network-related errors occur"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "NETWORK_ERROR", details)


class RepositoryValidator:
    """Validates repository URLs and paths with comprehensive checks"""
    
    SUPPORTED_HOSTS = {
        'github.com': {'protocols': ['https', 'git'], 'requires_auth': False},
        'gitlab.com': {'protocols': ['https', 'git'], 'requires_auth': False},
        'bitbucket.org': {'protocols': ['https', 'git'], 'requires_auth': False},
        'dev.azure.com': {'protocols': ['https'], 'requires_auth': True},
        'ssh.dev.azure.com': {'protocols': ['ssh'], 'requires_auth': True}
    }
    
    DANGEROUS_PATHS = [
        '/etc', '/usr', '/var', '/bin', '/sbin', '/boot', '/sys', '/proc',
        'C:\\Windows', 'C:\\Program Files', 'C:\\System32'
    ]
    
    @classmethod
    def validate_repository_url(cls, repo_url: str, allowed_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Comprehensive repository URL validation
        
        Args:
            repo_url: Repository URL to validate
            allowed_hosts: Optional list of allowed hosts (overrides settings)
            
        Returns:
            Dictionary with validation results and metadata
            
        Raises:
            InvalidRepositoryError: If URL is invalid
            UnsupportedRepositoryError: If repository type is not supported
        """
        if not repo_url or not isinstance(repo_url, str):
            raise InvalidRepositoryError(
                "Repository URL cannot be empty or non-string",
                {"provided_url": str(repo_url)}
            )
        
        repo_url = repo_url.strip()
        
        # Parse URL
        try:
            parsed = urlparse(repo_url)
        except Exception as e:
            raise InvalidRepositoryError(
                f"Invalid URL format: {str(e)}",
                {"provided_url": repo_url}
            )
        
        if not parsed.scheme or not parsed.netloc:
            raise InvalidRepositoryError(
                "URL must include protocol (https://) and hostname",
                {"provided_url": repo_url, "parsed_scheme": parsed.scheme, "parsed_netloc": parsed.netloc}
            )
        
        # Check protocol
        if parsed.scheme not in ['https', 'http', 'git', 'ssh']:
            raise UnsupportedRepositoryError(
                f"Unsupported protocol: {parsed.scheme}. Supported: https, http, git, ssh",
                {"provided_url": repo_url, "protocol": parsed.scheme}
            )
        
        # Security check: reject http in production
        if parsed.scheme == 'http' and not settings.debug:
            raise InvalidRepositoryError(
                "HTTP URLs are not allowed in production. Use HTTPS instead.",
                {"provided_url": repo_url, "protocol": parsed.scheme}
            )
        
        # Check allowed hosts
        allowed_hosts = allowed_hosts or settings.allowed_repo_hosts
        if allowed_hosts and parsed.netloc not in allowed_hosts:
            raise InvalidRepositoryError(
                f"Repository host '{parsed.netloc}' is not in allowed hosts",
                {
                    "provided_url": repo_url,
                    "host": parsed.netloc,
                    "allowed_hosts": allowed_hosts
                }
            )
        
        # Check if host is known and supported
        host_info = cls.SUPPORTED_HOSTS.get(parsed.netloc, {})
        if parsed.netloc in cls.SUPPORTED_HOSTS:
            supported_protocols = host_info.get('protocols', [])
            if parsed.scheme not in supported_protocols:
                raise UnsupportedRepositoryError(
                    f"Protocol '{parsed.scheme}' not supported for host '{parsed.netloc}'. "
                    f"Supported protocols: {supported_protocols}",
                    {
                        "provided_url": repo_url,
                        "host": parsed.netloc,
                        "protocol": parsed.scheme,
                        "supported_protocols": supported_protocols
                    }
                )
        
        # Validate repository path format
        path = parsed.path.strip('/')
        if not path:
            raise InvalidRepositoryError(
                "Repository path cannot be empty",
                {"provided_url": repo_url, "path": parsed.path}
            )
        
        # Check for valid repository path patterns
        if not cls._is_valid_repo_path(path):
            raise InvalidRepositoryError(
                "Invalid repository path format. Expected format: owner/repository",
                {"provided_url": repo_url, "path": path}
            )
        
        # Extract repository information
        path_parts = path.split('/')
        owner = path_parts[0] if len(path_parts) > 0 else None
        repo_name = path_parts[1] if len(path_parts) > 1 else None
        
        # Remove .git suffix if present
        if repo_name and repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        
        return {
            "is_valid": True,
            "url": repo_url,
            "protocol": parsed.scheme,
            "host": parsed.netloc,
            "owner": owner,
            "repository": repo_name,
            "requires_auth": host_info.get('requires_auth', False),
            "host_supported": parsed.netloc in cls.SUPPORTED_HOSTS
        }
    
    @classmethod
    def validate_local_path(cls, local_path: str) -> Dict[str, Any]:
        """
        Comprehensive local path validation
        
        Args:
            local_path: Local path to validate
            
        Returns:
            Dictionary with validation results and metadata
            
        Raises:
            InvalidRepositoryError: If path is invalid
            AccessDeniedError: If path access is denied
        """
        if not local_path or not isinstance(local_path, str):
            raise InvalidRepositoryError(
                "Local path cannot be empty or non-string",
                {"provided_path": str(local_path)}
            )
        
        local_path = local_path.strip()
        
        # Convert to Path object for better handling
        try:
            path = Path(local_path).resolve()
        except Exception as e:
            raise InvalidRepositoryError(
                f"Invalid path format: {str(e)}",
                {"provided_path": local_path}
            )
        
        # Security check: prevent access to dangerous system paths
        path_str = str(path).lower()
        for dangerous_path in cls.DANGEROUS_PATHS:
            if path_str.startswith(dangerous_path.lower()):
                raise AccessDeniedError(
                    f"Access to system directory '{dangerous_path}' is not allowed",
                    {"provided_path": local_path, "resolved_path": str(path)}
                )
        
        # Check if path exists
        if not path.exists():
            raise InvalidRepositoryError(
                f"Path does not exist: {local_path}",
                {"provided_path": local_path, "resolved_path": str(path)}
            )
        
        # Check if it's a directory
        if not path.is_dir():
            raise InvalidRepositoryError(
                f"Path is not a directory: {local_path}",
                {"provided_path": local_path, "resolved_path": str(path), "is_file": path.is_file()}
            )
        
        # Check read permissions
        if not os.access(path, os.R_OK):
            raise AccessDeniedError(
                f"No read permission for path: {local_path}",
                {"provided_path": local_path, "resolved_path": str(path)}
            )
        
        # Check if it looks like a repository (has .git or common project files)
        is_git_repo = (path / ".git").exists()
        has_project_files = any(
            (path / filename).exists() 
            for filename in ['package.json', 'requirements.txt', 'pom.xml', 'Cargo.toml', 'go.mod']
        )
        
        # Get basic directory info
        try:
            file_count = len([f for f in path.rglob('*') if f.is_file()])
            dir_count = len([d for d in path.rglob('*') if d.is_dir()])
        except PermissionError:
            raise AccessDeniedError(
                f"Insufficient permissions to read directory contents: {local_path}",
                {"provided_path": local_path, "resolved_path": str(path)}
            )
        except Exception as e:
            logger.warning(f"Could not count files in {path}: {e}")
            file_count = 0
            dir_count = 0
        
        return {
            "is_valid": True,
            "path": str(path),
            "original_path": local_path,
            "is_git_repo": is_git_repo,
            "has_project_files": has_project_files,
            "file_count": file_count,
            "directory_count": dir_count,
            "is_readable": True
        }
    
    @classmethod
    def _is_valid_repo_path(cls, path: str) -> bool:
        """Check if repository path follows valid patterns"""
        # Basic pattern: owner/repository
        if '/' not in path:
            return False
        
        parts = path.split('/')
        if len(parts) < 2:
            return False
        
        # Check owner and repo name patterns
        owner_pattern = r'^[a-zA-Z0-9._-]+$'
        repo_pattern = r'^[a-zA-Z0-9._-]+(?:\.git)?$'
        
        owner = parts[0]
        repo = parts[1]
        
        return (
            re.match(owner_pattern, owner) is not None and
            re.match(repo_pattern, repo) is not None and
            len(owner) > 0 and len(repo) > 0
        )


class RepoIngestor:
    """Handles repository cloning, local access, and basic structure analysis"""
    
    def __init__(self, settings):
        self.settings = settings
        self.storage_path = Path(settings.repos_storage_path)
        self.max_size_bytes = settings.max_repo_size_mb * 1024 * 1024
        self.timeout_seconds = settings.analysis_timeout_minutes * 60
        self.validator = RepositoryValidator()
        
        # Ensure storage directory exists
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
    def clone_repository(self, repo_url: str, target_dir: Optional[str] = None) -> RepoContext:
        """
        Clone a Git repository from URL with comprehensive error handling
        
        Args:
            repo_url: Git repository URL
            target_dir: Optional target directory name
            
        Returns:
            RepoContext with repository metadata
            
        Raises:
            InvalidRepositoryError: If URL is invalid or unsupported
            AccessDeniedError: If repository access is denied
            RepositoryTooLargeError: If repository exceeds size limits
            RepositoryTimeoutError: If cloning times out
            NetworkError: If network issues occur
        """
        # Validate repository URL
        validation_result = self.validator.validate_repository_url(repo_url)
        
        # Generate unique repo ID and target path
        repo_id = str(uuid.uuid4())
        if target_dir is None:
            target_dir = f"repo_{repo_id}"
        
        # Use storage manager to create isolated directory
        repo_dir = storage_manager.create_isolated_repo_directory(repo_id)
        local_path = repo_dir / "source"
        
        start_time = time.time()
        
        try:
            # Ensure storage directory exists
            self.storage_path.mkdir(parents=True, exist_ok=True)
            
            # Check available disk space
            self._check_disk_space(local_path.parent)
            
            # Clone repository with timeout
            logger.info(f"Cloning repository {repo_url} to {local_path}")
            
            clone_cmd = [
                "git", "clone", 
                "--depth", "1",  # Shallow clone for faster download
                "--single-branch",  # Only clone default branch
                repo_url, 
                str(local_path)
            ]
            
            result = subprocess.run(
                clone_cmd,
                capture_output=True, 
                text=True, 
                timeout=self.timeout_seconds
            )
            
            if result.returncode != 0:
                error_msg = result.stderr.strip()
                # Check if this is a Windows checkout failure (clone succeeded but checkout failed)
                if any(phrase in error_msg.lower() for phrase in [
                    'clone succeeded, but checkout failed', 'unable to write file',
                    'filename too long', 'path too long'
                ]):
                    # Log warning but continue - the repository was cloned successfully
                    logger.warning(f"Windows checkout issue (continuing with analysis): {error_msg}")
                else:
                    # Handle other Git errors normally
                    self._handle_git_error(error_msg, repo_url, validation_result)
            
            # Verify clone was successful
            if not local_path.exists() or not (local_path / ".git").exists():
                raise RepoIngestorError(
                    "Repository cloning appeared successful but directory is missing or invalid",
                    "CLONE_VERIFICATION_FAILED",
                    {"repo_url": repo_url, "local_path": str(local_path)}
                )
            
            # Check repository size
            repo_size = self._get_directory_size(local_path)
            if repo_size > self.max_size_bytes:
                shutil.rmtree(local_path, ignore_errors=True)
                raise RepositoryTooLargeError(
                    f"Repository size ({repo_size / 1024 / 1024:.1f}MB) exceeds limit "
                    f"({self.settings.max_repo_size_mb}MB)",
                    {
                        "repo_url": repo_url,
                        "size_bytes": repo_size,
                        "limit_bytes": self.max_size_bytes,
                        "size_mb": repo_size / 1024 / 1024,
                        "limit_mb": self.settings.max_repo_size_mb
                    }
                )
            
            # Get additional repository metadata
            repo_metadata = self._extract_repo_metadata(local_path, validation_result)
            
            # Create RepoContext
            repo_context = RepoContext(
                repo_id=repo_id,
                repo_url=repo_url,
                local_path=str(local_path),
                analysis_status="cloned"
            )
            
            clone_time = time.time() - start_time
            logger.info(
                f"Successfully cloned repository {repo_url} (ID: {repo_id}) "
                f"in {clone_time:.2f}s, size: {repo_size / 1024 / 1024:.1f}MB"
            )
            
            return repo_context
            
        except subprocess.TimeoutExpired:
            if local_path.exists():
                shutil.rmtree(local_path, ignore_errors=True)
            raise RepositoryTimeoutError(
                f"Repository cloning timed out after {self.timeout_seconds} seconds",
                {
                    "repo_url": repo_url,
                    "timeout_seconds": self.timeout_seconds,
                    "elapsed_time": time.time() - start_time
                }
            )
        except (RepoIngestorError, InvalidRepositoryError, AccessDeniedError, 
                RepositoryTooLargeError, RepositoryTimeoutError, NetworkError):
            # Clean up on known errors
            if local_path.exists():
                shutil.rmtree(local_path, ignore_errors=True)
            raise
        except Exception as e:
            # Clean up on unexpected errors
            if local_path.exists():
                shutil.rmtree(local_path, ignore_errors=True)
            raise RepoIngestorError(
                f"Unexpected error during repository cloning: {str(e)}",
                "UNEXPECTED_CLONE_ERROR",
                {"repo_url": repo_url, "error_type": type(e).__name__}
            )
            
            # Create RepoContext
            repo_context = RepoContext(
                repo_id=repo_id,
                repo_url=repo_url,
                local_path=str(local_path),
                analysis_status="cloned"
            )
            
            logger.info(f"Successfully cloned repository {repo_url} (ID: {repo_id})")
            return repo_context
            
        except subprocess.TimeoutExpired:
            if local_path.exists():
                shutil.rmtree(local_path, ignore_errors=True)
            raise RepoIngestorError("Repository cloning timed out")
        except Exception as e:
            if local_path.exists():
                shutil.rmtree(local_path, ignore_errors=True)
            if isinstance(e, RepoIngestorError):
                raise
            raise RepoIngestorError(f"Unexpected error during cloning: {str(e)}")
    
    def load_local_repository(self, local_path: str) -> RepoContext:
        """
        Load a local repository with comprehensive validation and error handling
        
        Args:
            local_path: Path to local repository
            
        Returns:
            RepoContext with repository metadata
            
        Raises:
            InvalidRepositoryError: If path is invalid or not accessible
            AccessDeniedError: If path access is denied
            RepositoryTooLargeError: If repository exceeds size limits
            UnsupportedRepositoryError: If local repos are disabled
        """
        if not self.settings.enable_local_repos:
            raise UnsupportedRepositoryError(
                "Local repository access is disabled in configuration",
                {"enable_local_repos": self.settings.enable_local_repos}
            )
        
        # Validate local path
        validation_result = self.validator.validate_local_path(local_path)
        path = Path(validation_result["path"])
        
        # Check repository size
        repo_size = self._get_directory_size(path)
        if repo_size > self.max_size_bytes:
            raise RepositoryTooLargeError(
                f"Repository size ({repo_size / 1024 / 1024:.1f}MB) exceeds limit "
                f"({self.settings.max_repo_size_mb}MB)",
                {
                    "local_path": local_path,
                    "size_bytes": repo_size,
                    "limit_bytes": self.max_size_bytes,
                    "size_mb": repo_size / 1024 / 1024,
                    "limit_mb": self.settings.max_repo_size_mb
                }
            )
        
        # Generate repo ID
        repo_id = str(uuid.uuid4())
        
        # Get additional repository metadata
        repo_metadata = self._extract_local_repo_metadata(path)
        
        # Create RepoContext
        repo_context = RepoContext(
            repo_id=repo_id,
            repo_url=None,
            local_path=str(path),
            analysis_status="loaded"
        )
        
        logger.info(
            f"Successfully loaded local repository {local_path} (ID: {repo_id}, "
            f"Git: {validation_result['is_git_repo']}, Size: {repo_size / 1024 / 1024:.1f}MB)"
        )
        
        return repo_context
    
    def _handle_git_error(self, error_msg: str, repo_url: str, validation_result: Dict[str, Any]):
        """Handle and categorize Git clone errors"""
        error_lower = error_msg.lower()
        
        # Authentication/Permission errors
        if any(phrase in error_lower for phrase in [
            'permission denied', 'authentication failed', 'access denied',
            'invalid username or password', 'bad credentials', 'unauthorized'
        ]):
            auth_required = validation_result.get('requires_auth', False)
            raise AccessDeniedError(
                f"Authentication required or access denied: {error_msg}",
                {
                    "repo_url": repo_url,
                    "git_error": error_msg,
                    "requires_auth": auth_required,
                    "suggestion": "Check repository permissions or provide authentication credentials"
                }
            )
        
        # Repository not found errors
        elif any(phrase in error_lower for phrase in [
            'repository not found', 'not found', '404', 'does not exist',
            'could not read from remote repository'
        ]):
            raise InvalidRepositoryError(
                f"Repository not found or does not exist: {error_msg}",
                {
                    "repo_url": repo_url,
                    "git_error": error_msg,
                    "suggestion": "Verify the repository URL is correct and the repository exists"
                }
            )
        
        # Network-related errors
        elif any(phrase in error_lower for phrase in [
            'network', 'connection', 'timeout', 'unreachable', 'dns',
            'could not resolve host', 'connection refused', 'connection timed out'
        ]):
            raise NetworkError(
                f"Network error while accessing repository: {error_msg}",
                {
                    "repo_url": repo_url,
                    "git_error": error_msg,
                    "suggestion": "Check network connectivity and repository host availability"
                }
            )
        
        # SSL/TLS errors
        elif any(phrase in error_lower for phrase in [
            'ssl', 'tls', 'certificate', 'handshake failed'
        ]):
            raise NetworkError(
                f"SSL/TLS error while accessing repository: {error_msg}",
                {
                    "repo_url": repo_url,
                    "git_error": error_msg,
                    "suggestion": "Check SSL certificates or try with --no-verify-ssl-cert flag"
                }
            )
        
        # Repository too large
        elif any(phrase in error_lower for phrase in [
            'repository too large', 'size limit', 'quota exceeded'
        ]):
            raise RepositoryTooLargeError(
                f"Repository exceeds size limits: {error_msg}",
                {
                    "repo_url": repo_url,
                    "git_error": error_msg,
                    "suggestion": "Check SSL certificate validity or network security settings"
                }
            )
        
        # Generic Git errors
        else:
            raise RepoIngestorError(
                f"Git clone failed: {error_msg}",
                "GIT_CLONE_FAILED",
                {
                    "repo_url": repo_url,
                    "git_error": error_msg,
                    "suggestion": "Check repository URL and access permissions"
                }
            )
    
    def _check_disk_space(self, path: Path, required_mb: int = 100):
        """Check available disk space before cloning"""
        try:
            stat = shutil.disk_usage(path)
            available_mb = stat.free / (1024 * 1024)
            
            if available_mb < required_mb:
                raise RepoIngestorError(
                    f"Insufficient disk space. Available: {available_mb:.1f}MB, Required: {required_mb}MB",
                    "INSUFFICIENT_DISK_SPACE",
                    {
                        "available_mb": available_mb,
                        "required_mb": required_mb,
                        "path": str(path)
                    }
                )
        except Exception as e:
            logger.warning(f"Could not check disk space: {e}")
    
    def _extract_repo_metadata(self, repo_path: Path, validation_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract additional metadata from cloned repository"""
        metadata = {
            "owner": validation_result.get("owner"),
            "repository": validation_result.get("repository"),
            "host": validation_result.get("host"),
            "protocol": validation_result.get("protocol")
        }
        
        try:
            # Get Git information
            result = subprocess.run(
                ["git", "log", "-1", "--format=%H|%an|%ae|%ad", "--date=iso"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                commit_info = result.stdout.strip().split('|')
                if len(commit_info) >= 4:
                    metadata.update({
                        "last_commit_hash": commit_info[0],
                        "last_commit_author": commit_info[1],
                        "last_commit_email": commit_info[2],
                        "last_commit_date": commit_info[3]
                    })
            
            # Get branch information
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                metadata["current_branch"] = result.stdout.strip()
                
        except Exception as e:
            logger.warning(f"Could not extract Git metadata: {e}")
        
        return metadata
    
    def _extract_local_repo_metadata(self, repo_path: Path) -> Dict[str, Any]:
        """Extract metadata from local repository"""
        metadata = {}
        
        try:
            # Check if it's a Git repository
            if (repo_path / ".git").exists():
                metadata.update(self._extract_repo_metadata(repo_path, {}))
            
            # Look for common project files
            project_files = []
            for filename in ['package.json', 'requirements.txt', 'pom.xml', 'Cargo.toml', 'go.mod', 'composer.json']:
                if (repo_path / filename).exists():
                    project_files.append(filename)
            
            metadata["project_files"] = project_files
            
        except Exception as e:
            logger.warning(f"Could not extract local repo metadata: {e}")
        
        return metadata
    
    def analyze_structure(self, repo_context: RepoContext) -> StructureAnalysis:
        """
        Perform comprehensive structure analysis of the repository
        
        Args:
            repo_context: Repository context
            
        Returns:
            StructureAnalysis with detailed repository structure information
        """
        path = Path(repo_context.local_path)
        
        if not path.exists():
            raise InvalidRepositoryError(f"Repository path does not exist: {repo_context.local_path}")
        
        logger.info(f"Analyzing structure for repository {repo_context.repo_id}")
        
        # Initialize analysis results
        total_files = 0
        file_extensions = {}
        directory_structure = {}
        key_directories = []
        
        # Walk through directory structure
        for root, dirs, files in os.walk(path):
            # Skip hidden directories and common ignore patterns
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {
                'node_modules', '__pycache__', 'venv', 'env', '.git', 
                'build', 'dist', 'target', 'bin', 'obj'
            }]
            
            rel_root = os.path.relpath(root, path)
            if rel_root == '.':
                rel_root = ''
            
            # Count files and track extensions
            for file in files:
                if not file.startswith('.'):
                    total_files += 1
                    ext = Path(file).suffix.lower()
                    if ext:
                        file_extensions[ext] = file_extensions.get(ext, 0) + 1
            
            # Build directory structure
            if rel_root:
                directory_structure[rel_root] = {
                    'files': len([f for f in files if not f.startswith('.')]),
                    'subdirs': len(dirs)
                }
        
        # Detect primary languages based on file extensions
        primary_languages = self._detect_primary_languages(file_extensions)
        
        # Identify key directories
        key_directories = self._identify_key_directories(path, directory_structure)
        
        # Detect frameworks (basic detection)
        detected_frameworks = self._detect_frameworks(path)
        
        # Perform advanced component analysis
        analyzer = StructureAnalyzer()
        component_analysis = analyzer.analyze_components(repo_context)
        
        # Create structure analysis
        structure_analysis = StructureAnalysis(
            total_files=total_files,
            primary_languages=primary_languages,
            directory_structure=directory_structure,
            key_directories=key_directories,
            detected_frameworks=detected_frameworks
        )
        
        # Update repo context with analysis results
        repo_context.primary_languages = primary_languages
        repo_context.structure_summary = {
            'total_files': total_files,
            'primary_languages': primary_languages,
            'key_directories': key_directories,
            'detected_frameworks': detected_frameworks,
            'component_analysis': component_analysis
        }
        repo_context.analysis_status = "analyzed"
        
        logger.info(f"Structure analysis complete for repository {repo_context.repo_id}: "
                   f"{total_files} files, languages: {primary_languages}, "
                   f"{component_analysis['summary']['total_components']} components")
        
        return structure_analysis
    
    def _validate_repo_url(self, repo_url: str) -> None:
        """Validate repository URL"""
        try:
            parsed = urlparse(repo_url)
            if not parsed.scheme or not parsed.netloc:
                raise InvalidRepositoryError(f"Invalid repository URL: {repo_url}")
            
            # Check if host is allowed
            if settings.allowed_repo_hosts and parsed.netloc not in settings.allowed_repo_hosts:
                raise InvalidRepositoryError(
                    f"Repository host {parsed.netloc} is not in allowed hosts: "
                    f"{settings.allowed_repo_hosts}"
                )
                
        except Exception as e:
            if isinstance(e, InvalidRepositoryError):
                raise
            raise InvalidRepositoryError(f"Invalid repository URL: {repo_url}")
    
    def _get_directory_size(self, path: Path) -> int:
        """Calculate total size of directory in bytes"""
        total_size = 0
        try:
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except (OSError, IOError):
                        # Skip files that can't be accessed
                        continue
        except (OSError, IOError):
            # If we can't walk the directory, return 0
            pass
        return total_size
    
    def _detect_primary_languages(self, file_extensions: Dict[str, int]) -> List[str]:
        """Detect primary programming languages based on file extensions"""
        # Language mapping
        language_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.go': 'Go',
            '.rs': 'Rust',
            '.cpp': 'C++',
            '.c': 'C',
            '.cs': 'C#',
            '.php': 'PHP',
            '.rb': 'Ruby',
            '.swift': 'Swift',
            '.kt': 'Kotlin',
            '.scala': 'Scala',
            '.clj': 'Clojure',
            '.hs': 'Haskell',
            '.ml': 'OCaml',
            '.fs': 'F#',
            '.dart': 'Dart',
            '.lua': 'Lua',
            '.r': 'R',
            '.m': 'Objective-C',
            '.sh': 'Shell',
            '.ps1': 'PowerShell',
            '.sql': 'SQL',
            '.html': 'HTML',
            '.css': 'CSS',
            '.scss': 'SCSS',
            '.less': 'LESS',
            '.vue': 'Vue',
            '.jsx': 'JSX',
            '.tsx': 'TSX'
        }
        
        # Count files by language
        language_counts = {}
        for ext, count in file_extensions.items():
            if ext in language_map:
                lang = language_map[ext]
                language_counts[lang] = language_counts.get(lang, 0) + count
        
        # Sort by count and return top languages
        sorted_languages = sorted(language_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Return languages that represent at least 5% of files or top 3
        total_lang_files = sum(language_counts.values())
        if total_lang_files == 0:
            return []
        
        primary_languages = []
        for lang, count in sorted_languages[:3]:  # Top 3 languages
            if count / total_lang_files >= 0.05 or len(primary_languages) < 1:  # At least 5% or ensure at least 1
                primary_languages.append(lang)
        
        return primary_languages
    
    def _identify_key_directories(self, repo_path: Path, directory_structure: Dict[str, Any]) -> List[str]:
        """Identify key directories in the repository"""
        key_dirs = []
        
        # Common important directory patterns
        important_patterns = {
            'src', 'source', 'lib', 'app', 'api', 'server', 'client',
            'controllers', 'models', 'views', 'services', 'components',
            'utils', 'helpers', 'middleware', 'routes', 'handlers',
            'config', 'configuration', 'settings', 'env',
            'tests', 'test', 'spec', '__tests__',
            'docs', 'documentation', 'readme',
            'scripts', 'bin', 'tools',
            'static', 'assets', 'public', 'resources',
            'templates', 'views', 'pages'
        }
        
        # Check for directories that exist and have significant content
        for dir_path, info in directory_structure.items():
            dir_name = os.path.basename(dir_path).lower()
            
            # Check if directory name matches important patterns
            if dir_name in important_patterns:
                key_dirs.append(dir_path)
            # Check for directories with many files (likely important)
            elif info['files'] > 5:
                key_dirs.append(dir_path)
        
        # Also check for root-level files that indicate project type
        root_files = []
        try:
            root_files = [f.name for f in repo_path.iterdir() if f.is_file()]
        except:
            pass
        
        # Add implied directories based on root files
        config_files = {
            'package.json': 'JavaScript/Node.js',
            'requirements.txt': 'Python',
            'Pipfile': 'Python',
            'setup.py': 'Python',
            'pom.xml': 'Java/Maven',
            'build.gradle': 'Java/Gradle',
            'Cargo.toml': 'Rust',
            'go.mod': 'Go',
            'composer.json': 'PHP',
            'Gemfile': 'Ruby'
        }
        
        for file in root_files:
            if file in config_files:
                # This helps identify the project type
                pass
        
        return sorted(list(set(key_dirs)))
    
    def _detect_frameworks(self, repo_path: Path) -> List[str]:
        """Detect frameworks and technologies used in the repository"""
        frameworks = []
        
        try:
            # Check for common framework indicators
            root_files = [f.name for f in repo_path.iterdir() if f.is_file()]
            
            # Package.json analysis for JavaScript/Node.js
            if 'package.json' in root_files:
                try:
                    import json
                    with open(repo_path / 'package.json', 'r', encoding='utf-8') as f:
                        package_data = json.load(f)
                        
                    dependencies = {}
                    dependencies.update(package_data.get('dependencies', {}))
                    dependencies.update(package_data.get('devDependencies', {}))
                    
                    # Common framework detection
                    if 'react' in dependencies:
                        frameworks.append('React')
                    if 'vue' in dependencies:
                        frameworks.append('Vue.js')
                    if 'angular' in dependencies or '@angular/core' in dependencies:
                        frameworks.append('Angular')
                    if 'express' in dependencies:
                        frameworks.append('Express.js')
                    if 'fastify' in dependencies:
                        frameworks.append('Fastify')
                    if 'next' in dependencies:
                        frameworks.append('Next.js')
                    if 'nuxt' in dependencies:
                        frameworks.append('Nuxt.js')
                        
                except (json.JSONDecodeError, IOError):
                    pass
            
            # Python framework detection
            if 'requirements.txt' in root_files:
                try:
                    with open(repo_path / 'requirements.txt', 'r', encoding='utf-8') as f:
                        requirements = f.read().lower()
                        
                    if 'django' in requirements:
                        frameworks.append('Django')
                    if 'flask' in requirements:
                        frameworks.append('Flask')
                    if 'fastapi' in requirements:
                        frameworks.append('FastAPI')
                    if 'tornado' in requirements:
                        frameworks.append('Tornado')
                        
                except IOError:
                    pass
            
            # Check for other common files
            if 'Dockerfile' in root_files:
                frameworks.append('Docker')
            if 'docker-compose.yml' in root_files or 'docker-compose.yaml' in root_files:
                frameworks.append('Docker Compose')
            if '.github' in [d.name for d in repo_path.iterdir() if d.is_dir()]:
                frameworks.append('GitHub Actions')
                
        except Exception as e:
            logger.warning(f"Error detecting frameworks: {e}")
        
        return frameworks


class StructureAnalyzer:
    """Advanced structure analysis for identifying components and patterns"""
    
    def __init__(self):
        self.component_patterns = self._initialize_component_patterns()
    
    def analyze_components(self, repo_context: RepoContext) -> Dict[str, Any]:
        """
        Analyze repository structure to identify components and patterns
        
        Args:
            repo_context: Repository context
            
        Returns:
            Dictionary containing component analysis results
        """
        repo_path = Path(repo_context.local_path)
        
        logger.info(f"Analyzing components for repository {repo_context.repo_id}")
        
        # Initialize results
        components = {
            'controllers': [],
            'services': [],
            'models': [],
            'middleware': [],
            'utilities': [],
            'config': [],
            'tests': []
        }
        
        api_endpoints = []
        database_models = []
        config_files = []
        
        # Walk through the repository
        for root, dirs, files in os.walk(repo_path):
            # Skip common ignore directories
            dirs[:] = [d for d in dirs if not self._should_skip_directory(d)]
            
            rel_root = os.path.relpath(root, repo_path)
            if rel_root == '.':
                rel_root = ''
            
            for file in files:
                if self._should_skip_file(file):
                    continue
                
                file_path = os.path.join(root, file)
                rel_file_path = os.path.relpath(file_path, repo_path)
                
                # Analyze file based on patterns and content
                file_analysis = self._analyze_file(file_path, rel_file_path, repo_context.primary_languages)
                
                # Categorize components
                if file_analysis['type'] == 'controller':
                    components['controllers'].append(file_analysis)
                elif file_analysis['type'] == 'service':
                    components['services'].append(file_analysis)
                elif file_analysis['type'] == 'model':
                    components['models'].append(file_analysis)
                    if file_analysis.get('is_database_model'):
                        database_models.append(file_analysis)
                elif file_analysis['type'] == 'middleware':
                    components['middleware'].append(file_analysis)
                elif file_analysis['type'] == 'utility':
                    components['utilities'].append(file_analysis)
                elif file_analysis['type'] == 'config':
                    components['config'].append(file_analysis)
                    config_files.append(file_analysis)
                elif file_analysis['type'] == 'test':
                    components['tests'].append(file_analysis)
                
                # Extract API endpoints
                if file_analysis.get('endpoints'):
                    api_endpoints.extend(file_analysis['endpoints'])
        
        # Generate summary statistics
        summary = {
            'total_components': sum(len(comp_list) for comp_list in components.values()),
            'api_endpoints_count': len(api_endpoints),
            'database_models_count': len(database_models),
            'config_files_count': len(config_files),
            'component_breakdown': {k: len(v) for k, v in components.items()}
        }
        
        logger.info(f"Component analysis complete for repository {repo_context.repo_id}: "
                   f"{summary['total_components']} components identified")
        
        return {
            'components': components,
            'api_endpoints': api_endpoints,
            'database_models': database_models,
            'config_files': config_files,
            'summary': summary
        }
    
    def _initialize_component_patterns(self) -> Dict[str, Any]:
        """Initialize patterns for component identification"""
        return {
            'controller_patterns': {
                'path_patterns': [
                    r'.*controller.*',
                    r'.*handler.*',
                    r'.*route.*',
                    r'.*endpoint.*',
                    r'.*api.*',
                    r'.*view.*'
                ],
                'file_patterns': [
                    r'.*controller\.(py|js|ts|java|go|php|rb)$',
                    r'.*handler\.(py|js|ts|java|go|php|rb)$',
                    r'.*route\.(py|js|ts|java|go|php|rb)$',
                    r'.*api\.(py|js|ts|java|go|php|rb)$',
                    r'.*view\.(py|js|ts|java|go|php|rb)$'
                ],
                'content_patterns': [
                    r'@app\.route',
                    r'@router\.',
                    r'app\.get|app\.post|app\.put|app\.delete',
                    r'router\.get|router\.post|router\.put|router\.delete',
                    r'@RestController',
                    r'@RequestMapping',
                    r'@GetMapping|@PostMapping|@PutMapping|@DeleteMapping',
                    r'func.*http\.ResponseWriter',
                    r'express\.Router',
                    r'fastify\.register'
                ]
            },
            'service_patterns': {
                'path_patterns': [
                    r'.*service.*',
                    r'.*business.*',
                    r'.*logic.*',
                    r'.*manager.*',
                    r'.*processor.*'
                ],
                'file_patterns': [
                    r'.*service\.(py|js|ts|java|go|php|rb)$',
                    r'.*manager\.(py|js|ts|java|go|php|rb)$',
                    r'.*processor\.(py|js|ts|java|go|php|rb)$'
                ],
                'content_patterns': [
                    r'@Service',
                    r'@Component',
                    r'class.*Service',
                    r'class.*Manager',
                    r'class.*Processor'
                ]
            },
            'model_patterns': {
                'path_patterns': [
                    r'.*model.*',
                    r'.*entity.*',
                    r'.*schema.*',
                    r'.*dto.*',
                    r'.*domain.*'
                ],
                'file_patterns': [
                    r'.*model\.(py|js|ts|java|go|php|rb)$',
                    r'.*entity\.(py|js|ts|java|go|php|rb)$',
                    r'.*schema\.(py|js|ts|java|go|php|rb)$',
                    r'models\.(py|js|ts)$'
                ],
                'content_patterns': [
                    r'@Entity',
                    r'@Table',
                    r'class.*Model',
                    r'from.*models.*import',
                    r'db\.Model',
                    r'models\.Model',
                    r'BaseModel',
                    r'Schema',
                    r'mongoose\.Schema'
                ]
            },
            'middleware_patterns': {
                'path_patterns': [
                    r'.*middleware.*',
                    r'.*interceptor.*',
                    r'.*filter.*',
                    r'.*guard.*'
                ],
                'file_patterns': [
                    r'.*middleware\.(py|js|ts|java|go|php|rb)$',
                    r'.*interceptor\.(py|js|ts|java|go|php|rb)$',
                    r'.*filter\.(py|js|ts|java|go|php|rb)$'
                ],
                'content_patterns': [
                    r'@middleware',
                    r'@Middleware',
                    r'@Filter',
                    r'@Guard',
                    r'def.*middleware',
                    r'function.*middleware',
                    r'class.*Middleware'
                ]
            },
            'config_patterns': {
                'path_patterns': [
                    r'.*config.*',
                    r'.*setting.*',
                    r'.*env.*',
                    r'.*constant.*'
                ],
                'file_patterns': [
                    r'config\.(py|js|ts|java|go|php|rb|json|yaml|yml|toml)$',
                    r'settings\.(py|js|ts|java|go|php|rb|json|yaml|yml)$',
                    r'.*\.env.*',
                    r'constants\.(py|js|ts|java|go|php|rb)$',
                    r'application\.(properties|yml|yaml)$'
                ]
            }
        }
    
    def _analyze_file(self, file_path: str, rel_file_path: str, primary_languages: List[str]) -> Dict[str, Any]:
        """
        Analyze a single file to determine its type and extract information
        
        Args:
            file_path: Absolute path to the file
            rel_file_path: Relative path from repository root
            primary_languages: Primary languages detected in the repository
            
        Returns:
            Dictionary containing file analysis results
        """
        file_info = {
            'file_path': rel_file_path,
            'type': 'unknown',
            'language': self._detect_file_language(file_path),
            'size_bytes': 0,
            'endpoints': [],
            'classes': [],
            'functions': [],
            'imports': [],
            'is_database_model': False,
            'has_auth_logic': False,
            'handles_sensitive_data': False
        }
        
        try:
            # Get file size
            file_info['size_bytes'] = os.path.getsize(file_path)
            
            # Skip very large files to avoid performance issues
            if file_info['size_bytes'] > 1024 * 1024:  # 1MB limit
                return file_info
            
            # Read file content
            content = self._read_file_safely(file_path)
            if not content:
                return file_info
            
            # Determine file type based on patterns
            file_info['type'] = self._classify_file_type(rel_file_path, content)
            
            # Extract detailed information based on language
            if file_info['language'] in ['Python', 'JavaScript', 'TypeScript']:
                self._analyze_python_js_file(content, file_info)
            elif file_info['language'] == 'Java':
                self._analyze_java_file(content, file_info)
            elif file_info['language'] == 'Go':
                self._analyze_go_file(content, file_info)
            
            # Check for security-related patterns
            self._analyze_security_patterns(content, file_info)
            
        except Exception as e:
            logger.warning(f"Error analyzing file {rel_file_path}: {e}")
        
        return file_info
    
    def _classify_file_type(self, file_path: str, content: str) -> str:
        """Classify file type based on path and content patterns"""
        file_path_lower = file_path.lower()
        
        # Check test files first
        if any(pattern in file_path_lower for pattern in ['test', 'spec', '__tests__']):
            return 'test'
        
        # Check each component type
        for component_type, patterns in self.component_patterns.items():
            if component_type.endswith('_patterns'):
                component_name = component_type.replace('_patterns', '')
                
                # Check path patterns
                if 'path_patterns' in patterns:
                    for pattern in patterns['path_patterns']:
                        if re.search(pattern, file_path_lower):
                            return component_name
                
                # Check file patterns
                if 'file_patterns' in patterns:
                    for pattern in patterns['file_patterns']:
                        if re.search(pattern, file_path_lower):
                            return component_name
                
                # Check content patterns
                if 'content_patterns' in patterns and content:
                    for pattern in patterns['content_patterns']:
                        if re.search(pattern, content, re.IGNORECASE):
                            return component_name
        
        # Default classification based on directory structure
        if 'util' in file_path_lower or 'helper' in file_path_lower:
            return 'utility'
        
        return 'unknown'
    
    def _analyze_python_js_file(self, content: str, file_info: Dict[str, Any]) -> None:
        """Analyze Python/JavaScript/TypeScript file content"""
        lines = content.split('\n')
        
        # Extract classes
        class_pattern = r'class\s+(\w+)'
        for match in re.finditer(class_pattern, content):
            file_info['classes'].append(match.group(1))
        
        # Extract functions
        func_patterns = [
            r'def\s+(\w+)',  # Python
            r'function\s+(\w+)',  # JavaScript
            r'const\s+(\w+)\s*=\s*\(',  # Arrow functions
            r'(\w+)\s*:\s*\([^)]*\)\s*=>'  # TypeScript arrow functions
        ]
        
        for pattern in func_patterns:
            for match in re.finditer(pattern, content):
                file_info['functions'].append(match.group(1))
        
        # Extract imports
        import_patterns = [
            r'from\s+[\w.]+\s+import\s+([\w,\s]+)',  # Python
            r'import\s+([\w,\s{}]+)\s+from',  # JavaScript/TypeScript
            r'import\s+([\w,\s]+)'  # Simple imports
        ]
        
        for pattern in import_patterns:
            for match in re.finditer(pattern, content):
                file_info['imports'].append(match.group(1).strip())
        
        # Extract API endpoints
        endpoint_patterns = [
            r'@app\.route\([\'"]([^\'"]+)[\'"].*methods=\[[\'"]([^\'"]+)[\'"]',
            r'@router\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',
            r'app\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',
            r'router\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in endpoint_patterns:
            for match in re.finditer(pattern, content):
                if len(match.groups()) >= 2:
                    method = match.group(1) if match.group(1) else match.group(2)
                    path = match.group(2) if len(match.groups()) > 2 else match.group(1)
                    file_info['endpoints'].append({
                        'method': method.upper(),
                        'path': path,
                        'line': content[:match.start()].count('\n') + 1
                    })
        
        # Check for database model patterns
        db_patterns = [
            r'db\.Model',
            r'models\.Model',
            r'BaseModel',
            r'@Entity',
            r'mongoose\.Schema'
        ]
        
        for pattern in db_patterns:
            if re.search(pattern, content):
                file_info['is_database_model'] = True
                break
    
    def _analyze_java_file(self, content: str, file_info: Dict[str, Any]) -> None:
        """Analyze Java file content"""
        # Extract classes
        class_pattern = r'class\s+(\w+)'
        for match in re.finditer(class_pattern, content):
            file_info['classes'].append(match.group(1))
        
        # Extract methods
        method_pattern = r'(public|private|protected).*\s+(\w+)\s*\([^)]*\)\s*{'
        for match in re.finditer(method_pattern, content):
            file_info['functions'].append(match.group(2))
        
        # Extract Spring Boot endpoints
        endpoint_patterns = [
            r'@(Get|Post|Put|Delete|Patch)Mapping\([\'"]([^\'"]+)[\'"]',
            r'@RequestMapping.*value\s*=\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in endpoint_patterns:
            for match in re.finditer(pattern, content):
                method = match.group(1) if match.group(1) else 'REQUEST'
                path = match.group(2)
                file_info['endpoints'].append({
                    'method': method.upper(),
                    'path': path,
                    'line': content[:match.start()].count('\n') + 1
                })
        
        # Check for JPA entity patterns
        if re.search(r'@Entity|@Table', content):
            file_info['is_database_model'] = True
    
    def _analyze_go_file(self, content: str, file_info: Dict[str, Any]) -> None:
        """Analyze Go file content"""
        # Extract functions
        func_pattern = r'func\s+(\w+)'
        for match in re.finditer(func_pattern, content):
            file_info['functions'].append(match.group(1))
        
        # Extract structs (similar to classes)
        struct_pattern = r'type\s+(\w+)\s+struct'
        for match in re.finditer(struct_pattern, content):
            file_info['classes'].append(match.group(1))
        
        # Extract HTTP handlers
        if re.search(r'http\.ResponseWriter|http\.Request', content):
            # This is likely an HTTP handler
            file_info['endpoints'].append({
                'method': 'HTTP',
                'path': 'detected_handler',
                'line': 0
            })
    
    def _analyze_security_patterns(self, content: str, file_info: Dict[str, Any]) -> None:
        """Analyze content for security-related patterns"""
        # Authentication patterns
        auth_patterns = [
            r'auth|Auth|authentication|Authentication',
            r'login|Login|signin|SignIn',
            r'password|Password|passwd',
            r'token|Token|jwt|JWT',
            r'session|Session',
            r'@login_required|@auth_required',
            r'authenticate|authorize'
        ]
        
        for pattern in auth_patterns:
            if re.search(pattern, content):
                file_info['has_auth_logic'] = True
                break
        
        # Sensitive data patterns
        sensitive_patterns = [
            r'password|secret|key|token',
            r'credit.*card|ssn|social.*security',
            r'email|phone|address',
            r'personal.*data|pii|PII',
            r'encrypt|decrypt|hash',
            r'api.*key|secret.*key'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                file_info['handles_sensitive_data'] = True
                break
    
    def _detect_file_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext = Path(file_path).suffix.lower()
        
        language_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.go': 'Go',
            '.rs': 'Rust',
            '.cpp': 'C++',
            '.c': 'C',
            '.cs': 'C#',
            '.php': 'PHP',
            '.rb': 'Ruby',
            '.swift': 'Swift',
            '.kt': 'Kotlin'
        }
        
        return language_map.get(ext, 'Unknown')
    
    def _read_file_safely(self, file_path: str) -> Optional[str]:
        """Safely read file content with encoding detection"""
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
            except (UnicodeDecodeError, IOError):
                continue
        
        logger.warning(f"Could not read file {file_path} with any encoding")
        return None
    
    def _should_skip_directory(self, dir_name: str) -> bool:
        """Check if directory should be skipped during analysis"""
        skip_dirs = {
            '.git', '.svn', '.hg',
            'node_modules', '__pycache__', '.pytest_cache',
            'venv', 'env', '.env', 'virtualenv',
            'build', 'dist', 'target', 'bin', 'obj',
            '.idea', '.vscode', '.vs',
            'logs', 'log', 'tmp', 'temp',
            'coverage', '.coverage', '.nyc_output'
        }
        return dir_name.lower() in skip_dirs or dir_name.startswith('.')
    
    def _should_skip_file(self, file_name: str) -> bool:
        """Check if file should be skipped during analysis"""
        skip_extensions = {
            '.pyc', '.pyo', '.class', '.o', '.so', '.dll',
            '.exe', '.bin', '.jar', '.war',
            '.log', '.tmp', '.temp', '.cache',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.zip', '.tar', '.gz', '.rar', '.7z'
        }
        
        skip_files = {
            '.DS_Store', 'Thumbs.db', '.gitignore', '.gitkeep',
            'package-lock.json', 'yarn.lock', 'poetry.lock'
        }
        
        ext = Path(file_name).suffix.lower()
        return (ext in skip_extensions or 
                file_name in skip_files or 
                file_name.startswith('.'))


# Add import for regex
import re