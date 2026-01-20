"""
Enhanced configuration management for the Threat Modeling Documentation Generator
"""
import os
import json
import logging
import threading
import time
from pathlib import Path
from typing import Optional, Dict, Any, List, Union, Callable
from datetime import datetime
from enum import Enum
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from pydantic_settings import BaseSettings
from pydantic import Field, validator, root_validator
from pydantic.types import SecretStr


logger = logging.getLogger(__name__)


class LogLevel(str, Enum):
    """Logging levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LLMProvider(str, Enum):
    """Supported LLM providers"""
    OPENAI = "openai"
    AZURE = "azure"
    ANTHROPIC = "anthropic"
    HUGGINGFACE = "huggingface"
    GOOGLE = "google"


class EmbeddingProvider(str, Enum):
    """Supported embedding providers"""
    OPENAI = "openai"
    SENTENCE_TRANSFORMERS = "sentence-transformers"
    HUGGINGFACE = "huggingface"


class FAISSIndexType(str, Enum):
    """FAISS index types"""
    FLAT_IP = "IndexFlatIP"
    FLAT_L2 = "IndexFlatL2"
    IVF_FLAT = "IndexIVFFlat"
    IVF_PQ = "IndexIVFPQ"


class ConfigurationError(Exception):
    """Configuration validation error"""
    pass


class ConfigFileWatcher(FileSystemEventHandler):
    """File system watcher for configuration changes"""
    
    def __init__(self, config_manager: 'ConfigurationManager'):
        self.config_manager = config_manager
        self.last_modified = {}
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        if file_path.endswith('.env') or file_path.endswith('.json'):
            # Debounce rapid file changes
            current_time = time.time()
            if (file_path not in self.last_modified or 
                current_time - self.last_modified[file_path] > 1.0):
                
                self.last_modified[file_path] = current_time
                logger.info(f"Configuration file changed: {file_path}")
                self.config_manager.reload_configuration()


class ConfigurationManager:
    """Manages configuration loading, validation, and hot-reloading"""
    
    def __init__(self, settings_class=None):
        self.settings_class = settings_class or Settings
        self.settings = None
        self.config_callbacks: List[Callable] = []
        self.file_observer = None
        self.lock = threading.Lock()
        
        # Load initial configuration
        self.reload_configuration()
        
        # Start file watcher if hot-reloading is enabled
        if self.settings and self.settings.enable_config_hot_reload:
            self.start_file_watcher()
    
    def reload_configuration(self):
        """Reload configuration from files and environment"""
        with self.lock:
            try:
                old_settings = self.settings
                self.settings = self.settings_class()
                
                # Validate configuration
                validation_result = self.validate_configuration()
                if not validation_result["valid"]:
                    logger.error(f"Configuration validation failed: {validation_result['errors']}")
                    if old_settings:
                        logger.info("Reverting to previous configuration")
                        self.settings = old_settings
                        return False
                    else:
                        raise ConfigurationError(f"Invalid configuration: {validation_result['errors']}")
                
                logger.info("Configuration reloaded successfully")
                
                # Notify callbacks
                for callback in self.config_callbacks:
                    try:
                        callback(self.settings)
                    except Exception as e:
                        logger.error(f"Configuration callback failed: {e}")
                
                return True
                
            except Exception as e:
                logger.error(f"Failed to reload configuration: {e}")
                return False
    
    def validate_configuration(self) -> Dict[str, Any]:
        """Comprehensive configuration validation"""
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "checks": {}
        }
        
        if not self.settings:
            validation_result["valid"] = False
            validation_result["errors"].append("No settings loaded")
            return validation_result
        
        # LLM Configuration validation
        llm_check = self._validate_llm_config()
        validation_result["checks"]["llm"] = llm_check
        if not llm_check["valid"]:
            validation_result["errors"].extend(llm_check["errors"])
            validation_result["valid"] = False
        
        # Storage validation
        storage_check = self._validate_storage_config()
        validation_result["checks"]["storage"] = storage_check
        if not storage_check["valid"]:
            validation_result["errors"].extend(storage_check["errors"])
            validation_result["valid"] = False
        
        # Security validation
        security_check = self._validate_security_config()
        validation_result["checks"]["security"] = security_check
        validation_result["warnings"].extend(security_check["warnings"])
        
        # Performance validation
        performance_check = self._validate_performance_config()
        validation_result["checks"]["performance"] = performance_check
        validation_result["warnings"].extend(performance_check["warnings"])
        
        # GitHub API validation
        github_check = self._validate_github_config()
        validation_result["checks"]["github"] = github_check
        validation_result["warnings"].extend(github_check["warnings"])
        if not github_check["valid"]:
            validation_result["errors"].extend(github_check["errors"])
            validation_result["valid"] = False
        
        return validation_result
    
    def _validate_llm_config(self) -> Dict[str, Any]:
        """Validate LLM configuration"""
        result = {"valid": True, "errors": [], "warnings": []}
        
        if self.settings.llm_provider == LLMProvider.OPENAI:
            if not self.settings.openai_api_key:
                result["valid"] = False
                result["errors"].append("OpenAI API key is required")
            
            if self.settings.openai_base_url and not self.settings.openai_base_url.startswith(('http://', 'https://')):
                result["valid"] = False
                result["errors"].append("OpenAI base URL must start with http:// or https://")
        
        elif self.settings.llm_provider == LLMProvider.AZURE:
            required_fields = [
                ("azure_openai_endpoint", "Azure OpenAI endpoint"),
                ("azure_openai_api_key", "Azure OpenAI API key"),
                ("azure_openai_deployment_name", "Azure OpenAI deployment name")
            ]
            
            for field, description in required_fields:
                if not getattr(self.settings, field):
                    result["valid"] = False
                    result["errors"].append(f"{description} is required for Azure provider")
        
        # Rate limiting validation
        if self.settings.llm_requests_per_minute <= 0:
            result["valid"] = False
            result["errors"].append("LLM requests per minute must be positive")
        
        if self.settings.max_tokens_per_request <= 0:
            result["valid"] = False
            result["errors"].append("Max tokens per request must be positive")
        
        return result
    
    def _validate_storage_config(self) -> Dict[str, Any]:
        """Validate storage configuration"""
        result = {"valid": True, "errors": [], "warnings": []}
        
        # Check storage paths
        try:
            base_path = Path(self.settings.storage_base_path)
            if not base_path.exists():
                base_path.mkdir(parents=True, exist_ok=True)
            
            # Check write permissions
            test_file = base_path / "test_write_permission"
            try:
                test_file.write_text("test")
                test_file.unlink()
            except Exception:
                result["valid"] = False
                result["errors"].append(f"No write permission for storage path: {base_path}")
        
        except Exception as e:
            result["valid"] = False
            result["errors"].append(f"Invalid storage base path: {e}")
        
        # Validate size limits
        if self.settings.max_repo_size_mb <= 0:
            result["valid"] = False
            result["errors"].append("Max repository size must be positive")
        
        if self.settings.max_repo_size_mb > 10000:  # 10GB
            result["warnings"].append("Very large repository size limit may cause performance issues")
        
        return result
    
    def _validate_security_config(self) -> Dict[str, Any]:
        """Validate security configuration"""
        result = {"valid": True, "errors": [], "warnings": []}
        
        # Check allowed hosts
        if not self.settings.allowed_repo_hosts:
            result["warnings"].append("No repository hosts restrictions - all hosts allowed")
        
        # Debug mode warnings
        if self.settings.debug:
            result["warnings"].append("Debug mode is enabled - not recommended for production")
        
        # Local repo access
        if self.settings.enable_local_repos:
            result["warnings"].append("Local repository access is enabled - ensure proper access controls")
        
        return result
    
    def _validate_performance_config(self) -> Dict[str, Any]:
        """Validate performance configuration"""
        result = {"valid": True, "errors": [], "warnings": []}
        
        # Concurrent analyses
        if self.settings.max_concurrent_analyses > 10:
            result["warnings"].append("High concurrent analysis limit may cause resource exhaustion")
        
        # Timeout settings
        if self.settings.analysis_timeout_minutes < 5:
            result["warnings"].append("Very short analysis timeout may cause failures for large repositories")
        
        # GPU configuration
        if self.settings.enable_gpu_acceleration:
            try:
                import torch
                if not torch.cuda.is_available():
                    result["warnings"].append("GPU acceleration enabled but CUDA not available")
            except ImportError:
                result["warnings"].append("GPU acceleration enabled but PyTorch not installed")
        
        return result
    
    def _validate_github_config(self) -> Dict[str, Any]:
        """Validate GitHub API configuration"""
        result = {"valid": True, "errors": [], "warnings": []}
        
        # Check GitHub token
        if not self.settings.github_token:
            result["warnings"].append("No GitHub token configured - PR analysis will have limited rate limits")
        else:
            token_value = self.settings.github_token.get_secret_value()
            if len(token_value) < 20:
                result["valid"] = False
                result["errors"].append("GitHub token appears to be invalid (too short)")
            
            # Check token format (GitHub tokens start with specific prefixes)
            valid_prefixes = ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_']
            if not any(token_value.startswith(prefix) for prefix in valid_prefixes):
                result["warnings"].append("GitHub token format may be invalid - ensure it's a valid personal access token")
        
        # Validate rate limits
        if self.settings.github_requests_per_hour <= 0:
            result["valid"] = False
            result["errors"].append("GitHub requests per hour must be positive")
        
        if self.settings.github_requests_per_minute <= 0:
            result["valid"] = False
            result["errors"].append("GitHub requests per minute must be positive")
        
        # Check if rate limits are reasonable
        if self.settings.github_requests_per_hour > 5000:
            result["warnings"].append("GitHub requests per hour is very high - may exceed API limits")
        
        if self.settings.github_requests_per_minute > 100:
            result["warnings"].append("GitHub requests per minute is very high - may exceed API limits")
        
        # Validate timeout settings
        if self.settings.github_timeout_seconds < 5:
            result["warnings"].append("GitHub API timeout is very short - may cause request failures")
        
        if self.settings.github_timeout_seconds > 120:
            result["warnings"].append("GitHub API timeout is very long - may cause slow responses")
        
        # Validate retry settings
        if self.settings.github_retry_attempts > 5:
            result["warnings"].append("High GitHub retry attempts may cause slow responses on failures")
        
        return result
    
    def start_file_watcher(self):
        """Start watching configuration files for changes"""
        if self.file_observer:
            return
        
        try:
            self.file_observer = Observer()
            event_handler = ConfigFileWatcher(self)
            
            # Watch current directory for .env files
            self.file_observer.schedule(event_handler, ".", recursive=False)
            
            # Watch config directory if it exists
            config_dir = Path("config")
            if config_dir.exists():
                self.file_observer.schedule(event_handler, str(config_dir), recursive=True)
            
            self.file_observer.start()
            logger.info("Configuration file watcher started")
            
        except Exception as e:
            logger.error(f"Failed to start configuration file watcher: {e}")
    
    def stop_file_watcher(self):
        """Stop watching configuration files"""
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
            self.file_observer = None
            logger.info("Configuration file watcher stopped")
    
    def add_config_callback(self, callback: Callable):
        """Add callback to be called when configuration changes"""
        self.config_callbacks.append(callback)
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for diagnostics"""
        if not self.settings:
            return {"error": "No configuration loaded"}
        
        return {
            "llm_provider": self.settings.llm_provider,
            "embedding_provider": self.settings.embedding_provider,
            "storage_base_path": self.settings.storage_base_path,
            "debug_mode": self.settings.debug,
            "max_concurrent_analyses": self.settings.max_concurrent_analyses,
            "gpu_acceleration": self.settings.enable_gpu_acceleration,
            "hot_reload_enabled": self.settings.enable_config_hot_reload,
            "validation_status": self.validate_configuration()
        }


class Settings(BaseSettings):
    """Enhanced application settings with comprehensive validation"""
    
    # API Configuration
    api_host: str = Field(default="0.0.0.0", description="API server host")
    api_port: int = Field(default=8000, ge=1, le=65535, description="API server port")
    debug: bool = Field(default=False, description="Enable debug mode")
    log_level: LogLevel = Field(default=LogLevel.INFO, description="Logging level")
    
    # Configuration Management
    enable_config_hot_reload: bool = Field(default=True, description="Enable configuration hot-reloading")
    config_validation_strict: bool = Field(default=True, description="Strict configuration validation")
    
    # LLM Configuration
    llm_provider: LLMProvider = Field(default=LLMProvider.OPENAI, description="LLM provider")
    openai_api_key: Optional[SecretStr] = Field(default=None, description="OpenAI API key")
    openai_model: str = Field(default="gpt-4", description="OpenAI model name")
    openai_base_url: Optional[str] = Field(default=None, description="OpenAI base URL for compatible APIs")
    
    # Azure OpenAI Configuration
    azure_openai_endpoint: Optional[str] = Field(default=None, description="Azure OpenAI endpoint")
    azure_openai_api_key: Optional[SecretStr] = Field(default=None, description="Azure OpenAI API key")
    azure_openai_api_version: str = Field(default="2023-12-01-preview", description="Azure OpenAI API version")
    azure_openai_deployment_name: Optional[str] = Field(default=None, description="Azure OpenAI deployment name")
    
    # Anthropic Configuration
    anthropic_api_key: Optional[SecretStr] = Field(default=None, description="Anthropic API key")
    anthropic_model: str = Field(default="claude-3-sonnet-20240229", description="Anthropic model name")
    
    # Google Gemini Configuration
    google_api_key: Optional[SecretStr] = Field(default=None, description="Google AI API key")
    google_model: str = Field(default="gemini-1.5-pro", description="Google Gemini model name")
    
    # Hugging Face Configuration
    huggingface_model: str = Field(default="microsoft/DialoGPT-medium", description="Hugging Face model name")
    huggingface_cache_dir: Optional[str] = Field(default="./models", description="Hugging Face model cache directory")
    
    # Task Routing Configuration
    enable_task_routing: bool = Field(default=True, description="Enable task-based LLM routing")
    default_simple_provider: str = Field(default="huggingface", description="Default provider for simple tasks")
    default_complex_provider: str = Field(default="openai", description="Default provider for complex tasks")
    cost_optimization_mode: str = Field(default="balanced", description="Cost optimization mode: aggressive, balanced, quality")
    
    # GitHub API Configuration
    github_token: Optional[SecretStr] = Field(default=None, description="GitHub personal access token for PR analysis")
    github_api_base_url: str = Field(default="https://api.github.com", description="GitHub API base URL")
    github_requests_per_hour: int = Field(default=5000, ge=1, description="GitHub API requests per hour limit")
    github_requests_per_minute: int = Field(default=100, ge=1, description="GitHub API requests per minute limit")
    github_timeout_seconds: int = Field(default=30, ge=5, le=300, description="GitHub API request timeout in seconds")
    github_retry_attempts: int = Field(default=3, ge=1, le=10, description="GitHub API retry attempts on failure")
    github_retry_backoff_factor: float = Field(default=2.0, ge=1.0, le=10.0, description="GitHub API retry backoff factor")
    
    # Embedding Configuration
    embedding_provider: EmbeddingProvider = Field(default=EmbeddingProvider.OPENAI, description="Embedding provider")
    embedding_model: str = Field(default="text-embedding-ada-002", description="Embedding model name")
    sentence_transformer_model: str = Field(default="all-MiniLM-L6-v2", description="Sentence transformer model")
    
    # Storage Configuration
    storage_base_path: str = Field(default="./storage", description="Base storage directory")
    repos_storage_path: str = Field(default="./storage/repos", description="Repository storage directory")
    docs_storage_path: str = Field(default="./storage/docs", description="Documents storage directory")
    embeddings_storage_path: str = Field(default="./storage/embeddings", description="Embeddings storage directory")
    database_path: str = Field(default="./storage/threat_modeling.db", description="Database file path")
    
    # Storage Management
    enable_storage_quotas: bool = Field(default=True, description="Enable storage quota management")
    auto_cleanup_enabled: bool = Field(default=True, description="Enable automatic cleanup")
    backup_retention_days: int = Field(default=180, ge=1, description="Backup retention period in days")
    temp_file_retention_hours: int = Field(default=24, ge=1, description="Temporary file retention in hours")
    maintenance_interval_hours: int = Field(default=24, ge=1, description="Maintenance interval in hours")
    
    # Repository Analysis Configuration
    max_repo_size_mb: int = Field(default=500, ge=1, le=10000, description="Maximum repository size in MB")
    analysis_timeout_minutes: int = Field(default=10, ge=1, le=120, description="Analysis timeout in minutes")
    max_concurrent_analyses: int = Field(default=5, ge=1, le=50, description="Maximum concurrent analyses")
    
    # FAISS Configuration
    faiss_index_type: FAISSIndexType = Field(default=FAISSIndexType.FLAT_IP, description="FAISS index type")
    embedding_dimension: int = Field(default=1536, ge=1, description="Embedding vector dimension")
    use_gpu_for_faiss: bool = Field(default=False, description="Use GPU for FAISS operations")
    faiss_gpu_device: int = Field(default=0, ge=0, description="GPU device ID for FAISS")
    
    # GPU Configuration
    enable_gpu_acceleration: bool = Field(default=True, description="Enable GPU acceleration when available")
    
    # Rate Limiting
    llm_requests_per_minute: int = Field(default=60, ge=1, description="LLM requests per minute limit")
    max_tokens_per_request: int = Field(default=4000, ge=1, description="Maximum tokens per LLM request")
    
    # Security Configuration
    allowed_repo_hosts: List[str] = Field(
        default=["github.com", "gitlab.com", "bitbucket.org"], 
        description="Allowed repository hosts"
    )
    enable_local_repos: bool = Field(default=True, description="Enable local repository access")
    api_key_header: str = Field(default="X-API-Key", description="API key header name")
    cors_origins: List[str] = Field(default=["*"], description="CORS allowed origins")
    
    # Monitoring and Metrics
    enable_metrics: bool = Field(default=True, description="Enable metrics collection")
    metrics_retention_days: int = Field(default=30, ge=1, description="Metrics retention period")
    health_check_interval_seconds: int = Field(default=60, ge=10, description="Health check interval")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        use_enum_values = True
        
        # Field documentation for auto-generated docs
        schema_extra = {
            "example": {
                "api_host": "0.0.0.0",
                "api_port": 8000,
                "debug": False,
                "llm_provider": "openai",
                "openai_api_key": "sk-...",
                "github_token": "ghp_...",
                "storage_base_path": "./storage",
                "max_concurrent_analyses": 5
            }
        }
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._create_storage_directories()
    
    @validator('openai_api_key', 'azure_openai_api_key', 'github_token', pre=True)
    def validate_api_keys(cls, v):
        """Validate API key format"""
        if v and isinstance(v, str):
            if len(v) < 10:
                raise ValueError("API key too short")
        return v
    
    @validator('storage_base_path', 'repos_storage_path', 'docs_storage_path', 'embeddings_storage_path')
    def validate_storage_paths(cls, v):
        """Validate storage paths"""
        if not v:
            raise ValueError("Storage path cannot be empty")
        
        path = Path(v)
        if path.is_file():
            raise ValueError(f"Storage path cannot be a file: {v}")
        
        return str(path.resolve())
    
    @validator('cors_origins')
    def validate_cors_origins(cls, v):
        """Validate CORS origins"""
        if not v:
            return ["*"]
        
        for origin in v:
            if origin != "*" and not origin.startswith(('http://', 'https://')):
                raise ValueError(f"Invalid CORS origin format: {origin}")
        
        return v
    
    @root_validator(skip_on_failure=True)
    def validate_provider_configs(cls, values):
        """Validate provider-specific configurations"""
        llm_provider = values.get('llm_provider')
        
        if llm_provider == LLMProvider.OPENAI:
            if not values.get('openai_api_key'):
                raise ValueError("OpenAI API key is required when using OpenAI provider")
        
        elif llm_provider == LLMProvider.AZURE:
            required_fields = ['azure_openai_endpoint', 'azure_openai_api_key', 'azure_openai_deployment_name']
            for field in required_fields:
                if not values.get(field):
                    raise ValueError(f"{field} is required when using Azure provider")
        
        # For huggingface and other providers, no additional validation needed
        return values
    
    def _create_storage_directories(self):
        """Create necessary storage directories"""
        directories = [
            self.storage_base_path,
            self.repos_storage_path,
            self.docs_storage_path,
            self.embeddings_storage_path,
            os.path.dirname(self.database_path)
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
            except Exception as e:
                logger.error(f"Failed to create storage directory {directory}: {e}")
    
    @property
    def llm_api_key(self) -> Optional[str]:
        """Get the appropriate API key based on provider"""
        if self.llm_provider == LLMProvider.OPENAI and self.openai_api_key:
            return self.openai_api_key.get_secret_value()
        elif self.llm_provider == LLMProvider.AZURE and self.azure_openai_api_key:
            return self.azure_openai_api_key.get_secret_value()
        return None
    
    @property
    def llm_base_url(self) -> Optional[str]:
        """Get the appropriate base URL based on provider"""
        if self.llm_provider == LLMProvider.OPENAI:
            return self.openai_base_url
        elif self.llm_provider == LLMProvider.AZURE:
            return self.azure_openai_endpoint
        return None
    
    def validate_llm_config(self) -> bool:
        """Validate LLM configuration"""
        if self.llm_provider == LLMProvider.OPENAI:
            return self.openai_api_key is not None
        elif self.llm_provider == LLMProvider.AZURE:
            return all([
                self.azure_openai_endpoint,
                self.azure_openai_api_key,
                self.azure_openai_deployment_name
            ])
        elif self.llm_provider == LLMProvider.GOOGLE:
            return self.google_api_key is not None
        elif self.llm_provider == LLMProvider.ANTHROPIC:
            return self.anthropic_api_key is not None
        elif self.llm_provider == LLMProvider.HUGGINGFACE:
            return True  # No API key needed for local models
        return False
    
    def check_gpu_availability(self) -> bool:
        """Check if GPU is available for acceleration"""
        if not self.enable_gpu_acceleration:
            return False
        
        try:
            import torch
            return torch.cuda.is_available()
        except ImportError:
            return False
    
    def get_device(self) -> str:
        """Get the appropriate device (cuda or cpu)"""
        if self.check_gpu_availability():
            return f"cuda:{self.faiss_gpu_device}"
        return "cpu"
    
    def to_dict(self, include_secrets: bool = False) -> Dict[str, Any]:
        """Convert settings to dictionary"""
        data = self.dict()
        
        if not include_secrets:
            # Mask secret values
            for key, value in data.items():
                if 'api_key' in key.lower() or 'secret' in key.lower():
                    if value:
                        data[key] = "***masked***"
        
        return data


# Global configuration manager
config_manager = ConfigurationManager()

# Global settings instance (for backward compatibility)
settings = config_manager.settings