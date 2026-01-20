"""
Comprehensive Error Handling and Logging System for Chat System
Provides structured error logging, diagnostic information, and recovery suggestions
"""

import json
import logging
import traceback
from datetime import datetime
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    """Error categories for classification"""
    IMPORT = "import"
    DATABASE = "database"
    RAG_SYSTEM = "rag_system"
    LLM_SERVICE = "llm_service"
    SESSION_MANAGEMENT = "session_management"
    CONTEXT_LOADING = "context_loading"
    VALIDATION = "validation"
    NETWORK = "network"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"

@dataclass
class ErrorContext:
    """Structured error context information"""
    error_id: str
    timestamp: str
    component: str
    operation: str
    severity: ErrorSeverity
    category: ErrorCategory
    error_message: str
    stack_trace: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    repo_id: Optional[str] = None
    request_data: Optional[Dict[str, Any]] = None
    system_state: Optional[Dict[str, Any]] = None
    recovery_suggestions: List[str] = None
    diagnostic_info: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.recovery_suggestions is None:
            self.recovery_suggestions = []
        if self.diagnostic_info is None:
            self.diagnostic_info = {}

class ChatErrorHandler:
    """Comprehensive error handler for chat system components"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.error_history: List[ErrorContext] = []
        self.max_history_size = 1000
        
        # Configure structured logging
        self._setup_structured_logging()
    
    def _setup_structured_logging(self):
        """Setup structured logging configuration"""
        # Create formatter for structured logs
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Ensure handler exists
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def log_error(
        self,
        component: str,
        operation: str,
        error: Exception,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        repo_id: Optional[str] = None,
        request_data: Optional[Dict[str, Any]] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> ErrorContext:
        """Log a comprehensive error with structured information"""
        
        error_id = str(uuid.uuid4())
        
        # Capture system state
        system_state = self._capture_system_state()
        
        # Generate recovery suggestions
        recovery_suggestions = self._generate_recovery_suggestions(category, error)
        
        # Create diagnostic information
        diagnostic_info = self._create_diagnostic_info(error, additional_context)
        
        # Create error context
        error_context = ErrorContext(
            error_id=error_id,
            timestamp=datetime.now().isoformat(),
            component=component,
            operation=operation,
            severity=severity,
            category=category,
            error_message=str(error),
            stack_trace=traceback.format_exc(),
            user_id=user_id,
            session_id=session_id,
            repo_id=repo_id,
            request_data=request_data,
            system_state=system_state,
            recovery_suggestions=recovery_suggestions,
            diagnostic_info=diagnostic_info
        )
        
        # Add to history
        self._add_to_history(error_context)
        
        # Log structured error
        self._log_structured_error(error_context)
        
        return error_context
    
    def log_import_error(
        self,
        module_name: str,
        error: Exception,
        import_type: str = "unknown",
        fallback_available: bool = False
    ) -> ErrorContext:
        """Log import-specific errors with detailed context"""
        
        diagnostic_info = {
            "module_name": module_name,
            "import_type": import_type,
            "fallback_available": fallback_available,
            "python_path": str(__import__('sys').path),
            "current_working_directory": str(__import__('os').getcwd())
        }
        
        severity = ErrorSeverity.HIGH if not fallback_available else ErrorSeverity.MEDIUM
        
        return self.log_error(
            component="ImportManager",
            operation=f"import_{module_name}",
            error=error,
            severity=severity,
            category=ErrorCategory.IMPORT,
            additional_context=diagnostic_info
        )
    
    def log_database_error(
        self,
        operation: str,
        query: Optional[str] = None,
        params: Optional[tuple] = None,
        error: Exception = None,
        repo_id: Optional[str] = None
    ) -> ErrorContext:
        """Log database-specific errors with query context"""
        
        diagnostic_info = {
            "query": query,
            "params": str(params) if params else None,
            "database_file": self._get_database_file_info(),
            "connection_status": self._check_database_connection()
        }
        
        return self.log_error(
            component="DatabaseManager",
            operation=operation,
            error=error,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.DATABASE,
            repo_id=repo_id,
            additional_context=diagnostic_info
        )
    
    def log_rag_error(
        self,
        operation: str,
        query: Optional[str] = None,
        error: Exception = None,
        repo_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> ErrorContext:
        """Log RAG system errors with search context"""
        
        diagnostic_info = {
            "search_query": query,
            "embeddings_status": self._check_embeddings_status(),
            "vector_store_status": self._check_vector_store_status()
        }
        
        return self.log_error(
            component="RAGSystem",
            operation=operation,
            error=error,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.RAG_SYSTEM,
            repo_id=repo_id,
            session_id=session_id,
            additional_context=diagnostic_info
        )
    
    def log_llm_error(
        self,
        operation: str,
        prompt: Optional[str] = None,
        error: Exception = None,
        session_id: Optional[str] = None
    ) -> ErrorContext:
        """Log LLM service errors with request context"""
        
        diagnostic_info = {
            "prompt_length": len(prompt) if prompt else 0,
            "llm_service_status": self._check_llm_service_status(),
            "api_key_configured": self._check_api_key_configured()
        }
        
        return self.log_error(
            component="LLMManager",
            operation=operation,
            error=error,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.LLM_SERVICE,
            session_id=session_id,
            additional_context=diagnostic_info
        )
    
    def log_session_error(
        self,
        operation: str,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        error: Exception = None
    ) -> ErrorContext:
        """Log session management errors"""
        
        diagnostic_info = {
            "active_sessions_count": self._get_active_sessions_count(),
            "session_exists": self._check_session_exists(session_id) if session_id else False
        }
        
        return self.log_error(
            component="SessionManager",
            operation=operation,
            error=error,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.SESSION_MANAGEMENT,
            session_id=session_id,
            user_id=user_id,
            additional_context=diagnostic_info
        )
    
    def _capture_system_state(self) -> Dict[str, Any]:
        """Capture current system state for diagnostics"""
        try:
            import psutil
            import sys
            
            return {
                "memory_usage": psutil.virtual_memory()._asdict(),
                "cpu_usage": psutil.cpu_percent(),
                "python_version": sys.version,
                "timestamp": datetime.now().isoformat()
            }
        except ImportError:
            return {
                "memory_usage": "unavailable",
                "cpu_usage": "unavailable",
                "python_version": __import__('sys').version,
                "timestamp": datetime.now().isoformat()
            }
    
    def _generate_recovery_suggestions(
        self, 
        category: ErrorCategory, 
        error: Exception
    ) -> List[str]:
        """Generate context-specific recovery suggestions"""
        
        suggestions = []
        error_str = str(error).lower()
        
        if category == ErrorCategory.IMPORT:
            suggestions.extend([
                "Check if the required module is installed",
                "Verify Python path configuration",
                "Try restarting the application",
                "Check for circular import dependencies"
            ])
            
        elif category == ErrorCategory.DATABASE:
            suggestions.extend([
                "Check database file permissions",
                "Verify database file exists and is not corrupted",
                "Try reconnecting to the database",
                "Check available disk space"
            ])
            
            if "locked" in error_str:
                suggestions.append("Database may be locked by another process")
            if "no such table" in error_str:
                suggestions.append("Run database migrations to create missing tables")
                
        elif category == ErrorCategory.RAG_SYSTEM:
            suggestions.extend([
                "Check if embeddings are properly generated",
                "Verify vector store is accessible",
                "Try regenerating embeddings for the repository",
                "Check if the search query is valid"
            ])
            
        elif category == ErrorCategory.LLM_SERVICE:
            suggestions.extend([
                "Check API key configuration",
                "Verify network connectivity",
                "Check API rate limits",
                "Try with a shorter prompt"
            ])
            
            if "api key" in error_str or "unauthorized" in error_str:
                suggestions.append("Verify API key is valid and has sufficient permissions")
            if "rate limit" in error_str:
                suggestions.append("Wait before making additional requests")
                
        elif category == ErrorCategory.SESSION_MANAGEMENT:
            suggestions.extend([
                "Try starting a new chat session",
                "Check if session has expired",
                "Verify session ID is valid"
            ])
        
        # Add general suggestions
        suggestions.extend([
            "Check application logs for more details",
            "Contact support if the issue persists"
        ])
        
        return suggestions
    
    def _create_diagnostic_info(
        self, 
        error: Exception, 
        additional_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create comprehensive diagnostic information"""
        
        diagnostic = {
            "error_type": type(error).__name__,
            "error_module": getattr(error, '__module__', 'unknown'),
            "error_args": str(error.args) if hasattr(error, 'args') else None,
            "timestamp": datetime.now().isoformat()
        }
        
        if additional_context:
            diagnostic.update(additional_context)
        
        return diagnostic
    
    def _add_to_history(self, error_context: ErrorContext):
        """Add error to history with size management"""
        self.error_history.append(error_context)
        
        # Maintain history size
        if len(self.error_history) > self.max_history_size:
            self.error_history = self.error_history[-self.max_history_size:]
    
    def _log_structured_error(self, error_context: ErrorContext):
        """Log structured error information"""
        
        # Create log message
        log_message = (
            f"[{error_context.severity.value.upper()}] "
            f"{error_context.component}.{error_context.operation} - "
            f"{error_context.error_message}"
        )
        
        # Log with appropriate level
        if error_context.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(log_message)
        elif error_context.severity == ErrorSeverity.HIGH:
            self.logger.error(log_message)
        elif error_context.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
        
        # Log detailed context as JSON for structured logging systems
        detailed_context = {
            "error_id": error_context.error_id,
            "component": error_context.component,
            "operation": error_context.operation,
            "category": error_context.category.value,
            "severity": error_context.severity.value,
            "diagnostic_info": error_context.diagnostic_info,
            "recovery_suggestions": error_context.recovery_suggestions
        }
        
        self.logger.debug(f"Error Context: {json.dumps(detailed_context, indent=2)}")
    
    def get_error_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get error summary for the specified time period"""
        
        from datetime import timedelta
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent_errors = [
            error for error in self.error_history
            if datetime.fromisoformat(error.timestamp) > cutoff_time
        ]
        
        # Group by category
        category_counts = {}
        severity_counts = {}
        
        for error in recent_errors:
            category = error.category.value
            severity = error.severity.value
            
            category_counts[category] = category_counts.get(category, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "time_period_hours": hours,
            "total_errors": len(recent_errors),
            "errors_by_category": category_counts,
            "errors_by_severity": severity_counts,
            "most_recent_error": asdict(recent_errors[-1]) if recent_errors else None
        }
    
    def get_recovery_suggestions_for_category(self, category: ErrorCategory) -> List[str]:
        """Get general recovery suggestions for a specific error category"""
        return self._generate_recovery_suggestions(category, Exception("Generic error"))
    
    # Helper methods for diagnostic information
    def _get_database_file_info(self) -> Dict[str, Any]:
        """Get database file information"""
        try:
            import os
            db_path = "data/threatlens.db"  # Default path
            
            if os.path.exists(db_path):
                stat = os.stat(db_path)
                return {
                    "exists": True,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "readable": os.access(db_path, os.R_OK),
                    "writable": os.access(db_path, os.W_OK)
                }
            else:
                return {"exists": False}
        except Exception as e:
            return {"error": str(e)}
    
    def _check_database_connection(self) -> str:
        """Check database connection status"""
        try:
            # This would need to be implemented based on your database manager
            return "unknown"
        except Exception:
            return "failed"
    
    def _check_embeddings_status(self) -> str:
        """Check embeddings system status"""
        try:
            # This would check if embeddings are available
            return "unknown"
        except Exception:
            return "failed"
    
    def _check_vector_store_status(self) -> str:
        """Check vector store status"""
        try:
            # This would check vector store availability
            return "unknown"
        except Exception:
            return "failed"
    
    def _check_llm_service_status(self) -> str:
        """Check LLM service status"""
        try:
            # This would ping the LLM service
            return "unknown"
        except Exception:
            return "failed"
    
    def _check_api_key_configured(self) -> bool:
        """Check if API key is configured"""
        try:
            import os
            return bool(os.getenv('OPENAI_API_KEY') or os.getenv('ANTHROPIC_API_KEY'))
        except Exception:
            return False
    
    def _get_active_sessions_count(self) -> int:
        """Get count of active sessions"""
        try:
            # This would need to be implemented based on session manager
            return 0
        except Exception:
            return -1
    
    def _check_session_exists(self, session_id: str) -> bool:
        """Check if session exists"""
        try:
            # This would check session existence
            return False
        except Exception:
            return False


# Global error handler instance
_error_handler = None

def get_error_handler() -> ChatErrorHandler:
    """Get or create the global error handler instance"""
    global _error_handler
    if _error_handler is None:
        _error_handler = ChatErrorHandler()
    return _error_handler