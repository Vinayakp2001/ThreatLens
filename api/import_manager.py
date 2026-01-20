"""
Standardized import manager for ThreatLens chat system modules
Provides robust import resolution with comprehensive error handling and fallback mechanisms
"""

import importlib
import logging
import sys
import traceback
from typing import Any, Dict, List, Optional, Type, Union
from pathlib import Path
from dataclasses import dataclass
from enum import Enum


logger = logging.getLogger(__name__)


class ImportErrorType(Enum):
    """Types of import errors"""
    MODULE_NOT_FOUND = "module_not_found"
    RELATIVE_IMPORT_FAILED = "relative_import_failed"
    ABSOLUTE_IMPORT_FAILED = "absolute_import_failed"
    ATTRIBUTE_ERROR = "attribute_error"
    CIRCULAR_IMPORT = "circular_import"
    PERMISSION_ERROR = "permission_error"
    UNKNOWN_ERROR = "unknown_error"


@dataclass
class ImportResult:
    """Result of an import operation"""
    success: bool
    module: Optional[Any] = None
    error_type: Optional[ImportErrorType] = None
    error_message: Optional[str] = None
    fallback_used: bool = False
    import_path: Optional[str] = None


class ImportManager:
    """
    Centralized import manager for handling both relative and absolute imports
    with comprehensive error handling and fallback mechanisms
    """
    
    def __init__(self):
        self.import_cache: Dict[str, ImportResult] = {}
        self.failed_imports: Dict[str, ImportResult] = {}
        self.fallback_modules: Dict[str, Any] = {}
        
        # Register common fallback modules
        self._register_fallbacks()
    
    def _register_fallbacks(self):
        """Register fallback implementations for critical modules"""
        # Fallback for database operations
        class MockDatabaseManager:
            def __init__(self):
                logger.warning("Using mock database manager - database operations will be limited")
            
            def fetch_one(self, query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
                logger.warning(f"Mock database fetch_one called: {query}")
                return None
            
            def fetch_all(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
                logger.warning(f"Mock database fetch_all called: {query}")
                return []
            
            def execute(self, query: str, params: tuple = ()) -> bool:
                logger.warning(f"Mock database execute called: {query}")
                return False
        
        # Fallback for RAG system
        class MockRAGSystem:
            def __init__(self, settings=None):
                logger.warning("Using mock RAG system - search functionality will be limited")
            
            def search_with_context(self, query: str, repo_id: str, context_type: str = 'security') -> Dict[str, Any]:
                logger.warning(f"Mock RAG search called: {query}")
                return {"results": [], "query": query, "repo_id": repo_id}
        
        # Fallback for LLM client
        class MockLLMManager:
            def __init__(self):
                logger.warning("Using mock LLM manager - AI responses will be limited")
            
            async def generate_response(self, prompt: str, **kwargs) -> str:
                logger.warning(f"Mock LLM generate_response called")
                return "I apologize, but the AI service is currently unavailable. Please try again later."
        
        # Fallback for settings
        class MockSettings:
            def __init__(self):
                logger.warning("Using mock settings - configuration will use defaults")
                self.database_path = "./storage/threat_modeling.db"
                self.storage_base_path = "./storage"
                self.llm_provider = "openai"
                self.openai_api_key = None
                self.debug = True
        
        self.fallback_modules = {
            "database": {
                "_db_manager": MockDatabaseManager(),
                "init_database": lambda: MockDatabaseManager(),
                "DatabaseManager": MockDatabaseManager
            },
            "rag": {
                "RAGSystem": MockRAGSystem
            },
            "llm_client": {
                "LLMManager": MockLLMManager
            },
            "config": {
                "settings": MockSettings()
            },
            "models": {
                "ChatMessage": type("ChatMessage", (), {}),
                "ChatSession": type("ChatSession", (), {}),
                "ChatRequest": type("ChatRequest", (), {}),
                "ChatResponse": type("ChatResponse", (), {}),
                "ChatHistoryResponse": type("ChatHistoryResponse", (), {})
            }
        }
    
    def safe_import(
        self, 
        module_name: str, 
        attribute_name: Optional[str] = None,
        package: Optional[str] = None,
        fallback_value: Any = None,
        use_cache: bool = True
    ) -> ImportResult:
        """
        Safely import a module or attribute with comprehensive error handling
        
        Args:
            module_name: Name of the module to import
            attribute_name: Specific attribute to get from the module
            package: Package name for relative imports
            fallback_value: Value to return if import fails
            use_cache: Whether to use cached import results
            
        Returns:
            ImportResult with success status and imported module/attribute
        """
        cache_key = f"{package or ''}.{module_name}.{attribute_name or ''}"
        
        # Check cache first
        if use_cache and cache_key in self.import_cache:
            cached_result = self.import_cache[cache_key]
            logger.debug(f"Using cached import result for {cache_key}")
            return cached_result
        
        result = ImportResult(success=False)
        
        try:
            # Try relative import first if package is provided
            if package:
                result = self._try_relative_import(module_name, attribute_name, package)
                if result.success:
                    self._cache_result(cache_key, result, use_cache)
                    return result
            
            # Try absolute import
            result = self._try_absolute_import(module_name, attribute_name)
            if result.success:
                self._cache_result(cache_key, result, use_cache)
                return result
            
            # Try fallback mechanisms
            result = self._try_fallback_import(module_name, attribute_name, fallback_value)
            if result.success:
                result.fallback_used = True
                self._cache_result(cache_key, result, use_cache)
                return result
            
            # All import attempts failed
            error_msg = f"Failed to import {module_name}"
            if attribute_name:
                error_msg += f".{attribute_name}"
            
            result.error_message = error_msg
            result.error_type = ImportErrorType.MODULE_NOT_FOUND
            
            logger.error(f"Import failed: {error_msg}")
            self.failed_imports[cache_key] = result
            
        except Exception as e:
            result.success = False
            result.error_message = f"Unexpected error during import: {str(e)}"
            result.error_type = ImportErrorType.UNKNOWN_ERROR
            logger.error(f"Unexpected import error for {module_name}: {e}")
            logger.debug(f"Import traceback: {traceback.format_exc()}")
        
        return result
    
    def _try_relative_import(
        self, 
        module_name: str, 
        attribute_name: Optional[str], 
        package: str
    ) -> ImportResult:
        """Try relative import"""
        result = ImportResult(success=False)
        
        try:
            # Try relative import with dot notation
            relative_name = f".{module_name}"
            module = importlib.import_module(relative_name, package=package)
            
            if attribute_name:
                if hasattr(module, attribute_name):
                    result.module = getattr(module, attribute_name)
                else:
                    result.error_type = ImportErrorType.ATTRIBUTE_ERROR
                    result.error_message = f"Module {module_name} has no attribute {attribute_name}"
                    return result
            else:
                result.module = module
            
            result.success = True
            result.import_path = f"{package}.{module_name}"
            logger.debug(f"Successful relative import: {result.import_path}")
            
        except ImportError as e:
            result.error_type = ImportErrorType.RELATIVE_IMPORT_FAILED
            result.error_message = f"Relative import failed: {str(e)}"
            logger.debug(f"Relative import failed for {module_name}: {e}")
        except AttributeError as e:
            result.error_type = ImportErrorType.ATTRIBUTE_ERROR
            result.error_message = f"Attribute error in relative import: {str(e)}"
        except Exception as e:
            result.error_type = ImportErrorType.UNKNOWN_ERROR
            result.error_message = f"Unexpected error in relative import: {str(e)}"
        
        return result
    
    def _try_absolute_import(
        self, 
        module_name: str, 
        attribute_name: Optional[str]
    ) -> ImportResult:
        """Try absolute import"""
        result = ImportResult(success=False)
        
        try:
            # Try direct absolute import
            module = importlib.import_module(module_name)
            
            if attribute_name:
                if hasattr(module, attribute_name):
                    result.module = getattr(module, attribute_name)
                else:
                    result.error_type = ImportErrorType.ATTRIBUTE_ERROR
                    result.error_message = f"Module {module_name} has no attribute {attribute_name}"
                    return result
            else:
                result.module = module
            
            result.success = True
            result.import_path = module_name
            logger.debug(f"Successful absolute import: {result.import_path}")
            
        except ImportError as e:
            result.error_type = ImportErrorType.ABSOLUTE_IMPORT_FAILED
            result.error_message = f"Absolute import failed: {str(e)}"
            logger.debug(f"Absolute import failed for {module_name}: {e}")
        except AttributeError as e:
            result.error_type = ImportErrorType.ATTRIBUTE_ERROR
            result.error_message = f"Attribute error in absolute import: {str(e)}"
        except Exception as e:
            result.error_type = ImportErrorType.UNKNOWN_ERROR
            result.error_message = f"Unexpected error in absolute import: {str(e)}"
        
        return result
    
    def _try_fallback_import(
        self, 
        module_name: str, 
        attribute_name: Optional[str], 
        fallback_value: Any
    ) -> ImportResult:
        """Try fallback mechanisms"""
        result = ImportResult(success=False)
        
        # Check if we have a registered fallback for this module
        if module_name in self.fallback_modules:
            fallback_module = self.fallback_modules[module_name]
            
            if attribute_name:
                if attribute_name in fallback_module:
                    result.module = fallback_module[attribute_name]
                    result.success = True
                    result.fallback_used = True
                    logger.warning(f"Using fallback for {module_name}.{attribute_name}")
                elif fallback_value is not None:
                    result.module = fallback_value
                    result.success = True
                    result.fallback_used = True
                    logger.warning(f"Using provided fallback value for {module_name}.{attribute_name}")
            else:
                # Return the entire fallback module dict as a mock module
                class MockModule:
                    def __init__(self, fallback_dict):
                        for key, value in fallback_dict.items():
                            setattr(self, key, value)
                
                result.module = MockModule(fallback_module)
                result.success = True
                result.fallback_used = True
                logger.warning(f"Using fallback module for {module_name}")
        
        elif fallback_value is not None:
            result.module = fallback_value
            result.success = True
            result.fallback_used = True
            logger.warning(f"Using provided fallback value for {module_name}")
        
        return result
    
    def _cache_result(self, cache_key: str, result: ImportResult, use_cache: bool):
        """Cache import result if caching is enabled"""
        if use_cache and result.success:
            self.import_cache[cache_key] = result
    
    def get_import_stats(self) -> Dict[str, Any]:
        """Get statistics about import operations"""
        return {
            "cached_imports": len(self.import_cache),
            "failed_imports": len(self.failed_imports),
            "fallback_modules_available": len(self.fallback_modules),
            "success_rate": len(self.import_cache) / (len(self.import_cache) + len(self.failed_imports)) if (len(self.import_cache) + len(self.failed_imports)) > 0 else 0
        }
    
    def clear_cache(self):
        """Clear import cache"""
        self.import_cache.clear()
        self.failed_imports.clear()
        logger.info("Import cache cleared")
    
    def register_fallback(self, module_name: str, fallback_dict: Dict[str, Any]):
        """Register a fallback module"""
        self.fallback_modules[module_name] = fallback_dict
        logger.info(f"Registered fallback for module: {module_name}")


# Global import manager instance
_import_manager = ImportManager()


def safe_import(
    module_name: str, 
    attribute_name: Optional[str] = None,
    package: Optional[str] = None,
    fallback_value: Any = None
) -> ImportResult:
    """
    Convenience function for safe imports using the global import manager
    
    Args:
        module_name: Name of the module to import
        attribute_name: Specific attribute to get from the module
        package: Package name for relative imports
        fallback_value: Value to return if import fails
        
    Returns:
        ImportResult with success status and imported module/attribute
    """
    return _import_manager.safe_import(
        module_name=module_name,
        attribute_name=attribute_name,
        package=package,
        fallback_value=fallback_value
    )


def get_import_manager() -> ImportManager:
    """Get the global import manager instance"""
    return _import_manager


# Convenience functions for common import patterns
def import_with_fallback(module_name: str, fallback_class: Type) -> Any:
    """Import a module with a fallback class"""
    result = safe_import(module_name, fallback_value=fallback_class)
    return result.module if result.success else fallback_class


def import_attribute_with_fallback(module_name: str, attribute_name: str, fallback_value: Any) -> Any:
    """Import a specific attribute with a fallback value"""
    result = safe_import(module_name, attribute_name=attribute_name, fallback_value=fallback_value)
    return result.module if result.success else fallback_value


def try_imports(*import_specs) -> Dict[str, Any]:
    """
    Try multiple imports and return a dictionary of results
    
    Args:
        import_specs: Tuples of (module_name, attribute_name, fallback_value)
        
    Returns:
        Dictionary mapping attribute names to imported values
    """
    results = {}
    
    for spec in import_specs:
        if len(spec) == 2:
            module_name, attribute_name = spec
            fallback_value = None
        elif len(spec) == 3:
            module_name, attribute_name, fallback_value = spec
        else:
            logger.error(f"Invalid import spec: {spec}")
            continue
        
        result = safe_import(module_name, attribute_name, fallback_value=fallback_value)
        results[attribute_name] = result.module if result.success else fallback_value
        
        if not result.success:
            logger.warning(f"Failed to import {module_name}.{attribute_name}: {result.error_message}")
    
    return results