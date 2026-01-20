"""
DeepWiki-style Chat System for ThreatLens
RAG-powered conversational interface over security wikis
"""

import json
import logging
import sqlite3
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

# Import comprehensive error handling
try:
    from .chat_error_handler import get_error_handler, ErrorSeverity, ErrorCategory
except ImportError:
    from chat_error_handler import get_error_handler, ErrorSeverity, ErrorCategory

# Import service degradation manager
try:
    from .service_degradation import get_degradation_manager, ServiceStatus
except ImportError:
    from service_degradation import get_degradation_manager, ServiceStatus

# Initialize error handler and degradation manager
error_handler = get_error_handler()
degradation_manager = get_degradation_manager()

# Standardized import system with comprehensive error handling
try:
    from .import_manager import safe_import, get_import_manager
except ImportError:
    from import_manager import safe_import, get_import_manager

# Import required modules using the safe import system
import_manager = get_import_manager()

# Import core dependencies with fallbacks
rag_result = safe_import("rag", "OWASPGuidedRAGSystem", package="api")
RAGSystem = rag_result.module
if not rag_result.success:
    # Fallback to EnhancedRAGSystem
    rag_result = safe_import("rag", "EnhancedRAGSystem", package="api")
    RAGSystem = rag_result.module
    if not rag_result.success:
        # Final fallback to basic RAGSystem
        rag_result = safe_import("rag", "RAGSystem", package="api")
        RAGSystem = rag_result.module
        if not rag_result.success:
            error_context = error_handler.log_import_error(
                module_name="rag.RAGSystem",
                error=Exception(rag_result.error_message),
                import_type="core_dependency",
                fallback_available=False
            )
            logger.error(f"Failed to import RAGSystem: {rag_result.error_message}")

llm_result = safe_import("llm_client", "LLMManager", package="api")
LLMManager = llm_result.module
if not llm_result.success:
    error_context = error_handler.log_import_error(
        module_name="llm_client.LLMManager",
        error=Exception(llm_result.error_message),
        import_type="core_dependency",
        fallback_available=False
    )
    logger.error(f"Failed to import LLMManager: {llm_result.error_message}")

# Import database components
db_imports = safe_import("database", package="api")
if db_imports.success:
    _db_manager = getattr(db_imports.module, '_db_manager', None)
    init_database = getattr(db_imports.module, 'init_database', None)
else:
    error_context = error_handler.log_import_error(
        module_name="database",
        error=Exception(db_imports.error_message),
        import_type="core_dependency",
        fallback_available=True
    )
    logger.error(f"Failed to import database module: {db_imports.error_message}")
    _db_manager = None
    init_database = lambda: None

# Import models
models_result = safe_import("models", package="api")
if models_result.success:
    ChatMessage = getattr(models_result.module, 'ChatMessage', None)
    ChatSession = getattr(models_result.module, 'ChatSession', None)
else:
    error_context = error_handler.log_import_error(
        module_name="models",
        error=Exception(models_result.error_message),
        import_type="data_models",
        fallback_available=True
    )
    logger.error(f"Failed to import models: {models_result.error_message}")
    # Use fallback classes
    from dataclasses import dataclass
    from datetime import datetime
    from typing import List, Dict, Any
    
    @dataclass
    class ChatMessage:
        id: str
        role: str
        content: str
        timestamp: datetime
        sources: List[Dict[str, Any]] = None
    
    @dataclass
    class ChatSession:
        session_id: str
        repo_id: str
        user_id: str
        created_at: datetime
        messages: List[ChatMessage] = None
        context: Dict[str, Any] = None

# Import settings
settings_result = safe_import("config", "settings", package="api")
settings = settings_result.module
if not settings_result.success:
    error_context = error_handler.log_import_error(
        module_name="config.settings",
        error=Exception(settings_result.error_message),
        import_type="configuration",
        fallback_available=False
    )
    logger.error(f"Failed to import settings: {settings_result.error_message}")

# Log import status
import_stats = import_manager.get_import_stats()
logger.info(f"Chat system import stats: {import_stats}")
if import_stats['success_rate'] < 1.0:
    logger.warning("Some imports failed - system may have limited functionality")

logger = logging.getLogger(__name__)

# Global chat system instance
_chat_system = None

class RepositoryContextLoader:
    """Enhanced repository context loading with comprehensive error handling"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.logger = logging.getLogger(__name__ + ".RepositoryContextLoader")
    
    async def load_context(self, repo_id: str) -> Dict[str, Any]:
        """Load repository context with fallback mechanisms"""
        try:
            # Validate inputs
            if not repo_id or not isinstance(repo_id, str):
                error_context = error_handler.log_error(
                    component="RepositoryContextLoader",
                    operation="load_context",
                    error=ValueError(f"Invalid repo_id: {repo_id}"),
                    severity=ErrorSeverity.MEDIUM,
                    category=ErrorCategory.VALIDATION,
                    repo_id=repo_id,
                    request_data={"repo_id": repo_id}
                )
                self.logger.error(f"Invalid repo_id provided: {repo_id}")
                return self._create_error_context(repo_id, "Invalid repository ID")
            
            # Validate database connection
            if not self._validate_database():
                error_context = error_handler.log_database_error(
                    operation="connection_validation",
                    error=Exception("Database connection validation failed"),
                    repo_id=repo_id
                )
                return self._create_error_context(repo_id, "Database connection failed")
            
            # Load repository information
            repo_info = self._load_repository_info(repo_id)
            if not repo_info:
                error_context = error_handler.log_database_error(
                    operation="repository_lookup",
                    query="SELECT id, name, url, analysis_status, created_at, updated_at FROM repositories WHERE id = ?",
                    params=(repo_id,),
                    error=Exception("Repository not found"),
                    repo_id=repo_id
                )
                return self._create_error_context(repo_id, "Repository not found")
            
            # Load wiki information
            wiki_info = self._load_wiki_info(repo_id)
            
            # Combine into comprehensive context
            context = self._build_context(repo_info, wiki_info)
            
            self.logger.info(f"Successfully loaded context for repository {repo_id}")
            return context
            
        except Exception as e:
            error_context = error_handler.log_error(
                component="RepositoryContextLoader",
                operation="load_context",
                error=e,
                severity=ErrorSeverity.HIGH,
                category=ErrorCategory.CONTEXT_LOADING,
                repo_id=repo_id,
                additional_context={"repo_id": repo_id}
            )
            self.logger.error(f"Unexpected error loading context for {repo_id}: {e}")
            return self._create_error_context(repo_id, f"Unexpected error: {str(e)}")
    
    def _validate_database(self) -> bool:
        """Validate database connection"""
        try:
            # Check if db_manager exists and is not None
            if self.db_manager is None:
                self.logger.error("Database manager is None")
                return False
            
            if hasattr(self.db_manager, 'validate_connection'):
                return self.db_manager.validate_connection()
            elif hasattr(self.db_manager, 'health_check'):
                return self.db_manager.health_check()
            else:
                # Fallback validation
                test_result = self.db_manager.fetch_one("SELECT 1 as test", ())
                return test_result is not None
        except Exception as e:
            error_context = error_handler.log_database_error(
                operation="connection_validation",
                query="SELECT 1 as test",
                params=(),
                error=e
            )
            self.logger.error(f"Database validation failed: {e}")
            return False
    
    def _load_repository_info(self, repo_id: str) -> Optional[Dict[str, Any]]:
        """Load repository information from database"""
        try:
            query = "SELECT id, name, url, analysis_status, created_at, updated_at FROM repositories WHERE id = ?"
            result = self.db_manager.fetch_one(query, (repo_id,))
            
            if result:
                self.logger.debug(f"Found repository: {result['name']}")
                return result
            else:
                self.logger.warning(f"Repository not found: {repo_id}")
                return None
                
        except Exception as e:
            error_context = error_handler.log_database_error(
                operation="repository_info_lookup",
                query="SELECT id, name, url, analysis_status, created_at, updated_at FROM repositories WHERE id = ?",
                params=(repo_id,),
                error=e,
                repo_id=repo_id
            )
            self.logger.error(f"Error loading repository info for {repo_id}: {e}")
            return None
    
    def _load_wiki_info(self, repo_id: str) -> Dict[str, Any]:
        """Load wiki information from database using actual schema"""
        try:
            query = """
                SELECT id, title, content, section_type, created_at, updated_at 
                FROM security_wikis 
                WHERE repository_id = ?
                ORDER BY created_at DESC
            """
            results = self.db_manager.fetch_all(query, (repo_id,))
            
            wiki_info = {
                "wikis": [],
                "total_sections": 0,
                "total_content_length": 0,
                "section_titles": []
            }
            
            if results:
                for wiki in results:
                    wiki_data = {
                        "id": wiki['id'],
                        "title": wiki['title'],
                        "section_type": wiki.get('section_type', 'general'),
                        "created_at": wiki['created_at'],
                        "updated_at": wiki['updated_at']
                    }
                    
                    # Use content directly (not JSON sections)
                    content = wiki.get('content', '')
                    if content:
                        wiki_data['sections'] = [wiki['title']]  # Use title as section name
                        wiki_info["section_titles"].append(wiki['title'])
                        wiki_info["total_sections"] += 1
                        wiki_info["total_content_length"] += len(content)
                    
                    wiki_info["wikis"].append(wiki_data)
                
                self.logger.debug(f"Loaded {len(results)} wikis with {wiki_info['total_sections']} sections")
            
            return wiki_info
            
        except Exception as e:
            error_context = error_handler.log_database_error(
                operation="wiki_info_lookup",
                query="SELECT id, title, content, section_type, created_at, updated_at FROM security_wikis WHERE repository_id = ?",
                params=(repo_id,),
                error=e,
                repo_id=repo_id
            )
            self.logger.error(f"Error loading wiki info for {repo_id}: {e}")
            return {
                "wikis": [],
                "total_sections": 0,
                "total_content_length": 0,
                "section_titles": []
            }
    
    def _build_context(self, repo_info: Dict[str, Any], wiki_info: Dict[str, Any]) -> Dict[str, Any]:
        """Build comprehensive repository context"""
        return {
            "repository_id": repo_info['id'],
            "repository_name": repo_info['name'],
            "repository_url": repo_info.get('url'),
            "analysis_status": repo_info.get('analysis_status'),
            "has_wiki": len(wiki_info['wikis']) > 0,
            "wiki_count": len(wiki_info['wikis']),
            "sections": wiki_info['section_titles'],
            "section_count": wiki_info['total_sections'],
            "content_length": wiki_info['total_content_length'],
            "created_at": repo_info.get('created_at'),
            "updated_at": repo_info.get('updated_at'),
            "context_loaded_at": datetime.now().isoformat(),
            "context_source": "database"
        }
    
    def _create_error_context(self, repo_id: str, error_reason: str) -> Dict[str, Any]:
        """Create fallback context for error cases"""
        self.logger.warning(f"Creating error context for {repo_id}: {error_reason}")
        
        return {
            "repository_id": repo_id,
            "repository_name": "Unknown Repository",
            "repository_url": None,
            "analysis_status": "unknown",
            "has_wiki": False,
            "wiki_count": 0,
            "sections": [],
            "section_count": 0,
            "content_length": 0,
            "created_at": None,
            "updated_at": None,
            "context_loaded_at": datetime.now().isoformat(),
            "context_source": "fallback",
            "error_reason": error_reason,
            "fallback_created": True
        }


class SecurityChatSystem:
    """
    DeepWiki-style conversational system for security wikis
    Combines RAG search with LLM for intelligent Q&A
    """
    
    def __init__(self):
        try:
            self.rag_system = RAGSystem(settings)
            degradation_manager.update_service_health("rag_system", ServiceStatus.HEALTHY)
        except Exception as e:
            error_handler.log_error(
                component="SecurityChatSystem",
                operation="init_rag_system",
                error=e,
                severity=ErrorSeverity.HIGH,
                category=ErrorCategory.RAG_SYSTEM
            )
            self.rag_system = None
            degradation_manager.update_service_health("rag_system", ServiceStatus.UNAVAILABLE, str(e))
        
        try:
            self.llm_client = LLMManager()
            degradation_manager.update_service_health("llm_service", ServiceStatus.HEALTHY)
        except Exception as e:
            error_handler.log_error(
                component="SecurityChatSystem", 
                operation="init_llm_client",
                error=e,
                severity=ErrorSeverity.HIGH,
                category=ErrorCategory.LLM_SERVICE
            )
            self.llm_client = None
            degradation_manager.update_service_health("llm_service", ServiceStatus.UNAVAILABLE, str(e))
        
        # Initialize database if needed
        global _db_manager
        try:
            if _db_manager is None:
                _db_manager = init_database()
            # Ensure we have a valid database manager
            if _db_manager is None:
                raise Exception("Failed to initialize database manager")
            degradation_manager.update_service_health("database", ServiceStatus.HEALTHY)
        except Exception as e:
            error_handler.log_database_error(
                operation="init_database",
                error=e
            )
            degradation_manager.update_service_health("database", ServiceStatus.UNAVAILABLE, str(e))
        
        # Initialize repository context loader with the correct database manager
        # Use _db_manager if available, otherwise create a mock for graceful degradation
        if _db_manager is not None:
            self.context_loader = RepositoryContextLoader(_db_manager)
            logger.info(f"Initialized RepositoryContextLoader with database manager: {type(_db_manager)}")
        else:
            # Create a mock database manager for graceful degradation
            class MockDatabaseManager:
                def fetch_one(self, query, params):
                    return None
                def fetch_all(self, query, params):
                    return []
                def validate_connection(self):
                    return False
                def health_check(self):
                    return False
            
            mock_db = MockDatabaseManager()
            self.context_loader = RepositoryContextLoader(mock_db)
            logger.warning("Using mock database manager for context loader - functionality will be limited")
        
        # Chat session storage (in-memory for now, can be moved to DB)
        self.active_sessions: Dict[str, ChatSession] = {}
        
    async def start_chat_session(self, repo_id: str, user_id: str = "default") -> str:
        """Start a new chat session for a repository"""
        print(f"🟠 STEP 7: SecurityChatSystem.start_chat_session() called")
        print(f"🟠 STEP 7: repo_id = {repo_id}")
        print(f"🟠 STEP 7: user_id = {user_id}")
        
        session_id = str(uuid.uuid4())
        print(f"🟠 STEP 7: Generated session_id = {session_id}")
        
        print(f"🟠 STEP 8: About to call context_loader.load_context()")
        # Get repository context using enhanced loader
        repo_context = await self.context_loader.load_context(repo_id)
        print(f"🟠 STEP 8: context_loader.load_context() returned = {repo_context}")
        
        session = ChatSession(
            session_id=session_id,
            repo_id=repo_id,
            user_id=user_id,
            created_at=datetime.now(),
            messages=[],
            context=repo_context
        )
        
        self.active_sessions[session_id] = session
        
        print(f"🟠 STEP 9: About to call _generate_welcome_message()")
        # Generate welcome message and add it as the first message
        welcome_message = self._generate_welcome_message(repo_context)
        print(f"🟠 STEP 9: _generate_welcome_message() returned = {welcome_message}")
        
        # Add welcome message to session history
        welcome_msg = ChatMessage(
            id=str(uuid.uuid4()),
            role="assistant",
            content=welcome_message,
            timestamp=datetime.now()
        )
        session.messages.append(welcome_msg)
        
        print(f"🟠 STEP 9: Returning session_id = {session_id}")
        return session_id
    
    async def send_message(self, session_id: str, message: str) -> Dict[str, Any]:
        """Send a message and get AI response with graceful degradation"""
        try:
            # Validate session with fallback
            session_validation_result = await degradation_manager.execute_with_fallback(
                "session_validation",
                self._validate_session,
                {"session_id": session_id},
                session_id
            )
            
            if not session_validation_result["success"]:
                error_context = error_handler.log_session_error(
                    operation="send_message",
                    session_id=session_id,
                    error=ValueError("Session not found")
                )
                raise ValueError("Session not found")
            
            session = self.active_sessions[session_id]
            
            # Add user message
            user_message = ChatMessage(
                id=str(uuid.uuid4()),
                role="user",
                content=message,
                timestamp=datetime.now()
            )
            session.messages.append(user_message)
            
            # Get relevant context using RAG with fallback
            rag_result = await degradation_manager.execute_with_fallback(
                "rag_system",
                self._perform_rag_search,
                {
                    "repo_context": session.context,
                    "message": message
                },
                message,
                session.repo_id
            )
            
            context_docs = rag_result.get("result", {}).get("results", [])
            
            # Generate AI response with fallback
            llm_result = await degradation_manager.execute_with_fallback(
                "llm_service",
                self._generate_llm_response,
                {
                    "repo_context": session.context,
                    "message": message,
                    "context_docs": context_docs
                },
                message,
                context_docs,
                session.context,
                session.messages[-10:]
            )
            
            ai_response = llm_result.get("result", "I apologize, but I'm currently unable to generate a response. Please try again later.")
            
            # Add service status information if using fallbacks
            if rag_result.get("source") == "fallback" or llm_result.get("source") == "fallback":
                service_status = degradation_manager.get_system_health_summary()
                if service_status["unavailable_services"] > 0:
                    ai_response += f"\n\n*Note: Some services are currently experiencing issues. Functionality may be limited.*"
            
            # Add AI message
            ai_message = ChatMessage(
                id=str(uuid.uuid4()),
                role="assistant",
                content=ai_response,
                timestamp=datetime.now()
            )
            session.messages.append(ai_message)
            
            # Convert SearchResult objects to dictionaries for API response
            sources_dict = []
            for doc in context_docs:
                if hasattr(doc, 'doc_id'):  # SearchResult object
                    sources_dict.append({
                        "doc_id": doc.doc_id,
                        "title": getattr(doc, 'title', None),
                        "content": getattr(doc, 'content', None),
                        "score": getattr(doc, 'score', None),
                        "metadata": getattr(doc, 'metadata', {}),
                        "code_snippet": getattr(doc, 'code_snippet', None)
                    })
                elif isinstance(doc, dict):  # Already a dictionary
                    sources_dict.append(doc)
                else:
                    # Fallback for unknown types
                    sources_dict.append({"content": str(doc)})
            
            return {
                "message": ai_response,
                "sources": sources_dict,
                "session_id": session_id,
                "timestamp": datetime.now().isoformat(),
                "service_status": {
                    "rag_fallback": rag_result.get("source") == "fallback",
                    "llm_fallback": llm_result.get("source") == "fallback"
                }
            }
            
        except Exception as e:
            error_context = error_handler.log_error(
                component="SecurityChatSystem",
                operation="send_message",
                error=e,
                severity=ErrorSeverity.HIGH,
                category=ErrorCategory.SESSION_MANAGEMENT,
                session_id=session_id,
                request_data={"message": message[:100]}  # Truncate for privacy
            )
            
            # Return graceful error response
            return {
                "message": degradation_manager.create_user_friendly_error_message("chat_system", "send_message"),
                "sources": [],
                "session_id": session_id,
                "timestamp": datetime.now().isoformat(),
                "error": True,
                "error_id": error_context.error_id
            }
    
    async def _get_repository_context(self, repo_id: str) -> Dict[str, Any]:
        """Get repository context from database with enhanced error handling"""
        try:
            print(f"🟣 STEP 8: _get_repository_context() called with repo_id = {repo_id}")
            
            # Ensure database manager is initialized and validate connection
            global _db_manager
            if _db_manager is None:
                print(f"🟣 STEP 8: _db_manager is None, initializing...")
                _db_manager = init_database()
                print(f"🟣 STEP 8: _db_manager initialized = {_db_manager}")
            
            # Validate database connection
            if not self._validate_database_connection():
                logger.error("Database connection validation failed")
                return self._create_fallback_context(repo_id, "Database connection failed")
            
            print(f"🟣 STEP 8: About to query repositories table")
            # Get repository info with proper error handling
            repo_query = "SELECT name, url FROM repositories WHERE id = ?"
            repo_result = self._execute_database_query_with_retry(
                "fetch_one", repo_query, (repo_id,), "repository lookup"
            )
            
            print(f"🟣 STEP 8: Repository query result = {repo_result}")
            
            if not repo_result:
                logger.warning(f"Repository not found for id: {repo_id}")
                print(f"🟣 STEP 8: No repository found, returning default context")
                return self._create_fallback_context(repo_id, "Repository not found in database")
            
            repo_name = repo_result['name']
            print(f"🟣 STEP 8: Found repository name = {repo_name}")
            
            print(f"🟣 STEP 8: About to query security_wikis table")
            # Get wiki sections with corrected column name
            wiki_query = """
                SELECT title, sections 
                FROM security_wikis 
                WHERE repo_id = ?
            """
            wiki_results = self._execute_database_query_with_retry(
                "fetch_all", wiki_query, (repo_id,), "wiki sections lookup"
            )
            
            print(f"🟣 STEP 8: Wiki query result count = {len(wiki_results) if wiki_results else 0}")
            
            sections = []
            total_content_length = 0
            
            if wiki_results:
                for wiki in wiki_results:
                    title = wiki['title']
                    sections_data = wiki['sections']
                    
                    # Parse sections JSON if it exists
                    if sections_data:
                        try:
                            import json
                            parsed_sections = json.loads(sections_data)
                            if isinstance(parsed_sections, dict):
                                for section_title, section_data in parsed_sections.items():
                                    sections.append(section_title)
                                    if isinstance(section_data, dict) and 'content' in section_data:
                                        total_content_length += len(section_data['content'])
                                    print(f"🟣 STEP 8: Found wiki section: {section_title}")
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse sections JSON for wiki {title}: {e}")
                            sections.append(title)
            
            context = {
                "repository_name": repo_name,
                "has_wiki": len(sections) > 0,
                "sections": sections,
                "section_count": len(sections),
                "content_length": total_content_length
            }
            
            print(f"🟣 STEP 8: Final context = {context}")
            return context
            
        except Exception as e:
            print(f"🟣 STEP 8: ERROR in _get_repository_context: {e}")
            logger.error(f"Error getting repository context for {repo_id}: {e}")
            return self._create_fallback_context(repo_id, f"Database error: {str(e)}")
    
    def _validate_database_connection(self) -> bool:
        """Validate database connection and health"""
        try:
            global _db_manager
            if _db_manager is None:
                return False
            
            # Perform a simple health check
            if hasattr(_db_manager, 'health_check'):
                return _db_manager.health_check()
            else:
                # Fallback health check
                test_result = _db_manager.fetch_one("SELECT 1 as test", ())
                return test_result is not None and test_result.get('test') == 1
                
        except Exception as e:
            logger.error(f"Database connection validation failed: {e}")
            return False
    
    def _execute_database_query_with_retry(self, method: str, query: str, params: tuple, operation_name: str, max_retries: int = 3):
        """Execute database query with retry mechanism and comprehensive error logging"""
        global _db_manager
        
        for attempt in range(max_retries):
            try:
                if method == "fetch_one":
                    result = _db_manager.fetch_one(query, params)
                elif method == "fetch_all":
                    result = _db_manager.fetch_all(query, params)
                else:
                    raise ValueError(f"Unsupported database method: {method}")
                
                logger.debug(f"Database {operation_name} successful on attempt {attempt + 1}")
                return result
                
            except Exception as e:
                logger.error(f"Database {operation_name} failed on attempt {attempt + 1}: {e}")
                logger.error(f"Query: {query}")
                logger.error(f"Params: {params}")
                
                if attempt == max_retries - 1:
                    # Last attempt failed, log comprehensive error
                    logger.error(f"Database {operation_name} failed after {max_retries} attempts")
                    raise
                
                # Wait before retry (exponential backoff)
                import time
                time.sleep(0.1 * (2 ** attempt))
        
        return None
    
    def _create_fallback_context(self, repo_id: str, error_reason: str) -> Dict[str, Any]:
        """Create fallback repository context when database operations fail"""
        logger.warning(f"Creating fallback context for {repo_id}: {error_reason}")
        
        return {
            "repository_name": "Unknown Repository",
            "has_wiki": False,
            "sections": [],
            "section_count": 0,
            "content_length": 0,
            "error_reason": error_reason,
            "fallback_created": True
        }
    
    def _generate_welcome_message(self, context: Dict[str, Any]) -> str:
        """Generate a welcome message based on repository context"""
        print(f"🟡 STEP 9: _generate_welcome_message() called")
        print(f"🟡 STEP 9: context = {context}")
        
        repo_name = context.get("repository_name", "this repository")
        has_wiki = context.get("has_wiki", False)
        section_count = context.get("section_count", 0)
        wiki_count = context.get("wiki_count", 0)
        is_fallback = context.get("fallback_created", False)
        
        print(f"🟡 STEP 9: repo_name = {repo_name}")
        print(f"🟡 STEP 9: has_wiki = {has_wiki}")
        print(f"🟡 STEP 9: section_count = {section_count}")
        print(f"🟡 STEP 9: is_fallback = {is_fallback}")
        
        if is_fallback:
            error_reason = context.get("error_reason", "unknown error")
            message = f"""👋 Welcome to ThreatLens Chat!

⚠️ I encountered an issue loading information for **{repo_name}**: {error_reason}

I can still help you with:
• General security questions and best practices
• OWASP guidelines and recommendations
• Security analysis concepts
• Code review suggestions

How can I assist you with security today?"""
            print(f"🟡 STEP 9: Generated FALLBACK welcome message")
            
        elif has_wiki and section_count > 0:
            sections_text = "sections" if section_count > 1 else "section"
            wiki_text = "analyses" if wiki_count > 1 else "analysis"
            
            message = f"""👋 Welcome to ThreatLens Chat for **{repo_name}**!

I have access to **{wiki_count} security {wiki_text}** with **{section_count} {sections_text}** including:
• Executive Summary
• Security Architecture Review  
• Vulnerability Assessment
• Code Quality Analysis
• OWASP Compliance Check
• Threat Modeling
• Security Recommendations

Ask me anything about the security posture, vulnerabilities, or recommendations for this repository!"""
            print(f"🟡 STEP 9: Generated POSITIVE welcome message")
        else:
            message = f"""👋 Welcome to ThreatLens Chat for **{repo_name}**!

I don't see a security analysis for this repository yet. You can:
• Ask general security questions
• Request a security analysis to be generated
• Get information about security best practices

How can I help you with security today?"""
            print(f"🟡 STEP 9: Generated NEGATIVE welcome message (no wiki found)")
        
        print(f"🟡 STEP 9: Final message = {message}")
        return message
    
    async def _validate_session(self, session_id: str) -> bool:
        """Validate session exists"""
        return session_id in self.active_sessions
    
    async def _perform_rag_search(self, message: str, repo_id: str) -> Dict[str, Any]:
        """Perform RAG search with error handling"""
        try:
            if self.rag_system is None:
                raise Exception("RAG system not available")
            
            # Perform search with context for security-related queries
            context_result = self.rag_system.search_with_context(
                query=message,
                repo_id=repo_id,
                context_type='security'
            )
            
            # Ensure we return a properly formatted result
            if isinstance(context_result, dict) and 'results' in context_result:
                return context_result
            else:
                # Fallback to database search if context search fails
                logger.warning("Context search returned unexpected format, falling back to database search")
                try:
                    db_results = self.rag_system.search_database_embeddings(
                        query=message,
                        repo_id=repo_id,
                        top_k=5
                    )
                except Exception as db_e:
                    logger.warning(f"Database embeddings search failed: {db_e}, using direct wiki search")
                    db_results = self._search_security_wikis_fallback(message, repo_id)
                return {
                    'results': db_results,
                    'query': message,
                    'repo_id': repo_id,
                    'search_type': 'database_fallback'
                }
                
        except Exception as e:
            logger.error(f"RAG search failed: {e}")
            # Try fallback search directly in database
            try:
                fallback_results = self._search_security_wikis_fallback(message, repo_id)
                return {
                    'results': fallback_results,
                    'query': message,
                    'repo_id': repo_id,
                    'search_type': 'wiki_fallback'
                }
            except Exception as fallback_e:
                logger.error(f"Fallback search also failed: {fallback_e}")
                # Return empty results on complete failure
                return {
                    'results': [],
                    'query': message,
                    'repo_id': repo_id,
                    'error': str(e),
                    'search_type': 'failed'
                }
    
    def _search_security_wikis_fallback(self, query: str, repo_id: str) -> List[Dict[str, Any]]:
        """Fallback search directly in security_wikis database table"""
        try:
            global _db_manager
            if _db_manager is None:
                return []
            
            # Search in security wikis content using the actual schema
            search_query = """
                SELECT id, title, content, section_type
                FROM security_wikis 
                WHERE repository_id = ? AND (
                    title LIKE ? OR 
                    content LIKE ?
                )
                LIMIT 5
            """
            
            search_term = f"%{query}%"
            results = _db_manager.fetch_all(search_query, (repo_id, search_term, search_term))
            
            formatted_results = []
            for result in results:
                title = result.get('title', 'Security Information')
                content = result.get('content', '')
                section_type = result.get('section_type', 'general')
                
                # Format the result to match expected structure
                formatted_results.append({
                    'doc_id': result['id'],
                    'title': title,
                    'content_snippet': content[:500] if content else "No content available",
                    'relevance_score': 0.7,  # Default score for database search
                    'doc_type': 'security_wiki',
                    'section_type': section_type,
                    'sections': [{
                        'section': title,
                        'content': content[:300] if content else "No content available"
                    }]
                })
            
            return formatted_results
            
        except Exception as e:
            logger.error(f"Fallback wiki search failed: {e}")
            return []

    async def _generate_llm_response(
        self, 
        user_message: str, 
        context_docs: List[Dict], 
        repo_context: Dict[str, Any],
        recent_messages: List[ChatMessage]
    ) -> str:
        """Generate LLM response with error handling"""
        if self.llm_client is None:
            raise Exception("LLM service not available")
        
        return await self._generate_response(user_message, context_docs, repo_context, recent_messages)
    
    async def _generate_response(
        self, 
        user_message: str, 
        context_docs: List[Dict], 
        repo_context: Dict[str, Any],
        recent_messages: List[ChatMessage]
    ) -> str:
        """Generate AI response using LLM"""
        try:
            # Build context from retrieved documents
            context_text = ""
            if context_docs:
                context_sections = []
                for doc in context_docs[:3]:  # Top 3 most relevant
                    # Handle both SearchResult objects and dictionaries
                    if hasattr(doc, 'title'):  # SearchResult object
                        title = doc.title or 'Security Information'
                        content = doc.content_snippet or ''
                        doc_type = getattr(doc, 'doc_type', 'general')
                        
                        # SearchResult objects don't have sections attribute, use content_snippet
                        content = content[:300] if content else "No content available"
                        context_sections.append(f"**{title}**: {content}")
                        
                    else:  # Dictionary format (fallback results)
                        title = doc.get('title', doc.get('section_title', 'Security Information'))
                        content = doc.get('content_snippet', doc.get('content', ''))
                        
                        # Handle different document formats
                        if doc.get('sections'):  # Wiki-style documents
                            for section in doc['sections'][:2]:  # Top 2 sections
                                section_title = section.get('section', title)
                                section_content = section.get('content', '')[:300]
                                context_sections.append(f"**{section_title}**: {section_content}")
                        else:
                            # Regular documents
                            content = content[:300] if content else "No content available"
                            context_sections.append(f"**{title}**: {content}")
                
                context_text = "\n\n".join(context_sections)
            
            # Build conversation history
            history_text = ""
            if recent_messages:
                history_text = "\n".join([
                    f"{msg.role}: {msg.content}"
                    for msg in recent_messages[-6:]  # Last 6 messages
                ])
            
            # Create prompt
            repo_name = repo_context.get("repository_name", "the repository")
            
            prompt = f"""You are a security expert assistant for ThreatLens, helping analyze the security of {repo_name}.

REPOSITORY CONTEXT:
- Repository: {repo_name}
- Has Security Analysis: {repo_context.get('has_wiki', False)}
- Analysis Sections: {repo_context.get('section_count', 0)}

RELEVANT SECURITY INFORMATION:
{context_text if context_text else "No specific security analysis available for this query."}

RECENT CONVERSATION:
{history_text}

USER QUESTION: {user_message}

Please provide a helpful, accurate response about the repository's security. If you have specific security analysis data above, reference it. If not, provide general security guidance. Be concise but thorough."""

            # Get response from LLM
            response = await self.llm_client.generate_completion(
                prompt=prompt,
                max_tokens=500,
                temperature=0.7,
                operation="chat_response",
                repository=repo_context.get('repository_name', 'unknown')
            )
            
            # Extract content from LLMResponse object
            if hasattr(response, 'content'):
                return response.content.strip()
            else:
                return str(response).strip()
            
        except Exception as e:
            error_context = error_handler.log_error(
                component="SecurityChatSystem",
                operation="generate_response",
                error=e,
                severity=ErrorSeverity.MEDIUM,
                category=ErrorCategory.LLM_SERVICE,
                additional_context={"user_message": user_message[:100]}
            )
            logger.error(f"Error generating response: {e}")
            
            # Generate fallback response based on available context
            return self._generate_fallback_response(user_message, context_docs, repo_context)
    
    def _generate_fallback_response(self, user_message: str, context_docs: List[Dict], repo_context: Dict[str, Any]) -> str:
        """Generate a fallback response when LLM is unavailable"""
        repo_name = repo_context.get('repository_name', 'the repository')
        
        # If we have context documents, provide information from them
        if context_docs:
            context_summary = []
            for doc in context_docs[:2]:  # Use top 2 documents
                # Handle both SearchResult objects and dictionaries
                if hasattr(doc, 'title'):  # SearchResult object
                    title = doc.title or 'Security Information'
                    content = doc.content_snippet or ''
                    content = content[:200] if content else "No content available"
                else:  # Dictionary format
                    title = doc.get('title', 'Security Information')
                    content = doc.get('content_snippet', '')[:200]  # Limit content
                
                context_summary.append(f"**{title}**: {content}...")
            
            return f"""I found some relevant security information for {repo_name}:

{chr(10).join(context_summary)}

I apologize, but I'm currently unable to provide a detailed analysis due to a temporary service issue. The information above is from your repository's security documentation. 

For immediate assistance, you can:
• Review the security sections mentioned above
• Check OWASP guidelines for best practices
• Consult your repository's existing security documentation

Please try your question again in a moment."""
        
        # If no context available, provide general guidance
        else:
            return f"""I apologize, but I'm currently experiencing a temporary service issue and cannot access specific information about {repo_name}.

However, I can suggest some general security best practices:

• **Input Validation**: Always validate and sanitize user inputs
• **Authentication**: Implement strong authentication mechanisms
• **Authorization**: Use proper access controls and permissions
• **Data Protection**: Encrypt sensitive data in transit and at rest
• **Error Handling**: Avoid exposing sensitive information in error messages
• **Logging**: Implement comprehensive security logging

For repository-specific guidance, please try your question again in a moment when the service is restored."""
    
    def get_session_history(self, session_id: str) -> Dict[str, Any]:
        """Get chat history for a session"""
        if session_id not in self.active_sessions:
            return {"error": "Session not found"}
        
        session = self.active_sessions[session_id]
        
        return {
            "session_id": session_id,
            "repo_id": session.repo_id,
            "user_id": session.user_id,
            "created_at": session.created_at.isoformat(),
            "messages": [
                {
                    "role": msg.role,
                    "content": msg.content,
                    "timestamp": msg.timestamp.isoformat()
                }
                for msg in session.messages
            ]
        }
    
    async def get_chat_history(self, session_id: str) -> List[Dict[str, Any]]:
        """Get chat history for a session (async version for router compatibility)"""
        if session_id not in self.active_sessions:
            return []
        
        session = self.active_sessions[session_id]
        
        return [
            {
                "role": msg.role,
                "content": msg.content,
                "timestamp": msg.timestamp.isoformat()
            }
            for msg in session.messages
        ]
    
    def _add_message_to_session(self, session_id: str, message: ChatMessage):
        """Add a message to session history"""
        if session_id not in self.active_sessions:
            return
        
        session = self.active_sessions[session_id]
        session.messages.append(message)
        
        # Keep only last 50 messages to prevent memory issues
        if len(session.messages) > 50:
            session.messages = session.messages[-50:]
    
    def get_session_stats(self, session_id: str) -> Dict[str, Any]:
        """Get statistics for a chat session"""
        if session_id not in self.active_sessions:
            return {"error": "Session not found"}
        
        session = self.active_sessions[session_id]
        user_messages = [msg for msg in session.messages if msg.role == "user"]
        assistant_messages = [msg for msg in session.messages if msg.role == "assistant"]
        
        return {
            "session_id": session_id,
            "repo_id": session.repo_id,
            "repository_name": session.context.get("repository_name", "Unknown"),
            "created_at": session.created_at.isoformat(),
            "message_count": len(session.messages),
            "user_message_count": len(user_messages),
            "assistant_message_count": len(assistant_messages),
            "has_wiki_context": session.context.get("has_wiki", False)
        }
    
    def validate_and_recover_session(self, session_id: str, repo_id: str, user_id: str = "default") -> Dict[str, Any]:
        """Validate session state and recover if necessary"""
        try:
            # Check if session exists
            if session_id not in self.active_sessions:
                logger.warning(f"Session {session_id} not found, attempting recovery")
                
                # Try to recover session from database or create new one
                recovery_result = self._attempt_session_recovery(session_id, repo_id, user_id)
                
                if recovery_result["success"]:
                    return {
                        "valid": True,
                        "recovered": True,
                        "message": "Session recovered successfully"
                    }
                else:
                    return {
                        "valid": False,
                        "recovered": False,
                        "message": "Session recovery failed",
                        "error": recovery_result.get("error")
                    }
            
            # Validate existing session
            session = self.active_sessions[session_id]
            
            # Check session integrity
            if not hasattr(session, 'context') or session.context is None:
                logger.warning(f"Session {session_id} has invalid context, recovering")
                session.context = self._create_fallback_context(repo_id, "Session context corrupted")
            
            # Check if session is too old (optional cleanup)
            session_age = datetime.now() - session.created_at
            if session_age.total_seconds() > 86400:  # 24 hours
                logger.info(f"Session {session_id} is old ({session_age}), but keeping active")
            
            return {
                "valid": True,
                "recovered": False,
                "message": "Session is valid"
            }
            
        except Exception as e:
            error_context = error_handler.log_session_error(
                operation="validate_and_recover_session",
                session_id=session_id,
                error=e
            )
            
            return {
                "valid": False,
                "recovered": False,
                "message": "Session validation failed",
                "error": str(e),
                "error_id": error_context.error_id
            }
    
    def _attempt_session_recovery(self, session_id: str, repo_id: str, user_id: str) -> Dict[str, Any]:
        """Attempt to recover a lost session"""
        try:
            # In a real implementation, this might check a database for session data
            # For now, we'll create a new session with the same ID
            
            logger.info(f"Creating new session with ID {session_id} for recovery")
            
            # Load repository context
            repo_context = asyncio.run(self.context_loader.load_context(repo_id))
            
            # Create new session
            session = ChatSession(
                session_id=session_id,
                repo_id=repo_id,
                user_id=user_id,
                created_at=datetime.now(),
                messages=[],
                context=repo_context
            )
            
            # Add recovery message
            recovery_message = ChatMessage(
                id=str(uuid.uuid4()),
                role="assistant",
                content="Your session has been recovered. You can continue our conversation about security.",
                timestamp=datetime.now()
            )
            session.messages.append(recovery_message)
            
            self.active_sessions[session_id] = session
            
            return {
                "success": True,
                "message": "Session recovered successfully"
            }
            
        except Exception as e:
            logger.error(f"Session recovery failed for {session_id}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_system_health_status(self) -> Dict[str, Any]:
        """Get comprehensive system health status"""
        try:
            # Get service degradation status
            degradation_status = degradation_manager.get_system_health_summary()
            
            # Add chat system specific metrics
            chat_metrics = {
                "active_sessions": len(self.active_sessions),
                "total_messages": sum(len(session.messages) for session in self.active_sessions.values()),
                "services_available": {
                    "rag_system": self.rag_system is not None,
                    "llm_client": self.llm_client is not None,
                    "database": _db_manager is not None
                }
            }
            
            # Combine status
            return {
                **degradation_status,
                "chat_system": chat_metrics,
                "recommendations": self._get_health_recommendations(degradation_status)
            }
            
        except Exception as e:
            error_context = error_handler.log_error(
                component="SecurityChatSystem",
                operation="get_system_health_status",
                error=e,
                severity=ErrorSeverity.MEDIUM,
                category=ErrorCategory.UNKNOWN
            )
            
            return {
                "error": "Unable to retrieve system health status",
                "error_id": error_context.error_id
            }
    
    def _get_health_recommendations(self, degradation_status: Dict[str, Any]) -> List[str]:
        """Get health recommendations based on system status"""
        recommendations = []
        
        if degradation_status.get("unavailable_services", 0) > 0:
            recommendations.append("Some services are unavailable. Check service logs for details.")
        
        if degradation_status.get("degraded_services", 0) > 0:
            recommendations.append("Some services are running in degraded mode. Performance may be affected.")
        
        if len(self.active_sessions) > 100:
            recommendations.append("High number of active sessions. Consider implementing session cleanup.")
        
        if not recommendations:
            recommendations.append("All systems are operating normally.")
        
        return recommendations


# Global chat system instance
_chat_system = None


def get_chat_system() -> SecurityChatSystem:
    """Get or create the global chat system instance"""
    global _chat_system
    if _chat_system is None:
        _chat_system = SecurityChatSystem()
    return _chat_system