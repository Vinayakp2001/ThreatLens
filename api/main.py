"""
FastAPI main application for Threat Modeling Documentation Generator
Enhanced with intelligent CPU/GPU resource management.
"""
import logging
import time
import uuid
import sys
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Request, Depends, Query, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ValidationError
import uvicorn

from api.config import settings
from api.models import (
    ThreatDoc, SecurityDocument, SecurityModel, SearchResult,
    RepoContext, StructureAnalysis
)
from api.database import DatabaseManager
from api.repo_ingest import (
    RepoIngestor, RepoIngestorError, InvalidRepositoryError, 
    AccessDeniedError, RepositoryTooLargeError, RepositoryTimeoutError,
    UnsupportedRepositoryError, NetworkError
)
from api.resource_manager import initialize_resource_manager, get_resource_manager
from api.security_model import SecurityModelBuilder
from api.threat_docs import ThreatDocGenerator
from api.security_wiki_generator import SecurityWikiGenerator
from api.knowledge_base import RepositoryKnowledgeBase
from api.pr_analyzer import PRChangeDetector
from api.rag import RAGSystem
from api.partial_results import PartialResultsManager, AnalysisStage, AnalysisStatus
from api.concurrency import lock_manager, analysis_queue, LockAcquisitionError, LockTimeoutError
from api.storage_manager import storage_manager, StorageType, CleanupResult
from api.config import config_manager, ConfigurationError
from api.analysis_router import AnalysisRouter
from api.monitoring import (
    metrics_collector, system_monitor, application_monitor, 
    health_checker, alert_manager
)

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Request/Response Models
class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    service: str
    version: str
    timestamp: str
    database_status: str
    llm_config_valid: bool
    storage_paths_exist: bool

class AnalyzeRepoRequest(BaseModel):
    """Request model for repository analysis"""
    repo_url: Optional[str] = Field(None, description="Git repository URL")
    local_path: Optional[str] = Field(None, description="Local repository path")
    
    class Config:
        json_schema_extra = {
            "example": {
                "repo_url": "https://github.com/user/repo.git"
            }
        }

class AnalyzeRepoResponse(BaseModel):
    """Response model for repository analysis"""
    analysis_id: str = Field(description="Unique analysis identifier")
    repo_id: str = Field(description="Repository identifier")
    status: str = Field(description="Analysis status")
    message: str = Field(description="Status message")
    estimated_completion_time: Optional[str] = None

class AnalyzePRRequest(BaseModel):
    """Request model for PR security analysis"""
    pr_url: str = Field(description="GitHub PR URL (e.g., https://github.com/user/repo/pull/123)")
    repo_id: Optional[str] = Field(None, description="Repository ID if known (for context lookup)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "pr_url": "https://github.com/user/repo/pull/123",
                "repo_id": "optional-repo-id-for-context"
            }
        }

class AnalyzePRResponse(BaseModel):
    """Response model for PR security analysis"""
    analysis_id: str = Field(description="Unique analysis identifier")
    pr_id: str = Field(description="PR identifier")
    repo_id: str = Field(description="Repository identifier")
    status: str = Field(description="Analysis status")
    message: str = Field(description="Status message")
    has_repo_context: bool = Field(description="Whether repository context was available")
    security_doc_id: Optional[str] = Field(None, description="Generated security document ID")
    risk_level: Optional[str] = Field(None, description="Overall risk level assessment")
    guidance: Optional[Dict[str, Any]] = Field(None, description="User guidance information")
    context_status: Optional[Dict[str, Any]] = Field(None, description="Repository context status")
    routing_info: Optional[Dict[str, Any]] = Field(None, description="Analysis routing information")

class RepoStatusResponse(BaseModel):
    """Response model for repository status check"""
    repo_id: str = Field(description="Repository identifier")
    exists: bool = Field(description="Whether repository analysis exists")
    status: str = Field(description="Analysis status")
    message: str = Field(description="Status message")
    analysis_date: Optional[str] = Field(None, description="Date of last analysis")
    document_count: int = Field(description="Number of security documents")
    has_search_index: bool = Field(description="Whether search index is available")
    repo_context: Optional[Dict[str, Any]] = Field(None, description="Repository context information")

class DocumentListResponse(BaseModel):
    """Response model for document listing"""
    repo_id: str
    documents: List[ThreatDoc]
    total_count: int

class SearchDocsRequest(BaseModel):
    """Request model for document search"""
    query: str = Field(description="Search query")
    repo_id: Optional[str] = Field(None, description="Filter by repository ID")
    doc_types: Optional[List[str]] = Field(None, description="Filter by document types")
    limit: int = Field(default=10, ge=1, le=100, description="Maximum results to return")
    offset: int = Field(default=0, ge=0, description="Results offset for pagination")

class SearchDocsResponse(BaseModel):
    """Response model for document search"""
    query: str
    results: List[SearchResult]
    total_count: int
    limit: int
    offset: int

class ErrorResponse(BaseModel):
    """Standard error response model"""
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None

# Global instances
db_manager: Optional[DatabaseManager] = None
repo_ingestor: Optional[RepoIngestor] = None
security_model_builder: Optional[SecurityModelBuilder] = None
threat_doc_generator: Optional[ThreatDocGenerator] = None
security_wiki_generator: Optional[SecurityWikiGenerator] = None
knowledge_base_manager: Optional[RepositoryKnowledgeBase] = None
pr_analyzer: Optional[PRChangeDetector] = None
rag_system: Optional[RAGSystem] = None
partial_results_manager: Optional[PartialResultsManager] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global db_manager, repo_ingestor, security_model_builder, threat_doc_generator, rag_system, partial_results_manager
    
    logger.info("Starting Threat Modeling Documentation Generator")
    
    # Initialize components
    try:
        # Initialize resource manager first
        resource_manager = initialize_resource_manager()
        logger.info(f"Resource Manager initialized: {resource_manager.processing_mode.value}")
        logger.info(f"System capabilities: CPU cores={resource_manager.capabilities.cpu_cores}, "
                   f"RAM={resource_manager.capabilities.total_ram_gb:.1f}GB, "
                   f"GPU={resource_manager.capabilities.has_gpu}")
        
        db_manager = DatabaseManager(settings.database_path)
        db_manager.initialize_database()
        
        repo_ingestor = RepoIngestor(settings)
        security_model_builder = SecurityModelBuilder()
        threat_doc_generator = ThreatDocGenerator(settings)
        security_wiki_generator = SecurityWikiGenerator(settings)
        knowledge_base_manager = RepositoryKnowledgeBase()
        pr_analyzer = PRChangeDetector()
        rag_system = RAGSystem(settings)
        partial_results_manager = PartialResultsManager()
        
        # Cleanup stale locks and old progress files
        lock_manager.cleanup_stale_locks()
        partial_results_manager.cleanup_old_progress()
        
        # Start monitoring
        system_monitor.start_monitoring(settings.health_check_interval_seconds)
        
        logger.info("All components initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize components: {e}")
        raise
    
    yield
    
    # Cleanup
    logger.info("Shutting down Threat Modeling Documentation Generator")
    
    # Stop monitoring
    system_monitor.stop_monitoring()
    
    if db_manager:
        db_manager.close()
    if threat_doc_generator:
        await threat_doc_generator.close()
    
    # Stop configuration file watcher
    config_manager.stop_file_watcher()

app = FastAPI(
    title="Threat Modeling Documentation Generator",
    description="Generate comprehensive threat modeling documentation from code repositories using OWASP methodologies",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else ["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if settings.debug else ["localhost", "127.0.0.1"]
)

@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Log all requests with timing and request ID"""
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    start_time = time.time()
    
    logger.info(
        f"Request started - ID: {request_id}, Method: {request.method}, "
        f"URL: {request.url}, Client: {request.client.host if request.client else 'unknown'}"
    )
    
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Record metrics
        application_monitor.record_request(
            duration_ms=process_time * 1000,
            status_code=response.status_code,
            endpoint=str(request.url.path)
        )
        
        logger.info(
            f"Request completed - ID: {request_id}, Status: {response.status_code}, "
            f"Duration: {process_time:.3f}s"
        )
        
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = str(process_time)
        
        return response
        
    except Exception as e:
        process_time = time.time() - start_time
        
        # Record error metrics
        application_monitor.record_request(
            duration_ms=process_time * 1000,
            status_code=500,
            endpoint=str(request.url.path)
        )
        
        logger.error(
            f"Request failed - ID: {request_id}, Error: {str(e)}, "
            f"Duration: {process_time:.3f}s"
        )
        raise

# Exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors"""
    request_id = getattr(request.state, 'request_id', None)
    logger.warning(f"Validation error - Request ID: {request_id}, Errors: {exc.errors()}")
    
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error="validation_error",
            message="Request validation failed",
            details={"validation_errors": exc.errors()},
            request_id=request_id
        ).dict()
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    request_id = getattr(request.state, 'request_id', None)
    logger.warning(f"HTTP error - Request ID: {request_id}, Status: {exc.status_code}, Detail: {exc.detail}")
    
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error="http_error",
            message=exc.detail,
            request_id=request_id
        ).dict()
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    request_id = getattr(request.state, 'request_id', None)
    logger.error(f"Unexpected error - Request ID: {request_id}, Error: {str(exc)}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="internal_server_error",
            message="An unexpected error occurred",
            details={"error_type": type(exc).__name__} if settings.debug else None,
            request_id=request_id
        ).dict()
    )

# Repository-specific exception handlers
@app.exception_handler(InvalidRepositoryError)
async def invalid_repository_handler(request: Request, exc: InvalidRepositoryError):
    """Handle invalid repository errors"""
    request_id = getattr(request.state, 'request_id', None)
    logger.warning(f"Invalid repository - Request ID: {request_id}, Error: {str(exc)}")
    
    return JSONResponse(
        status_code=400,
        content=ErrorResponse(
            error=exc.error_code.lower(),
            message=str(exc),
            details=exc.details if settings.debug else None,
            request_id=request_id
        ).dict()
    )

@app.exception_handler(AccessDeniedError)
async def access_denied_handler(request: Request, exc: AccessDeniedError):
    """Handle access denied errors"""
    request_id = getattr(request.state, 'request_id', None)
    logger.warning(f"Access denied - Request ID: {request_id}, Error: {str(exc)}")
    
    return JSONResponse(
        status_code=403,
        content=ErrorResponse(
            error=exc.error_code.lower(),
            message=str(exc),
            details=exc.details if settings.debug else None,
            request_id=request_id
        ).dict()
    )

@app.exception_handler(RepositoryTooLargeError)
async def repository_too_large_handler(request: Request, exc: RepositoryTooLargeError):
    """Handle repository too large errors"""
    request_id = getattr(request.state, 'request_id', None)
    logger.warning(f"Repository too large - Request ID: {request_id}, Error: {str(exc)}")
    
    return JSONResponse(
        status_code=413,
        content=ErrorResponse(
            error=exc.error_code.lower(),
            message=str(exc),
            details=exc.details if settings.debug else None,
            request_id=request_id
        ).dict()
    )

@app.exception_handler(RepositoryTimeoutError)
async def repository_timeout_handler(request: Request, exc: RepositoryTimeoutError):
    """Handle repository timeout errors"""
    request_id = getattr(request.state, 'request_id', None)
    logger.warning(f"Repository timeout - Request ID: {request_id}, Error: {str(exc)}")
    
    return JSONResponse(
        status_code=408,
        content=ErrorResponse(
            error=exc.error_code.lower(),
            message=str(exc),
            details=exc.details if settings.debug else None,
            request_id=request_id
        ).dict()
    )

@app.exception_handler(UnsupportedRepositoryError)
async def unsupported_repository_handler(request: Request, exc: UnsupportedRepositoryError):
    """Handle unsupported repository errors"""
    request_id = getattr(request.state, 'request_id', None)
    logger.warning(f"Unsupported repository - Request ID: {request_id}, Error: {str(exc)}")
    
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error=exc.error_code.lower(),
            message=str(exc),
            details=exc.details if settings.debug else None,
            request_id=request_id
        ).dict()
    )

@app.exception_handler(NetworkError)
async def network_error_handler(request: Request, exc: NetworkError):
    """Handle network errors"""
    request_id = getattr(request.state, 'request_id', None)
    logger.warning(f"Network error - Request ID: {request_id}, Error: {str(exc)}")
    
    return JSONResponse(
        status_code=502,
        content=ErrorResponse(
            error=exc.error_code.lower(),
            message=str(exc),
            details=exc.details if settings.debug else None,
            request_id=request_id
        ).dict()
    )

@app.exception_handler(RepoIngestorError)
async def repo_ingestor_error_handler(request: Request, exc: RepoIngestorError):
    """Handle general repository ingestor errors"""
    request_id = getattr(request.state, 'request_id', None)
    logger.error(f"Repository ingestor error - Request ID: {request_id}, Error: {str(exc)}")
    
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error=exc.error_code.lower(),
            message=str(exc),
            details=exc.details if settings.debug else None,
            request_id=request_id
        ).dict()
    )

@app.exception_handler(LockAcquisitionError)
async def lock_acquisition_error_handler(request: Request, exc: LockAcquisitionError):
    """Handle lock acquisition errors"""
    request_id = getattr(request.state, 'request_id', None)
    logger.warning(f"Lock acquisition error - Request ID: {request_id}, Error: {str(exc)}")
    
    return JSONResponse(
        status_code=409,
        content=ErrorResponse(
            error="resource_locked",
            message=str(exc),
            details={"suggestion": "Repository is currently being analyzed by another process"},
            request_id=request_id
        ).dict()
    )

@app.exception_handler(LockTimeoutError)
async def lock_timeout_error_handler(request: Request, exc: LockTimeoutError):
    """Handle lock timeout errors"""
    request_id = getattr(request.state, 'request_id', None)
    logger.warning(f"Lock timeout error - Request ID: {request_id}, Error: {str(exc)}")
    
    return JSONResponse(
        status_code=408,
        content=ErrorResponse(
            error="lock_timeout",
            message=str(exc),
            details={"suggestion": "Try again later when the resource is available"},
            request_id=request_id
        ).dict()
    )

# Dependency functions
def get_db_manager() -> DatabaseManager:
    """Get database manager dependency"""
    if db_manager is None:
        raise HTTPException(status_code=503, detail="Database manager not initialized")
    return db_manager

def get_repo_ingestor() -> RepoIngestor:
    """Get repository ingestor dependency"""
    if repo_ingestor is None:
        raise HTTPException(status_code=503, detail="Repository ingestor not initialized")
    return repo_ingestor

def get_security_model_builder() -> SecurityModelBuilder:
    """Get security model builder dependency"""
    if security_model_builder is None:
        raise HTTPException(status_code=503, detail="Security model builder not initialized")
    return security_model_builder

def get_threat_doc_generator() -> ThreatDocGenerator:
    """Get threat document generator dependency"""
    if threat_doc_generator is None:
        raise HTTPException(status_code=503, detail="Threat document generator not initialized")
    return threat_doc_generator

def get_security_wiki_generator() -> SecurityWikiGenerator:
    """Get security wiki generator dependency"""
    if security_wiki_generator is None:
        raise HTTPException(status_code=503, detail="Security wiki generator not initialized")
    return security_wiki_generator

def get_knowledge_base_manager() -> RepositoryKnowledgeBase:
    """Get knowledge base manager dependency"""
    if knowledge_base_manager is None:
        raise HTTPException(status_code=503, detail="Knowledge base manager not initialized")
    return knowledge_base_manager

def get_pr_analyzer() -> PRChangeDetector:
    """Get PR analyzer dependency"""
    if pr_analyzer is None:
        raise HTTPException(status_code=503, detail="PR analyzer not initialized")
    return pr_analyzer

def get_smart_workflow_manager():
    """Get smart workflow manager dependency"""
    from api.smart_workflow import SmartWorkflowManager
    return SmartWorkflowManager()

def get_analysis_router():
    """Get analysis router dependency"""
    from api.analysis_router import AnalysisRouter
    return AnalysisRouter()

def get_rag_system() -> RAGSystem:
    """Get RAG system dependency"""
    if rag_system is None:
        raise HTTPException(status_code=503, detail="RAG system not initialized")
    return rag_system

def get_partial_results_manager() -> PartialResultsManager:
    """Get partial results manager dependency"""
    if partial_results_manager is None:
        raise HTTPException(status_code=503, detail="Partial results manager not initialized")
    return partial_results_manager

# Health check endpoint
@app.get("/github_status", tags=["Health"])
async def github_api_status() -> Dict[str, Any]:
    """
    Check GitHub API status and rate limits
    
    Returns information about GitHub API connectivity, authentication status,
    and current rate limits. Useful for monitoring and debugging PR analysis issues.
    """
    try:
        from api.pr_analyzer import GitHubAPIClient
        
        github_client = GitHubAPIClient()
        
        # Get rate limit status
        rate_limit_info = github_client.get_rate_limit_status()
        
        # Check if we have authentication
        has_token = settings.github_token is not None
        
        # Test basic API access
        test_repo_access = github_client.check_repository_access("octocat", "Hello-World")
        
        return {
            "github_api_status": "available" if test_repo_access["accessible"] else "limited",
            "authentication": {
                "has_token": has_token,
                "token_configured": has_token,
                "rate_limit_type": "authenticated" if has_token else "unauthenticated"
            },
            "rate_limits": rate_limit_info,
            "configuration": {
                "base_url": settings.github_api_base_url,
                "timeout_seconds": settings.github_timeout_seconds,
                "retry_attempts": settings.github_retry_attempts,
                "requests_per_hour_limit": settings.github_requests_per_hour,
                "requests_per_minute_limit": settings.github_requests_per_minute
            },
            "test_access": test_repo_access,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error checking GitHub API status: {e}")
        return {
            "github_api_status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check(db: DatabaseManager = Depends(get_db_manager)) -> HealthResponse:
    """
    Health check endpoint with system status monitoring
    
    Returns comprehensive health information including:
    - Service status
    - Database connectivity
    - LLM configuration validation
    - Storage path verification
    """
    import os
    from datetime import datetime
    
    # Check database status
    try:
        db_status = "healthy" if db.health_check() else "unhealthy"
    except Exception:
        db_status = "error"
    
    # Check LLM configuration
    llm_config_valid = settings.validate_llm_config()
    
    # Check storage paths
    storage_paths_exist = all([
        os.path.exists(settings.repos_storage_path),
        os.path.exists(settings.docs_storage_path),
        os.path.exists(settings.embeddings_storage_path),
        os.path.exists(os.path.dirname(settings.database_path))
    ])
    
    return HealthResponse(
        status="healthy" if all([
            db_status == "healthy",
            llm_config_valid,
            storage_paths_exist
        ]) else "degraded",
        service="threat-modeling-generator",
        version="1.0.0",
        timestamp=datetime.now().isoformat(),
        database_status=db_status,
        llm_config_valid=llm_config_valid,
        storage_paths_exist=storage_paths_exist
    )


@app.get("/resources", tags=["Health"])
async def get_resource_status() -> Dict[str, Any]:
    """
    Get current system resource usage and configuration
    
    Returns information about:
    - CPU and memory usage
    - GPU availability and usage
    - Resource allocation strategy
    - Processing mode configuration
    """
    try:
        resource_manager = get_resource_manager()
        
        # Get current resource usage
        usage = resource_manager.monitor_resource_usage()
        
        # Get configuration details
        embedding_config = resource_manager.get_embedding_config()
        faiss_config = resource_manager.get_faiss_config()
        concurrency_config = resource_manager.get_concurrency_config()
        
        return {
            "status": "healthy",
            "processing_mode": resource_manager.processing_mode.value,
            "system_capabilities": {
                "cpu_cores": resource_manager.capabilities.cpu_cores,
                "total_ram_gb": resource_manager.capabilities.total_ram_gb,
                "available_ram_gb": resource_manager.capabilities.available_ram_gb,
                "has_gpu": resource_manager.capabilities.has_gpu,
                "gpu_memory_gb": resource_manager.capabilities.gpu_memory_gb,
                "gpu_name": resource_manager.capabilities.gpu_name,
                "storage_type": resource_manager.capabilities.storage_type
            },
            "current_usage": usage,
            "resource_allocation": {
                "embedding_batch_size": resource_manager.allocation.embedding_batch_size,
                "vector_search_device": resource_manager.allocation.vector_search_device,
                "max_concurrent_operations": resource_manager.allocation.max_concurrent_operations,
                "use_gpu_for_embeddings": resource_manager.allocation.use_gpu_for_embeddings,
                "faiss_index_type": resource_manager.allocation.faiss_index_type
            },
            "configurations": {
                "embedding": embedding_config,
                "faiss": faiss_config,
                "concurrency": concurrency_config
            }
        }
    except Exception as e:
        logger.error(f"Failed to get resource status: {e}")
        raise HTTPException(status_code=500, detail=f"Resource monitoring failed: {str(e)}")


# Repository Analysis Endpoints

@app.post("/validate_repo", tags=["Repository Analysis"])
async def validate_repository(
    request: AnalyzeRepoRequest
) -> Dict[str, Any]:
    """
    Validate a repository URL or local path without performing analysis
    
    This endpoint allows users to check if a repository is accessible and valid
    before starting the full analysis process.
    """
    from api.repo_ingest import RepositoryValidator
    
    # Validate input
    if not request.repo_url and not request.local_path:
        raise HTTPException(
            status_code=400,
            detail="Either repo_url or local_path must be provided"
        )
    
    if request.repo_url and request.local_path:
        raise HTTPException(
            status_code=400,
            detail="Only one of repo_url or local_path should be provided"
        )
    
    validator = RepositoryValidator()
    
    try:
        if request.repo_url:
            validation_result = validator.validate_repository_url(request.repo_url)
            validation_result["type"] = "remote"
            validation_result["input"] = request.repo_url
        else:
            validation_result = validator.validate_local_path(request.local_path)
            validation_result["type"] = "local"
            validation_result["input"] = request.local_path
        
        return {
            "valid": True,
            "validation_result": validation_result,
            "message": "Repository validation successful"
        }
        
    except (InvalidRepositoryError, AccessDeniedError, UnsupportedRepositoryError) as e:
        return {
            "valid": False,
            "error_code": e.error_code,
            "message": str(e),
            "details": e.details if settings.debug else None
        }

@app.post("/intelligent_analysis", tags=["Repository Analysis"])
async def intelligent_analysis_routing(
    request: Dict[str, Any],
    db: DatabaseManager = Depends(get_db_manager),
    wiki_generator: SecurityWikiGenerator = Depends(get_security_wiki_generator),
    analysis_router: AnalysisRouter = Depends(get_analysis_router)
) -> Dict[str, Any]:
    """
    Intelligent analysis routing endpoint that automatically determines the best analysis approach
    
    This endpoint accepts various types of analysis requests and intelligently routes them
    to the appropriate analysis mode based on the input type, repository context availability,
    and complexity. Supports both repository and PR analysis with automatic fallback handling.
    
    Request format:
    {
        "url": "https://github.com/user/repo" or "https://github.com/user/repo/pull/123",
        "analysis_type": "auto" | "repository" | "pr" (optional),
        "force_mode": "full_repository" | "context_aware_pr" | "pr_analysis" | "fallback_pr" (optional),
        "options": {
            "enable_fallback": true,
            "max_duration": "20m",
            "priority": "normal" | "high"
        }
    }
    """
    try:
        logger.info(f"Intelligent analysis routing request: {request}")
        
        # Route the analysis request
        routing_result = analysis_router.route_analysis_request(request)
        
        if "error" in routing_result:
            raise HTTPException(
                status_code=400,
                detail=routing_result["error"]
            )
        
        # Execute the routed analysis
        execution_result = analysis_router.execute_routed_analysis(
            routing_result, wiki_generator, db
        )
        
        # Combine routing and execution results
        response = {
            "routing": routing_result,
            "execution": execution_result,
            "intelligent_routing": True,
            "timestamp": datetime.now().isoformat()
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Intelligent analysis routing failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Intelligent analysis routing failed: {str(e)}"
        )


@app.get("/routing_stats", tags=["Repository Analysis"])
async def get_routing_statistics(
    analysis_router: AnalysisRouter = Depends(get_analysis_router)
) -> Dict[str, Any]:
    """
    Get intelligent routing statistics and configuration
    
    Returns information about the routing system including cache statistics,
    supported analysis types, and routing strategies.
    """
    try:
        stats = analysis_router.get_routing_stats()
        return {
            "routing_stats": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting routing stats: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get routing statistics: {str(e)}"
        )


@app.post("/clear_routing_cache", tags=["Repository Analysis"])
async def clear_routing_cache(
    analysis_router: AnalysisRouter = Depends(get_analysis_router)
) -> Dict[str, Any]:
    """
    Clear the intelligent routing cache
    
    Clears cached routing decisions to force fresh analysis of routing requirements.
    Useful for testing or when routing logic has been updated.
    """
    try:
        analysis_router.clear_routing_cache()
        return {
            "message": "Routing cache cleared successfully",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error clearing routing cache: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to clear routing cache: {str(e)}"
        )


@app.post("/analyze_repo", response_model=AnalyzeRepoResponse, tags=["Repository Analysis"])
async def analyze_repository(
    request: AnalyzeRepoRequest,
    db: DatabaseManager = Depends(get_db_manager),
    ingestor: RepoIngestor = Depends(get_repo_ingestor),
    security_builder: SecurityModelBuilder = Depends(get_security_model_builder),
    doc_generator: ThreatDocGenerator = Depends(get_threat_doc_generator),
    wiki_generator: SecurityWikiGenerator = Depends(get_security_wiki_generator),
    kb_manager: RepositoryKnowledgeBase = Depends(get_knowledge_base_manager),
    rag: RAGSystem = Depends(get_rag_system),
    partial_manager: PartialResultsManager = Depends(get_partial_results_manager)
) -> AnalyzeRepoResponse:
    """
    Analyze a repository and generate threat modeling documentation with error recovery
    
    Accepts either a repository URL for cloning or a local path for analysis.
    Returns an analysis ID that can be used to track progress and retrieve results.
    Includes comprehensive error recovery and partial result storage.
    """
    # Validate input
    if not request.repo_url and not request.local_path:
        raise HTTPException(
            status_code=400,
            detail="Either repo_url or local_path must be provided"
        )
    
    if request.repo_url and request.local_path:
        raise HTTPException(
            status_code=400,
            detail="Only one of repo_url or local_path should be provided"
        )
    
    # Generate unique IDs
    analysis_id = str(uuid.uuid4())
    repo_id = str(uuid.uuid4())
    
    logger.info(f"Starting repository analysis - Analysis ID: {analysis_id}, Repo ID: {repo_id}")
    
    # Check if analysis can be started (queue management)
    if not analysis_queue.can_start_analysis(repo_id):
        # Add to queue
        analysis_queue.start_analysis(analysis_id, repo_id)
        queue_position = analysis_queue.get_analysis_position(analysis_id)
        
        return AnalyzeRepoResponse(
            analysis_id=analysis_id,
            repo_id=repo_id,
            status="queued",
            message=f"Analysis queued at position {queue_position + 1 if queue_position is not None else 'unknown'}",
            estimated_completion_time=None
        )
    
    # Start analysis
    analysis_queue.start_analysis(analysis_id, repo_id)
    
    # Create progress tracking
    progress = partial_manager.create_analysis_progress(
        analysis_id=analysis_id,
        repo_id=repo_id,
        repo_url=request.repo_url,
        local_path=request.local_path
    )
    
    try:
        # Acquire repository lock
        with lock_manager.acquire_repo_lock(repo_id, analysis_id, "analysis"):
            
            # Stage 1: Repository Ingestion
            await _execute_stage_with_recovery(
                partial_manager, analysis_id, AnalysisStage.REPOSITORY_INGESTION,
                _stage_repository_ingestion, 
                request, repo_id, ingestor, db
            )
            
            # Stage 2: Structure Analysis
            await _execute_stage_with_recovery(
                partial_manager, analysis_id, AnalysisStage.STRUCTURE_ANALYSIS,
                _stage_structure_analysis,
                partial_manager, analysis_id, ingestor
            )
            
            # Stage 3: Security Model Building
            await _execute_stage_with_recovery(
                partial_manager, analysis_id, AnalysisStage.SECURITY_MODEL_BUILDING,
                _stage_security_model_building,
                partial_manager, analysis_id, security_builder
            )
            
            # Stage 4: Document Generation
            await _execute_stage_with_recovery(
                partial_manager, analysis_id, AnalysisStage.DOCUMENT_GENERATION,
                _stage_document_generation,
                partial_manager, analysis_id, doc_generator, wiki_generator, kb_manager, db
            )
            
            # Stage 5: RAG Indexing
            await _execute_stage_with_recovery(
                partial_manager, analysis_id, AnalysisStage.RAG_INDEXING,
                _stage_rag_indexing,
                partial_manager, analysis_id, rag, db
            )
            
            # Mark as completed
            partial_manager.complete_stage(analysis_id, AnalysisStage.COMPLETED)
            
            # Update final repo status
            repo_context = partial_manager.get_partial_results(analysis_id, AnalysisStage.REPOSITORY_INGESTION)
            if repo_context:
                repo_context_obj = RepoContext(**repo_context)
                repo_context_obj.analysis_status = "completed"
                db.save_repo_context(repo_context_obj)
        
        # Mark analysis as completed in queue
        analysis_queue.complete_analysis(analysis_id)
        
        logger.info(f"Repository analysis completed successfully - Repo ID: {repo_id}")
        
        return AnalyzeRepoResponse(
            analysis_id=analysis_id,
            repo_id=repo_id,
            status="completed",
            message="Repository analysis completed successfully",
            estimated_completion_time=None
        )
        
    except (InvalidRepositoryError, AccessDeniedError, RepositoryTooLargeError, 
            RepositoryTimeoutError, UnsupportedRepositoryError, NetworkError, RepoIngestorError,
            LockAcquisitionError, LockTimeoutError):
        # These errors are handled by dedicated exception handlers
        analysis_queue.fail_analysis(analysis_id, str(exc))
        
        # Mark analysis as failed
        try:
            partial_manager.fail_stage(analysis_id, progress.current_stage, str(exc), type(exc).__name__)
        except:
            pass
        raise
        
    except Exception as e:
        logger.error(f"Repository analysis failed - Analysis ID: {analysis_id}, Error: {str(e)}")
        
        # Mark analysis as failed in queue
        analysis_queue.fail_analysis(analysis_id, str(e))
        
        # Mark current stage as failed
        try:
            partial_manager.fail_stage(analysis_id, progress.current_stage, str(e), type(e).__name__)
        except:
            pass
        
        # Re-raise as a generic repository error
        raise RepoIngestorError(
            f"Analysis failed due to unexpected error: {str(e)}",
            "ANALYSIS_FAILED",
            {"analysis_id": analysis_id, "error_type": type(e).__name__}
        )


async def _execute_stage_with_recovery(
    partial_manager: PartialResultsManager,
    analysis_id: str,
    stage: AnalysisStage,
    stage_func,
    *args
):
    """Execute a stage with error recovery"""
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            # Start stage
            partial_manager.start_stage(analysis_id, stage)
            
            # Execute stage function
            result = await stage_func(*args)
            
            # Complete stage
            partial_manager.complete_stage(analysis_id, stage, result)
            return result
            
        except Exception as e:
            retry_count += 1
            logger.error(f"Stage {stage.value} failed (attempt {retry_count}): {e}")
            
            # Mark stage as failed
            partial_manager.fail_stage(analysis_id, stage, str(e), type(e).__name__)
            
            # Check if we can recover
            if retry_count < max_retries and partial_manager.can_recover_stage(analysis_id, stage):
                logger.info(f"Attempting recovery for stage {stage.value} (attempt {retry_count + 1})")
                partial_manager.recover_stage(analysis_id, stage)
                await asyncio.sleep(2 ** retry_count)  # Exponential backoff
                continue
            else:
                raise


async def _stage_repository_ingestion(request, repo_id, ingestor, db):
    """Repository ingestion stage"""
    if request.repo_url:
        logger.info(f"Cloning repository from URL: {request.repo_url}")
        repo_context = ingestor.clone_repository(request.repo_url, repo_id)
    else:
        logger.info(f"Loading local repository from path: {request.local_path}")
        repo_context = ingestor.load_local_repository(request.local_path)
    
    # Save initial repo context
    repo_context.analysis_status = "ingesting"
    db.save_repo_context(repo_context)
    
    return repo_context.dict()


async def _stage_structure_analysis(partial_manager, analysis_id, ingestor):
    """Structure analysis stage"""
    repo_context_data = partial_manager.get_partial_results(analysis_id, AnalysisStage.REPOSITORY_INGESTION)
    repo_context = RepoContext(**repo_context_data)
    
    logger.info(f"Analyzing repository structure for repo: {repo_context.repo_id}")
    structure_analysis = ingestor.analyze_structure(repo_context)
    
    # Update repo context with structure analysis
    repo_context.structure_summary = structure_analysis.dict()
    repo_context.primary_languages = structure_analysis.primary_languages
    repo_context.analysis_status = "analyzing_security_model"
    
    return {
        "repo_context": repo_context.dict(),
        "structure_analysis": structure_analysis.dict()
    }


async def _stage_security_model_building(partial_manager, analysis_id, security_builder):
    """Security model building stage"""
    stage_data = partial_manager.get_partial_results(analysis_id, AnalysisStage.STRUCTURE_ANALYSIS)
    repo_context = RepoContext(**stage_data["repo_context"])
    
    logger.info(f"Building security model for repo: {repo_context.repo_id}")
    security_model = security_builder.build_security_model(repo_context)
    
    return {
        "repo_context": repo_context.dict(),
        "security_model": security_model.dict()
    }


async def _stage_document_generation(partial_manager, analysis_id, doc_generator, wiki_generator, kb_manager, db):
    """Document generation stage - now uses flexible SecurityWikiGenerator and creates knowledge base"""
    stage_data = partial_manager.get_partial_results(analysis_id, AnalysisStage.SECURITY_MODEL_BUILDING)
    repo_context = RepoContext(**stage_data["repo_context"])
    security_model = SecurityModel(**stage_data["security_model"])
    
    logger.info(f"Generating comprehensive security documentation for repo: {repo_context.repo_id}")
    
    # Update status
    repo_context.analysis_status = "generating_documents"
    
    generated_docs = []
    security_documents = []
    
    try:
        # Generate comprehensive security documentation using new SecurityWikiGenerator
        security_doc = await wiki_generator.generate_comprehensive_security_documentation(
            security_model, scope="full_repo"
        )
        
        # Save the new security document
        db.save_security_document(security_doc)
        generated_docs.append(security_doc.dict())
        security_documents.append(security_doc)
        
        logger.info(f"Generated comprehensive security documentation: {security_doc.id}")
        
        # Also generate legacy threat documents for backward compatibility
        # This ensures existing functionality continues to work
        try:
            legacy_docs = await doc_generator.generate_all_documents(security_model)
            for legacy_doc in legacy_docs:
                db.save_threat_doc(legacy_doc)
                generated_docs.append(legacy_doc.dict())
            
            logger.info(f"Generated {len(legacy_docs)} legacy threat documents for compatibility")
        except Exception as e:
            logger.warning(f"Failed to generate legacy documents (non-critical): {e}")
        
        # Create and store knowledge base for future PR analysis
        logger.info(f"Creating knowledge base for repo: {repo_context.repo_id}")
        kb_success = kb_manager.store_security_knowledge(repo_context.repo_id, security_documents)
        
        if kb_success:
            logger.info(f"Successfully created knowledge base for repo: {repo_context.repo_id}")
        else:
            logger.warning(f"Failed to create knowledge base for repo: {repo_context.repo_id}")
        
        # Store results
        partial_manager.store_partial_results(
            analysis_id, 
            AnalysisStage.DOCUMENT_GENERATION,
            {
                "repo_context": repo_context.dict(),
                "security_model": security_model.dict(),
                "generated_documents": generated_docs,
                "primary_security_doc_id": security_doc.id,
                "document_count": len(generated_docs),
                "knowledge_base_created": kb_success
            }
        )
        
        logger.info(f"Document generation completed for repo: {repo_context.repo_id}")
        
    except Exception as e:
        logger.error(f"Document generation failed for repo {repo_context.repo_id}: {e}")
        raise


async def _stage_rag_indexing(partial_manager, analysis_id, rag, db):
    """RAG indexing stage"""
    stage_data = partial_manager.get_partial_results(analysis_id, AnalysisStage.DOCUMENT_GENERATION)
    repo_context = RepoContext(**stage_data["repo_context"])
    
    logger.info(f"Indexing documents in RAG system for repo: {repo_context.repo_id}")
    repo_context.analysis_status = "indexing_documents"
    
    # Get all documents for the repository
    all_docs = db.get_threat_docs_by_repo(repo_context.repo_id)
    
    if all_docs:
        rag.embed_documents(all_docs)
        
        # Extract and embed relevant code snippets
        code_references = []
        for doc in all_docs:
            code_references.extend(doc.code_references)
        
        if code_references:
            rag.embed_code_snippets(code_references)
    
    return {
        "repo_context": repo_context.dict(),
        "indexed_documents": len(all_docs),
        "indexed_code_references": len(code_references) if 'code_references' in locals() else 0
    }


@app.post("/analyze_pr", response_model=AnalyzePRResponse, tags=["Repository Analysis"])
async def analyze_pull_request(
    request: AnalyzePRRequest,
    db: DatabaseManager = Depends(get_db_manager),
    wiki_generator: SecurityWikiGenerator = Depends(get_security_wiki_generator),
    analysis_router: AnalysisRouter = Depends(get_analysis_router)
) -> AnalyzePRResponse:
    """
    Analyze a pull request for security implications with intelligent routing
    
    Uses intelligent analysis routing to determine the optimal analysis approach
    based on repository context availability, PR complexity, and system state.
    Automatically handles fallback scenarios when optimal analysis isn't possible.
    """
    # Generate unique IDs
    analysis_id = str(uuid.uuid4())
    pr_id = str(uuid.uuid4())
    
    logger.info(f"Starting intelligent PR analysis - Analysis ID: {analysis_id}, PR URL: {request.pr_url}")
    
    try:
        # Prepare routing request
        routing_request = {
            "pr_url": request.pr_url,
            "repo_id": request.repo_id,
            "analysis_type": "pr",
            "options": {
                "enable_fallback": True,
                "priority": "normal"
            }
        }
        
        # Route the analysis request
        routing_result = analysis_router.route_analysis_request(routing_request)
        
        if "error" in routing_result:
            raise HTTPException(
                status_code=400,
                detail=f"PR analysis routing failed: {routing_result['error']}"
            )
        
        # Check if user guidance is required
        user_guidance = routing_result.get("user_guidance", {})
        if user_guidance.get("action_required"):
            # Return guidance without executing analysis
            return AnalyzePRResponse(
                analysis_id=analysis_id,
                pr_id=pr_id,
                repo_id=routing_result["execution_plan"]["input"]["repo_id"],
                status="guidance_required",
                message="User guidance required before proceeding with analysis",
                has_repo_context=False,
                guidance=user_guidance,
                context_status=routing_result.get("workflow_analysis", {}).get("context_status"),
                routing_info=routing_result
            )
        
        # Execute the routed analysis
        execution_result = analysis_router.execute_routed_analysis(
            routing_result, wiki_generator, db
        )
        
        if "error" in execution_result:
            raise HTTPException(
                status_code=500,
                detail=f"PR analysis execution failed: {execution_result['error']}"
            )
        
        # Extract results based on execution mode
        execution_mode = execution_result.get("execution_mode")
        analysis_result = execution_result.get("analysis_result", {})
        
        # Determine repository ID and context status
        repo_id = routing_result["execution_plan"]["input"]["repo_id"]
        has_repo_context = execution_result.get("context_used", False)
        
        # Extract security information from analysis result
        security_issues = []
        recommendations = []
        risk_level = "low"
        
        if execution_mode in ["context_aware_pr", "basic_pr"]:
            # Extract from contextual or basic analysis
            if "file_analysis" in analysis_result:
                security_issues = [
                    {
                        "file": f['filename'],
                        "risk_level": f['risk_level'],
                        "categories": f['security_categories']
                    }
                    for f in analysis_result['file_analysis']['security_relevant_files']
                ]
            
            if "contextual_recommendations" in analysis_result:
                recommendations = analysis_result['contextual_recommendations']
            elif "overall_assessment" in analysis_result:
                recommendations = analysis_result['overall_assessment'].get('recommendations', [])
            
            if "contextual_assessment" in analysis_result:
                risk_level = analysis_result["contextual_assessment"].get("contextual_risk_level", "low")
            elif "overall_assessment" in analysis_result:
                risk_level = analysis_result['overall_assessment'].get('overall_risk_level', 'low')
                
        elif execution_mode == "fallback_pr":
            # Extract from fallback analysis
            if "file_analysis" in analysis_result:
                security_issues = [
                    {
                        "file": f['filename'],
                        "risk_level": f.get('risk_level', 'low'),
                        "categories": f.get('security_categories', [])
                    }
                    for f in analysis_result['file_analysis']['security_relevant_files']
                ]
            
            if "overall_assessment" in analysis_result:
                recommendations = analysis_result['overall_assessment'].get('recommendations', [])
                risk_level = analysis_result['overall_assessment'].get('overall_risk_level', 'low')
        
        # Extract changed files
        changed_files = []
        if "file_analysis" in analysis_result:
            changed_files = [f['filename'] for f in analysis_result['file_analysis']['security_relevant_files']]
        
        # Create security model and generate documentation
        from api.models import SecurityModel, Component, ComponentType
        
        components = []
        for file_info in analysis_result.get('file_analysis', {}).get('security_relevant_files', []):
            component = Component(
                id=str(uuid.uuid4()),
                name=file_info['filename'].split('/')[-1],
                type=ComponentType.SERVICE,
                file_path=file_info['filename'],
                handles_sensitive_data=file_info.get('risk_level') in ['high', 'critical'],
                description=f"Component from PR analysis: {file_info.get('status', 'modified')}"
            )
            components.append(component)
        
        security_model = SecurityModel(repo_id=repo_id, components=components)
        
        # Generate security documentation
        repo_context = None
        if has_repo_context:
            from api.knowledge_base import RepositoryKnowledgeBase
            kb_manager = RepositoryKnowledgeBase()
            repo_context = kb_manager.get_repo_security_context(repo_id)
        
        security_doc = await wiki_generator.generate_pr_security_analysis(
            security_model=security_model,
            changed_files=changed_files,
            repo_context=repo_context
        )
        
        # Save the security document
        db.save_security_document(security_doc)
        
        # Create PR analysis record
        from api.models import PRAnalysis
        
        pr_analysis_record = PRAnalysis(
            id=analysis_id,
            pr_id=pr_id,
            repo_id=repo_id,
            pr_url=request.pr_url,
            changed_files=changed_files,
            security_issues=security_issues,
            recommendations=recommendations,
            risk_level=risk_level,
            has_repo_context=has_repo_context,
            context_used={
                "repo_context_available": has_repo_context,
                "repo_id": repo_id if has_repo_context else None,
                "analysis_mode": execution_mode,
                "routing_strategy": routing_result.get("routing_strategy"),
                "fallback_used": execution_result.get("fallback_used", False)
            }
        )
        
        # Save PR analysis to database
        db.save_pr_analysis(pr_analysis_record)
        
        logger.info(f"PR analysis completed successfully - Analysis ID: {analysis_id}, Mode: {execution_mode}")
        
        return AnalyzePRResponse(
            analysis_id=analysis_id,
            pr_id=pr_id,
            repo_id=repo_id,
            status="completed",
            message=f"PR security analysis completed using {execution_mode} mode",
            has_repo_context=has_repo_context,
            security_doc_id=security_doc.id,
            risk_level=risk_level,
            guidance=user_guidance if user_guidance.get("show_guidance") else None,
            context_status=routing_result.get("workflow_analysis", {}).get("context_status"),
            routing_info={
                "execution_mode": execution_mode,
                "routing_strategy": routing_result.get("routing_strategy"),
                "fallback_used": execution_result.get("fallback_used", False),
                "confidence": routing_result.get("confidence")
            }
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(f"PR analysis failed - Analysis ID: {analysis_id}, Error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"PR analysis failed: {str(e)}"
        )


@app.get("/repo_status/{repo_id}", response_model=RepoStatusResponse, tags=["Repository Analysis"])
async def get_repository_status(
    repo_id: str = Path(description="Repository identifier"),
    kb_manager: RepositoryKnowledgeBase = Depends(get_knowledge_base_manager)
) -> RepoStatusResponse:
    """
    Check if repository analysis exists and return status information
    
    This endpoint allows checking whether a repository has been analyzed
    and is available for context-aware PR analysis. Returns analysis metadata
    and last update timestamp.
    """
    try:
        logger.info(f"Checking repository status for repo_id: {repo_id}")
        
        # Check repository analysis status using knowledge base manager
        analysis_status = kb_manager.check_repo_analysis_exists(repo_id)
        
        return RepoStatusResponse(
            repo_id=repo_id,
            exists=analysis_status["exists"],
            status=analysis_status["status"],
            message=analysis_status["message"],
            analysis_date=analysis_status.get("analysis_date"),
            document_count=analysis_status.get("document_count", 0),
            has_search_index=analysis_status.get("has_search_index", False),
            repo_context=analysis_status.get("repo_context", {})
        )
        
    except Exception as e:
        logger.error(f"Error checking repository status for {repo_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to check repository status: {str(e)}"
        )


@app.post("/check_pr_context", tags=["Repository Analysis"])
async def check_pr_context_requirements(
    request: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Check context requirements for PR analysis and provide intelligent guidance
    
    Analyzes a PR URL to determine the best analysis approach, checks repository
    context availability, and provides user guidance on whether to analyze the
    full repository first or proceed with PR-only analysis.
    """
    from api.smart_workflow import SmartWorkflowManager
    
    try:
        pr_url = request.get("pr_url")
        repo_id = request.get("repo_id")
        
        if not pr_url:
            raise HTTPException(
                status_code=400,
                detail="PR URL is required"
            )
        
        logger.info(f"Checking PR context requirements for: {pr_url}")
        
        # Initialize smart workflow manager
        workflow_manager = SmartWorkflowManager()
        
        # Check context requirements
        context_requirements = workflow_manager.check_context_requirements(pr_url, repo_id)
        
        if "error" in context_requirements:
            raise HTTPException(
                status_code=400,
                detail=context_requirements["error"]
            )
        
        return context_requirements
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking PR context requirements: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to check context requirements: {str(e)}"
        )


@app.post("/route_pr_analysis", tags=["Repository Analysis"])
async def route_pr_analysis_request(
    request: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Route PR analysis request to appropriate analysis mode with intelligent guidance
    
    Determines the optimal analysis approach based on repository context availability,
    PR complexity, and user preferences. Provides routing decision with alternatives
    and user guidance.
    """
    from api.smart_workflow import SmartWorkflowManager
    
    try:
        pr_url = request.get("pr_url")
        repo_id = request.get("repo_id")
        force_mode = request.get("force_mode")
        
        if not pr_url:
            raise HTTPException(
                status_code=400,
                detail="PR URL is required"
            )
        
        logger.info(f"Routing PR analysis request for: {pr_url}")
        
        # Initialize smart workflow manager
        workflow_manager = SmartWorkflowManager()
        
        # Route analysis request
        routing_result = workflow_manager.route_analysis_request(pr_url, repo_id, force_mode)
        
        if "error" in routing_result:
            raise HTTPException(
                status_code=400,
                detail=routing_result["error"]
            )
        
        return routing_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error routing PR analysis request: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to route analysis request: {str(e)}"
        )

# Document Management Endpoints

@app.get("/repos/{repo_id}/documents", response_model=DocumentListResponse, tags=["Repository Analysis"])
async def get_repository_documents(
    repo_id: str = Path(description="Repository identifier"),
    doc_type: Optional[str] = Query(None, description="Filter by document type"),
    include_versions: bool = Query(False, description="Include all document versions"),
    db: DatabaseManager = Depends(get_db_manager)
) -> DocumentListResponse:
    """
    Get all threat modeling documents for a repository
    
    Returns a list of generated threat modeling documents with optional filtering
    by document type and version inclusion.
    """
    logger.info(f"Retrieving documents for repository: {repo_id}")
    
    # Verify repository exists
    repo_context = db.get_repo_context(repo_id)
    if not repo_context:
        raise HTTPException(status_code=404, detail=f"Repository {repo_id} not found")
    
    try:
        if doc_type:
            # Get documents by specific type
            documents = db.get_documents_by_type(repo_id, doc_type.value)
        else:
            # Get all documents for the repository
            documents = db.get_threat_docs_by_repo(repo_id, include_all_versions=include_versions)
        
        logger.info(f"Retrieved {len(documents)} documents for repository: {repo_id}")
        
        return DocumentListResponse(
            repo_id=repo_id,
            documents=documents,
            total_count=len(documents)
        )
        
    except Exception as e:
        logger.error(f"Error retrieving documents for repository {repo_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve documents: {str(e)}")

@app.get("/repos/{repo_id}/documents/{doc_id}", response_model=ThreatDoc, tags=["Repository Analysis"])
async def get_repository_document(
    repo_id: str = Path(description="Repository identifier"),
    doc_id: str = Path(description="Document identifier"),
    version: Optional[int] = Query(None, description="Specific document version"),
    db: DatabaseManager = Depends(get_db_manager)
) -> ThreatDoc:
    """
    Get a specific threat modeling document
    
    Returns the full content of a specific threat modeling document,
    optionally for a specific version.
    """
    logger.info(f"Retrieving document {doc_id} for repository: {repo_id}")
    
    # Verify repository exists
    repo_context = db.get_repo_context(repo_id)
    if not repo_context:
        raise HTTPException(status_code=404, detail=f"Repository {repo_id} not found")
    
    try:
        document = db.get_threat_doc_by_id(doc_id, version)
        
        if not document:
            raise HTTPException(status_code=404, detail=f"Document {doc_id} not found")
        
        # Verify document belongs to the specified repository
        if document.repo_id != repo_id:
            raise HTTPException(
                status_code=404, 
                detail=f"Document {doc_id} not found in repository {repo_id}"
            )
        
        logger.info(f"Retrieved document {doc_id} for repository: {repo_id}")
        return document
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving document {doc_id} for repository {repo_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve document: {str(e)}")

@app.get("/repos/{repo_id}/security_model", response_model=SecurityModel, tags=["Repository Analysis"])
async def get_repository_security_model(
    repo_id: str = Path(description="Repository identifier"),
    db: DatabaseManager = Depends(get_db_manager),
    security_builder: SecurityModelBuilder = Depends(get_security_model_builder)
) -> SecurityModel:
    """
    Get the internal security model for a repository
    
    Returns the complete security model used for threat document generation,
    useful for debugging and inspection purposes.
    """
    logger.info(f"Retrieving security model for repository: {repo_id}")
    
    # Verify repository exists
    repo_context = db.get_repo_context(repo_id)
    if not repo_context:
        raise HTTPException(status_code=404, detail=f"Repository {repo_id} not found")
    
    # Check if analysis is complete
    if repo_context.analysis_status not in ["completed", "indexing_documents"]:
        raise HTTPException(
            status_code=409, 
            detail=f"Repository analysis not complete. Current status: {repo_context.analysis_status}"
        )
    
    try:
        # Rebuild security model from repository context
        # In a production system, you might want to cache this
        security_model = security_builder.build_security_model(repo_context)
        
        logger.info(f"Retrieved security model for repository: {repo_id}")
        return security_model
        
    except Exception as e:
        logger.error(f"Error retrieving security model for repository {repo_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve security model: {str(e)}")

@app.get("/repos/{repo_id}/status", tags=["Repository Analysis"])
async def get_repository_status(
    repo_id: str = Path(description="Repository identifier"),
    db: DatabaseManager = Depends(get_db_manager)
) -> Dict[str, Any]:
    """
    Get the current analysis status and statistics for a repository
    
    Returns detailed status information including analysis progress,
    document counts, and last update times.
    """
    logger.info(f"Retrieving status for repository: {repo_id}")
    
    # Get repository context
    repo_context = db.get_repo_context(repo_id)
    if not repo_context:
        raise HTTPException(status_code=404, detail=f"Repository {repo_id} not found")
    
    try:
        # Get repository statistics
        stats = db.get_repo_statistics(repo_id)
        
        return {
            "repo_id": repo_id,
            "analysis_status": repo_context.analysis_status,
            "created_at": repo_context.created_at.isoformat(),
            "primary_languages": repo_context.primary_languages,
            "statistics": stats,
            "repo_url": repo_context.repo_url,
            "local_path": repo_context.local_path
        }
        
    except Exception as e:
        logger.error(f"Error retrieving status for repository {repo_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve repository status: {str(e)}")

@app.get("/analysis/{analysis_id}/progress", tags=["Repository Analysis"])
async def get_analysis_progress(
    analysis_id: str = Path(description="Analysis identifier"),
    partial_manager: PartialResultsManager = Depends(get_partial_results_manager)
) -> Dict[str, Any]:
    """
    Get detailed progress information for an analysis
    
    Returns current stage, completion status, and any error information
    for ongoing or completed analyses.
    """
    progress = partial_manager.load_progress(analysis_id)
    if not progress:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")
    
    # Calculate progress percentage
    total_stages = len(AnalysisStage) - 1  # Exclude COMPLETED stage
    completed_stages = len([s for s in progress.stages.values() if s.status == AnalysisStatus.COMPLETED])
    progress_percentage = (completed_stages / total_stages) * 100
    
    # Get queue status if applicable
    queue_position = analysis_queue.get_analysis_position(analysis_id)
    queue_status = analysis_queue.get_queue_status()
    
    return {
        "analysis_id": analysis_id,
        "repo_id": progress.repo_id,
        "overall_status": progress.overall_status.value,
        "current_stage": progress.current_stage.value,
        "progress_percentage": progress_percentage,
        "created_at": progress.created_at.isoformat(),
        "updated_at": progress.updated_at.isoformat(),
        "error_recovery_attempts": progress.error_recovery_attempts,
        "queue_position": queue_position,
        "queue_status": queue_status,
        "stages": {
            stage.value: {
                "status": result.status.value,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "error_message": result.error_message,
                "error_type": result.error_type,
                "retry_count": result.retry_count
            }
            for stage, result in progress.stages.items()
        }
    }

@app.post("/analysis/{analysis_id}/recover", tags=["Repository Analysis"])
async def recover_analysis(
    analysis_id: str = Path(description="Analysis identifier"),
    stage: Optional[AnalysisStage] = Query(None, description="Specific stage to recover"),
    partial_manager: PartialResultsManager = Depends(get_partial_results_manager)
) -> Dict[str, Any]:
    """
    Attempt to recover a failed analysis
    
    Can recover from a specific failed stage or automatically determine
    the recovery point based on the current analysis state.
    """
    progress = partial_manager.load_progress(analysis_id)
    if not progress:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")
    
    if progress.overall_status != AnalysisStatus.FAILED:
        raise HTTPException(
            status_code=400, 
            detail=f"Analysis is not in failed state (current: {progress.overall_status.value})"
        )
    
    # Determine recovery stage
    if stage is None:
        # Find the first failed stage
        for stage_enum, stage_result in progress.stages.items():
            if stage_result.status == AnalysisStatus.FAILED:
                stage = stage_enum
                break
    
    if stage is None:
        raise HTTPException(status_code=400, detail="No failed stage found to recover")
    
    # Check if recovery is possible
    if not partial_manager.can_recover_stage(analysis_id, stage):
        raise HTTPException(
            status_code=400, 
            detail=f"Stage {stage.value} cannot be recovered (max attempts reached)"
        )
    
    # Attempt recovery
    recovered_progress = partial_manager.recover_stage(analysis_id, stage)
    if not recovered_progress:
        raise HTTPException(status_code=500, detail="Recovery failed")
    
    return {
        "analysis_id": analysis_id,
        "recovered_stage": stage.value,
        "recovery_attempt": recovered_progress.error_recovery_attempts,
        "message": f"Recovery initiated for stage {stage.value}",
        "next_steps": "Re-run the analysis to continue from the recovered stage"
    }

@app.get("/system/queue", tags=["System Management"])
async def get_analysis_queue_status() -> Dict[str, Any]:
    """
    Get current analysis queue status
    
    Returns information about active and queued analyses,
    useful for monitoring system load and capacity.
    """
    queue_status = analysis_queue.get_queue_status()
    lock_status = {
        "active_locks": len(lock_manager.get_active_locks()),
        "lock_details": [
            {
                "lock_id": lock_info.lock_id,
                "repo_id": lock_info.repo_id,
                "analysis_id": lock_info.analysis_id,
                "lock_type": lock_info.lock_type,
                "created_at": lock_info.created_at.isoformat()
            }
            for lock_info in lock_manager.get_active_locks().values()
        ]
    }
    
    return {
        "queue": queue_status,
        "locks": lock_status,
        "system_capacity": {
            "max_concurrent_analyses": settings.max_concurrent_analyses,
            "available_slots": max(0, settings.max_concurrent_analyses - queue_status["active_count"])
        }
    }

@app.post("/system/cleanup", tags=["System Management"])
async def cleanup_system_resources() -> Dict[str, Any]:
    """
    Clean up stale locks and old progress files
    
    Performs maintenance operations to clean up resources
    from failed or abandoned analyses.
    """
    try:
        # Cleanup stale locks
        initial_locks = len(lock_manager.get_active_locks())
        lock_manager.cleanup_stale_locks()
        final_locks = len(lock_manager.get_active_locks())
        cleaned_locks = initial_locks - final_locks
        
        # Cleanup old progress files
        partial_manager = get_partial_results_manager()
        partial_manager.cleanup_old_progress()
        
        return {
            "success": True,
            "cleaned_locks": cleaned_locks,
            "remaining_locks": final_locks,
            "message": "System cleanup completed successfully"
        }
        
    except Exception as e:
        logger.error(f"System cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {str(e)}")

@app.get("/system/failed_analyses", tags=["System Management"])
async def get_failed_analyses(
    partial_manager: PartialResultsManager = Depends(get_partial_results_manager)
) -> Dict[str, Any]:
    """
    Get all failed analyses that can potentially be recovered
    
    Returns a list of analyses that failed but haven't exceeded
    the maximum recovery attempts.
    """
    failed_analyses = partial_manager.get_failed_analyses()
    
    return {
        "failed_count": len(failed_analyses),
        "analyses": [
            {
                "analysis_id": progress.analysis_id,
                "repo_id": progress.repo_id,
                "repo_url": progress.repo_url,
                "local_path": progress.local_path,
                "current_stage": progress.current_stage.value,
                "created_at": progress.created_at.isoformat(),
                "updated_at": progress.updated_at.isoformat(),
                "error_recovery_attempts": progress.error_recovery_attempts,
                "can_recover": progress.error_recovery_attempts < 3
            }
            for progress in failed_analyses
        ]
    }

# Storage Management Endpoints

@app.get("/storage/health", tags=["Storage Management"])
async def get_storage_health() -> Dict[str, Any]:
    """
    Get comprehensive storage system health information
    
    Returns storage usage, quota status, and health warnings
    for all storage areas.
    """
    try:
        health = storage_manager.get_system_health()
        return health
    except Exception as e:
        logger.error(f"Storage health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Storage health check failed: {str(e)}")

@app.get("/storage/stats", tags=["Storage Management"])
async def get_storage_statistics(
    storage_type: Optional[StorageType] = Query(None, description="Specific storage type to query")
) -> Dict[str, Any]:
    """
    Get detailed storage statistics
    
    Returns file counts, sizes, and usage information for storage areas.
    """
    try:
        stats = storage_manager.get_storage_stats(storage_type)
        
        # Convert to serializable format
        serializable_stats = {}
        for key, stat in stats.items():
            serializable_stats[key] = {
                "total_size_bytes": stat.total_size_bytes,
                "used_size_bytes": stat.used_size_bytes,
                "available_size_bytes": stat.available_size_bytes,
                "file_count": stat.file_count,
                "directory_count": stat.directory_count,
                "oldest_file_date": stat.oldest_file_date.isoformat() if stat.oldest_file_date else None,
                "newest_file_date": stat.newest_file_date.isoformat() if stat.newest_file_date else None,
                "used_size_mb": stat.used_size_bytes / 1024 / 1024,
                "available_size_gb": stat.available_size_bytes / 1024 / 1024 / 1024
            }
        
        return {
            "statistics": serializable_stats,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Storage statistics query failed: {e}")
        raise HTTPException(status_code=500, detail=f"Storage statistics failed: {str(e)}")

@app.get("/storage/quotas", tags=["Storage Management"])
async def get_storage_quotas() -> Dict[str, Any]:
    """
    Get storage quota information for all storage types
    
    Returns quota limits, current usage, and status for each storage area.
    """
    try:
        quotas = {}
        for storage_type in StorageType:
            quota_info = storage_manager.check_quota_usage(storage_type)
            quotas[storage_type.value] = quota_info
        
        return {
            "quotas": quotas,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Storage quota query failed: {e}")
        raise HTTPException(status_code=500, detail=f"Storage quota query failed: {str(e)}")

@app.post("/storage/cleanup", tags=["Storage Management"])
async def cleanup_storage(
    storage_type: StorageType = Query(description="Storage type to clean up"),
    max_age_days: Optional[int] = Query(None, description="Maximum age of files to keep"),
    dry_run: bool = Query(False, description="Perform dry run without actual deletion")
) -> Dict[str, Any]:
    """
    Clean up old files in specified storage area
    
    Removes files older than the specified age or default retention period.
    Use dry_run=true to preview what would be deleted.
    """
    try:
        cleanup_result = storage_manager.cleanup_old_files(storage_type, max_age_days, dry_run)
        
        return {
            "storage_type": storage_type.value,
            "dry_run": dry_run,
            "files_removed": cleanup_result.files_removed,
            "directories_removed": cleanup_result.directories_removed,
            "bytes_freed": cleanup_result.bytes_freed,
            "mb_freed": cleanup_result.bytes_freed / 1024 / 1024,
            "errors": cleanup_result.errors,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Storage cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Storage cleanup failed: {str(e)}")

@app.post("/storage/cleanup/failed_analyses", tags=["Storage Management"])
async def cleanup_failed_analyses(
    max_age_hours: int = Query(24, description="Maximum age of failed analysis artifacts in hours")
) -> Dict[str, Any]:
    """
    Clean up temporary files from failed analyses
    
    Removes temporary files and directories left behind by failed analysis operations.
    """
    try:
        cleanup_result = storage_manager.cleanup_failed_analyses(max_age_hours)
        
        return {
            "max_age_hours": max_age_hours,
            "files_removed": cleanup_result.files_removed,
            "directories_removed": cleanup_result.directories_removed,
            "bytes_freed": cleanup_result.bytes_freed,
            "mb_freed": cleanup_result.bytes_freed / 1024 / 1024,
            "errors": cleanup_result.errors,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed analysis cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed analysis cleanup failed: {str(e)}")

@app.post("/storage/maintenance", tags=["Storage Management"])
async def perform_storage_maintenance() -> Dict[str, Any]:
    """
    Perform comprehensive storage maintenance
    
    Runs quota checks, cleanup operations, and creates backups as needed.
    This is a comprehensive maintenance operation that may take some time.
    """
    try:
        maintenance_result = storage_manager.perform_maintenance()
        return maintenance_result
        
    except Exception as e:
        logger.error(f"Storage maintenance failed: {e}")
        raise HTTPException(status_code=500, detail=f"Storage maintenance failed: {str(e)}")

@app.post("/storage/backup", tags=["Storage Management"])
async def create_backup(
    storage_types: Optional[List[StorageType]] = Query(None, description="Storage types to backup")
) -> Dict[str, Any]:
    """
    Create backup of specified storage areas
    
    Creates compressed archives of the specified storage areas.
    If no storage types specified, backs up documents and embeddings.
    """
    try:
        backup_result = storage_manager.create_backup(storage_types)
        return backup_result
        
    except Exception as e:
        logger.error(f"Backup creation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Backup creation failed: {str(e)}")

@app.get("/storage/backups", tags=["Storage Management"])
async def list_backups() -> Dict[str, Any]:
    """
    List all available backups
    
    Returns information about all available backup archives including
    creation dates, sizes, and contents.
    """
    try:
        backups = storage_manager.get_backup_list()
        return {
            "backups": backups,
            "count": len(backups),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Backup listing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Backup listing failed: {str(e)}")

@app.post("/storage/restore/{backup_id}", tags=["Storage Management"])
async def restore_backup(
    backup_id: str = Path(description="Backup identifier to restore")
) -> Dict[str, Any]:
    """
    Restore from a backup
    
    Restores storage areas from the specified backup archive.
    This will replace current data with backup data.
    """
    try:
        restore_result = storage_manager.restore_backup(backup_id)
        return restore_result
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Backup restore failed: {e}")
        raise HTTPException(status_code=500, detail=f"Backup restore failed: {str(e)}")

# Database Management Endpoints

@app.get("/database/health", tags=["Database Management"])
async def get_database_health(
    db: DatabaseManager = Depends(get_db_manager)
) -> Dict[str, Any]:
    """
    Get database health and integrity status
    
    Returns comprehensive database health information including
    connectivity, integrity checks, and basic statistics.
    """
    try:
        health_status = {
            "timestamp": datetime.now().isoformat(),
            "connectivity": db.health_check(),
            "integrity": db.check_integrity(),
            "statistics": db.get_database_statistics()
        }
        
        # Determine overall status
        if health_status["connectivity"] and health_status["integrity"]:
            health_status["status"] = "healthy"
        elif health_status["connectivity"]:
            health_status["status"] = "degraded"
        else:
            health_status["status"] = "unhealthy"
        
        return health_status
        
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database health check failed: {str(e)}")

@app.get("/database/statistics", tags=["Database Management"])
async def get_database_statistics(
    db: DatabaseManager = Depends(get_db_manager)
) -> Dict[str, Any]:
    """
    Get detailed database statistics
    
    Returns information about database size, table counts, indexes,
    and schema version.
    """
    try:
        stats = db.get_database_statistics()
        return stats
        
    except Exception as e:
        logger.error(f"Database statistics query failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database statistics failed: {str(e)}")

@app.post("/database/integrity_check", tags=["Database Management"])
async def check_database_integrity(
    db: DatabaseManager = Depends(get_db_manager)
) -> Dict[str, Any]:
    """
    Perform comprehensive database integrity check
    
    Checks for corruption, foreign key violations, and orphaned records.
    """
    try:
        integrity_ok = db.check_integrity()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "integrity_status": "ok" if integrity_ok else "failed",
            "details": "Database integrity check completed",
            "recommendation": "No action needed" if integrity_ok else "Consider running database repair"
        }
        
    except Exception as e:
        logger.error(f"Database integrity check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Integrity check failed: {str(e)}")

@app.post("/database/repair", tags=["Database Management"])
async def repair_database(
    db: DatabaseManager = Depends(get_db_manager)
) -> Dict[str, Any]:
    """
    Attempt to repair database issues
    
    Cleans up orphaned records, vacuums the database, and updates statistics.
    This operation may take some time for large databases.
    """
    try:
        repair_result = db.repair_database()
        return repair_result
        
    except Exception as e:
        logger.error(f"Database repair failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database repair failed: {str(e)}")

@app.post("/database/backup", tags=["Database Management"])
async def create_database_backup(
    backup_name: Optional[str] = Query(None, description="Custom backup name"),
    db: DatabaseManager = Depends(get_db_manager)
) -> Dict[str, Any]:
    """
    Create database backup
    
    Creates a complete backup of the database using SQLite's backup API.
    """
    try:
        backup_result = db.create_backup(backup_name)
        return backup_result
        
    except Exception as e:
        logger.error(f"Database backup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database backup failed: {str(e)}")

@app.post("/database/restore/{backup_name}", tags=["Database Management"])
async def restore_database_backup(
    backup_name: str = Path(description="Backup file name to restore"),
    db: DatabaseManager = Depends(get_db_manager)
) -> Dict[str, Any]:
    """
    Restore database from backup
    
    Restores the database from a previously created backup file.
    This will replace all current data with backup data.
    """
    try:
        restore_result = db.restore_backup(backup_name)
        return restore_result
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Database restore failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database restore failed: {str(e)}")

@app.post("/database/export", tags=["Database Management"])
async def export_database_data(
    export_path: str = Query(description="Export file path"),
    format: str = Query("json", description="Export format (json or sql)"),
    db: DatabaseManager = Depends(get_db_manager)
) -> Dict[str, Any]:
    """
    Export database data to file
    
    Exports all database data to JSON or SQL format for backup
    or migration purposes.
    """
    try:
        # Validate format
        if format.lower() not in ["json", "sql"]:
            raise HTTPException(status_code=400, detail="Format must be 'json' or 'sql'")
        
        export_result = db.export_data(export_path, format)
        return export_result
        
    except Exception as e:
        logger.error(f"Database export failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database export failed: {str(e)}")

@app.post("/database/import", tags=["Database Management"])
async def import_database_data(
    import_path: str = Query(description="Import file path"),
    format: str = Query("json", description="Import format (json or sql)"),
    db: DatabaseManager = Depends(get_db_manager)
) -> Dict[str, Any]:
    """
    Import database data from file
    
    Imports data from JSON or SQL format files. This will add to
    or replace existing data depending on the import format.
    """
    try:
        # Validate format
        if format.lower() not in ["json", "sql"]:
            raise HTTPException(status_code=400, detail="Format must be 'json' or 'sql'")
        
        # Check if file exists
        if not os.path.exists(import_path):
            raise HTTPException(status_code=404, detail=f"Import file not found: {import_path}")
        
        import_result = db.import_data(import_path, format)
        return import_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database import failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database import failed: {str(e)}")

# Configuration Management Endpoints

@app.get("/config/summary", tags=["Configuration Management"])
async def get_configuration_summary() -> Dict[str, Any]:
    """
    Get current configuration summary
    
    Returns a summary of the current configuration including
    validation status and key settings (with sensitive data masked).
    """
    try:
        summary = config_manager.get_config_summary()
        return summary
        
    except Exception as e:
        logger.error(f"Configuration summary failed: {e}")
        raise HTTPException(status_code=500, detail=f"Configuration summary failed: {str(e)}")

@app.get("/config/validate", tags=["Configuration Management"])
async def validate_configuration() -> Dict[str, Any]:
    """
    Validate current configuration
    
    Performs comprehensive validation of all configuration settings
    and returns detailed validation results.
    """
    try:
        validation_result = config_manager.validate_configuration()
        return validation_result
        
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Configuration validation failed: {str(e)}")

@app.post("/config/reload", tags=["Configuration Management"])
async def reload_configuration() -> Dict[str, Any]:
    """
    Reload configuration from files and environment
    
    Forces a reload of configuration from all sources.
    Only works if hot-reloading is enabled.
    """
    try:
        if not config_manager.settings.enable_config_hot_reload:
            raise HTTPException(
                status_code=400, 
                detail="Configuration hot-reloading is disabled"
            )
        
        success = config_manager.reload_configuration()
        
        return {
            "success": success,
            "timestamp": datetime.now().isoformat(),
            "message": "Configuration reloaded successfully" if success else "Configuration reload failed",
            "validation": config_manager.validate_configuration() if success else None
        }
        
    except Exception as e:
        logger.error(f"Configuration reload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Configuration reload failed: {str(e)}")

@app.get("/config/schema", tags=["Configuration Management"])
async def get_configuration_schema() -> Dict[str, Any]:
    """
    Get configuration schema documentation
    
    Returns the complete configuration schema with field descriptions,
    types, defaults, and validation rules.
    """
    try:
        from api.config import Settings
        
        schema = Settings.schema()
        
        # Add additional metadata
        schema_info = {
            "schema": schema,
            "version": "1.0",
            "generated_at": datetime.now().isoformat(),
            "description": "Threat Modeling Documentation Generator Configuration Schema",
            "examples": {
                "development": {
                    "debug": True,
                    "log_level": "DEBUG",
                    "max_concurrent_analyses": 2,
                    "cors_origins": ["http://localhost:3000"]
                },
                "production": {
                    "debug": False,
                    "log_level": "INFO",
                    "enable_config_hot_reload": False,
                    "max_concurrent_analyses": 10,
                    "cors_origins": ["https://yourdomain.com"]
                }
            }
        }
        
        return schema_info
        
    except Exception as e:
        logger.error(f"Configuration schema generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Configuration schema failed: {str(e)}")

@app.get("/config/health", tags=["Configuration Management"])
async def get_configuration_health() -> Dict[str, Any]:
    """
    Get configuration health status
    
    Returns health information about configuration including
    file watcher status, validation status, and recommendations.
    """
    try:
        validation = config_manager.validate_configuration()
        
        health_info = {
            "timestamp": datetime.now().isoformat(),
            "configuration_valid": validation["valid"],
            "hot_reload_enabled": config_manager.settings.enable_config_hot_reload,
            "file_watcher_active": config_manager.file_observer is not None,
            "validation_errors": validation["errors"],
            "validation_warnings": validation["warnings"],
            "recommendations": []
        }
        
        # Add recommendations based on validation results
        if validation["warnings"]:
            health_info["recommendations"].append("Review configuration warnings")
        
        if config_manager.settings.debug:
            health_info["recommendations"].append("Disable debug mode in production")
        
        if not config_manager.settings.enable_config_hot_reload:
            health_info["recommendations"].append("Consider enabling hot-reload for development")
        
        # Determine overall health status
        if validation["valid"] and not validation["warnings"]:
            health_info["status"] = "healthy"
        elif validation["valid"]:
            health_info["status"] = "warning"
        else:
            health_info["status"] = "unhealthy"
        
        return health_info
        
    except Exception as e:
        logger.error(f"Configuration health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Configuration health check failed: {str(e)}")

@app.post("/config/test", tags=["Configuration Management"])
async def test_configuration_connections() -> Dict[str, Any]:
    """
    Test configuration by attempting connections to external services
    
    Tests LLM API connectivity, storage accessibility, and other
    configured external services.
    """
    try:
        test_results = {
            "timestamp": datetime.now().isoformat(),
            "overall_success": True,
            "tests": {}
        }
        
        # Test LLM connectivity
        try:
            if config_manager.settings.validate_llm_config():
                # Import here to avoid circular imports
                from api.llm_client import LLMManager
                llm_manager = LLMManager()
                
                # Test with a simple prompt
                response = await llm_manager.generate_completion(
                    "Test connection", 
                    max_tokens=10, 
                    temperature=0.1
                )
                
                test_results["tests"]["llm_connection"] = {
                    "success": True,
                    "response_time": response.response_time,
                    "model": response.model
                }
            else:
                test_results["tests"]["llm_connection"] = {
                    "success": False,
                    "error": "LLM configuration invalid"
                }
                test_results["overall_success"] = False
                
        except Exception as e:
            test_results["tests"]["llm_connection"] = {
                "success": False,
                "error": str(e)
            }
            test_results["overall_success"] = False
        
        # Test storage accessibility
        try:
            import tempfile
            test_file = Path(config_manager.settings.storage_base_path) / "connection_test.tmp"
            test_file.write_text("test")
            test_file.unlink()
            
            test_results["tests"]["storage_access"] = {
                "success": True,
                "path": config_manager.settings.storage_base_path
            }
            
        except Exception as e:
            test_results["tests"]["storage_access"] = {
                "success": False,
                "error": str(e)
            }
            test_results["overall_success"] = False
        
        # Test database connectivity
        try:
            from api.database import DatabaseManager
            db = DatabaseManager()
            db_healthy = db.health_check()
            
            test_results["tests"]["database_connection"] = {
                "success": db_healthy,
                "path": config_manager.settings.database_path
            }
            
            if not db_healthy:
                test_results["overall_success"] = False
                
        except Exception as e:
            test_results["tests"]["database_connection"] = {
                "success": False,
                "error": str(e)
            }
            test_results["overall_success"] = False
        
        return test_results
        
    except Exception as e:
        logger.error(f"Configuration connection test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Configuration test failed: {str(e)}")

# Monitoring and Operational Endpoints

@app.get("/metrics", tags=["Monitoring"])
async def get_metrics_summary() -> Dict[str, Any]:
    """
    Get comprehensive metrics summary
    
    Returns current system metrics, application metrics, and performance statistics.
    """
    try:
        # Get system metrics
        system_metrics = system_monitor.get_current_system_metrics()
        
        # Get application metrics
        app_metrics = application_monitor.get_current_application_metrics()
        
        # Get metrics collector summary
        collector_summary = metrics_collector.get_all_metrics_summary()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "system": {
                "cpu_percent": system_metrics.cpu_percent,
                "memory_percent": system_metrics.memory_percent,
                "memory_used_mb": system_metrics.memory_used_mb,
                "disk_usage_percent": system_metrics.disk_usage_percent,
                "disk_free_gb": system_metrics.disk_free_gb,
                "process_count": system_metrics.process_count,
                "thread_count": system_metrics.thread_count
            },
            "application": {
                "active_analyses": app_metrics.active_analyses,
                "queued_analyses": app_metrics.queued_analyses,
                "total_repositories": app_metrics.total_repositories,
                "total_documents": app_metrics.total_documents,
                "avg_response_time_ms": app_metrics.avg_response_time_ms,
                "error_rate": app_metrics.error_rate,
                "llm_requests_total": app_metrics.llm_requests_total,
                "llm_requests_failed": app_metrics.llm_requests_failed,
                "storage_usage_mb": app_metrics.storage_usage_mb
            },
            "collector": collector_summary
        }
        
    except Exception as e:
        logger.error(f"Metrics collection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Metrics collection failed: {str(e)}")

@app.get("/metrics/{metric_name}", tags=["Monitoring"])
async def get_specific_metric(
    metric_name: str = Path(description="Metric name to retrieve"),
    minutes: int = Query(60, description="Time range in minutes")
) -> Dict[str, Any]:
    """
    Get specific metric data over time
    
    Returns historical data points for a specific metric.
    """
    try:
        recent_metrics = metrics_collector.get_recent_metrics(metric_name, minutes)
        
        if not recent_metrics:
            raise HTTPException(status_code=404, detail=f"Metric '{metric_name}' not found")
        
        # Convert to serializable format
        data_points = []
        for metric in recent_metrics:
            data_points.append({
                "timestamp": metric.timestamp.isoformat(),
                "value": metric.value,
                "labels": metric.labels,
                "unit": metric.unit
            })
        
        return {
            "metric_name": metric_name,
            "time_range_minutes": minutes,
            "data_points": data_points,
            "count": len(data_points)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Metric retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Metric retrieval failed: {str(e)}")

@app.get("/health/comprehensive", tags=["Monitoring"])
async def get_comprehensive_health() -> Dict[str, Any]:
    """
    Get comprehensive health status
    
    Returns detailed health information for all system components
    including health checks, metrics, and alerts.
    """
    try:
        # Run all health checks
        health_results = health_checker.run_all_health_checks()
        
        # Get active alerts
        active_alerts = alert_manager.get_active_alerts()
        
        # Get system status
        system_metrics = system_monitor.get_current_system_metrics()
        
        # Determine overall health
        overall_healthy = (
            health_results["overall_status"] == "healthy" and
            len(active_alerts) == 0 and
            system_metrics.cpu_percent < 90 and
            system_metrics.memory_percent < 90
        )
        
        return {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "healthy" if overall_healthy else "unhealthy",
            "health_checks": health_results,
            "active_alerts": active_alerts,
            "system_resources": {
                "cpu_percent": system_metrics.cpu_percent,
                "memory_percent": system_metrics.memory_percent,
                "disk_usage_percent": system_metrics.disk_usage_percent
            },
            "recommendations": _get_health_recommendations(health_results, active_alerts, system_metrics)
        }
        
    except Exception as e:
        logger.error(f"Comprehensive health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@app.get("/alerts", tags=["Monitoring"])
async def get_active_alerts() -> Dict[str, Any]:
    """
    Get all active alerts
    
    Returns current active alerts with details about triggered conditions.
    """
    try:
        active_alerts = alert_manager.get_active_alerts()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "active_alerts": active_alerts,
            "alert_count": len(active_alerts),
            "severity_breakdown": _get_alert_severity_breakdown(active_alerts)
        }
        
    except Exception as e:
        logger.error(f"Alert retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Alert retrieval failed: {str(e)}")

@app.post("/alerts/check", tags=["Monitoring"])
async def trigger_alert_check() -> Dict[str, Any]:
    """
    Manually trigger alert rule evaluation
    
    Forces evaluation of all alert rules and returns any newly triggered alerts.
    """
    try:
        # Get current alerts before check
        alerts_before = len(alert_manager.get_active_alerts())
        
        # Run alert check
        alert_manager.check_alerts()
        
        # Get alerts after check
        alerts_after = alert_manager.get_active_alerts()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "alerts_before_check": alerts_before,
            "alerts_after_check": len(alerts_after),
            "new_alerts": len(alerts_after) - alerts_before,
            "active_alerts": alerts_after
        }
        
    except Exception as e:
        logger.error(f"Alert check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Alert check failed: {str(e)}")

@app.get("/diagnostics", tags=["Monitoring"])
async def get_system_diagnostics() -> Dict[str, Any]:
    """
    Get comprehensive system diagnostics
    
    Returns detailed diagnostic information for troubleshooting
    including performance metrics, resource usage, and system status.
    """
    try:
        # Get system information
        system_metrics = system_monitor.get_current_system_metrics()
        
        # Get application metrics
        app_metrics = application_monitor.get_current_application_metrics()
        
        # Get configuration summary
        config_summary = config_manager.get_config_summary()
        
        # Get storage health
        storage_health = storage_manager.get_system_health()
        
        # Get database statistics
        from api.database import DatabaseManager
        db = DatabaseManager()
        db_stats = db.get_database_statistics()
        
        # Get queue status
        queue_status = analysis_queue.get_queue_status()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "system": {
                "metrics": asdict(system_metrics),
                "uptime_seconds": time.time() - application_monitor.start_time,
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "platform": sys.platform
            },
            "application": {
                "metrics": asdict(app_metrics),
                "queue_status": queue_status,
                "configuration": config_summary
            },
            "storage": storage_health,
            "database": db_stats,
            "performance": {
                "avg_response_time_ms": app_metrics.avg_response_time_ms,
                "error_rate_percent": app_metrics.error_rate * 100,
                "requests_per_second": _calculate_requests_per_second(),
                "memory_usage_trend": _get_memory_usage_trend()
            }
        }
        
    except Exception as e:
        logger.error(f"System diagnostics failed: {e}")
        raise HTTPException(status_code=500, detail=f"System diagnostics failed: {str(e)}")

@app.get("/performance", tags=["Monitoring"])
async def get_performance_metrics() -> Dict[str, Any]:
    """
    Get detailed performance metrics
    
    Returns performance statistics including response times,
    throughput, and resource utilization trends.
    """
    try:
        # Get timer statistics
        api_response_stats = metrics_collector.get_timer_stats("api.request_duration")
        analysis_duration_stats = metrics_collector.get_timer_stats("analysis.duration")
        llm_request_stats = metrics_collector.get_timer_stats("llm.request_duration")
        
        # Get recent system metrics
        recent_cpu = metrics_collector.get_recent_metrics("system.cpu_percent", 60)
        recent_memory = metrics_collector.get_recent_metrics("system.memory_percent", 60)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "response_times": {
                "api_requests": api_response_stats,
                "analysis_duration": analysis_duration_stats,
                "llm_requests": llm_request_stats
            },
            "throughput": {
                "requests_per_minute": _calculate_requests_per_minute(),
                "analyses_per_hour": _calculate_analyses_per_hour(),
                "llm_requests_per_minute": _calculate_llm_requests_per_minute()
            },
            "resource_trends": {
                "cpu_usage_trend": _calculate_trend([m.value for m in recent_cpu]),
                "memory_usage_trend": _calculate_trend([m.value for m in recent_memory])
            },
            "efficiency_metrics": {
                "cache_hit_rate": 0.0,  # TODO: Implement cache metrics
                "error_rate": application_monitor.error_count / max(application_monitor.request_count, 1),
                "success_rate": 1.0 - (application_monitor.error_count / max(application_monitor.request_count, 1))
            }
        }
        
    except Exception as e:
        logger.error(f"Performance metrics failed: {e}")
        raise HTTPException(status_code=500, detail=f"Performance metrics failed: {str(e)}")

# Helper functions for monitoring endpoints

def _get_health_recommendations(health_results: Dict[str, Any], active_alerts: List[Dict[str, Any]], 
                              system_metrics) -> List[str]:
    """Generate health recommendations based on current status"""
    recommendations = []
    
    if health_results["overall_status"] != "healthy":
        recommendations.append("Review failed health checks and address underlying issues")
    
    if active_alerts:
        recommendations.append(f"Address {len(active_alerts)} active alerts")
    
    if system_metrics.cpu_percent > 80:
        recommendations.append("High CPU usage detected - consider scaling or optimization")
    
    if system_metrics.memory_percent > 85:
        recommendations.append("High memory usage detected - monitor for memory leaks")
    
    if system_metrics.disk_usage_percent > 90:
        recommendations.append("Low disk space - consider cleanup or expansion")
    
    return recommendations

def _get_alert_severity_breakdown(alerts: List[Dict[str, Any]]) -> Dict[str, int]:
    """Get breakdown of alerts by severity"""
    breakdown = {"critical": 0, "warning": 0, "info": 0}
    
    for alert in alerts:
        severity = alert.get("severity", "info")
        if severity in breakdown:
            breakdown[severity] += 1
    
    return breakdown

def _calculate_requests_per_second() -> float:
    """Calculate current requests per second"""
    recent_requests = metrics_collector.get_recent_metrics("api.requests_total", 1)
    return len(recent_requests) / 60.0  # Convert to per second

def _calculate_requests_per_minute() -> float:
    """Calculate requests per minute"""
    recent_requests = metrics_collector.get_recent_metrics("api.requests_total", 1)
    return float(len(recent_requests))

def _calculate_analyses_per_hour() -> float:
    """Calculate analyses per hour"""
    recent_analyses = metrics_collector.get_recent_metrics("analysis.completed_total", 60)
    return len(recent_analyses)

def _calculate_llm_requests_per_minute() -> float:
    """Calculate LLM requests per minute"""
    recent_llm = metrics_collector.get_recent_metrics("llm.requests_total", 1)
    return float(len(recent_llm))

def _get_memory_usage_trend() -> str:
    """Get memory usage trend"""
    recent_memory = metrics_collector.get_recent_metrics("system.memory_percent", 30)
    if len(recent_memory) < 2:
        return "insufficient_data"
    
    values = [m.value for m in recent_memory]
    trend = _calculate_trend(values)
    return trend

def _calculate_trend(values: List[float]) -> str:
    """Calculate trend from a list of values"""
    if len(values) < 2:
        return "stable"
    
    # Simple trend calculation
    first_half = sum(values[:len(values)//2]) / (len(values)//2)
    second_half = sum(values[len(values)//2:]) / (len(values) - len(values)//2)
    
    diff_percent = ((second_half - first_half) / first_half) * 100 if first_half > 0 else 0
    
    if diff_percent > 10:
        return "increasing"
    elif diff_percent < -10:
        return "decreasing"
    else:
        return "stable"

# Search and Retrieval Endpoints

@app.post("/search_docs", response_model=SearchDocsResponse, tags=["Search and Retrieval"])
async def search_documents(
    request: SearchDocsRequest,
    rag: RAGSystem = Depends(get_rag_system),
    db: DatabaseManager = Depends(get_db_manager)
) -> SearchDocsResponse:
    """
    Search threat modeling documents and code using RAG-based retrieval
    
    Performs semantic search across all threat modeling documents and code snippets,
    with optional filtering by repository and document type.
    """
    logger.info(f"Searching documents with query: '{request.query}' (limit: {request.limit}, offset: {request.offset})")
    
    # Validate query
    if not request.query.strip():
        raise HTTPException(status_code=400, detail="Search query cannot be empty")
    
    if len(request.query) > 1000:
        raise HTTPException(status_code=400, detail="Search query too long (max 1000 characters)")
    
    try:
        # Perform RAG search
        search_results = rag.search_similar_content(
            query=request.query,
            repo_id=request.repo_id,
            top_k=request.limit + request.offset,  # Get more results to handle offset
            content_types=[dt.value for dt in request.doc_types] if request.doc_types else None
        )
        
        # Apply pagination
        paginated_results = search_results[request.offset:request.offset + request.limit]
        
        # Enhance results with additional metadata
        enhanced_results = []
        for result in paginated_results:
            # Get full document metadata if available
            if result.doc_id:
                doc = db.get_threat_doc_by_id(result.doc_id)
                if doc:
                    result.title = doc.title
                    result.doc_type = doc.doc_type
                    # Add code references from the document
                    result.code_references = doc.code_references[:3]  # Limit to first 3
            
            enhanced_results.append(result)
        
        # Log search analytics
        logger.info(f"Search completed: query='{request.query}', results={len(enhanced_results)}, "
                   f"total_found={len(search_results)}")
        
        # Store search analytics (optional - could be expanded)
        await _log_search_analytics(request.query, len(search_results), request.repo_id)
        
        return SearchDocsResponse(
            query=request.query,
            results=enhanced_results,
            total_count=len(search_results),
            limit=request.limit,
            offset=request.offset
        )
        
    except Exception as e:
        logger.error(f"Search failed for query '{request.query}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

@app.get("/search_docs/suggestions", tags=["Search and Retrieval"])
async def get_search_suggestions(
    query: str = Query(description="Partial search query for suggestions"),
    repo_id: Optional[str] = Query(None, description="Filter suggestions by repository"),
    limit: int = Query(default=5, ge=1, le=20, description="Maximum suggestions to return"),
    db: DatabaseManager = Depends(get_db_manager)
) -> Dict[str, Any]:
    """
    Get search suggestions based on existing document content
    
    Returns suggested search terms and popular queries to help users
    discover relevant content.
    """
    logger.info(f"Getting search suggestions for query: '{query}'")
    
    if len(query) < 2:
        return {"suggestions": [], "popular_terms": []}
    
    try:
        suggestions = []
        popular_terms = []
        
        # Get documents for analysis
        if repo_id:
            docs = db.get_threat_docs_by_repo(repo_id)
        else:
            # For global suggestions, we'd need a method to get all docs
            # For now, return empty suggestions for global search
            docs = []
        
        # Extract terms from document titles and content
        all_terms = set()
        for doc in docs:
            # Extract terms from title
            title_terms = doc.title.lower().split()
            all_terms.update(term.strip('.,!?;:') for term in title_terms if len(term) > 2)
            
            # Extract key terms from content (simplified approach)
            content_words = doc.content.lower().split()
            security_terms = [word for word in content_words if any(
                keyword in word for keyword in [
                    'threat', 'security', 'auth', 'encrypt', 'attack', 'vuln',
                    'risk', 'mitigation', 'stride', 'owasp', 'access', 'data'
                ]
            )]
            all_terms.update(term.strip('.,!?;:') for term in security_terms if len(term) > 3)
        
        # Filter suggestions based on query
        query_lower = query.lower()
        matching_terms = [term for term in all_terms if query_lower in term and len(term) > len(query)]
        suggestions = sorted(matching_terms)[:limit]
        
        # Popular security-related terms (static list for now)
        popular_security_terms = [
            "authentication", "authorization", "encryption", "sql injection",
            "cross-site scripting", "csrf", "session management", "input validation",
            "access control", "data protection", "threat modeling", "stride analysis"
        ]
        
        popular_terms = [term for term in popular_security_terms if query_lower in term.lower()][:limit]
        
        return {
            "suggestions": suggestions,
            "popular_terms": popular_terms,
            "query": query
        }
        
    except Exception as e:
        logger.error(f"Failed to get search suggestions: {str(e)}")
        return {"suggestions": [], "popular_terms": [], "error": str(e)}

@app.get("/search_docs/analytics", tags=["Search and Retrieval"])
async def get_search_analytics(
    repo_id: Optional[str] = Query(None, description="Filter analytics by repository"),
    days: int = Query(default=7, ge=1, le=30, description="Number of days to analyze")
) -> Dict[str, Any]:
    """
    Get search analytics and usage statistics
    
    Returns information about popular search queries, search patterns,
    and content discovery metrics.
    """
    logger.info(f"Getting search analytics for repo: {repo_id}, days: {days}")
    
    try:
        # This is a placeholder implementation
        # In a production system, you would store search queries and analyze them
        analytics = {
            "period_days": days,
            "repo_id": repo_id,
            "total_searches": 0,
            "unique_queries": 0,
            "popular_queries": [],
            "search_trends": [],
            "content_discovery": {
                "most_accessed_docs": [],
                "popular_doc_types": {},
                "avg_results_per_query": 0
            },
            "performance_metrics": {
                "avg_response_time_ms": 0,
                "cache_hit_rate": 0.0
            }
        }
        
        return analytics
        
    except Exception as e:
        logger.error(f"Failed to get search analytics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve analytics: {str(e)}")

@app.get("/repos/{repo_id}/search", response_model=SearchDocsResponse, tags=["Search and Retrieval"])
async def search_repository_documents(
    repo_id: str = Path(description="Repository identifier"),
    query: str = Query(description="Search query"),
    doc_types: Optional[List[str]] = Query(None, description="Filter by document types"),
    limit: int = Query(default=10, ge=1, le=100, description="Maximum results to return"),
    offset: int = Query(default=0, ge=0, description="Results offset for pagination"),
    include_code: bool = Query(default=True, description="Include code snippets in search"),
    rag: RAGSystem = Depends(get_rag_system),
    db: DatabaseManager = Depends(get_db_manager)
) -> SearchDocsResponse:
    """
    Search documents within a specific repository
    
    Performs focused search within a single repository's threat modeling
    documents and code snippets.
    """
    logger.info(f"Searching repository {repo_id} with query: '{query}'")
    
    # Verify repository exists
    repo_context = db.get_repo_context(repo_id)
    if not repo_context:
        raise HTTPException(status_code=404, detail=f"Repository {repo_id} not found")
    
    # Create search request
    search_request = SearchDocsRequest(
        query=query,
        repo_id=repo_id,
        doc_types=doc_types,
        limit=limit,
        offset=offset
    )
    
    # Delegate to main search endpoint
    return await search_documents(search_request, rag, db)

@app.get("/docs/{doc_id}/similar", tags=["Search and Retrieval"])
async def get_similar_documents(
    doc_id: str = Path(description="Document identifier"),
    limit: int = Query(default=5, ge=1, le=20, description="Maximum similar documents to return"),
    rag: RAGSystem = Depends(get_rag_system),
    db: DatabaseManager = Depends(get_db_manager)
) -> Dict[str, Any]:
    """
    Find documents similar to a given document
    
    Uses the document's content to find semantically similar documents
    across the same repository or globally.
    """
    logger.info(f"Finding similar documents for doc: {doc_id}")
    
    try:
        # Get the source document
        source_doc = db.get_threat_doc_by_id(doc_id)
        if not source_doc:
            raise HTTPException(status_code=404, detail=f"Document {doc_id} not found")
        
        # Use document content as search query (truncated to avoid token limits)
        search_query = source_doc.content[:500] + "..." if len(source_doc.content) > 500 else source_doc.content
        
        # Search for similar documents
        similar_results = rag.search_similar_content(
            query=search_query,
            repo_id=source_doc.repo_id,  # Search within same repository
            top_k=limit + 1  # +1 to account for the source document itself
        )
        
        # Filter out the source document itself
        filtered_results = [result for result in similar_results if result.doc_id != doc_id][:limit]
        
        return {
            "source_document": {
                "id": source_doc.id,
                "title": source_doc.title,
                "doc_type": source_doc.doc_type.value
            },
            "similar_documents": filtered_results,
            "total_found": len(filtered_results)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to find similar documents for {doc_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to find similar documents: {str(e)}")

# Helper function for search analytics
async def _log_search_analytics(query: str, result_count: int, repo_id: Optional[str] = None):
    """Log search analytics for future analysis"""
    try:
        # In a production system, you would store this in a database or analytics service
        analytics_data = {
            "timestamp": datetime.now().isoformat(),
            "query": query,
            "result_count": result_count,
            "repo_id": repo_id,
            "query_length": len(query),
            "has_results": result_count > 0
        }
        
        # For now, just log it
        logger.info(f"Search analytics: {analytics_data}")
        
    except Exception as e:
        logger.warning(f"Failed to log search analytics: {e}")

if __name__ == "__main__":
    uvicorn.run(
        "api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level="debug" if settings.debug else "info"
    )