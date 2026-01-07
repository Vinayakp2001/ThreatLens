"""
FastAPI main application for ThreatLens backend
Migrated and enhanced from api/main.py with new backend structure.
"""
import logging
import time
import uuid
import sys
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional, List
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request, Depends, Query, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
import uvicorn

from ..config.settings import settings, config_manager
from ..database.manager import get_database_manager
from ..services.llm_client import get_llm_manager
from ..services.storage_manager import get_storage_manager
from ..main import ThreatLensBackend

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global backend instance
backend = ThreatLensBackend()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("Starting ThreatLens backend API")
    
    # Initialize services
    try:
        db_manager = get_database_manager()
        llm_manager = get_llm_manager()
        storage_manager = get_storage_manager()
        
        logger.info("All services initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down ThreatLens backend API")
    try:
        # Cleanup services
        if hasattr(llm_manager, 'close'):
            await llm_manager.close()
        
        logger.info("Services cleaned up successfully")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")


# Create FastAPI app
app = FastAPI(
    title="ThreatLens Backend API",
    description="Advanced threat modeling and security documentation generation API",
    version="2.0.0",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if not settings.debug:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", settings.api_host]
    )


# Request/Response Models
class AnalyzeRepositoryRequest(BaseModel):
    """Request model for repository analysis"""
    repo_url: Optional[str] = Field(None, description="Repository URL")
    repo_path: Optional[str] = Field(None, description="Local repository path")
    analysis_type: str = Field("full", description="Type of analysis to perform")
    include_documentation: bool = Field(True, description="Generate documentation")


class AnalyzePRRequest(BaseModel):
    """Request model for PR analysis"""
    pr_url: str = Field(..., description="Pull request URL")
    repo_path: Optional[str] = Field(None, description="Local repository path")


class GenerateDocsRequest(BaseModel):
    """Request model for documentation generation"""
    repo_path: str = Field(..., description="Repository path")
    doc_types: Optional[List[str]] = Field(None, description="Document types to generate")
    output_dir: Optional[str] = Field(None, description="Output directory")
    technology_stack: Optional[List[str]] = Field(None, description="Technology stack")


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: datetime
    version: str
    services: Dict[str, str]


# API Routes
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    services = {}
    
    try:
        # Check database
        db_manager = get_database_manager()
        db_stats = db_manager.get_database_stats()
        services["database"] = "healthy" if "error" not in db_stats else "unhealthy"
    except Exception:
        services["database"] = "unhealthy"
    
    try:
        # Check LLM service
        llm_manager = get_llm_manager()
        services["llm"] = "healthy" if llm_manager.validate_configuration() else "unhealthy"
    except Exception:
        services["llm"] = "unhealthy"
    
    try:
        # Check storage
        storage_manager = get_storage_manager()
        services["storage"] = "healthy"
    except Exception:
        services["storage"] = "unhealthy"
    
    overall_status = "healthy" if all(status == "healthy" for status in services.values()) else "degraded"
    
    return HealthResponse(
        status=overall_status,
        timestamp=datetime.utcnow(),
        version="2.0.0",
        services=services
    )


@app.post("/api/v1/analyze/repository")
async def analyze_repository(request: AnalyzeRepositoryRequest):
    """Analyze a repository for security threats"""
    try:
        if not request.repo_url and not request.repo_path:
            raise HTTPException(status_code=400, detail="Either repo_url or repo_path must be provided")
        
        # Use the backend to generate threat model
        result = await backend.generate_threat_model(
            repo_path=request.repo_path or request.repo_url,
            output_format="json"
        )
        
        # Generate documentation if requested
        if request.include_documentation:
            docs = await backend.generate_repository_documentation(
                repo_path=request.repo_path or request.repo_url
            )
            result["documentation_files"] = docs
        
        return result
        
    except Exception as e:
        logger.error(f"Repository analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/v1/analyze/pr")
async def analyze_pr(request: AnalyzePRRequest):
    """Analyze a pull request for security implications"""
    try:
        result = await backend.analyze_pr(
            pr_url=request.pr_url,
            repo_path=request.repo_path
        )
        
        return result
        
    except Exception as e:
        logger.error(f"PR analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"PR analysis failed: {str(e)}")


@app.post("/api/v1/generate/docs")
async def generate_documentation(request: GenerateDocsRequest):
    """Generate security documentation for a repository"""
    try:
        result = await backend.generate_repository_documentation(
            repo_path=request.repo_path,
            output_dir=request.output_dir,
            technology_stack=request.technology_stack
        )
        
        return {
            "status": "success",
            "generated_files": result,
            "message": f"Generated {len(result)} documentation files"
        }
        
    except Exception as e:
        logger.error(f"Documentation generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Documentation generation failed: {str(e)}")


@app.get("/api/v1/config")
async def get_configuration():
    """Get current configuration summary"""
    try:
        config_summary = config_manager.get_config_summary()
        return config_summary
    except Exception as e:
        logger.error(f"Failed to get configuration: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve configuration")


@app.get("/api/v1/stats")
async def get_system_stats():
    """Get system statistics"""
    try:
        db_manager = get_database_manager()
        storage_manager = get_storage_manager()
        
        stats = {
            "database": db_manager.get_database_stats(),
            "storage": {
                storage_type.value: storage_manager.get_storage_stats(storage_type)
                for storage_type in storage_manager.storage_paths.keys()
            },
            "system": {
                "uptime": time.time(),
                "version": "2.0.0"
            }
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"Failed to get system stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system statistics")


# Error handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors"""
    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "details": exc.errors(),
            "message": "Request validation failed"
        }
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTP Error",
            "message": exc.detail,
            "status_code": exc.status_code
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "type": type(exc).__name__
        }
    )


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "ThreatLens Backend API",
        "version": "2.0.0",
        "description": "Advanced threat modeling and security documentation generation",
        "endpoints": {
            "health": "/health",
            "analyze_repository": "/api/v1/analyze/repository",
            "analyze_pr": "/api/v1/analyze/pr",
            "generate_docs": "/api/v1/generate/docs",
            "config": "/api/v1/config",
            "stats": "/api/v1/stats"
        }
    }


if __name__ == "__main__":
    uvicorn.run(
        "backend.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.value.lower()
    )