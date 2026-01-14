"""
ThreatLens - AI-Powered Security Documentation Platform
FastAPI main application with comprehensive debugging
"""

import logging
import traceback
import uuid
import sqlite3
import json
from datetime import datetime
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Core imports
from .config import settings
from .database import init_database, get_db_session
from .models import SecurityModel, UserWiki
from .repo_ingest import RepoIngestor
from .security_wiki_generator import SecurityWikiGenerator
from .monitoring import HealthChecker

# Routers
from .cost_router import router as cost_router

# Debug logging setup
DEBUG_ANALYSIS = logging.getLogger('DEBUG_ANALYSIS')
DEBUG_ANALYSIS.setLevel(logging.DEBUG)
if not DEBUG_ANALYSIS.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - DEBUG_ANALYSIS - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    DEBUG_ANALYSIS.addHandler(handler)

logger = logging.getLogger(__name__)

# Global components
health_checker = None
security_wiki_generator = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    global health_checker, security_wiki_generator
    
    try:
        DEBUG_ANALYSIS.info("STARTUP: Initializing ThreatLens components")
        
        # Initialize database
        DEBUG_ANALYSIS.info("STARTUP: Initializing database")
        init_database()
        DEBUG_ANALYSIS.info("STARTUP: Database initialized")
        
        # Initialize health checker
        DEBUG_ANALYSIS.info("STARTUP: Initializing health checker")
        health_checker = HealthChecker()
        DEBUG_ANALYSIS.info("STARTUP: Health checker initialized")
        
        # Initialize security wiki generator
        DEBUG_ANALYSIS.info("STARTUP: Initializing security wiki generator")
        DEBUG_ANALYSIS.info("STEP 4: Initializing SecurityWikiGenerator")
        security_wiki_generator = SecurityWikiGenerator(settings)
        DEBUG_ANALYSIS.info("STEP 4: SecurityWikiGenerator initialized")
        DEBUG_ANALYSIS.info("STARTUP: Security wiki generator initialized")
        
        DEBUG_ANALYSIS.info("STARTUP: All components initialized successfully")
        logger.info("ThreatLens startup completed successfully")
        
        yield
        
    except Exception as e:
        DEBUG_ANALYSIS.error(f"STARTUP FAILED: {str(e)}")
        DEBUG_ANALYSIS.error(f"Traceback: {traceback.format_exc()}")
        logger.error(f"Startup failed: {e}")
        raise
    finally:
        DEBUG_ANALYSIS.info("SHUTDOWN: ThreatLens shutting down")
        logger.info("ThreatLens shutdown completed")


# Create FastAPI app
app = FastAPI(
    title="ThreatLens API",
    description="AI-Powered Security Documentation Platform",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(cost_router)


# Request/Response models
class AnalyzeRepoRequest(BaseModel):
    repo_url: str = Field(..., description="Repository URL to analyze")
    analysis_options: Optional[Dict[str, Any]] = Field(default=None, description="Analysis options")


class AnalysisResponse(BaseModel):
    status: str
    analysis_id: str
    repo_id: str
    user_wiki_id: str
    message: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: str
    database_status: str
    llm_config_valid: bool
    storage_paths_exist: bool


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """System health check endpoint"""
    try:
        DEBUG_ANALYSIS.info("HEALTH_CHECK: Starting health check")
        
        # Check database
        try:
            db_session = next(get_db_session())
            db_status = "healthy"
            db_session.close()
        except Exception:
            db_status = "error"
        
        # Check LLM configuration
        llm_config_valid = settings.validate_llm_config()
        
        # Check storage paths
        import os
        storage_paths_exist = all([
            os.path.exists(settings.storage_base_path),
            os.path.exists(settings.repos_storage_path),
            os.path.exists(settings.docs_storage_path)
        ])
        
        DEBUG_ANALYSIS.info("HEALTH_CHECK: Health check completed")
        
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
        
    except Exception as e:
        DEBUG_ANALYSIS.error(f"HEALTH_CHECK FAILED: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


@app.post("/analyze_repo", response_model=AnalysisResponse)
async def analyze_repo(
    request: AnalyzeRepoRequest,
    background_tasks: BackgroundTasks
):
    """Analyze repository and generate security wiki"""
    
    try:
        DEBUG_ANALYSIS.info("STEP 1: Starting repository analysis")
        
        # Generate IDs
        analysis_id = str(uuid.uuid4())
        repo_id = str(uuid.uuid4())
        
        # Use consistent user ID system (compatible with frontend)
        # For Phase 1 MVP, we'll use a default user ID that matches frontend expectations
        user_id = "user_52122388"  # Fixed user ID for Phase 1 MVP
        
        DEBUG_ANALYSIS.info("STEP 1: Starting repository analysis")
        logger.info(f"Starting repository analysis - Analysis ID: {analysis_id}, Repo ID: {repo_id}, User ID: {user_id}")
        
        # Create user wiki entry
        user_wiki = UserWiki(
            id=str(uuid.uuid4()),
            user_id=user_id,
            repo_id=repo_id,
            repository_url=request.repo_url,
            repository_name=request.repo_url.split('/')[-1].replace('.git', ''),  # Extract repo name from URL
            analysis_status="analyzing",
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        # Save to database using database manager
        from .database import _db_manager
        if not _db_manager.save_user_wiki(user_wiki):
            raise HTTPException(status_code=500, detail="Failed to save user wiki entry")
        logger.info(f"Created user wiki entry for user {user_id}: {user_wiki.id}")
        
        DEBUG_ANALYSIS.info("STEP 2: Initializing RepoIngest")
        DEBUG_ANALYSIS.info("STEP 2: Initializing RepoIngest")
        repo_ingest = RepoIngestor(settings)
        DEBUG_ANALYSIS.info("STEP 2: RepoIngest initialized")
        DEBUG_ANALYSIS.info("STEP 2: RepoIngest initialized")
        
        DEBUG_ANALYSIS.info("STEP 3: Starting repository ingestion")
        DEBUG_ANALYSIS.info("STEP 3: Starting repository ingestion")
        
        # Clone the repository
        repo_context = repo_ingest.clone_repository(request.repo_url)
        DEBUG_ANALYSIS.info("STEP 3a: Repository cloned successfully")
        
        # Analyze repository structure
        structure_analysis = repo_ingest.analyze_structure(repo_context)
        DEBUG_ANALYSIS.info("STEP 3b: Repository structure analyzed")
        
        # Create security model from repo context and structure analysis
        repo_name = request.repo_url.split('/')[-1].replace('.git', '')
        security_model = SecurityModel(
            id=repo_id,
            name=repo_name,
            description=f"Security model for {request.repo_url}",
            repo_id=repo_id,
            components=[],  # Will be populated by structure analysis
            flows=[],       # Will be populated by analysis
            created_at=datetime.now()
        )
        
        DEBUG_ANALYSIS.info("STEP 3: Repository ingestion completed")
        DEBUG_ANALYSIS.info("STEP 3: Repository ingestion completed")
        if not security_model:
            DEBUG_ANALYSIS.error("STEP 3: Repository ingestion failed - no security model")
            DEBUG_ANALYSIS.error("STEP 3: Repository ingestion failed - no security model")
            raise HTTPException(status_code=500, detail="Failed to analyze repository")
        
        DEBUG_ANALYSIS.info("STEP 4: Initializing SecurityWikiGenerator")
        DEBUG_ANALYSIS.info("STEP 4: Initializing SecurityWikiGenerator")
        wiki_generator = SecurityWikiGenerator(settings)
        DEBUG_ANALYSIS.info("STEP 4: SecurityWikiGenerator initialized")
        DEBUG_ANALYSIS.info("STEP 4: SecurityWikiGenerator initialized")
        
        DEBUG_ANALYSIS.info("STEP 5: Starting wiki generation")
        DEBUG_ANALYSIS.info("STEP 5: Starting wiki generation")
        wiki_content = await wiki_generator.generate_comprehensive_security_wiki(security_model)
        
        DEBUG_ANALYSIS.info("STEP 6: Saving wiki content to database")
        # Save the generated wiki content to database
        from .wiki_storage import WikiStorage
        from .storage_manager import StorageManager
        
        storage_manager = StorageManager()
        wiki_storage = WikiStorage(storage_manager)
        
        if not wiki_storage.save_wiki(wiki_content):
            DEBUG_ANALYSIS.error("STEP 6: Failed to save wiki content")
            raise HTTPException(status_code=500, detail="Failed to save wiki content")
        
        DEBUG_ANALYSIS.info("STEP 6: Wiki content saved successfully")
        
        # Update user wiki with the generated wiki ID
        user_wiki.wiki_id = wiki_content.id
        user_wiki.analysis_status = "completed"
        user_wiki.updated_at = datetime.now()
        _db_manager.save_user_wiki(user_wiki)
        
        DEBUG_ANALYSIS.info("STEP 5: Wiki generation completed")
        DEBUG_ANALYSIS.info("ANALYSIS COMPLETED SUCCESSFULLY")
        
        return AnalysisResponse(
            status="success",
            analysis_id=analysis_id,
            repo_id=repo_id,
            user_wiki_id=user_wiki.id,
            message="Repository analysis completed successfully"
        )
        
    except Exception as e:
        DEBUG_ANALYSIS.error(f"ANALYSIS FAILED: {str(e)}")
        DEBUG_ANALYSIS.error(f"Traceback: {traceback.format_exc()}")
        logger.error(f"Repository analysis failed: {e}")
        
        # Update user wiki status to failed if it exists
        try:
            if 'user_wiki' in locals():
                user_wiki.status = "failed"
                user_wiki.updated_at = datetime.now()
                db_session.commit()
        except:
            pass
        
        raise HTTPException(status_code=500, detail=f"Repository analysis failed: {str(e)}")


# Test endpoint for debugging
@app.post("/test-repo-analysis")
async def test_repo_analysis(request: AnalyzeRepoRequest):
    """Test endpoint to debug repository analysis issues"""
    try:
        DEBUG_ANALYSIS.info("TEST: Starting test analysis")
        
        # Test 1: Check if RepoIngestor can be initialized
        try:
            repo_ingest = RepoIngestor(settings)
            DEBUG_ANALYSIS.info("TEST: RepoIngestor initialized successfully")
        except Exception as e:
            DEBUG_ANALYSIS.error(f"TEST: RepoIngestor initialization failed: {e}")
            return {"error": f"RepoIngestor init failed: {str(e)}", "step": "initialization"}
        
        # Test 2: Try to clone repository (this is likely where it fails)
        try:
            repo_context = repo_ingest.clone_repository(request.repo_url)
            DEBUG_ANALYSIS.info("TEST: Repository cloned successfully")
        except Exception as e:
            DEBUG_ANALYSIS.error(f"TEST: Repository cloning failed: {e}")
            return {"error": f"Repository cloning failed: {str(e)}", "step": "cloning"}
        
        # Test 3: Try structure analysis
        try:
            structure_analysis = repo_ingest.analyze_structure(repo_context)
            DEBUG_ANALYSIS.info("TEST: Structure analysis completed")
        except Exception as e:
            DEBUG_ANALYSIS.error(f"TEST: Structure analysis failed: {e}")
            return {"error": f"Structure analysis failed: {str(e)}", "step": "structure_analysis"}
        
        # Test 4: Try SecurityModel creation
        try:
            repo_name = request.repo_url.split('/')[-1].replace('.git', '')
            security_model = SecurityModel(
                id=str(uuid.uuid4()),
                name=repo_name,
                description=f"Security model for {request.repo_url}",
                repo_id=str(uuid.uuid4()),
                components=[],
                flows=[],
                created_at=datetime.now()
            )
            DEBUG_ANALYSIS.info("TEST: SecurityModel created successfully")
        except Exception as e:
            DEBUG_ANALYSIS.error(f"TEST: SecurityModel creation failed: {e}")
            return {"error": f"SecurityModel creation failed: {str(e)}", "step": "security_model"}
        
        return {
            "status": "success", 
            "message": "All components working",
            "repo_context": {
                "repo_id": repo_context.repo_id,
                "local_path": repo_context.local_path,
                "primary_languages": repo_context.primary_languages
            }
        }
        
    except Exception as e:
        DEBUG_ANALYSIS.error(f"TEST: Unexpected error: {e}")
        return {"error": f"Unexpected error: {str(e)}", "step": "unknown"}


# User Wiki Management Endpoints
@app.get("/api/user-wikis/{user_id}")
async def get_user_wikis(user_id: str):
    """Get all wikis for a user"""
    try:
        DEBUG_ANALYSIS.info(f"Getting user wikis for user: {user_id}")
        
        from .database import _db_manager
        user_wikis = _db_manager.get_user_wikis(user_id)
        
        # Convert to dict format expected by frontend
        wikis_data = []
        for wiki in user_wikis:
            wikis_data.append({
                "id": wiki.id,
                "user_id": wiki.user_id,
                "repo_id": wiki.repo_id,
                "repository_url": wiki.repository_url,
                "repository_name": wiki.repository_name,
                "wiki_id": wiki.wiki_id,
                "analysis_status": wiki.analysis_status,
                "created_at": wiki.created_at.isoformat() if wiki.created_at else None,
                "updated_at": wiki.updated_at.isoformat() if wiki.updated_at else None,
                "metadata": wiki.metadata
            })
        
        DEBUG_ANALYSIS.info(f"Found {len(wikis_data)} wikis for user {user_id}")
        return {"wikis": wikis_data}
        
    except Exception as e:
        DEBUG_ANALYSIS.error(f"Failed to get user wikis: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get user wikis: {str(e)}")


@app.get("/api/wiki/{wiki_id}")
async def get_wiki_by_id(wiki_id: str):
    """Get a specific wiki by ID"""
    try:
        DEBUG_ANALYSIS.info(f"Getting wiki: {wiki_id}")
        
        from .database import _db_manager
        
        # Try to find the wiki (we'll search through all users for now)
        # In a production system, you'd want to include user authentication
        wiki = None
        
        # Get all users and search for the wiki
        cursor = _db_manager.conn.cursor()
        cursor.execute("SELECT user_id FROM user_wikis WHERE id = ?", (wiki_id,))
        result = cursor.fetchone()
        
        if result:
            user_id = result[0]
            wiki = _db_manager.get_user_wiki(user_id, wiki_id)
        
        if not wiki:
            raise HTTPException(status_code=404, detail="Wiki not found")
        
        # Convert to dict format
        wiki_data = {
            "id": wiki.id,
            "user_id": wiki.user_id,
            "repository_url": wiki.repository_url,
            "repository_name": wiki.repository_name,
            "analysis_type": wiki.analysis_type,
            "wiki_content": wiki.wiki_content,
            "created_at": wiki.created_at.isoformat() if wiki.created_at else None,
            "updated_at": wiki.updated_at.isoformat() if wiki.updated_at else None,
            "metadata": wiki.metadata
        }
        
        return {"wiki": wiki_data}
        
    except HTTPException:
        raise
    except Exception as e:
        DEBUG_ANALYSIS.error(f"Failed to get wiki: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get wiki: {str(e)}")


@app.get("/wiki/{repo_id}")
async def get_wiki_by_repo_id(repo_id: str):
    """Get a wiki by repository ID (for frontend compatibility)"""
    try:
        DEBUG_ANALYSIS.info(f"Getting wiki by repo_id: {repo_id}")
        
        from .database import _db_manager
        
        # Find the wiki by repo_id
        with sqlite3.connect(_db_manager.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT uw.*, sw.sections as wiki_content
                FROM user_wikis uw
                LEFT JOIN security_wikis sw ON uw.wiki_id = sw.id
                WHERE uw.repo_id = ?
                ORDER BY uw.created_at DESC
                LIMIT 1
            """, (repo_id,))
            
            row = cursor.fetchone()
            
            if not row:
                raise HTTPException(status_code=404, detail="Wiki not found")
            
            # Convert to dict format expected by frontend
            # Parse the wiki_content (sections) if it exists
            sections_data = {}
            if row['wiki_content']:
                try:
                    # Try to parse as JSON first
                    sections_data = json.loads(row['wiki_content'])
                except (json.JSONDecodeError, TypeError):
                    # If not JSON, create a default section with the content
                    sections_data = {
                        "overview": {
                            "id": "overview",
                            "title": "Security Overview",
                            "content": row['wiki_content'],
                            "subsections": [],
                            "cross_references": [],
                            "owasp_mappings": [],
                            "code_references": [],
                            "security_findings": [],
                            "recommendations": []
                        }
                    }
            else:
                # Create default content if no wiki content exists
                sections_data = {
                    "overview": {
                        "id": "overview", 
                        "title": "Security Overview",
                        "content": f"# {row['repository_name']} Security Wiki\n\nThis is a security analysis for the {row['repository_name']} repository.\n\n## Analysis Status\nStatus: {row['analysis_status']}\n\n## Repository Information\n- URL: {row['repository_url']}\n- Created: {row['created_at']}\n\nThis wiki will be populated with security findings and recommendations as the analysis progresses.",
                        "subsections": [],
                        "cross_references": [],
                        "owasp_mappings": [],
                        "code_references": [],
                        "security_findings": [],
                        "recommendations": []
                    }
                }
            
            wiki_data = {
                "id": row['wiki_id'] or row['id'],
                "repo_id": row['repo_id'],
                "title": f"{row['repository_name']} Security Wiki",
                "sections": sections_data,
                "cross_references": {},
                "search_index": {},
                "metadata": json.loads(row['metadata']) if row['metadata'] else {},
                "created_at": row['created_at'],
                "updated_at": row['updated_at'] or row['created_at']
            }
            
            DEBUG_ANALYSIS.info(f"Found wiki for repo {repo_id}: {row['repository_name']}")
            return wiki_data
        
    except HTTPException:
        raise
    except Exception as e:
        DEBUG_ANALYSIS.error(f"Failed to get wiki by repo_id: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get wiki by repo_id: {str(e)}")


@app.delete("/api/user-wikis/{user_id}/{wiki_id}")
async def delete_user_wiki(user_id: str, wiki_id: str):
    """Delete a user wiki"""
    try:
        DEBUG_ANALYSIS.info(f"Deleting wiki {wiki_id} for user {user_id}")
        
        from .database import _db_manager
        success = _db_manager.delete_user_wiki(user_id, wiki_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Wiki not found")
        
        DEBUG_ANALYSIS.info(f"Successfully deleted wiki {wiki_id}")
        return {"message": "Wiki deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        DEBUG_ANALYSIS.error(f"Failed to delete user wiki: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete user wiki: {str(e)}")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "ThreatLens API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)