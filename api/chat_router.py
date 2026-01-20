"""
Chat API Router for DeepWiki-style conversational interface
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Standardized import system with comprehensive error handling
try:
    from .import_manager import safe_import, get_import_manager
except ImportError:
    from import_manager import safe_import, get_import_manager

# Import required modules using the safe import system
import_manager = get_import_manager()

# Import chat system components
chat_system_result = safe_import("chat_system", package="api")
if chat_system_result.success:
    get_chat_system = getattr(chat_system_result.module, 'get_chat_system', None)
    SecurityChatSystem = getattr(chat_system_result.module, 'SecurityChatSystem', None)
else:
    logger.error(f"Failed to import chat_system: {chat_system_result.error_message}")
    # Create fallback implementations
    class MockSecurityChatSystem:
        def __init__(self):
            logger.warning("Using mock chat system - functionality will be limited")
        
        async def start_chat_session(self, repo_id: str, user_id: str = "default") -> str:
            logger.warning("Mock chat system: start_chat_session called")
            return "mock-session-id"
        
        async def send_message(self, session_id: str, message: str) -> Dict[str, Any]:
            logger.warning("Mock chat system: send_message called")
            return {
                "message": "I apologize, but the chat system is currently unavailable. Please try again later.",
                "session_id": session_id,
                "sources": [],
                "timestamp": datetime.now().isoformat()
            }
        
        async def get_chat_history(self, session_id: str) -> List[Dict[str, Any]]:
            logger.warning("Mock chat system: get_chat_history called")
            return []
        
        def get_session_stats(self, session_id: str) -> Dict[str, Any]:
            logger.warning("Mock chat system: get_session_stats called")
            return {"error": "Chat system unavailable"}
    
    SecurityChatSystem = MockSecurityChatSystem
    _mock_chat_system = MockSecurityChatSystem()
    get_chat_system = lambda: _mock_chat_system

# Import models
models_result = safe_import("models", package="api")
if models_result.success:
    ChatRequest = getattr(models_result.module, 'ChatRequest', None)
    ChatResponse = getattr(models_result.module, 'ChatResponse', None)
    ChatHistoryResponse = getattr(models_result.module, 'ChatHistoryResponse', None)
else:
    logger.error(f"Failed to import models: {models_result.error_message}")
    # Use Pydantic BaseModel as fallback
    from pydantic import BaseModel, Field
    from typing import List, Dict, Any
    
    class ChatRequest(BaseModel):
        repo_id: str = Field(..., description="Repository ID")
        user_id: str = Field(default="default", description="User ID")
    
    class ChatResponse(BaseModel):
        message: str = Field(..., description="AI response")
        session_id: str = Field(..., description="Session ID")
        sources: List[Dict[str, Any]] = Field(default_factory=list)
        timestamp: str = Field(..., description="Response timestamp")
    
    class ChatHistoryResponse(BaseModel):
        session_id: str = Field(..., description="Session ID")
        messages: List[Dict[str, Any]] = Field(..., description="Chat messages")
        repository_name: Optional[str] = Field(None, description="Repository name")

# Log import status
import_stats = import_manager.get_import_stats()
logger.info(f"Chat router import stats: {import_stats}")
if import_stats['success_rate'] < 1.0:
    logger.warning("Some imports failed - chat router may have limited functionality")

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/chat", tags=["chat"])

class StartChatRequest(BaseModel):
    """Request to start a new chat session"""
    repo_id: str = Field(..., description="Repository ID")
    user_id: str = Field(default="default", description="User ID")

class StartChatResponse(BaseModel):
    """Response for starting a chat session"""
    session_id: str = Field(..., description="New session ID")
    welcome_message: str = Field(..., description="Welcome message")
    repository_name: str = Field(..., description="Repository name")

@router.post("/start", response_model=StartChatResponse)
async def start_chat_session(
    request: StartChatRequest,
    chat_system: SecurityChatSystem = Depends(get_chat_system)
):
    """Start a new chat session for a repository"""
    try:
        print(f"🔴 STEP 5: Backend /api/chat/start endpoint called")
        print(f"🔴 STEP 5: request.repo_id = {request.repo_id}")
        print(f"🔴 STEP 5: request.user_id = {request.user_id}")
        
        logger.info(f"Starting chat session for repo: {request.repo_id}")
        
        print(f"🔴 STEP 6: About to call chat_system.start_chat_session()")
        # Start new session
        session_id = await chat_system.start_chat_session(
            repo_id=request.repo_id,
            user_id=request.user_id
        )
        
        print(f"🔴 STEP 6: chat_system.start_chat_session() returned session_id = {session_id}")
        
        # Get the welcome message from chat history
        history = await chat_system.get_chat_history(session_id)
        welcome_message = history[0]["content"] if history else "Welcome to ThreatLens Chat!"
        
        print(f"🔴 STEP 6: welcome_message = {welcome_message}")
        
        # Get session stats for repository name
        stats = chat_system.get_session_stats(session_id)
        repository_name = stats.get("repository_name") if stats else None
        if not repository_name:
            repository_name = request.repo_id or "Unknown Repository"
        
        print(f"🔴 STEP 6: repository_name = {repository_name}")
        
        logger.info(f"Started chat session: {session_id}")
        
        response = StartChatResponse(
            session_id=session_id,
            welcome_message=welcome_message,
            repository_name=repository_name
        )
        
        print(f"🔴 STEP 6: Final response = {response}")
        return response
        
    except Exception as e:
        print(f"🔴 STEP 6: ERROR in start_chat_session: {str(e)}")
        logger.error(f"Failed to start chat session: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start chat session: {str(e)}")

class SendMessageRequest(BaseModel):
    """Request to send a message in a chat session"""
    session_id: str = Field(..., description="Session ID")
    message: str = Field(..., description="User message")

@router.post("/message", response_model=ChatResponse)
async def send_chat_message(
    request: SendMessageRequest,
    chat_system: SecurityChatSystem = Depends(get_chat_system)
):
    """Send a message in a chat session"""
    try:
        if not request.session_id:
            raise HTTPException(status_code=400, detail="Session ID is required")
        
        logger.info(f"Processing message in session: {request.session_id}")
        
        # Send message and get response
        response = await chat_system.send_message(
            session_id=request.session_id,
            message=request.message
        )
        
        return ChatResponse(
            message=response["message"],
            session_id=response["session_id"],
            sources=response["sources"],
            timestamp=response["timestamp"]
        )
        
    except ValueError as e:
        logger.error(f"Chat session error: {str(e)}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to process chat message: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to process message: {str(e)}")

@router.get("/history/{session_id}", response_model=ChatHistoryResponse)
async def get_chat_history(
    session_id: str,
    chat_system: SecurityChatSystem = Depends(get_chat_system)
):
    """Get chat history for a session"""
    try:
        logger.info(f"Getting chat history for session: {session_id}")
        
        # Get chat history
        messages = await chat_system.get_chat_history(session_id)
        
        # Get session stats
        stats = chat_system.get_session_stats(session_id)
        
        return ChatHistoryResponse(
            session_id=session_id,
            messages=messages,
            repository_name=stats.get("repository_name")
        )
        
    except Exception as e:
        logger.error(f"Failed to get chat history: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get chat history: {str(e)}")

@router.get("/sessions/{repo_id}")
async def get_repo_chat_sessions(
    repo_id: str,
    chat_system: SecurityChatSystem = Depends(get_chat_system)
):
    """Get all chat sessions for a repository"""
    try:
        # For now, return active sessions (can be enhanced to store in DB)
        active_sessions = []
        
        for session_id, session in chat_system.active_sessions.items():
            if session.repo_id == repo_id:
                stats = chat_system.get_session_stats(session_id)
                active_sessions.append(stats)
        
        return {
            "repo_id": repo_id,
            "sessions": active_sessions,
            "total_sessions": len(active_sessions)
        }
        
    except Exception as e:
        logger.error(f"Failed to get repo sessions: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get sessions: {str(e)}")

@router.delete("/session/{session_id}")
async def delete_chat_session(
    session_id: str,
    chat_system: SecurityChatSystem = Depends(get_chat_system)
):
    """Delete a chat session"""
    try:
        if session_id in chat_system.active_sessions:
            del chat_system.active_sessions[session_id]
            logger.info(f"Deleted chat session: {session_id}")
            return {"message": "Session deleted successfully"}
        else:
            raise HTTPException(status_code=404, detail="Session not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete session: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete session: {str(e)}")

@router.get("/stats/{session_id}")
async def get_session_stats(
    session_id: str,
    chat_system: SecurityChatSystem = Depends(get_chat_system)
):
    """Get statistics for a chat session"""
    try:
        stats = chat_system.get_session_stats(session_id)
        
        if not stats:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return stats
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get session stats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")