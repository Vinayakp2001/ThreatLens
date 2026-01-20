"""
Service Degradation Manager for Chat System
Provides graceful fallbacks when services are unavailable
"""

import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import asyncio
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ServiceStatus(Enum):
    """Service status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"

@dataclass
class ServiceHealth:
    """Service health information"""
    service_name: str
    status: ServiceStatus
    last_check: datetime
    error_count: int = 0
    last_error: Optional[str] = None
    fallback_available: bool = False

class ServiceDegradationManager:
    """Manages service health and provides fallback mechanisms"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.service_health: Dict[str, ServiceHealth] = {}
        self.fallback_handlers: Dict[str, Callable] = {}
        self.health_check_interval = 300  # 5 minutes
        
        # Initialize service health tracking
        self._initialize_services()
    
    def _initialize_services(self):
        """Initialize service health tracking"""
        services = [
            "rag_system",
            "llm_service", 
            "database",
            "embeddings",
            "vector_store"
        ]
        
        for service in services:
            self.service_health[service] = ServiceHealth(
                service_name=service,
                status=ServiceStatus.UNKNOWN,
                last_check=datetime.now(),
                fallback_available=True
            )
    
    def register_fallback_handler(self, service_name: str, handler: Callable):
        """Register a fallback handler for a service"""
        self.fallback_handlers[service_name] = handler
        if service_name in self.service_health:
            self.service_health[service_name].fallback_available = True
        self.logger.info(f"Registered fallback handler for {service_name}")
    
    def update_service_health(self, service_name: str, status: ServiceStatus, error: Optional[str] = None):
        """Update service health status"""
        if service_name not in self.service_health:
            self.service_health[service_name] = ServiceHealth(
                service_name=service_name,
                status=status,
                last_check=datetime.now()
            )
        else:
            health = self.service_health[service_name]
            health.status = status
            health.last_check = datetime.now()
            
            if error:
                health.error_count += 1
                health.last_error = error
            elif status == ServiceStatus.HEALTHY:
                health.error_count = 0
                health.last_error = None
        
        self.logger.info(f"Service {service_name} status updated to {status.value}")
    
    def is_service_available(self, service_name: str) -> bool:
        """Check if a service is available"""
        if service_name not in self.service_health:
            return False
        
        health = self.service_health[service_name]
        return health.status in [ServiceStatus.HEALTHY, ServiceStatus.DEGRADED]
    
    def get_service_status(self, service_name: str) -> ServiceStatus:
        """Get current service status"""
        if service_name not in self.service_health:
            return ServiceStatus.UNKNOWN
        
        return self.service_health[service_name].status
    
    async def execute_with_fallback(
        self, 
        service_name: str, 
        primary_operation: Callable,
        fallback_data: Optional[Dict[str, Any]] = None,
        *args, 
        **kwargs
    ) -> Dict[str, Any]:
        """Execute operation with fallback if service is unavailable"""
        
        try:
            # Check service health
            if not self.is_service_available(service_name):
                self.logger.warning(f"Service {service_name} is unavailable, using fallback")
                return await self._execute_fallback(service_name, fallback_data, *args, **kwargs)
            
            # Try primary operation
            result = await primary_operation(*args, **kwargs)
            
            # Update service health on success
            self.update_service_health(service_name, ServiceStatus.HEALTHY)
            
            return {
                "success": True,
                "result": result,
                "source": "primary",
                "service": service_name
            }
            
        except Exception as e:
            # Update service health on failure
            self.update_service_health(service_name, ServiceStatus.UNAVAILABLE, str(e))
            
            self.logger.error(f"Primary operation failed for {service_name}: {e}")
            
            # Try fallback
            return await self._execute_fallback(service_name, fallback_data, *args, **kwargs)
    
    async def _execute_fallback(
        self, 
        service_name: str, 
        fallback_data: Optional[Dict[str, Any]] = None,
        *args, 
        **kwargs
    ) -> Dict[str, Any]:
        """Execute fallback operation"""
        
        # Check if fallback handler is registered
        if service_name in self.fallback_handlers:
            try:
                fallback_result = await self.fallback_handlers[service_name](fallback_data, *args, **kwargs)
                
                return {
                    "success": True,
                    "result": fallback_result,
                    "source": "fallback",
                    "service": service_name,
                    "message": f"Using fallback for {service_name}"
                }
                
            except Exception as e:
                self.logger.error(f"Fallback operation failed for {service_name}: {e}")
        
        # Return default fallback response
        return {
            "success": False,
            "result": self._get_default_fallback_response(service_name),
            "source": "default_fallback",
            "service": service_name,
            "message": f"Service {service_name} is currently unavailable"
        }
    
    def _get_default_fallback_response(self, service_name: str) -> Dict[str, Any]:
        """Get default fallback response for a service"""
        
        fallback_responses = {
            "rag_system": {
                "results": [],
                "message": "Search functionality is temporarily unavailable. Please try general security questions."
            },
            "llm_service": {
                "response": "I apologize, but I'm currently unable to generate a detailed response. The AI service is temporarily unavailable. Please try again later or contact support.",
                "fallback": True
            },
            "database": {
                "data": None,
                "message": "Database is temporarily unavailable. Some features may be limited."
            },
            "embeddings": {
                "embeddings": [],
                "message": "Embedding service is unavailable. Search functionality may be limited."
            },
            "vector_store": {
                "results": [],
                "message": "Vector search is temporarily unavailable."
            }
        }
        
        return fallback_responses.get(service_name, {
            "message": f"Service {service_name} is temporarily unavailable"
        })
    
    def get_system_health_summary(self) -> Dict[str, Any]:
        """Get overall system health summary"""
        
        total_services = len(self.service_health)
        healthy_services = sum(1 for h in self.service_health.values() if h.status == ServiceStatus.HEALTHY)
        degraded_services = sum(1 for h in self.service_health.values() if h.status == ServiceStatus.DEGRADED)
        unavailable_services = sum(1 for h in self.service_health.values() if h.status == ServiceStatus.UNAVAILABLE)
        
        overall_status = ServiceStatus.HEALTHY
        if unavailable_services > 0:
            overall_status = ServiceStatus.DEGRADED if unavailable_services < total_services else ServiceStatus.UNAVAILABLE
        elif degraded_services > 0:
            overall_status = ServiceStatus.DEGRADED
        
        return {
            "overall_status": overall_status.value,
            "total_services": total_services,
            "healthy_services": healthy_services,
            "degraded_services": degraded_services,
            "unavailable_services": unavailable_services,
            "services": {
                name: {
                    "status": health.status.value,
                    "last_check": health.last_check.isoformat(),
                    "error_count": health.error_count,
                    "fallback_available": health.fallback_available
                }
                for name, health in self.service_health.items()
            },
            "timestamp": datetime.now().isoformat()
        }
    
    def create_user_friendly_error_message(self, service_name: str, operation: str) -> str:
        """Create user-friendly error message for service failures"""
        
        messages = {
            "rag_system": f"I'm having trouble searching through the security documentation right now. You can still ask general security questions, and I'll do my best to help based on my knowledge.",
            "llm_service": f"I'm experiencing some technical difficulties generating responses right now. Please try again in a few moments, or contact support if the issue persists.",
            "database": f"I'm having trouble accessing the repository information right now. Some features may be limited until this is resolved.",
            "embeddings": f"The search functionality is temporarily limited. I can still help with general security questions.",
            "vector_store": f"Document search is currently unavailable, but I can still provide general security guidance."
        }
        
        default_message = f"I'm experiencing some technical difficulties with the {service_name} service. Please try again later."
        
        return messages.get(service_name, default_message)


# Fallback handlers for different services
class ChatSystemFallbacks:
    """Fallback implementations for chat system services"""
    
    @staticmethod
    async def rag_fallback(fallback_data: Optional[Dict[str, Any]] = None, *args, **kwargs) -> Dict[str, Any]:
        """Fallback for RAG system when unavailable"""
        return {
            "results": [],
            "total_results": 0,
            "message": "Search functionality is temporarily unavailable",
            "fallback_used": True
        }
    
    @staticmethod
    async def llm_fallback(fallback_data: Optional[Dict[str, Any]] = None, *args, **kwargs) -> str:
        """Fallback for LLM service when unavailable"""
        
        # Extract context from fallback_data if available
        repo_name = "your repository"
        if fallback_data and "repo_context" in fallback_data:
            repo_name = fallback_data["repo_context"].get("repository_name", repo_name)
        
        fallback_responses = [
            f"I apologize, but I'm currently experiencing technical difficulties generating a detailed response about {repo_name}.",
            "Here are some general security recommendations while I work to resolve this issue:",
            "• Regularly update dependencies to patch known vulnerabilities",
            "• Implement proper input validation and sanitization", 
            "• Use secure authentication and authorization mechanisms",
            "• Follow the principle of least privilege for access controls",
            "• Regularly review and audit your security configurations",
            "",
            "Please try your question again in a few moments, or contact support if this issue persists."
        ]
        
        return "\n".join(fallback_responses)
    
    @staticmethod
    async def database_fallback(fallback_data: Optional[Dict[str, Any]] = None, *args, **kwargs) -> Dict[str, Any]:
        """Fallback for database when unavailable"""
        return {
            "repository_name": "Unknown Repository",
            "has_wiki": False,
            "sections": [],
            "section_count": 0,
            "content_length": 0,
            "fallback_created": True,
            "error_reason": "Database temporarily unavailable"
        }
    
    @staticmethod
    async def session_validation_fallback(fallback_data: Optional[Dict[str, Any]] = None, *args, **kwargs) -> bool:
        """Fallback for session validation"""
        # In degraded mode, allow sessions to continue with limited functionality
        return True


# Global service degradation manager
_degradation_manager = None

def get_degradation_manager() -> ServiceDegradationManager:
    """Get or create the global service degradation manager"""
    global _degradation_manager
    if _degradation_manager is None:
        _degradation_manager = ServiceDegradationManager()
        
        # Register default fallback handlers
        _degradation_manager.register_fallback_handler("rag_system", ChatSystemFallbacks.rag_fallback)
        _degradation_manager.register_fallback_handler("llm_service", ChatSystemFallbacks.llm_fallback)
        _degradation_manager.register_fallback_handler("database", ChatSystemFallbacks.database_fallback)
        _degradation_manager.register_fallback_handler("session_validation", ChatSystemFallbacks.session_validation_fallback)
        
    return _degradation_manager