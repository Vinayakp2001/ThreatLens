"""
Intelligent Analysis Router for Security Wiki Generator

This module implements intelligent routing for analysis requests, directing
full repository requests to comprehensive analysis and PR requests to 
context-aware change analysis with appropriate fallback scenarios.
"""
import logging
from typing import Dict, Any, Optional, Tuple, Union
from datetime import datetime
from enum import Enum

from api.smart_workflow import SmartWorkflowManager, AnalysisMode
from api.knowledge_base import RepositoryKnowledgeBase
from api.pr_analyzer import PRChangeDetector
from api.context_integration import ContextualPRAnalyzer
from api.security_wiki_generator import SecurityWikiGenerator
from api.models import SecurityModel, Component, ComponentType

logger = logging.getLogger(__name__)


class AnalysisType(Enum):
    """Analysis type enumeration"""
    REPOSITORY_ANALYSIS = "repository_analysis"
    PR_ANALYSIS = "pr_analysis"
    UNKNOWN = "unknown"


class RoutingStrategy(Enum):
    """Routing strategy enumeration"""
    OPTIMAL = "optimal"
    FALLBACK = "fallback"
    FORCED = "forced"
    ERROR_RECOVERY = "error_recovery"


class AnalysisRouter:
    """Intelligent analysis router for security wiki generator"""
    
    def __init__(self):
        self.workflow_manager = SmartWorkflowManager()
        self.knowledge_base = RepositoryKnowledgeBase()
        self.pr_analyzer = PRChangeDetector()
        self.contextual_analyzer = ContextualPRAnalyzer()
        
        # Routing configuration
        self.max_fallback_attempts = 3
        self.enable_auto_fallback = True
        self.routing_cache = {}  # Simple in-memory cache for routing decisions
    
    def route_analysis_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route analysis request to appropriate handler with intelligent decision making
        
        Args:
            request_data: Analysis request data containing URL, type, and options
            
        Returns:
            Routing result with analysis configuration and execution plan
        """
        try:
            # Determine analysis type
            analysis_type = self._determine_analysis_type(request_data)
            
            # Generate routing key for caching
            routing_key = self._generate_routing_key(request_data)
            
            # Check cache for recent routing decision
            if routing_key in self.routing_cache:
                cached_result = self.routing_cache[routing_key]
                if self._is_cache_valid(cached_result):
                    logger.info(f"Using cached routing decision for {routing_key}")
                    return cached_result
            
            # Route based on analysis type
            if analysis_type == AnalysisType.REPOSITORY_ANALYSIS:
                routing_result = self._route_repository_analysis(request_data)
            elif analysis_type == AnalysisType.PR_ANALYSIS:
                routing_result = self._route_pr_analysis(request_data)
            else:
                routing_result = self._handle_unknown_analysis_type(request_data)
            
            # Cache the routing decision
            routing_result["cached_at"] = datetime.now().isoformat()
            self.routing_cache[routing_key] = routing_result
            
            return routing_result
            
        except Exception as e:
            logger.error(f"Error routing analysis request: {e}")
            return self._create_error_routing_result(str(e), request_data)
    
    def execute_routed_analysis(self, routing_result: Dict[str, Any], 
                              wiki_generator: SecurityWikiGenerator,
                              db_manager) -> Dict[str, Any]:
        """
        Execute analysis based on routing result
        
        Args:
            routing_result: Result from route_analysis_request
            wiki_generator: Security wiki generator instance
            db_manager: Database manager instance
            
        Returns:
            Analysis execution result
        """
        try:
            execution_plan = routing_result.get("execution_plan", {})
            analysis_mode = execution_plan.get("mode")
            
            logger.info(f"Executing analysis with mode: {analysis_mode}")
            
            if analysis_mode == AnalysisMode.FULL_REPOSITORY.value:
                return self._execute_repository_analysis(routing_result, wiki_generator, db_manager)
            elif analysis_mode == AnalysisMode.CONTEXT_AWARE_PR.value:
                return self._execute_context_aware_pr_analysis(routing_result, wiki_generator, db_manager)
            elif analysis_mode == AnalysisMode.PR_ANALYSIS.value:
                return self._execute_basic_pr_analysis(routing_result, wiki_generator, db_manager)
            elif analysis_mode == AnalysisMode.FALLBACK_PR.value:
                return self._execute_fallback_pr_analysis(routing_result, wiki_generator, db_manager)
            else:
                return self._handle_unknown_execution_mode(routing_result)
                
        except Exception as e:
            logger.error(f"Error executing routed analysis: {e}")
            # Attempt fallback execution if enabled
            if self.enable_auto_fallback and routing_result.get("fallback_available"):
                return self._attempt_fallback_execution(routing_result, wiki_generator, db_manager, str(e))
            else:
                return {"error": f"Analysis execution failed: {str(e)}"}
    
    def _determine_analysis_type(self, request_data: Dict[str, Any]) -> AnalysisType:
        """Determine the type of analysis request"""
        
        # Check for explicit analysis type
        if "analysis_type" in request_data:
            analysis_type = request_data["analysis_type"].lower()
            if "repository" in analysis_type or "repo" in analysis_type:
                return AnalysisType.REPOSITORY_ANALYSIS
            elif "pr" in analysis_type or "pull" in analysis_type:
                return AnalysisType.PR_ANALYSIS
        
        # Infer from URL patterns
        url = request_data.get("url", "") or request_data.get("repo_url", "") or request_data.get("pr_url", "")
        
        if "/pull/" in url or "/pulls/" in url:
            return AnalysisType.PR_ANALYSIS
        elif "github.com" in url and "/pull/" not in url:
            return AnalysisType.REPOSITORY_ANALYSIS
        
        # Check for local path (repository analysis)
        if request_data.get("local_path"):
            return AnalysisType.REPOSITORY_ANALYSIS
        
        return AnalysisType.UNKNOWN
    
    def _route_repository_analysis(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Route repository analysis request"""
        
        repo_url = request_data.get("repo_url") or request_data.get("url")
        local_path = request_data.get("local_path")
        force_mode = request_data.get("force_mode")
        
        # Repository analysis always uses full repository mode
        recommended_mode = AnalysisMode.FULL_REPOSITORY
        strategy = RoutingStrategy.OPTIMAL
        
        if force_mode and force_mode != recommended_mode.value:
            logger.warning(f"Force mode {force_mode} not applicable for repository analysis, using {recommended_mode.value}")
        
        # Generate execution plan
        execution_plan = {
            "mode": recommended_mode.value,
            "strategy": strategy.value,
            "input": {
                "repo_url": repo_url,
                "local_path": local_path
            },
            "options": {
                "comprehensive_analysis": True,
                "create_knowledge_base": True,
                "enable_search_index": True,
                "generate_security_docs": True
            },
            "estimated_duration": self._estimate_repository_analysis_duration(request_data),
            "resource_requirements": {
                "cpu_intensive": True,
                "memory_usage": "high",
                "storage_usage": "medium"
            }
        }
        
        return {
            "analysis_type": AnalysisType.REPOSITORY_ANALYSIS.value,
            "routing_strategy": strategy.value,
            "execution_plan": execution_plan,
            "fallback_available": False,  # Repository analysis has no fallback
            "confidence": "high",
            "reasoning": "Repository analysis requires comprehensive full-repository mode",
            "user_guidance": {
                "message": "Performing comprehensive repository security analysis",
                "expected_outcome": "Complete security documentation and knowledge base creation"
            }
        }
    
    def _route_pr_analysis(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Route PR analysis request with intelligent context-aware routing"""
        
        pr_url = request_data.get("pr_url") or request_data.get("url")
        repo_id = request_data.get("repo_id")
        force_mode = request_data.get("force_mode")
        
        # Use smart workflow manager for intelligent routing
        workflow_analysis = self.workflow_manager.analyze_pr_request(pr_url, repo_id)
        
        if "error" in workflow_analysis:
            return self._create_error_routing_result(workflow_analysis["error"], request_data)
        
        # Extract routing information
        routing_decision = workflow_analysis["routing_decision"]
        context_status = workflow_analysis["context_status"]
        pr_complexity = workflow_analysis["pr_complexity"]
        user_guidance = workflow_analysis["user_guidance"]
        
        recommended_mode = routing_decision["recommended_mode"]
        
        # Apply force mode if specified
        if force_mode:
            if force_mode in [mode.value for mode in AnalysisMode]:
                recommended_mode = force_mode
                strategy = RoutingStrategy.FORCED
                logger.info(f"Using forced analysis mode: {force_mode}")
            else:
                logger.warning(f"Invalid force mode: {force_mode}, using recommended mode: {recommended_mode}")
                strategy = RoutingStrategy.OPTIMAL
        else:
            strategy = RoutingStrategy.OPTIMAL
        
        # Determine fallback options
        fallback_available = True
        fallback_modes = []
        
        if recommended_mode != AnalysisMode.FALLBACK_PR.value:
            fallback_modes.append(AnalysisMode.FALLBACK_PR.value)
        
        if (recommended_mode != AnalysisMode.PR_ANALYSIS.value and 
            context_status.get("availability") != "no_context"):
            fallback_modes.append(AnalysisMode.PR_ANALYSIS.value)
        
        # Generate execution plan
        execution_plan = {
            "mode": recommended_mode,
            "strategy": strategy.value,
            "input": {
                "pr_url": pr_url,
                "repo_id": workflow_analysis["repo_id"]
            },
            "context_info": context_status,
            "complexity_info": pr_complexity,
            "options": {
                "use_repo_context": context_status.get("availability") != "no_context",
                "context_quality": context_status.get("quality_score", 0.0),
                "enable_deep_analysis": pr_complexity.get("security_relevance") == "high",
                "generate_contextual_recommendations": True
            },
            "fallback_modes": fallback_modes,
            "estimated_duration": self._estimate_pr_analysis_duration(recommended_mode, pr_complexity),
            "resource_requirements": {
                "cpu_intensive": False,
                "memory_usage": "medium" if recommended_mode == AnalysisMode.CONTEXT_AWARE_PR.value else "low",
                "storage_usage": "low"
            }
        }
        
        return {
            "analysis_type": AnalysisType.PR_ANALYSIS.value,
            "routing_strategy": strategy.value,
            "execution_plan": execution_plan,
            "fallback_available": fallback_available,
            "confidence": routing_decision.get("confidence", "medium"),
            "reasoning": routing_decision.get("reasoning", "Context-aware PR analysis routing"),
            "user_guidance": user_guidance,
            "workflow_analysis": workflow_analysis
        }
    
    def _handle_unknown_analysis_type(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle unknown analysis type with intelligent inference"""
        
        # Try to infer from available data
        if request_data.get("repo_url") or request_data.get("local_path"):
            logger.info("Unknown analysis type, inferring repository analysis from repo_url/local_path")
            request_data["analysis_type"] = "repository"
            return self._route_repository_analysis(request_data)
        
        if request_data.get("pr_url"):
            logger.info("Unknown analysis type, inferring PR analysis from pr_url")
            request_data["analysis_type"] = "pr"
            return self._route_pr_analysis(request_data)
        
        # Cannot determine analysis type
        return self._create_error_routing_result(
            "Cannot determine analysis type from request data", 
            request_data
        )
    
    def _execute_repository_analysis(self, routing_result: Dict[str, Any], 
                                   wiki_generator: SecurityWikiGenerator,
                                   db_manager) -> Dict[str, Any]:
        """Execute full repository analysis"""
        
        execution_plan = routing_result["execution_plan"]
        input_data = execution_plan["input"]
        
        try:
            # This would integrate with the existing repository analysis workflow
            # For now, return a structured result that indicates what should happen
            
            return {
                "status": "routed_for_execution",
                "execution_mode": "full_repository",
                "next_steps": [
                    "Initialize repository ingestion",
                    "Perform security model extraction",
                    "Generate comprehensive security documentation",
                    "Create knowledge base and search index",
                    "Save analysis results"
                ],
                "routing_info": routing_result,
                "estimated_completion": execution_plan.get("estimated_duration", "10-20 minutes")
            }
            
        except Exception as e:
            logger.error(f"Error in repository analysis execution: {e}")
            return {"error": f"Repository analysis execution failed: {str(e)}"}
    
    def _execute_context_aware_pr_analysis(self, routing_result: Dict[str, Any],
                                         wiki_generator: SecurityWikiGenerator,
                                         db_manager) -> Dict[str, Any]:
        """Execute context-aware PR analysis"""
        
        execution_plan = routing_result["execution_plan"]
        input_data = execution_plan["input"]
        
        try:
            pr_url = input_data["pr_url"]
            repo_id = input_data["repo_id"]
            
            # Perform contextual PR analysis
            analysis_result = self.contextual_analyzer.analyze_pr_with_context(pr_url, repo_id)
            
            if "error" in analysis_result:
                # Attempt fallback if available
                if routing_result.get("fallback_available"):
                    logger.warning(f"Context-aware analysis failed, attempting fallback: {analysis_result['error']}")
                    return self._attempt_fallback_execution(routing_result, wiki_generator, db_manager, analysis_result["error"])
                else:
                    return {"error": f"Context-aware PR analysis failed: {analysis_result['error']}"}
            
            return {
                "status": "completed",
                "execution_mode": "context_aware_pr",
                "analysis_result": analysis_result,
                "routing_info": routing_result,
                "context_used": True,
                "context_quality": execution_plan["options"]["context_quality"]
            }
            
        except Exception as e:
            logger.error(f"Error in context-aware PR analysis: {e}")
            # Attempt fallback if available
            if routing_result.get("fallback_available"):
                return self._attempt_fallback_execution(routing_result, wiki_generator, db_manager, str(e))
            else:
                return {"error": f"Context-aware PR analysis failed: {str(e)}"}
    
    def _execute_basic_pr_analysis(self, routing_result: Dict[str, Any],
                                 wiki_generator: SecurityWikiGenerator,
                                 db_manager) -> Dict[str, Any]:
        """Execute basic PR analysis with partial context"""
        
        execution_plan = routing_result["execution_plan"]
        input_data = execution_plan["input"]
        
        try:
            pr_url = input_data["pr_url"]
            
            # Perform basic PR analysis
            analysis_result = self.pr_analyzer.analyze_pr(pr_url)
            
            if "error" in analysis_result:
                # Attempt fallback if available
                if routing_result.get("fallback_available"):
                    logger.warning(f"Basic PR analysis failed, attempting fallback: {analysis_result['error']}")
                    return self._attempt_fallback_execution(routing_result, wiki_generator, db_manager, analysis_result["error"])
                else:
                    return {"error": f"Basic PR analysis failed: {analysis_result['error']}"}
            
            return {
                "status": "completed",
                "execution_mode": "basic_pr",
                "analysis_result": analysis_result,
                "routing_info": routing_result,
                "context_used": False
            }
            
        except Exception as e:
            logger.error(f"Error in basic PR analysis: {e}")
            # Attempt fallback if available
            if routing_result.get("fallback_available"):
                return self._attempt_fallback_execution(routing_result, wiki_generator, db_manager, str(e))
            else:
                return {"error": f"Basic PR analysis failed: {str(e)}"}
    
    def _execute_fallback_pr_analysis(self, routing_result: Dict[str, Any],
                                    wiki_generator: SecurityWikiGenerator,
                                    db_manager) -> Dict[str, Any]:
        """Execute fallback PR analysis (minimal analysis)"""
        
        execution_plan = routing_result["execution_plan"]
        input_data = execution_plan["input"]
        
        try:
            pr_url = input_data["pr_url"]
            
            # Perform minimal PR analysis
            analysis_result = self.pr_analyzer.analyze_pr(pr_url)
            
            if "error" in analysis_result:
                return {"error": f"Fallback PR analysis failed: {analysis_result['error']}"}
            
            # Simplify the analysis result for fallback mode
            simplified_result = {
                "pr_info": analysis_result.get("pr_info", {}),
                "file_analysis": {
                    "total_files": analysis_result.get("file_analysis", {}).get("total_files", 0),
                    "security_relevant_files": analysis_result.get("file_analysis", {}).get("security_relevant_files", [])[:5]  # Limit to 5 files
                },
                "overall_assessment": analysis_result.get("overall_assessment", {}),
                "fallback_mode": True,
                "limitations": [
                    "Analysis limited to PR changes only",
                    "No repository context available",
                    "Limited security recommendations",
                    "Reduced analysis depth"
                ]
            }
            
            return {
                "status": "completed",
                "execution_mode": "fallback_pr",
                "analysis_result": simplified_result,
                "routing_info": routing_result,
                "context_used": False,
                "fallback_mode": True
            }
            
        except Exception as e:
            logger.error(f"Error in fallback PR analysis: {e}")
            return {"error": f"Fallback PR analysis failed: {str(e)}"}
    
    def _attempt_fallback_execution(self, routing_result: Dict[str, Any],
                                  wiki_generator: SecurityWikiGenerator,
                                  db_manager, original_error: str) -> Dict[str, Any]:
        """Attempt fallback execution when primary analysis fails"""
        
        execution_plan = routing_result["execution_plan"]
        fallback_modes = execution_plan.get("fallback_modes", [])
        
        if not fallback_modes:
            return {"error": f"No fallback available. Original error: {original_error}"}
        
        logger.info(f"Attempting fallback execution. Available modes: {fallback_modes}")
        
        # Try each fallback mode in order
        for fallback_mode in fallback_modes:
            try:
                # Create fallback routing result
                fallback_routing = routing_result.copy()
                fallback_routing["execution_plan"]["mode"] = fallback_mode
                fallback_routing["routing_strategy"] = RoutingStrategy.ERROR_RECOVERY.value
                
                if fallback_mode == AnalysisMode.FALLBACK_PR.value:
                    result = self._execute_fallback_pr_analysis(fallback_routing, wiki_generator, db_manager)
                elif fallback_mode == AnalysisMode.PR_ANALYSIS.value:
                    result = self._execute_basic_pr_analysis(fallback_routing, wiki_generator, db_manager)
                else:
                    continue
                
                if "error" not in result:
                    result["fallback_used"] = True
                    result["original_error"] = original_error
                    result["fallback_mode"] = fallback_mode
                    logger.info(f"Fallback execution successful with mode: {fallback_mode}")
                    return result
                    
            except Exception as e:
                logger.warning(f"Fallback mode {fallback_mode} also failed: {e}")
                continue
        
        return {"error": f"All fallback attempts failed. Original error: {original_error}"}
    
    def _handle_unknown_execution_mode(self, routing_result: Dict[str, Any]) -> Dict[str, Any]:
        """Handle unknown execution mode"""
        execution_plan = routing_result.get("execution_plan", {})
        mode = execution_plan.get("mode", "unknown")
        
        return {
            "error": f"Unknown execution mode: {mode}",
            "routing_info": routing_result
        }
    
    def _create_error_routing_result(self, error_message: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create error routing result"""
        return {
            "error": error_message,
            "analysis_type": AnalysisType.UNKNOWN.value,
            "routing_strategy": RoutingStrategy.ERROR_RECOVERY.value,
            "request_data": request_data,
            "fallback_available": False,
            "user_guidance": {
                "message": "Analysis routing failed",
                "recommendation": "Please check your request parameters and try again"
            }
        }
    
    def _generate_routing_key(self, request_data: Dict[str, Any]) -> str:
        """Generate cache key for routing decision"""
        # Create a simple key based on URL and analysis type
        url = request_data.get("url", "") or request_data.get("repo_url", "") or request_data.get("pr_url", "")
        analysis_type = self._determine_analysis_type(request_data).value
        return f"{analysis_type}:{hash(url)}"
    
    def _is_cache_valid(self, cached_result: Dict[str, Any], max_age_minutes: int = 10) -> bool:
        """Check if cached routing result is still valid"""
        try:
            cached_at = datetime.fromisoformat(cached_result.get("cached_at", ""))
            age = datetime.now() - cached_at
            return age.total_seconds() < (max_age_minutes * 60)
        except:
            return False
    
    def _estimate_repository_analysis_duration(self, request_data: Dict[str, Any]) -> str:
        """Estimate duration for repository analysis"""
        # This could be enhanced with actual repository size analysis
        return "10-20 minutes"
    
    def _estimate_pr_analysis_duration(self, analysis_mode: str, pr_complexity: Dict[str, Any]) -> str:
        """Estimate duration for PR analysis"""
        complexity_level = pr_complexity.get("complexity_level", "low")
        
        if analysis_mode == AnalysisMode.CONTEXT_AWARE_PR.value:
            if complexity_level == "high":
                return "3-7 minutes"
            else:
                return "2-5 minutes"
        elif analysis_mode == AnalysisMode.PR_ANALYSIS.value:
            if complexity_level == "high":
                return "2-4 minutes"
            else:
                return "1-3 minutes"
        else:  # FALLBACK_PR
            return "1-2 minutes"
    
    def get_routing_stats(self) -> Dict[str, Any]:
        """Get routing statistics"""
        return {
            "cache_size": len(self.routing_cache),
            "max_fallback_attempts": self.max_fallback_attempts,
            "auto_fallback_enabled": self.enable_auto_fallback,
            "supported_analysis_types": [t.value for t in AnalysisType],
            "supported_routing_strategies": [s.value for s in RoutingStrategy]
        }
    
    def clear_routing_cache(self):
        """Clear routing cache"""
        self.routing_cache.clear()
        logger.info("Routing cache cleared")