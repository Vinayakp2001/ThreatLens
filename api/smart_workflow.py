"""
Smart Workflow Logic for Security Wiki Generator

This module implements intelligent routing and context checking for dual analysis modes.
It provides user guidance when repository context is missing and handles fallback scenarios.
"""
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum

from api.knowledge_base import RepositoryKnowledgeBase
from api.pr_analyzer import PRChangeDetector, PRChangeParser
from api.context_integration import ContextualPRAnalyzer

logger = logging.getLogger(__name__)


class AnalysisMode(Enum):
    """Analysis mode enumeration"""
    FULL_REPOSITORY = "full_repository"
    PR_ANALYSIS = "pr_analysis"
    CONTEXT_AWARE_PR = "context_aware_pr"
    FALLBACK_PR = "fallback_pr"


class ContextAvailability(Enum):
    """Context availability levels"""
    FULL_CONTEXT = "full_context"
    PARTIAL_CONTEXT = "partial_context"
    NO_CONTEXT = "no_context"
    STALE_CONTEXT = "stale_context"


class UserGuidanceLevel(Enum):
    """User guidance recommendation levels"""
    NONE = "none"
    SUGGESTION = "suggestion"
    RECOMMENDATION = "recommendation"
    STRONG_RECOMMENDATION = "strong_recommendation"
    REQUIRED = "required"


class SmartWorkflowManager:
    """Manages intelligent analysis routing and user guidance"""
    
    def __init__(self):
        self.knowledge_base = RepositoryKnowledgeBase()
        self.pr_parser = PRChangeParser()
        self.contextual_analyzer = ContextualPRAnalyzer()
        
        # Configuration for context freshness
        self.context_freshness_threshold = timedelta(days=30)  # Context older than 30 days is stale
        self.high_risk_context_threshold = timedelta(days=7)   # High-risk changes need fresh context
    
    def analyze_pr_request(self, pr_url: str, repo_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze PR analysis request and provide intelligent routing and guidance
        
        Args:
            pr_url: GitHub PR URL
            repo_id: Optional repository ID
            
        Returns:
            Analysis routing decision with user guidance
        """
        try:
            # Parse PR URL to extract repository information
            pr_info = self.pr_parser.parse_pr_url(pr_url)
            if not pr_info:
                return {
                    "error": "Invalid PR URL format",
                    "guidance": {
                        "level": UserGuidanceLevel.REQUIRED.value,
                        "message": "Please provide a valid GitHub PR URL",
                        "action_required": True
                    }
                }
            
            # Determine repository ID if not provided
            if not repo_id:
                repo_id = f"github_{pr_info['owner']}_{pr_info['repo']}"
            
            # Check repository context availability
            context_status = self._assess_context_availability(repo_id)
            
            # Analyze PR complexity and risk
            pr_complexity = self._assess_pr_complexity(pr_url)
            
            # Generate routing decision
            routing_decision = self._generate_routing_decision(
                context_status, pr_complexity, pr_info, repo_id
            )
            
            # Generate user guidance
            user_guidance = self._generate_user_guidance(
                context_status, pr_complexity, routing_decision
            )
            
            return {
                "pr_info": pr_info,
                "repo_id": repo_id,
                "context_status": context_status,
                "pr_complexity": pr_complexity,
                "routing_decision": routing_decision,
                "user_guidance": user_guidance,
                "analysis_recommendations": self._generate_analysis_recommendations(
                    context_status, pr_complexity
                )
            }
            
        except Exception as e:
            logger.error(f"Error analyzing PR request: {e}")
            return {
                "error": f"Failed to analyze PR request: {str(e)}",
                "guidance": {
                    "level": UserGuidanceLevel.RECOMMENDATION.value,
                    "message": "Unable to analyze PR request. Please try again or contact support.",
                    "action_required": False
                }
            }
    
    def check_context_requirements(self, pr_url: str, repo_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Check context requirements for PR analysis and provide specific guidance
        
        Args:
            pr_url: GitHub PR URL
            repo_id: Optional repository ID
            
        Returns:
            Context requirements analysis with specific guidance
        """
        try:
            analysis_result = self.analyze_pr_request(pr_url, repo_id)
            
            if "error" in analysis_result:
                return analysis_result
            
            context_status = analysis_result["context_status"]
            pr_complexity = analysis_result["pr_complexity"]
            
            # Generate specific context requirements
            requirements = {
                "context_available": context_status["availability"] != ContextAvailability.NO_CONTEXT.value,
                "context_quality": context_status["quality_score"],
                "context_freshness": context_status["freshness"],
                "recommended_action": self._get_recommended_action(context_status, pr_complexity),
                "benefits_of_full_analysis": self._get_full_analysis_benefits(pr_complexity),
                "fallback_limitations": self._get_fallback_limitations(context_status),
                "estimated_analysis_time": self._estimate_analysis_time(context_status, pr_complexity)
            }
            
            return {
                "requirements": requirements,
                "guidance": analysis_result["user_guidance"],
                "context_details": context_status
            }
            
        except Exception as e:
            logger.error(f"Error checking context requirements: {e}")
            return {
                "error": f"Failed to check context requirements: {str(e)}"
            }
    
    def route_analysis_request(self, pr_url: str, repo_id: Optional[str] = None, 
                             force_mode: Optional[str] = None) -> Dict[str, Any]:
        """
        Route analysis request to appropriate analysis mode
        
        Args:
            pr_url: GitHub PR URL
            repo_id: Optional repository ID
            force_mode: Optional forced analysis mode
            
        Returns:
            Routing decision with analysis configuration
        """
        try:
            # Get analysis routing information
            analysis_result = self.analyze_pr_request(pr_url, repo_id)
            
            if "error" in analysis_result:
                return analysis_result
            
            # Apply forced mode if specified
            if force_mode:
                if force_mode in [mode.value for mode in AnalysisMode]:
                    analysis_result["routing_decision"]["recommended_mode"] = force_mode
                    analysis_result["routing_decision"]["mode_forced"] = True
                else:
                    return {
                        "error": f"Invalid forced mode: {force_mode}",
                        "valid_modes": [mode.value for mode in AnalysisMode]
                    }
            
            # Generate analysis configuration
            analysis_config = self._generate_analysis_config(analysis_result)
            
            return {
                "routing": analysis_result["routing_decision"],
                "config": analysis_config,
                "guidance": analysis_result["user_guidance"],
                "context_info": analysis_result["context_status"]
            }
            
        except Exception as e:
            logger.error(f"Error routing analysis request: {e}")
            return {
                "error": f"Failed to route analysis request: {str(e)}"
            }
    
    def _assess_context_availability(self, repo_id: str) -> Dict[str, Any]:
        """Assess repository context availability and quality"""
        try:
            # Check if repository analysis exists
            repo_status = self.knowledge_base.check_repo_analysis_exists(repo_id)
            
            if not repo_status["exists"]:
                return {
                    "availability": ContextAvailability.NO_CONTEXT.value,
                    "quality_score": 0.0,
                    "freshness": "none",
                    "details": {
                        "has_documents": False,
                        "has_search_index": False,
                        "document_count": 0,
                        "last_analysis": None
                    },
                    "limitations": [
                        "No repository security analysis available",
                        "PR analysis will be limited to change-only assessment",
                        "Cannot provide context-aware security recommendations"
                    ]
                }
            
            # Get detailed context information
            context_details = self.knowledge_base.get_repo_security_context(repo_id)
            kb_stats = self.knowledge_base.get_knowledge_base_stats(repo_id)
            
            # Assess context quality
            quality_score = self._calculate_context_quality_score(repo_status, kb_stats)
            
            # Assess context freshness
            freshness_assessment = self._assess_context_freshness(repo_status.get("analysis_date"))
            
            # Determine overall availability level
            if quality_score >= 0.8 and freshness_assessment["is_fresh"]:
                availability = ContextAvailability.FULL_CONTEXT
            elif quality_score >= 0.5:
                if freshness_assessment["is_fresh"]:
                    availability = ContextAvailability.PARTIAL_CONTEXT
                else:
                    availability = ContextAvailability.STALE_CONTEXT
            else:
                availability = ContextAvailability.NO_CONTEXT
            
            return {
                "availability": availability.value,
                "quality_score": quality_score,
                "freshness": freshness_assessment["status"],
                "details": {
                    "has_documents": repo_status["document_count"] > 0,
                    "has_search_index": repo_status["has_search_index"],
                    "document_count": repo_status["document_count"],
                    "last_analysis": repo_status["analysis_date"],
                    "analysis_status": repo_status["status"]
                },
                "limitations": self._get_context_limitations(availability, quality_score, freshness_assessment)
            }
            
        except Exception as e:
            logger.error(f"Error assessing context availability: {e}")
            return {
                "availability": ContextAvailability.NO_CONTEXT.value,
                "quality_score": 0.0,
                "freshness": "unknown",
                "error": str(e)
            }
    
    def _assess_pr_complexity(self, pr_url: str) -> Dict[str, Any]:
        """Assess PR complexity and security relevance"""
        try:
            # Use PR analyzer to get basic PR information
            pr_detector = PRChangeDetector()
            pr_analysis = pr_detector.analyze_pr(pr_url)
            
            if "error" in pr_analysis:
                return {
                    "complexity_level": "unknown",
                    "security_relevance": "unknown",
                    "risk_indicators": [],
                    "error": pr_analysis["error"]
                }
            
            file_analysis = pr_analysis.get("file_analysis", {})
            security_changes = pr_analysis.get("security_changes", {})
            
            # Calculate complexity metrics
            total_files = file_analysis.get("total_files", 0)
            security_files = len(file_analysis.get("security_relevant_files", []))
            total_changes = file_analysis.get("change_summary", {}).get("additions", 0) + \
                          file_analysis.get("change_summary", {}).get("deletions", 0)
            
            # Assess complexity level
            complexity_score = 0
            if total_files > 20:
                complexity_score += 3
            elif total_files > 10:
                complexity_score += 2
            elif total_files > 5:
                complexity_score += 1
            
            if total_changes > 500:
                complexity_score += 3
            elif total_changes > 200:
                complexity_score += 2
            elif total_changes > 50:
                complexity_score += 1
            
            if security_files > 5:
                complexity_score += 2
            elif security_files > 2:
                complexity_score += 1
            
            # Determine complexity level
            if complexity_score >= 6:
                complexity_level = "high"
            elif complexity_score >= 3:
                complexity_level = "medium"
            else:
                complexity_level = "low"
            
            # Assess security relevance
            security_categories = len([cat for cat, files in file_analysis.get("file_categories", {}).items() if files])
            risk_level = pr_analysis.get("overall_assessment", {}).get("overall_risk_level", "low")
            
            if risk_level in ["high", "critical"] or security_categories >= 3:
                security_relevance = "high"
            elif risk_level == "medium" or security_categories >= 2:
                security_relevance = "medium"
            else:
                security_relevance = "low"
            
            # Identify risk indicators
            risk_indicators = []
            if security_files > 0:
                risk_indicators.append(f"{security_files} security-relevant files modified")
            
            for category, files in file_analysis.get("file_categories", {}).items():
                if files:
                    risk_indicators.append(f"{category} components affected")
            
            if file_analysis.get("risk_indicators"):
                risk_indicators.extend(file_analysis["risk_indicators"])
            
            return {
                "complexity_level": complexity_level,
                "security_relevance": security_relevance,
                "complexity_score": complexity_score,
                "metrics": {
                    "total_files": total_files,
                    "security_files": security_files,
                    "total_changes": total_changes,
                    "security_categories": security_categories
                },
                "risk_indicators": risk_indicators,
                "overall_risk": risk_level
            }
            
        except Exception as e:
            logger.error(f"Error assessing PR complexity: {e}")
            return {
                "complexity_level": "unknown",
                "security_relevance": "unknown",
                "error": str(e)
            }
    
    def _generate_routing_decision(self, context_status: Dict[str, Any], 
                                 pr_complexity: Dict[str, Any], 
                                 pr_info: Dict[str, str], 
                                 repo_id: str) -> Dict[str, Any]:
        """Generate intelligent routing decision"""
        
        context_availability = context_status.get("availability")
        complexity_level = pr_complexity.get("complexity_level")
        security_relevance = pr_complexity.get("security_relevance")
        
        # Decision matrix for routing
        if context_availability == ContextAvailability.FULL_CONTEXT.value:
            recommended_mode = AnalysisMode.CONTEXT_AWARE_PR
            confidence = "high"
            reasoning = "Full repository context available for comprehensive PR analysis"
            
        elif context_availability == ContextAvailability.PARTIAL_CONTEXT.value:
            if security_relevance == "high" or complexity_level == "high":
                recommended_mode = AnalysisMode.CONTEXT_AWARE_PR
                confidence = "medium"
                reasoning = "Partial context available, sufficient for high-complexity PR analysis"
            else:
                recommended_mode = AnalysisMode.PR_ANALYSIS
                confidence = "medium"
                reasoning = "Partial context available, adequate for low-complexity PR analysis"
                
        elif context_availability == ContextAvailability.STALE_CONTEXT.value:
            if security_relevance == "high":
                recommended_mode = AnalysisMode.FULL_REPOSITORY
                confidence = "low"
                reasoning = "Stale context with high-security PR requires fresh repository analysis"
            else:
                recommended_mode = AnalysisMode.FALLBACK_PR
                confidence = "medium"
                reasoning = "Stale context, using fallback PR analysis"
                
        else:  # NO_CONTEXT
            if security_relevance == "high" or complexity_level == "high":
                recommended_mode = AnalysisMode.FULL_REPOSITORY
                confidence = "low"
                reasoning = "No context available for high-risk PR, full repository analysis recommended"
            else:
                recommended_mode = AnalysisMode.FALLBACK_PR
                confidence = "medium"
                reasoning = "No context available, using fallback PR analysis"
        
        return {
            "recommended_mode": recommended_mode.value,
            "confidence": confidence,
            "reasoning": reasoning,
            "alternatives": self._get_alternative_modes(recommended_mode, context_status, pr_complexity),
            "mode_forced": False
        }
    
    def _generate_user_guidance(self, context_status: Dict[str, Any], 
                              pr_complexity: Dict[str, Any], 
                              routing_decision: Dict[str, Any]) -> Dict[str, Any]:
        """Generate user guidance based on analysis"""
        
        recommended_mode = routing_decision["recommended_mode"]
        context_availability = context_status.get("availability")
        security_relevance = pr_complexity.get("security_relevance")
        
        # Determine guidance level
        if recommended_mode == AnalysisMode.FULL_REPOSITORY.value:
            if security_relevance == "high":
                guidance_level = UserGuidanceLevel.STRONG_RECOMMENDATION
            else:
                guidance_level = UserGuidanceLevel.RECOMMENDATION
        elif context_availability == ContextAvailability.NO_CONTEXT.value:
            guidance_level = UserGuidanceLevel.SUGGESTION
        else:
            guidance_level = UserGuidanceLevel.NONE
        
        # Generate guidance message
        messages = []
        actions = []
        
        if context_availability == ContextAvailability.NO_CONTEXT.value:
            messages.append("No repository security analysis found.")
            if security_relevance == "high":
                messages.append("For high-security PRs, we strongly recommend analyzing the full repository first.")
                actions.append({
                    "action": "analyze_repository",
                    "label": "Analyze Full Repository",
                    "description": "Run comprehensive security analysis on the entire repository",
                    "estimated_time": "5-15 minutes"
                })
            else:
                messages.append("Consider analyzing the full repository for better security insights.")
                actions.append({
                    "action": "analyze_repository",
                    "label": "Analyze Repository (Recommended)",
                    "description": "Get comprehensive security context for better PR analysis",
                    "estimated_time": "5-15 minutes"
                })
            
            actions.append({
                "action": "proceed_without_context",
                "label": "Analyze PR Only",
                "description": "Proceed with limited PR-only analysis",
                "estimated_time": "1-2 minutes"
            })
            
        elif context_availability == ContextAvailability.STALE_CONTEXT.value:
            messages.append("Repository analysis is outdated (older than 30 days).")
            if security_relevance == "high":
                messages.append("Fresh analysis is recommended for high-security changes.")
                actions.append({
                    "action": "refresh_analysis",
                    "label": "Refresh Repository Analysis",
                    "description": "Update repository security analysis with latest code",
                    "estimated_time": "5-15 minutes"
                })
            
        elif context_availability == ContextAvailability.PARTIAL_CONTEXT.value:
            messages.append("Partial repository context available.")
            messages.append("Analysis will proceed with available context.")
            
        else:  # FULL_CONTEXT
            messages.append("Full repository security context available.")
            messages.append("Proceeding with comprehensive context-aware analysis.")
        
        return {
            "level": guidance_level.value,
            "messages": messages,
            "actions": actions,
            "show_guidance": guidance_level != UserGuidanceLevel.NONE,
            "action_required": guidance_level in [UserGuidanceLevel.STRONG_RECOMMENDATION, UserGuidanceLevel.REQUIRED]
        }
    
    def _calculate_context_quality_score(self, repo_status: Dict[str, Any], 
                                       kb_stats: Dict[str, Any]) -> float:
        """Calculate context quality score (0.0 to 1.0)"""
        if not repo_status.get("exists"):
            return 0.0
        
        score = 0.0
        
        # Base score for existence
        score += 0.3
        
        # Score for document count
        doc_count = repo_status.get("document_count", 0)
        if doc_count >= 10:
            score += 0.3
        elif doc_count >= 5:
            score += 0.2
        elif doc_count >= 1:
            score += 0.1
        
        # Score for search index
        if repo_status.get("has_search_index"):
            score += 0.2
        
        # Score for analysis completeness
        if repo_status.get("status") == "complete":
            score += 0.2
        elif repo_status.get("status") == "partial":
            score += 0.1
        
        return min(1.0, score)
    
    def _assess_context_freshness(self, analysis_date: Optional[str]) -> Dict[str, Any]:
        """Assess context freshness"""
        if not analysis_date:
            return {
                "is_fresh": False,
                "status": "none",
                "age_days": None
            }
        
        try:
            analysis_datetime = datetime.fromisoformat(analysis_date.replace('Z', '+00:00'))
            age = datetime.now(analysis_datetime.tzinfo) - analysis_datetime
            age_days = age.days
            
            if age <= self.high_risk_context_threshold:
                status = "very_fresh"
                is_fresh = True
            elif age <= self.context_freshness_threshold:
                status = "fresh"
                is_fresh = True
            elif age <= timedelta(days=90):
                status = "stale"
                is_fresh = False
            else:
                status = "very_stale"
                is_fresh = False
            
            return {
                "is_fresh": is_fresh,
                "status": status,
                "age_days": age_days
            }
            
        except Exception as e:
            logger.error(f"Error assessing context freshness: {e}")
            return {
                "is_fresh": False,
                "status": "unknown",
                "age_days": None
            }
    
    def _get_context_limitations(self, availability: ContextAvailability, 
                               quality_score: float, 
                               freshness_assessment: Dict[str, Any]) -> List[str]:
        """Get context limitations based on availability and quality"""
        limitations = []
        
        if availability == ContextAvailability.NO_CONTEXT:
            limitations.extend([
                "No repository security baseline available",
                "Cannot assess PR changes against existing security architecture",
                "Limited ability to identify security pattern violations",
                "No context-aware recommendations possible"
            ])
        elif availability == ContextAvailability.PARTIAL_CONTEXT:
            limitations.extend([
                "Incomplete repository security analysis",
                "Some security patterns may not be detected",
                "Limited context for comprehensive recommendations"
            ])
        elif availability == ContextAvailability.STALE_CONTEXT:
            limitations.extend([
                "Repository analysis is outdated",
                "May miss recent security changes",
                "Context may not reflect current codebase state"
            ])
        
        if quality_score < 0.5:
            limitations.append("Low-quality security analysis available")
        
        if not freshness_assessment.get("is_fresh"):
            limitations.append(f"Analysis is {freshness_assessment.get('age_days', 'unknown')} days old")
        
        return limitations
    
    def _get_alternative_modes(self, recommended_mode: AnalysisMode, 
                             context_status: Dict[str, Any], 
                             pr_complexity: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get alternative analysis modes"""
        alternatives = []
        
        # Always offer fallback PR analysis
        if recommended_mode != AnalysisMode.FALLBACK_PR:
            alternatives.append({
                "mode": AnalysisMode.FALLBACK_PR.value,
                "description": "Basic PR analysis without repository context",
                "pros": ["Fast analysis", "No dependencies"],
                "cons": ["Limited security insights", "No context-aware recommendations"]
            })
        
        # Offer full repository analysis if not recommended
        if recommended_mode != AnalysisMode.FULL_REPOSITORY:
            alternatives.append({
                "mode": AnalysisMode.FULL_REPOSITORY.value,
                "description": "Complete repository security analysis followed by PR analysis",
                "pros": ["Comprehensive security baseline", "Best quality analysis"],
                "cons": ["Longer analysis time", "Higher resource usage"]
            })
        
        # Offer context-aware PR if context is available
        if (recommended_mode != AnalysisMode.CONTEXT_AWARE_PR and 
            context_status.get("availability") != ContextAvailability.NO_CONTEXT.value):
            alternatives.append({
                "mode": AnalysisMode.CONTEXT_AWARE_PR.value,
                "description": "PR analysis using available repository context",
                "pros": ["Faster than full analysis", "Uses existing context"],
                "cons": ["May have context limitations", "Depends on context quality"]
            })
        
        return alternatives
    
    def _generate_analysis_recommendations(self, context_status: Dict[str, Any], 
                                         pr_complexity: Dict[str, Any]) -> List[str]:
        """Generate analysis recommendations"""
        recommendations = []
        
        context_availability = context_status.get("availability")
        security_relevance = pr_complexity.get("security_relevance")
        complexity_level = pr_complexity.get("complexity_level")
        
        if context_availability == ContextAvailability.NO_CONTEXT.value:
            recommendations.append("Consider running full repository analysis to establish security baseline")
            
        if security_relevance == "high":
            recommendations.append("High-security changes detected - thorough review recommended")
            recommendations.append("Consider involving security team in review process")
            
        if complexity_level == "high":
            recommendations.append("Complex PR detected - break down into smaller changes if possible")
            
        if context_status.get("quality_score", 0) < 0.5:
            recommendations.append("Low-quality repository context - consider refreshing analysis")
            
        return recommendations
    
    def _get_recommended_action(self, context_status: Dict[str, Any], 
                              pr_complexity: Dict[str, Any]) -> str:
        """Get recommended action for user"""
        context_availability = context_status.get("availability")
        security_relevance = pr_complexity.get("security_relevance")
        
        if context_availability == ContextAvailability.NO_CONTEXT.value:
            if security_relevance == "high":
                return "analyze_repository_first"
            else:
                return "consider_repository_analysis"
        elif context_availability == ContextAvailability.STALE_CONTEXT.value:
            return "refresh_repository_analysis"
        else:
            return "proceed_with_pr_analysis"
    
    def _get_full_analysis_benefits(self, pr_complexity: Dict[str, Any]) -> List[str]:
        """Get benefits of running full repository analysis"""
        benefits = [
            "Comprehensive security baseline establishment",
            "Context-aware PR analysis for future changes",
            "Better security recommendations",
            "Identification of existing security patterns"
        ]
        
        if pr_complexity.get("security_relevance") == "high":
            benefits.extend([
                "Critical for high-security changes",
                "Enables detection of security architecture violations"
            ])
        
        return benefits
    
    def _get_fallback_limitations(self, context_status: Dict[str, Any]) -> List[str]:
        """Get limitations of fallback analysis"""
        return [
            "Analysis limited to PR changes only",
            "Cannot assess impact on existing security architecture",
            "No context-aware security recommendations",
            "May miss security pattern violations",
            "Limited ability to assess overall security impact"
        ]
    
    def _estimate_analysis_time(self, context_status: Dict[str, Any], 
                              pr_complexity: Dict[str, Any]) -> Dict[str, str]:
        """Estimate analysis time for different modes"""
        complexity_level = pr_complexity.get("complexity_level", "low")
        
        estimates = {
            "pr_only": "1-2 minutes",
            "context_aware_pr": "2-5 minutes",
            "full_repository": "5-15 minutes"
        }
        
        if complexity_level == "high":
            estimates["pr_only"] = "2-3 minutes"
            estimates["context_aware_pr"] = "3-7 minutes"
            estimates["full_repository"] = "10-20 minutes"
        
        return estimates
    
    def _generate_analysis_config(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate analysis configuration based on routing decision"""
        routing_decision = analysis_result["routing_decision"]
        context_status = analysis_result["context_status"]
        pr_complexity = analysis_result["pr_complexity"]
        
        config = {
            "mode": routing_decision["recommended_mode"],
            "use_context": context_status.get("availability") != ContextAvailability.NO_CONTEXT.value,
            "context_quality": context_status.get("quality_score", 0.0),
            "enable_deep_analysis": pr_complexity.get("security_relevance") == "high",
            "priority_level": self._determine_priority_level(pr_complexity),
            "timeout_minutes": self._calculate_timeout(routing_decision["recommended_mode"], pr_complexity),
            "fallback_enabled": True
        }
        
        return config
    
    def _determine_priority_level(self, pr_complexity: Dict[str, Any]) -> str:
        """Determine analysis priority level"""
        security_relevance = pr_complexity.get("security_relevance", "low")
        complexity_level = pr_complexity.get("complexity_level", "low")
        
        if security_relevance == "high" or complexity_level == "high":
            return "high"
        elif security_relevance == "medium" or complexity_level == "medium":
            return "medium"
        else:
            return "low"
    
    def _calculate_timeout(self, analysis_mode: str, pr_complexity: Dict[str, Any]) -> int:
        """Calculate analysis timeout in minutes"""
        base_timeouts = {
            AnalysisMode.FALLBACK_PR.value: 5,
            AnalysisMode.PR_ANALYSIS.value: 10,
            AnalysisMode.CONTEXT_AWARE_PR.value: 15,
            AnalysisMode.FULL_REPOSITORY.value: 30
        }
        
        timeout = base_timeouts.get(analysis_mode, 10)
        
        # Increase timeout for complex PRs
        if pr_complexity.get("complexity_level") == "high":
            timeout = int(timeout * 1.5)
        
        return timeout