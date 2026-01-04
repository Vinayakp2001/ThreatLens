"""
Smart Context Integration for Security Wiki Generator

This module handles loading existing repository security knowledge for PR analysis
and merging repository context with PR changes for comprehensive analysis.
"""
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from api.knowledge_base import RepositoryKnowledgeBase
from api.pr_analyzer import PRChangeDetector
from api.models import PRAnalysis

logger = logging.getLogger(__name__)


class ContextualPRAnalyzer:
    """Analyzes PRs with full repository security context"""
    
    def __init__(self):
        self.knowledge_base = RepositoryKnowledgeBase()
        self.pr_detector = PRChangeDetector()
    
    def analyze_pr_with_context(self, pr_url: str, repo_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze PR with full repository security context
        
        Args:
            pr_url: GitHub PR URL
            repo_id: Repository ID (will be derived from URL if not provided)
            
        Returns:
            Comprehensive PR analysis with repository context
        """
        try:
            # First, perform basic PR analysis
            pr_analysis = self.pr_detector.analyze_pr(pr_url)
            
            if 'error' in pr_analysis:
                return pr_analysis
            
            # Derive repo_id if not provided
            if not repo_id:
                repo_info = pr_analysis.get('repository', {})
                repo_id = f"{repo_info.get('owner', '')}_{repo_info.get('name', '')}"
            
            # Check if repository security context exists
            repo_status = self.knowledge_base.check_repo_analysis_exists(repo_id)
            
            # Get repository security context if available
            repo_context = None
            if repo_status['exists']:
                repo_context = self.knowledge_base.get_repo_security_context(repo_id)
            
            # Enhance PR analysis with repository context
            contextual_analysis = self._merge_pr_with_repo_context(pr_analysis, repo_context, repo_status)
            
            # Generate context-aware security assessment
            contextual_analysis['contextual_assessment'] = self._generate_contextual_assessment(
                pr_analysis, repo_context
            )
            
            # Generate context-aware recommendations
            contextual_analysis['contextual_recommendations'] = self._generate_contextual_recommendations(
                pr_analysis, repo_context
            )
            
            return contextual_analysis
            
        except Exception as e:
            logger.error(f"Error in contextual PR analysis: {e}")
            return {'error': f'Contextual analysis failed: {str(e)}'}
    
    def search_related_security_knowledge(self, pr_analysis: Dict[str, Any], repo_id: str, 
                                        top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Search for security knowledge related to PR changes
        
        Args:
            pr_analysis: PR analysis results
            repo_id: Repository identifier
            top_k: Number of results to return
            
        Returns:
            List of related security knowledge items
        """
        try:
            # Extract search queries from PR analysis
            search_queries = self._extract_search_queries_from_pr(pr_analysis)
            
            related_knowledge = []
            
            for query in search_queries:
                results = self.knowledge_base.search_security_knowledge(repo_id, query, top_k)
                for result in results:
                    result['search_query'] = query
                    related_knowledge.append(result)
            
            # Remove duplicates and sort by relevance
            unique_results = {}
            for item in related_knowledge:
                doc_id = item.get('document_id')
                if doc_id not in unique_results or item['relevance_score'] > unique_results[doc_id]['relevance_score']:
                    unique_results[doc_id] = item
            
            # Sort by relevance score
            sorted_results = sorted(unique_results.values(), key=lambda x: x['relevance_score'], reverse=True)
            
            return sorted_results[:top_k]
            
        except Exception as e:
            logger.error(f"Error searching related security knowledge: {e}")
            return []
    
    def generate_context_aware_security_report(self, pr_url: str, repo_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate comprehensive security report for PR with full context
        
        Args:
            pr_url: GitHub PR URL
            repo_id: Repository ID
            
        Returns:
            Comprehensive security report
        """
        try:
            # Perform contextual analysis
            analysis = self.analyze_pr_with_context(pr_url, repo_id)
            
            if 'error' in analysis:
                return analysis
            
            # Extract repo_id from analysis if not provided
            if not repo_id:
                repo_info = analysis.get('repository', {})
                repo_id = f"{repo_info.get('owner', '')}_{repo_info.get('name', '')}"
            
            # Search for related security knowledge
            related_knowledge = self.search_related_security_knowledge(analysis, repo_id)
            
            # Generate comprehensive report
            report = {
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'pr_url': pr_url,
                    'repo_id': repo_id,
                    'analysis_type': 'context_aware_security_analysis'
                },
                'executive_summary': self._generate_executive_summary(analysis),
                'pr_analysis': analysis,
                'related_security_knowledge': related_knowledge,
                'security_impact_assessment': self._assess_security_impact(analysis, related_knowledge),
                'detailed_findings': self._generate_detailed_findings(analysis, related_knowledge),
                'action_items': self._generate_action_items(analysis, related_knowledge)
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating context-aware security report: {e}")
            return {'error': f'Report generation failed: {str(e)}'}
    
    def _merge_pr_with_repo_context(self, pr_analysis: Dict[str, Any], repo_context: Optional[Dict[str, Any]], 
                                   repo_status: Dict[str, Any]) -> Dict[str, Any]:
        """Merge PR analysis with repository context"""
        merged_analysis = pr_analysis.copy()
        
        # Add repository context information
        merged_analysis['repository_context'] = {
            'has_context': repo_context is not None,
            'context_status': repo_status,
            'context_summary': {}
        }
        
        if repo_context:
            merged_analysis['repository_context']['context_summary'] = {
                'analysis_date': repo_context.get('analysis_date'),
                'document_count': len(repo_context.get('security_documents', [])),
                'primary_languages': repo_context.get('repo_info', {}).get('primary_languages', []),
                'security_summary': repo_context.get('security_summary', {}),
                'searchable': repo_context.get('searchable', False)
            }
            
            # Enhance file analysis with repository context
            self._enhance_file_analysis_with_context(merged_analysis, repo_context)
            
            # Enhance security changes with repository context
            self._enhance_security_changes_with_context(merged_analysis, repo_context)
        
        return merged_analysis
    
    def _enhance_file_analysis_with_context(self, pr_analysis: Dict[str, Any], repo_context: Dict[str, Any]):
        """Enhance file analysis with repository context"""
        file_analysis = pr_analysis.get('file_analysis', {})
        security_files = file_analysis.get('security_relevant_files', [])
        
        # Get repository security documents for context
        repo_docs = repo_context.get('security_documents', [])
        
        for file_info in security_files:
            filename = file_info.get('filename', '')
            
            # Check if this file is mentioned in existing security documentation
            file_info['mentioned_in_repo_docs'] = []
            for doc in repo_docs:
                if filename in doc.get('content_preview', ''):
                    file_info['mentioned_in_repo_docs'].append({
                        'doc_id': doc['id'],
                        'doc_title': doc['title'],
                        'doc_scope': doc['scope']
                    })
            
            # Enhance risk assessment based on repository context
            if file_info['mentioned_in_repo_docs']:
                file_info['context_enhanced_risk'] = self._calculate_context_enhanced_risk(
                    file_info, file_info['mentioned_in_repo_docs']
                )
            else:
                file_info['context_enhanced_risk'] = file_info.get('risk_level', 'low')
    
    def _enhance_security_changes_with_context(self, pr_analysis: Dict[str, Any], repo_context: Dict[str, Any]):
        """Enhance security changes analysis with repository context"""
        security_changes = pr_analysis.get('security_changes', {})
        
        # Add context about what security patterns exist in the repository
        repo_summary = repo_context.get('security_summary', {})
        security_changes['repository_security_context'] = {
            'existing_security_topics': repo_summary.get('key_topics', []),
            'existing_risk_indicators': repo_summary.get('risk_indicators', []),
            'document_types': repo_summary.get('document_types', {})
        }
        
        # Analyze how PR changes relate to existing security documentation
        patterns_found = security_changes.get('patterns_found', {})
        existing_topics = repo_summary.get('key_topics', [])
        
        security_changes['context_analysis'] = {
            'new_security_patterns': [],
            'modified_existing_patterns': [],
            'potential_conflicts': []
        }
        
        for category, patterns in patterns_found.items():
            if patterns:
                # Check if these patterns are new or modify existing ones
                category_lower = category.lower()
                if any(topic.lower() in category_lower or category_lower in topic.lower() 
                      for topic in existing_topics):
                    security_changes['context_analysis']['modified_existing_patterns'].append({
                        'category': category,
                        'patterns': patterns,
                        'existing_context': 'Found in existing security documentation'
                    })
                else:
                    security_changes['context_analysis']['new_security_patterns'].append({
                        'category': category,
                        'patterns': patterns,
                        'context': 'New security pattern not previously documented'
                    })
    
    def _generate_contextual_assessment(self, pr_analysis: Dict[str, Any], 
                                      repo_context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate contextual security assessment"""
        assessment = {
            'context_availability': repo_context is not None,
            'assessment_confidence': 'low',
            'contextual_risk_level': 'unknown',
            'context_insights': []
        }
        
        if not repo_context:
            assessment['context_insights'].append(
                "No repository security context available - analysis limited to PR changes only"
            )
            assessment['contextual_risk_level'] = pr_analysis.get('overall_assessment', {}).get('overall_risk_level', 'unknown')
            return assessment
        
        # High confidence assessment with context
        assessment['assessment_confidence'] = 'high'
        
        # Analyze contextual risk
        pr_risk = pr_analysis.get('overall_assessment', {}).get('overall_risk_level', 'low')
        repo_risk_indicators = repo_context.get('security_summary', {}).get('risk_indicators', [])
        
        # Calculate contextual risk level
        risk_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        pr_risk_score = risk_levels.get(pr_risk, 1)
        
        # Increase risk if PR affects areas with existing high risk
        if repo_risk_indicators and any(risk in ['high', 'critical'] for risk in repo_risk_indicators):
            pr_risk_score = min(4, pr_risk_score + 1)
            assessment['context_insights'].append(
                "PR affects repository areas with existing high-risk security indicators"
            )
        
        # Check if PR introduces new security patterns
        security_changes = pr_analysis.get('security_changes', {})
        context_analysis = security_changes.get('context_analysis', {})
        
        if context_analysis.get('new_security_patterns'):
            assessment['context_insights'].append(
                f"PR introduces {len(context_analysis['new_security_patterns'])} new security patterns"
            )
        
        if context_analysis.get('modified_existing_patterns'):
            pr_risk_score = min(4, pr_risk_score + 1)
            assessment['context_insights'].append(
                f"PR modifies {len(context_analysis['modified_existing_patterns'])} existing security patterns"
            )
        
        # Convert back to risk level
        assessment['contextual_risk_level'] = {v: k for k, v in risk_levels.items()}[pr_risk_score]
        
        return assessment
    
    def _generate_contextual_recommendations(self, pr_analysis: Dict[str, Any], 
                                           repo_context: Optional[Dict[str, Any]]) -> List[str]:
        """Generate context-aware recommendations"""
        recommendations = []
        
        if not repo_context:
            recommendations.append("Consider running full repository security analysis first for better context")
            recommendations.extend(pr_analysis.get('overall_assessment', {}).get('recommendations', []))
            return recommendations
        
        # Context-aware recommendations
        contextual_assessment = pr_analysis.get('contextual_assessment', {})
        
        if contextual_assessment.get('contextual_risk_level') in ['high', 'critical']:
            recommendations.append("High-risk changes detected - require thorough security review")
        
        # Recommendations based on context analysis
        security_changes = pr_analysis.get('security_changes', {})
        context_analysis = security_changes.get('context_analysis', {})
        
        if context_analysis.get('new_security_patterns'):
            recommendations.append("New security patterns introduced - ensure they align with existing security architecture")
        
        if context_analysis.get('modified_existing_patterns'):
            recommendations.append("Existing security patterns modified - verify compatibility with current security model")
        
        # File-specific recommendations
        file_analysis = pr_analysis.get('file_analysis', {})
        for file_info in file_analysis.get('security_relevant_files', []):
            if file_info.get('mentioned_in_repo_docs'):
                recommendations.append(
                    f"File {file_info['filename']} is referenced in existing security documentation - "
                    "review for consistency"
                )
        
        # Repository-specific recommendations
        repo_summary = repo_context.get('security_summary', {})
        if repo_summary.get('key_topics'):
            recommendations.append(
                f"Consider impact on existing security topics: {', '.join(repo_summary['key_topics'][:3])}"
            )
        
        return recommendations
    
    def _extract_search_queries_from_pr(self, pr_analysis: Dict[str, Any]) -> List[str]:
        """Extract relevant search queries from PR analysis"""
        queries = []
        
        # Extract from file names
        file_analysis = pr_analysis.get('file_analysis', {})
        for file_info in file_analysis.get('security_relevant_files', []):
            filename = file_info.get('filename', '')
            # Extract meaningful terms from filename
            filename_terms = filename.replace('/', ' ').replace('_', ' ').replace('.', ' ').split()
            for term in filename_terms:
                if len(term) > 3 and term.lower() not in ['test', 'spec', 'mock']:
                    queries.append(term)
        
        # Extract from security categories
        for category, files in file_analysis.get('file_categories', {}).items():
            if files:
                queries.append(category)
        
        # Extract from security patterns
        security_changes = pr_analysis.get('security_changes', {})
        for category, patterns in security_changes.get('patterns_found', {}).items():
            if patterns:
                queries.append(category)
                # Add specific patterns as queries
                for pattern_info in patterns[:2]:  # Limit to avoid too many queries
                    if isinstance(pattern_info, dict):
                        queries.append(pattern_info.get('pattern', ''))
                    else:
                        queries.append(str(pattern_info))
        
        # Clean and deduplicate queries
        clean_queries = []
        for query in queries:
            query = query.strip().lower()
            if len(query) > 2 and query not in clean_queries:
                clean_queries.append(query)
        
        return clean_queries[:10]  # Limit to 10 queries
    
    def _calculate_context_enhanced_risk(self, file_info: Dict[str, Any], 
                                       mentioned_docs: List[Dict[str, Any]]) -> str:
        """Calculate enhanced risk level based on repository context"""
        base_risk = file_info.get('risk_level', 'low')
        risk_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        
        risk_score = risk_levels.get(base_risk, 1)
        
        # Increase risk if file is mentioned in multiple security documents
        if len(mentioned_docs) > 1:
            risk_score = min(4, risk_score + 1)
        
        # Increase risk if mentioned in high-scope documents
        for doc in mentioned_docs:
            if doc.get('doc_scope') == 'full_repo':
                risk_score = min(4, risk_score + 1)
                break
        
        return {v: k for k, v in risk_levels.items()}[risk_score]
    
    def _generate_executive_summary(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of the analysis"""
        pr_info = analysis.get('pr_info', {})
        overall_assessment = analysis.get('overall_assessment', {})
        contextual_assessment = analysis.get('contextual_assessment', {})
        
        return {
            'pr_title': pr_info.get('title', ''),
            'pr_author': pr_info.get('author', ''),
            'risk_level': contextual_assessment.get('contextual_risk_level', 'unknown'),
            'confidence': contextual_assessment.get('assessment_confidence', 'low'),
            'security_files_changed': overall_assessment.get('security_file_count', 0),
            'requires_security_review': overall_assessment.get('requires_security_review', False),
            'has_repository_context': contextual_assessment.get('context_availability', False),
            'key_concerns': contextual_assessment.get('context_insights', [])[:3]
        }
    
    def _assess_security_impact(self, analysis: Dict[str, Any], 
                              related_knowledge: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall security impact"""
        impact_assessment = {
            'impact_level': 'low',
            'affected_security_areas': [],
            'potential_vulnerabilities': [],
            'mitigation_priority': 'low'
        }
        
        # Analyze impact based on file changes
        file_analysis = analysis.get('file_analysis', {})
        for category, files in file_analysis.get('file_categories', {}).items():
            if files:
                impact_assessment['affected_security_areas'].append(category)
        
        # Analyze impact based on related knowledge
        for knowledge_item in related_knowledge:
            if knowledge_item.get('relevance_score', 0) > 0.7:
                impact_assessment['potential_vulnerabilities'].append({
                    'area': knowledge_item.get('title', ''),
                    'relevance': knowledge_item.get('relevance_score', 0)
                })
        
        # Determine overall impact level
        contextual_risk = analysis.get('contextual_assessment', {}).get('contextual_risk_level', 'low')
        if contextual_risk in ['high', 'critical']:
            impact_assessment['impact_level'] = 'high'
            impact_assessment['mitigation_priority'] = 'high'
        elif contextual_risk == 'medium':
            impact_assessment['impact_level'] = 'medium'
            impact_assessment['mitigation_priority'] = 'medium'
        
        return impact_assessment
    
    def _generate_detailed_findings(self, analysis: Dict[str, Any], 
                                  related_knowledge: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate detailed security findings"""
        findings = []
        
        # Findings from file analysis
        file_analysis = analysis.get('file_analysis', {})
        for file_info in file_analysis.get('security_relevant_files', []):
            if file_info.get('risk_level') in ['medium', 'high', 'critical']:
                finding = {
                    'type': 'file_change',
                    'severity': file_info.get('risk_level', 'low'),
                    'title': f"Security-relevant changes in {file_info.get('filename', '')}",
                    'description': f"File contains {file_info.get('additions', 0)} additions and "
                                 f"{file_info.get('deletions', 0)} deletions in security-sensitive areas",
                    'categories': file_info.get('security_categories', []),
                    'recommendations': []
                }
                
                if file_info.get('mentioned_in_repo_docs'):
                    finding['recommendations'].append(
                        "Review changes against existing security documentation"
                    )
                
                findings.append(finding)
        
        # Findings from security pattern analysis
        security_changes = analysis.get('security_changes', {})
        context_analysis = security_changes.get('context_analysis', {})
        
        if context_analysis.get('new_security_patterns'):
            findings.append({
                'type': 'new_security_pattern',
                'severity': 'medium',
                'title': 'New security patterns introduced',
                'description': f"PR introduces {len(context_analysis['new_security_patterns'])} "
                             "new security patterns not previously documented",
                'patterns': context_analysis['new_security_patterns'],
                'recommendations': ['Ensure new patterns follow security best practices']
            })
        
        return findings
    
    def _generate_action_items(self, analysis: Dict[str, Any], 
                             related_knowledge: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate actionable items for security review"""
        action_items = []
        
        contextual_assessment = analysis.get('contextual_assessment', {})
        
        # High-priority actions for high-risk changes
        if contextual_assessment.get('contextual_risk_level') in ['high', 'critical']:
            action_items.append({
                'priority': 'high',
                'action': 'Conduct thorough security review',
                'description': 'High-risk security changes detected requiring expert review',
                'assignee': 'security_team'
            })
        
        # Actions based on file changes
        file_analysis = analysis.get('file_analysis', {})
        if file_analysis.get('file_categories', {}).get('authentication'):
            action_items.append({
                'priority': 'high',
                'action': 'Review authentication changes',
                'description': 'Verify authentication mechanisms remain secure',
                'assignee': 'security_reviewer'
            })
        
        # Actions based on related knowledge
        if related_knowledge:
            action_items.append({
                'priority': 'medium',
                'action': 'Review related security documentation',
                'description': f'Check {len(related_knowledge)} related security documents for consistency',
                'assignee': 'code_reviewer'
            })
        
        # General actions
        if not contextual_assessment.get('context_availability'):
            action_items.append({
                'priority': 'low',
                'action': 'Generate repository security baseline',
                'description': 'Run full repository analysis to improve future PR reviews',
                'assignee': 'security_team'
            })
        
        return action_items