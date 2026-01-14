"""
Security Search Service

Provides advanced search capabilities for security content with OWASP-aware
filtering, pattern recognition, and semantic search functionality.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta

from api.security_indexing import security_indexer, SearchableContent, SecurityPattern
from api.security_pattern_recognition import security_pattern_recognizer

logger = logging.getLogger(__name__)

class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class OWASPCategory(Enum):
    INJECTION = "Injection"
    BROKEN_AUTHENTICATION = "Broken Authentication"
    SENSITIVE_DATA_EXPOSURE = "Sensitive Data Exposure"
    XML_EXTERNAL_ENTITIES = "XML External Entities"
    BROKEN_ACCESS_CONTROL = "Broken Access Control"
    SECURITY_MISCONFIGURATION = "Security Misconfiguration"
    CROSS_SITE_SCRIPTING = "Cross-Site Scripting"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    KNOWN_VULNERABILITIES = "Using Components with Known Vulnerabilities"
    INSUFFICIENT_LOGGING = "Insufficient Logging & Monitoring"

@dataclass
class SecurityFilter:
    """Filter criteria for security searches"""
    filter_type: str
    values: List[str]

@dataclass
class DateRange:
    """Date range for filtering"""
    start_date: datetime
    end_date: datetime

@dataclass
class SearchQuery:
    """Comprehensive search query structure"""
    text: str
    filters: List[SecurityFilter]
    owasp_categories: List[OWASPCategory]
    severity_levels: List[SeverityLevel]
    date_range: Optional[DateRange] = None
    limit: int = 50
    offset: int = 0

@dataclass
class SearchResult:
    """Individual search result"""
    wiki_id: str
    title: str
    snippet: str
    relevance_score: float
    threat_count: int
    mitigation_count: int
    owasp_categories: List[str]
    security_patterns: List[SecurityPattern]
    last_updated: datetime

@dataclass
class SecuritySearchResults:
    """Complete search results with metadata"""
    results: List[SearchResult]
    total_count: int
    query_time_ms: int
    facets: Dict[str, Dict[str, int]]
    suggestions: List[str]

class SecuritySearchService:
    """Main service for security content search"""
    
    def __init__(self):
        self.indexer = security_indexer
    
    def search_wikis(self, query: SearchQuery) -> SecuritySearchResults:
        """Perform comprehensive security wiki search"""
        start_time = datetime.now()
        
        try:
            # Build search filters
            search_filters = self._build_search_filters(query)
            
            # Perform the search
            raw_results = self.indexer.search_content(query.text, search_filters)
            
            # Convert to search results
            results = []
            for wiki_id, score in raw_results[query.offset:query.offset + query.limit]:
                result = self._build_search_result(wiki_id, score, query.text)
                if result:
                    results.append(result)
            
            # Generate facets
            facets = self._generate_facets(raw_results)
            
            # Generate suggestions
            suggestions = self._generate_suggestions(query.text)
            
            query_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return SecuritySearchResults(
                results=results,
                total_count=len(raw_results),
                query_time_ms=query_time,
                facets=facets,
                suggestions=suggestions
            )
            
        except Exception as e:
            logger.error(f"Search failed for query '{query.text}': {e}")
            return SecuritySearchResults(
                results=[],
                total_count=0,
                query_time_ms=0,
                facets={},
                suggestions=[]
            )
    
    def _build_search_filters(self, query: SearchQuery) -> Dict:
        """Build search filters from query"""
        filters = {}
        
        # OWASP category filters
        if query.owasp_categories:
            filters["owasp_categories"] = [cat.value for cat in query.owasp_categories]
        
        # Security tag filters from custom filters
        security_tags = []
        for filter_item in query.filters:
            if filter_item.filter_type == "security_tags":
                security_tags.extend(filter_item.values)
            elif filter_item.filter_type == "severity":
                security_tags.extend([f"severity_{level}" for level in filter_item.values])
        
        if security_tags:
            filters["security_tags"] = security_tags
        
        return filters
    
    def _build_search_result(self, wiki_id: str, score: float, query_text: str) -> Optional[SearchResult]:
        """Build a search result from indexed content"""
        try:
            # Get indexed content
            content = self.indexer.get_indexed_content(wiki_id)
            if not content:
                return None
            
            # Generate snippet
            snippet = self._generate_snippet(content.full_text_index, query_text)
            
            # Count threats and mitigations
            threat_count = len(content.threat_keywords)
            mitigation_count = len(content.mitigation_keywords)
            
            # Extract OWASP categories
            owasp_categories = [kw for kw in content.owasp_keywords 
                             if kw.title() in [cat.value for cat in OWASPCategory]]
            
            return SearchResult(
                wiki_id=wiki_id,
                title=f"Security Wiki {wiki_id}",  # Would get from main wiki data
                snippet=snippet,
                relevance_score=score,
                threat_count=threat_count,
                mitigation_count=mitigation_count,
                owasp_categories=owasp_categories,
                security_patterns=content.patterns,
                last_updated=content.indexed_at
            )
            
        except Exception as e:
            logger.error(f"Failed to build search result for {wiki_id}: {e}")
            return None
    
    def _generate_snippet(self, full_text: str, query_text: str, max_length: int = 200) -> str:
        """Generate a relevant snippet from the full text"""
        query_terms = query_text.lower().split()
        text_lower = full_text.lower()
        
        # Find the best position to start the snippet
        best_pos = 0
        best_score = 0
        
        for i in range(0, len(full_text) - max_length, 20):
            window = text_lower[i:i + max_length]
            score = sum(1 for term in query_terms if term in window)
            if score > best_score:
                best_score = score
                best_pos = i
        
        # Extract snippet
        snippet = full_text[best_pos:best_pos + max_length]
        
        # Clean up snippet boundaries
        if best_pos > 0:
            snippet = "..." + snippet
        if best_pos + max_length < len(full_text):
            snippet = snippet + "..."
        
        return snippet.strip()
    
    def _generate_facets(self, raw_results: List[Tuple[str, float]]) -> Dict[str, Dict[str, int]]:
        """Generate search facets for filtering"""
        facets = {
            "owasp_categories": {},
            "security_patterns": {},
            "severity_levels": {}
        }
        
        for wiki_id, _ in raw_results:
            content = self.indexer.get_indexed_content(wiki_id)
            if not content:
                continue
            
            # OWASP category facets
            for keyword in content.owasp_keywords:
                if keyword.title() in [cat.value for cat in OWASPCategory]:
                    facets["owasp_categories"][keyword] = facets["owasp_categories"].get(keyword, 0) + 1
            
            # Security pattern facets
            for pattern in content.patterns:
                pattern_name = pattern.pattern_name
                facets["security_patterns"][pattern_name] = facets["security_patterns"].get(pattern_name, 0) + 1
            
            # Severity level facets
            for tag in content.security_tags:
                if tag.startswith("severity_"):
                    severity = tag.replace("severity_", "")
                    facets["severity_levels"][severity] = facets["severity_levels"].get(severity, 0) + 1
        
        return facets
    
    def _generate_suggestions(self, query_text: str) -> List[str]:
        """Generate search suggestions based on query"""
        suggestions = []
        
        # Common security search suggestions
        common_suggestions = [
            "SQL injection vulnerabilities",
            "Cross-site scripting (XSS)",
            "Authentication bypass",
            "Access control issues",
            "Data encryption",
            "Input validation",
            "Session management",
            "OWASP Top 10"
        ]
        
        # Filter suggestions based on query
        query_lower = query_text.lower()
        for suggestion in common_suggestions:
            if any(term in suggestion.lower() for term in query_lower.split()):
                suggestions.append(suggestion)
        
        # Add pattern-based suggestions
        if "injection" in query_lower:
            suggestions.extend(["SQL injection", "Command injection", "LDAP injection"])
        elif "xss" in query_lower or "script" in query_lower:
            suggestions.extend(["Stored XSS", "Reflected XSS", "DOM-based XSS"])
        elif "auth" in query_lower:
            suggestions.extend(["Multi-factor authentication", "Session fixation", "Credential stuffing"])
        
        return suggestions[:5]  # Limit to 5 suggestions
    
    def filter_by_owasp(self, category: OWASPCategory) -> List[str]:
        """Filter wikis by OWASP category"""
        filters = {"owasp_categories": [category.value]}
        results = self.indexer.search_content("", filters)
        return [wiki_id for wiki_id, _ in results]
    
    def find_patterns(self, pattern_criteria: Dict) -> List[SecurityPattern]:
        """Find security patterns matching criteria"""
        # Get patterns from the pattern recognizer
        if pattern_criteria.get("type") == "recurring":
            # Get recurring patterns
            time_window = pattern_criteria.get("time_window_days", 30)
            recurring_patterns = security_pattern_recognizer.identify_recurring_patterns(time_window)
            
            # Convert to SecurityPattern objects
            patterns = []
            for recurring in recurring_patterns:
                pattern = SecurityPattern(
                    pattern_type="recurring",
                    pattern_name=recurring.pattern_signature,
                    description=f"Recurring pattern found in {len(recurring.affected_wikis)} wikis. {recurring.common_context}",
                    severity=self._risk_score_to_severity(recurring.risk_score),
                    owasp_category="Multiple",
                    keywords=recurring.pattern_variations,
                    confidence_score=recurring.risk_score
                )
                patterns.append(pattern)
            return patterns
        
        elif pattern_criteria.get("type") == "vulnerability":
            # Get vulnerability patterns from recent analyses
            all_patterns = []
            
            # Get pattern summary from indexer
            pattern_summary = self.indexer.get_security_patterns_summary()
            
            # Filter patterns based on criteria
            severity = pattern_criteria.get("severity")
            owasp_category = pattern_criteria.get("owasp_category")
            
            # Get detailed patterns from pattern recognizer database
            import sqlite3
            with sqlite3.connect(security_pattern_recognizer.db_path) as conn:
                query = """
                    SELECT DISTINCT pattern_name, pattern_type, severity, owasp_category, 
                           AVG(confidence_score) as avg_confidence, COUNT(*) as occurrence_count
                    FROM pattern_occurrences 
                    WHERE 1=1
                """
                params = []
                
                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                
                if owasp_category:
                    query += " AND owasp_category = ?"
                    params.append(owasp_category)
                
                query += " GROUP BY pattern_name, pattern_type, severity, owasp_category"
                
                cursor = conn.execute(query, params)
                
                for row in cursor.fetchall():
                    pattern_name, pattern_type, sev, owasp_cat, confidence, count = row
                    
                    pattern = SecurityPattern(
                        pattern_type=pattern_type,
                        pattern_name=pattern_name,
                        description=f"Vulnerability pattern found {count} times across repositories",
                        severity=sev,
                        owasp_category=owasp_cat,
                        keywords=[],
                        confidence_score=confidence
                    )
                    all_patterns.append(pattern)
            
            return all_patterns
        
        else:
            # Fallback to original implementation
            all_patterns = []
            
            # Get pattern summary
            pattern_summary = self.indexer.get_security_patterns_summary()
            
            # Filter patterns based on criteria
            pattern_type = pattern_criteria.get("type")
            severity = pattern_criteria.get("severity")
            owasp_category = pattern_criteria.get("owasp_category")
            
            # This would typically query the database for detailed pattern information
            # For now, we'll return a summary based on the pattern counts
            for pattern_name, count in pattern_summary.items():
                # Create a representative pattern (in real implementation, 
                # this would come from the database)
                pattern = SecurityPattern(
                    pattern_type="vulnerability",  # Would be determined from data
                    pattern_name=pattern_name,
                    description=f"Pattern found {count} times across wikis",
                    severity="medium",  # Would be determined from data
                    owasp_category="Unknown",  # Would be determined from data
                    keywords=[],
                    confidence_score=0.8
                )
                
                # Apply filters
                if pattern_type and pattern.pattern_type != pattern_type:
                    continue
                if severity and pattern.severity != severity:
                    continue
                if owasp_category and pattern.owasp_category != owasp_category:
                    continue
                
                all_patterns.append(pattern)
            
            return all_patterns
    
    def rank_by_relevance(self, results: List[SearchResult]) -> List[SearchResult]:
        """Rank search results by relevance"""
        def relevance_key(result: SearchResult) -> float:
            # Base score from search
            score = result.relevance_score
            
            # Boost for recent updates
            days_old = (datetime.now() - result.last_updated).days
            recency_boost = max(0, 1.0 - (days_old / 365))  # Decay over a year
            
            # Boost for security pattern matches
            pattern_boost = len(result.security_patterns) * 0.1
            
            # Boost for OWASP category matches
            owasp_boost = len(result.owasp_categories) * 0.05
            
            return score + (recency_boost * 0.2) + pattern_boost + owasp_boost
        
        return sorted(results, key=relevance_key, reverse=True)
    
    def get_search_analytics(self) -> Dict:
        """Get search analytics and statistics"""
        pattern_summary = self.indexer.get_security_patterns_summary()
        
        # Get pattern recognition statistics
        pattern_stats = security_pattern_recognizer.get_pattern_statistics()
        
        # Get emerging threat trends
        emerging_trends = security_pattern_recognizer.analyze_emerging_threats(30)
        
        # Get recurring patterns
        recurring_patterns = security_pattern_recognizer.identify_recurring_patterns(30)
        
        return {
            "total_indexed_wikis": self._get_total_indexed_wikis(),
            "security_patterns": pattern_summary,
            "top_owasp_categories": self._get_top_owasp_categories(),
            "search_performance": {
                "average_query_time_ms": 150,  # Would be calculated from metrics
                "cache_hit_rate": 0.85
            },
            "pattern_recognition": {
                "total_patterns_detected": pattern_stats.get("total_patterns", 0),
                "patterns_by_type": pattern_stats.get("patterns_by_type", {}),
                "top_patterns": pattern_stats.get("top_patterns", {}),
                "vulnerability_patterns_loaded": pattern_stats.get("vulnerability_patterns_loaded", 0)
            },
            "emerging_threats": [
                {
                    "pattern_name": trend.pattern_name,
                    "growth_rate": trend.growth_rate,
                    "occurrence_count": trend.occurrence_count,
                    "affected_repositories": len(trend.affected_repositories)
                }
                for trend in emerging_trends[:5]  # Top 5 emerging threats
            ],
            "recurring_patterns": [
                {
                    "pattern_signature": pattern.pattern_signature,
                    "occurrence_count": pattern.occurrence_count,
                    "risk_score": pattern.risk_score,
                    "trend_direction": pattern.trend_direction,
                    "affected_wikis": len(pattern.affected_wikis)
                }
                for pattern in recurring_patterns[:5]  # Top 5 recurring patterns
            ]
        }
    
    def _risk_score_to_severity(self, risk_score: float) -> str:
        """Convert risk score to severity level"""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        else:
            return "low"
    
    def _get_total_indexed_wikis(self) -> int:
        """Get total number of indexed wikis"""
        import sqlite3
        with sqlite3.connect(self.indexer.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM security_index")
            return cursor.fetchone()[0]
    
    def _get_top_owasp_categories(self) -> Dict[str, int]:
        """Get top OWASP categories by frequency"""
        category_counts = {}
        
        import sqlite3
        with sqlite3.connect(self.indexer.db_path) as conn:
            cursor = conn.execute("SELECT owasp_keywords FROM security_index")
            
            for (keywords_json,) in cursor.fetchall():
                import json
                keywords = json.loads(keywords_json)
                for keyword in keywords:
                    if keyword.title() in [cat.value for cat in OWASPCategory]:
                        category_counts[keyword] = category_counts.get(keyword, 0) + 1
        
        # Return top 10
        return dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:10])

# Global search service instance
security_search_service = SecuritySearchService()