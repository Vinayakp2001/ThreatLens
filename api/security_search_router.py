"""
Security Search API Router

Provides REST API endpoints for security content search functionality.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

from api.security_search import (
    SecuritySearchService, SearchQuery, SecurityFilter, 
    OWASPCategory, SeverityLevel, DateRange, security_search_service
)
from security_pattern_recognition import security_pattern_recognizer
from security_pattern_recognition import security_pattern_recognizer

router = APIRouter(prefix="/api/security/search", tags=["Security Search"])

# Request/Response Models
class SearchFilterModel(BaseModel):
    filter_type: str = Field(..., description="Type of filter (security_tags, severity, etc.)")
    values: List[str] = Field(..., description="Filter values")

class DateRangeModel(BaseModel):
    start_date: datetime
    end_date: datetime

class SearchQueryModel(BaseModel):
    text: str = Field(..., description="Search query text")
    filters: List[SearchFilterModel] = Field(default=[], description="Search filters")
    owasp_categories: List[str] = Field(default=[], description="OWASP categories to filter by")
    severity_levels: List[str] = Field(default=[], description="Severity levels to filter by")
    date_range: Optional[DateRangeModel] = Field(None, description="Date range filter")
    limit: int = Field(default=50, ge=1, le=100, description="Maximum results to return")
    offset: int = Field(default=0, ge=0, description="Results offset for pagination")

class SecurityPatternResponse(BaseModel):
    pattern_type: str
    pattern_name: str
    description: str
    severity: str
    owasp_category: str
    keywords: List[str]
    confidence_score: float

class SearchResultResponse(BaseModel):
    wiki_id: str
    title: str
    snippet: str
    relevance_score: float
    threat_count: int
    mitigation_count: int
    owasp_categories: List[str]
    security_patterns: List[SecurityPatternResponse]
    last_updated: datetime

class SearchResultsResponse(BaseModel):
    results: List[SearchResultResponse]
    total_count: int
    query_time_ms: int
    facets: Dict[str, Dict[str, int]]
    suggestions: List[str]

class PatternTrendResponse(BaseModel):
    pattern_name: str
    time_period: str
    occurrence_count: int
    growth_rate: float
    severity_distribution: Dict[str, int]
    affected_repositories: List[str]
    first_seen: datetime
    last_seen: datetime

class RecurringPatternResponse(BaseModel):
    pattern_signature: str
    occurrence_count: int
    affected_wikis: List[str]
    pattern_variations: List[str]
    common_context: str
    risk_score: float
    trend_direction: str

class PatternCriteriaModel(BaseModel):
    type: Optional[str] = Field(None, description="Pattern type filter")
    severity: Optional[str] = Field(None, description="Severity filter")
    owasp_category: Optional[str] = Field(None, description="OWASP category filter")

class VulnerabilityAnalysisRequest(BaseModel):
    wiki_id: str = Field(..., description="Wiki ID for analysis")
    content: str = Field(..., description="Wiki content to analyze for vulnerabilities")

def get_search_service() -> SecuritySearchService:
    """Dependency to get search service instance"""
    return security_search_service

@router.post("/wikis", response_model=SearchResultsResponse)
async def search_security_wikis(
    query: SearchQueryModel,
    search_service: SecuritySearchService = Depends(get_search_service)
):
    """
    Search security wikis with advanced filtering and ranking.
    
    Supports full-text search across security content with OWASP-aware indexing,
    pattern recognition, and semantic search capabilities.
    """
    try:
        # Convert request model to internal query
        search_query = SearchQuery(
            text=query.text,
            filters=[
                SecurityFilter(filter_type=f.filter_type, values=f.values)
                for f in query.filters
            ],
            owasp_categories=[
                OWASPCategory(cat) for cat in query.owasp_categories
                if cat in [c.value for c in OWASPCategory]
            ],
            severity_levels=[
                SeverityLevel(level) for level in query.severity_levels
                if level in [s.value for s in SeverityLevel]
            ],
            date_range=DateRange(
                start_date=query.date_range.start_date,
                end_date=query.date_range.end_date
            ) if query.date_range else None,
            limit=query.limit,
            offset=query.offset
        )
        
        # Perform search
        results = search_service.search_wikis(search_query)
        
        # Convert to response model
        return SearchResultsResponse(
            results=[
                SearchResultResponse(
                    wiki_id=result.wiki_id,
                    title=result.title,
                    snippet=result.snippet,
                    relevance_score=result.relevance_score,
                    threat_count=result.threat_count,
                    mitigation_count=result.mitigation_count,
                    owasp_categories=result.owasp_categories,
                    security_patterns=[
                        SecurityPatternResponse(
                            pattern_type=pattern.pattern_type,
                            pattern_name=pattern.pattern_name,
                            description=pattern.description,
                            severity=pattern.severity,
                            owasp_category=pattern.owasp_category,
                            keywords=pattern.keywords,
                            confidence_score=pattern.confidence_score
                        )
                        for pattern in result.security_patterns
                    ],
                    last_updated=result.last_updated
                )
                for result in results.results
            ],
            total_count=results.total_count,
            query_time_ms=results.query_time_ms,
            facets=results.facets,
            suggestions=results.suggestions
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

@router.get("/owasp/{category}", response_model=List[str])
async def filter_by_owasp_category(
    category: str,
    search_service: SecuritySearchService = Depends(get_search_service)
):
    """
    Filter security wikis by OWASP category.
    
    Returns a list of wiki IDs that contain content related to the specified
    OWASP category.
    """
    try:
        # Validate OWASP category
        owasp_category = None
        for cat in OWASPCategory:
            if cat.value.lower().replace(" ", "_") == category.lower():
                owasp_category = cat
                break
        
        if not owasp_category:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid OWASP category: {category}"
            )
        
        wiki_ids = search_service.filter_by_owasp(owasp_category)
        return wiki_ids
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OWASP filtering failed: {str(e)}")

@router.post("/patterns", response_model=List[SecurityPatternResponse])
async def find_security_patterns(
    criteria: PatternCriteriaModel,
    search_service: SecuritySearchService = Depends(get_search_service)
):
    """
    Find security patterns matching the specified criteria.
    
    Identifies recurring security patterns across repositories based on
    pattern type, severity, and OWASP category filters.
    """
    try:
        # Convert criteria to dict
        pattern_criteria = {}
        if criteria.type:
            pattern_criteria["type"] = criteria.type
        if criteria.severity:
            pattern_criteria["severity"] = criteria.severity
        if criteria.owasp_category:
            pattern_criteria["owasp_category"] = criteria.owasp_category
        
        patterns = search_service.find_patterns(pattern_criteria)
        
        return [
            SecurityPatternResponse(
                pattern_type=pattern.pattern_type,
                pattern_name=pattern.pattern_name,
                description=pattern.description,
                severity=pattern.severity,
                owasp_category=pattern.owasp_category,
                keywords=pattern.keywords,
                confidence_score=pattern.confidence_score
            )
            for pattern in patterns
        ]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pattern search failed: {str(e)}")

@router.get("/analytics", response_model=Dict[str, Any])
async def get_search_analytics(
    search_service: SecuritySearchService = Depends(get_search_service)
):
    """
    Get search analytics and statistics.
    
    Provides insights into indexed content, security patterns, OWASP categories,
    and search performance metrics.
    """
    try:
        analytics = search_service.get_search_analytics()
        return analytics
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analytics retrieval failed: {str(e)}")

@router.get("/suggestions")
async def get_search_suggestions(
    query: str = Query(..., description="Partial search query for suggestions"),
    limit: int = Query(default=5, ge=1, le=10, description="Maximum suggestions to return")
):
    """
    Get search suggestions based on partial query.
    
    Provides intelligent search suggestions to help users discover relevant
    security content and common search patterns.
    """
    try:
        # For now, return static suggestions based on query
        # In a full implementation, this would use ML or query logs
        suggestions = []
        
        query_lower = query.lower()
        
        # Common security terms and their expansions
        suggestion_map = {
            "sql": ["SQL injection", "SQL injection prevention", "SQL parameterized queries"],
            "xss": ["Cross-site scripting", "XSS prevention", "XSS filtering"],
            "auth": ["Authentication", "Authorization", "Multi-factor authentication"],
            "encrypt": ["Encryption", "Data encryption", "Encryption at rest"],
            "owasp": ["OWASP Top 10", "OWASP guidelines", "OWASP compliance"],
            "inject": ["Injection attacks", "Command injection", "LDAP injection"],
            "access": ["Access control", "Privilege escalation", "Access control bypass"]
        }
        
        for term, term_suggestions in suggestion_map.items():
            if term in query_lower:
                suggestions.extend(term_suggestions)
        
        # Remove duplicates and limit results
        unique_suggestions = list(dict.fromkeys(suggestions))[:limit]
        
        return {"suggestions": unique_suggestions}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Suggestion generation failed: {str(e)}")

@router.post("/index/rebuild")
async def rebuild_search_index(
    search_service: SecuritySearchService = Depends(get_search_service)
):
    """
    Rebuild the security search index.
    
    Recreates the search index from scratch. This operation may take some time
    and should be used sparingly in production environments.
    """
    try:
        search_service.indexer.rebuild_index()
        return {"message": "Search index rebuild initiated successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Index rebuild failed: {str(e)}")

@router.get("/owasp/categories")
async def get_owasp_categories():
    """
    Get all available OWASP categories for filtering.
    
    Returns the complete list of OWASP categories that can be used
    for filtering search results.
    """
    return {
        "categories": [
            {
                "value": category.value,
                "key": category.value.lower().replace(" ", "_")
            }
            for category in OWASPCategory
        ]
    }

@router.get("/severity/levels")
async def get_severity_levels():
    """
    Get all available severity levels for filtering.
    
    Returns the complete list of severity levels that can be used
    for filtering search results.
    """
    return {
        "levels": [
            {
                "value": level.value,
                "key": level.value
            }
            for level in SeverityLevel
        ]
    }

# New Pattern Recognition Endpoints

@router.get("/patterns/recurring")
async def get_recurring_patterns(
    time_window_days: int = Query(default=30, ge=1, le=365, description="Time window in days for pattern analysis")
):
    """
    Get recurring security patterns across repositories.
    
    Identifies security patterns that appear multiple times across different
    repositories within the specified time window.
    """
    try:
        patterns = security_pattern_recognizer.identify_recurring_patterns(time_window_days)
        
        return {
            "patterns": [
                {
                    "pattern_signature": pattern.pattern_signature,
                    "occurrence_count": pattern.occurrence_count,
                    "affected_wikis": pattern.affected_wikis,
                    "pattern_variations": pattern.pattern_variations,
                    "common_context": pattern.common_context,
                    "risk_score": pattern.risk_score,
                    "trend_direction": pattern.trend_direction
                }
                for pattern in patterns
            ],
            "analysis_period_days": time_window_days,
            "total_patterns": len(patterns)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Recurring pattern analysis failed: {str(e)}")

@router.get("/patterns/emerging-threats")
async def get_emerging_threats(
    analysis_period_days: int = Query(default=90, ge=7, le=365, description="Analysis period in days")
):
    """
    Analyze trends for emerging security threats.
    
    Identifies security patterns that are showing increasing trends and
    could represent emerging threats.
    """
    try:
        trends = security_pattern_recognizer.analyze_emerging_threats(analysis_period_days)
        
        return {
            "trends": [
                {
                    "pattern_name": trend.pattern_name,
                    "time_period": trend.time_period,
                    "occurrence_count": trend.occurrence_count,
                    "growth_rate": trend.growth_rate,
                    "severity_distribution": trend.severity_distribution,
                    "affected_repositories": trend.affected_repositories,
                    "first_seen": trend.first_seen.isoformat(),
                    "last_seen": trend.last_seen.isoformat()
                }
                for trend in trends
            ],
            "analysis_period_days": analysis_period_days,
            "total_trends": len(trends)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Emerging threat analysis failed: {str(e)}")

@router.post("/patterns/analyze-content")
async def analyze_content_patterns(
    content: str = Field(..., description="Security content to analyze for patterns"),
    wiki_id: str = Field(..., description="Wiki ID for tracking purposes")
):
    """
    Analyze security content for vulnerability patterns.
    
    Scans the provided content against known vulnerability patterns and
    returns matches with confidence scores.
    """
    try:
        patterns = security_pattern_recognizer.match_vulnerability_patterns(content, wiki_id)
        
        return {
            "patterns": [
                {
                    "pattern_type": pattern.pattern_type,
                    "pattern_name": pattern.pattern_name,
                    "description": pattern.description,
                    "severity": pattern.severity,
                    "owasp_category": pattern.owasp_category,
                    "keywords": pattern.keywords,
                    "confidence_score": pattern.confidence_score
                }
                for pattern in patterns
            ],
            "wiki_id": wiki_id,
            "total_patterns_found": len(patterns),
            "analysis_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Content pattern analysis failed: {str(e)}")

@router.get("/patterns/statistics")
async def get_pattern_statistics():
    """
    Get comprehensive pattern recognition statistics.
    
    Provides detailed statistics about pattern recognition performance,
    pattern types, and detection metrics.
    """
    try:
        stats = security_pattern_recognizer.get_pattern_statistics()
        
        return {
            "statistics": stats,
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pattern statistics retrieval failed: {str(e)}")

@router.get("/patterns/vulnerability-types")
async def get_vulnerability_pattern_types():
    """
    Get all available vulnerability pattern types.
    
    Returns information about the vulnerability patterns that the system
    can detect, including their descriptions and OWASP mappings.
    """
    try:
        vulnerability_patterns = security_pattern_recognizer.vulnerability_patterns
        
        return {
            "vulnerability_patterns": [
                {
                    "pattern_id": pattern.pattern_id,
                    "vulnerability_type": pattern.vulnerability_type,
                    "attack_vector": pattern.attack_vector,
                    "description": pattern.description,
                    "owasp_mapping": pattern.owasp_mapping,
                    "confidence_threshold": pattern.confidence_threshold,
                    "mitigation_patterns": pattern.mitigation_patterns
                }
                for pattern in vulnerability_patterns
            ],
            "total_patterns": len(vulnerability_patterns)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Vulnerability pattern types retrieval failed: {str(e)}")

@router.post("/patterns/analyze", response_model=List[SecurityPatternResponse])
async def analyze_vulnerability_patterns(request: VulnerabilityAnalysisRequest):
    """
    Analyze wiki content for vulnerability patterns.
    
    Uses advanced pattern recognition algorithms to identify security
    vulnerabilities and attack vectors in the provided content.
    """
    try:
        patterns = security_pattern_recognizer.match_vulnerability_patterns(
            request.content, request.wiki_id
        )
        
        return [
            SecurityPatternResponse(
                pattern_type=pattern.pattern_type,
                pattern_name=pattern.pattern_name,
                description=pattern.description,
                severity=pattern.severity,
                owasp_category=pattern.owasp_category,
                keywords=pattern.keywords,
                confidence_score=pattern.confidence_score
            )
            for pattern in patterns
        ]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pattern analysis failed: {str(e)}")

@router.get("/patterns/recurring", response_model=List[RecurringPatternResponse])
async def get_recurring_patterns(
    time_window_days: int = Query(default=30, ge=1, le=365, description="Time window in days")
):
    """
    Identify recurring security patterns across repositories.
    
    Analyzes security patterns over the specified time window to identify
    patterns that occur frequently across multiple repositories.
    """
    try:
        patterns = security_pattern_recognizer.identify_recurring_patterns(time_window_days)
        
        return [
            RecurringPatternResponse(
                pattern_signature=pattern.pattern_signature,
                occurrence_count=pattern.occurrence_count,
                affected_wikis=pattern.affected_wikis,
                pattern_variations=pattern.pattern_variations,
                common_context=pattern.common_context,
                risk_score=pattern.risk_score,
                trend_direction=pattern.trend_direction
            )
            for pattern in patterns
        ]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Recurring pattern analysis failed: {str(e)}")

@router.get("/patterns/trends", response_model=List[PatternTrendResponse])
async def analyze_emerging_threats(
    analysis_period_days: int = Query(default=90, ge=7, le=365, description="Analysis period in days")
):
    """
    Analyze trends for emerging security threats.
    
    Performs trend analysis over the specified period to identify emerging
    security threats and attack patterns.
    """
    try:
        trends = security_pattern_recognizer.analyze_emerging_threats(analysis_period_days)
        
        return [
            PatternTrendResponse(
                pattern_name=trend.pattern_name,
                time_period=trend.time_period,
                occurrence_count=trend.occurrence_count,
                growth_rate=trend.growth_rate,
                severity_distribution=trend.severity_distribution,
                affected_repositories=trend.affected_repositories,
                first_seen=trend.first_seen,
                last_seen=trend.last_seen
            )
            for trend in trends
        ]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat trend analysis failed: {str(e)}")

@router.get("/patterns/statistics", response_model=PatternStatisticsResponse)
async def get_pattern_statistics():
    """
    Get comprehensive pattern recognition statistics.
    
    Provides detailed statistics about security patterns, including
    occurrence counts, types, and trend information.
    """
    try:
        stats = security_pattern_recognizer.get_pattern_statistics()
        
        return PatternStatisticsResponse(
            total_patterns=stats["total_patterns"],
            patterns_by_type=stats["patterns_by_type"],
            top_patterns=stats["top_patterns"],
            recent_trends=stats["recent_trends"],
            vulnerability_patterns_loaded=stats["vulnerability_patterns_loaded"]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Statistics retrieval failed: {str(e)}")