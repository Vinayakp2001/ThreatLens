"""
API router for wiki comparison functionality
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from .wiki_comparison import WikiComparisonEngine, SecurityComparison, SecurityMaturityScore
from .wiki_storage import WikiStorage
from .models import SecurityWiki
from .user_utils import get_current_user
from .security_trend_analysis import SecurityTrendAnalyzer, TrendPeriod

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/wikis", tags=["wiki-comparison"])

# Initialize services
wiki_comparison_engine = WikiComparisonEngine()
wiki_storage = WikiStorage()
trend_analyzer = SecurityTrendAnalyzer()


class ComparisonRequest(BaseModel):
    """Request model for wiki comparison"""
    baseline_wiki_id: str
    current_wiki_id: str


class MaturityScoreRequest(BaseModel):
    """Request model for security maturity scoring"""
    wiki_id: str


class TrendAnalysisRequest(BaseModel):
    """Request model for security trend analysis"""
    period: str = "weekly"  # weekly, monthly, quarterly
    lookback_days: int = 90


class WikiListResponse(BaseModel):
    """Response model for wiki list"""
    id: str
    title: str
    repo_id: str
    created_at: datetime
    updated_at: Optional[datetime] = None


@router.get("/", response_model=List[WikiListResponse])
async def get_available_wikis(user_id: str = Depends(get_current_user)):
    """
    Get list of available wikis for comparison
    
    Returns:
        List of available security wikis
    """
    try:
        # For now, get all wikis - in production, filter by user access
        # This is a simplified implementation for the MVP
        
        # Get all unique repo IDs and their latest wikis
        # In a real implementation, you'd query the database for user's accessible repos
        available_wikis = []
        
        # Mock data for demonstration - replace with actual database query
        sample_wikis = [
            {
                "id": "wiki_1",
                "title": "ThreatLens Security Analysis v1.0",
                "repo_id": "threatlens_repo",
                "created_at": datetime.now().isoformat(),
                "updated_at": None
            },
            {
                "id": "wiki_2", 
                "title": "ThreatLens Security Analysis v1.1",
                "repo_id": "threatlens_repo",
                "created_at": datetime.now().isoformat(),
                "updated_at": None
            }
        ]
        
        return sample_wikis
        
    except Exception as e:
        logger.error(f"Error getting available wikis: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve available wikis")


@router.post("/compare", response_model=Dict[str, Any])
async def compare_wikis(
    request: ComparisonRequest,
    user_id: str = Depends(get_current_user)
):
    """
    Compare two security wikis for security posture analysis
    
    Args:
        request: Comparison request with baseline and current wiki IDs
        user_id: Current user ID for access control
        
    Returns:
        Detailed security comparison results
    """
    try:
        logger.info(f"Comparing wikis: {request.baseline_wiki_id} vs {request.current_wiki_id}")
        
        # Validate wiki access (simplified for MVP)
        baseline_wiki = wiki_storage.load_wiki(request.baseline_wiki_id)
        current_wiki = wiki_storage.load_wiki(request.current_wiki_id)
        
        if not baseline_wiki:
            raise HTTPException(status_code=404, detail=f"Baseline wiki {request.baseline_wiki_id} not found")
        
        if not current_wiki:
            raise HTTPException(status_code=404, detail=f"Current wiki {request.current_wiki_id} not found")
        
        # Perform comparison
        comparison = wiki_comparison_engine.compare_wikis(
            request.baseline_wiki_id,
            request.current_wiki_id
        )
        
        if not comparison:
            raise HTTPException(status_code=500, detail="Failed to perform wiki comparison")
        
        # Convert to dictionary for JSON response
        comparison_dict = {
            "baseline_wiki_id": comparison.baseline_wiki_id,
            "current_wiki_id": comparison.current_wiki_id,
            "comparison_timestamp": comparison.comparison_timestamp.isoformat(),
            "threat_comparison": {
                "baseline_threats": comparison.threat_comparison.baseline_threats,
                "current_threats": comparison.threat_comparison.current_threats,
                "new_threats": [
                    {
                        "id": threat.id,
                        "type": threat.type,
                        "severity": threat.severity,
                        "description": threat.description,
                        "owasp_category": threat.owasp_category,
                        "recommendations": threat.recommendations
                    }
                    for threat in comparison.threat_comparison.new_threats
                ],
                "resolved_threats": [
                    {
                        "id": threat.id,
                        "type": threat.type,
                        "severity": threat.severity,
                        "description": threat.description,
                        "owasp_category": threat.owasp_category,
                        "recommendations": threat.recommendations
                    }
                    for threat in comparison.threat_comparison.resolved_threats
                ],
                "modified_threats": [
                    {
                        "baseline": {
                            "id": baseline.id,
                            "type": baseline.type,
                            "severity": baseline.severity,
                            "description": baseline.description
                        },
                        "current": {
                            "id": current.id,
                            "type": current.type,
                            "severity": current.severity,
                            "description": current.description
                        }
                    }
                    for baseline, current in comparison.threat_comparison.modified_threats
                ],
                "threat_severity_distribution": comparison.threat_comparison.threat_severity_distribution,
                "owasp_category_changes": comparison.threat_comparison.owasp_category_changes
            },
            "mitigation_comparison": {
                "baseline_mitigations": comparison.mitigation_comparison.baseline_mitigations,
                "current_mitigations": comparison.mitigation_comparison.current_mitigations,
                "new_mitigations": comparison.mitigation_comparison.new_mitigations,
                "removed_mitigations": comparison.mitigation_comparison.removed_mitigations,
                "coverage_by_owasp": comparison.mitigation_comparison.coverage_by_owasp,
                "effectiveness_changes": comparison.mitigation_comparison.effectiveness_changes
            },
            "compliance_comparison": {
                "baseline_compliance_score": comparison.compliance_comparison.baseline_compliance_score,
                "current_compliance_score": comparison.compliance_comparison.current_compliance_score,
                "compliance_changes": comparison.compliance_comparison.compliance_changes,
                "missing_guidelines": comparison.compliance_comparison.missing_guidelines,
                "new_guidelines_covered": comparison.compliance_comparison.new_guidelines_covered,
                "compliance_trend": comparison.compliance_comparison.compliance_trend
            },
            "security_changes": [
                {
                    "change_type": change.change_type,
                    "section_id": change.section_id,
                    "section_title": change.section_title,
                    "old_content": change.old_content,
                    "new_content": change.new_content,
                    "impact_level": change.impact_level,
                    "description": change.description,
                    "owasp_categories": change.owasp_categories
                }
                for change in comparison.security_changes
            ],
            "regression_detected": comparison.regression_detected,
            "improvement_detected": comparison.improvement_detected,
            "summary": comparison.summary
        }
        
        logger.info(f"Wiki comparison completed successfully")
        return comparison_dict
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error comparing wikis: {e}")
        raise HTTPException(status_code=500, detail="Failed to compare wikis")


@router.post("/maturity-score", response_model=Dict[str, Any])
async def calculate_maturity_score(
    request: MaturityScoreRequest,
    user_id: str = Depends(get_current_user)
):
    """
    Calculate security maturity score for a wiki based on OWASP criteria
    
    Args:
        request: Maturity score request with wiki ID
        user_id: Current user ID for access control
        
    Returns:
        Security maturity score and analysis
    """
    try:
        logger.info(f"Calculating maturity score for wiki: {request.wiki_id}")
        
        # Load wiki
        wiki = wiki_storage.load_wiki(request.wiki_id)
        if not wiki:
            raise HTTPException(status_code=404, detail=f"Wiki {request.wiki_id} not found")
        
        # Calculate maturity score
        maturity_score = wiki_comparison_engine.calculate_security_maturity_score(wiki)
        
        # Convert to dictionary for JSON response
        score_dict = {
            "overall_score": maturity_score.overall_score,
            "category_scores": maturity_score.category_scores,
            "maturity_level": maturity_score.maturity_level,
            "improvement_areas": maturity_score.improvement_areas,
            "strengths": maturity_score.strengths,
            "calculated_at": datetime.now().isoformat()
        }
        
        logger.info(f"Maturity score calculated: {maturity_score.overall_score:.2f} ({maturity_score.maturity_level})")
        return score_dict
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error calculating maturity score: {e}")
        raise HTTPException(status_code=500, detail="Failed to calculate maturity score")


@router.get("/{repo_id}/history", response_model=List[WikiListResponse])
async def get_wiki_history(
    repo_id: str,
    user_id: str = Depends(get_current_user)
):
    """
    Get wiki history for a repository to enable trend analysis
    
    Args:
        repo_id: Repository ID
        user_id: Current user ID for access control
        
    Returns:
        List of wikis for the repository ordered by creation date
    """
    try:
        logger.info(f"Getting wiki history for repo: {repo_id}")
        
        # Get all wikis for the repository
        wikis = wiki_storage.get_wikis_by_repo(repo_id)
        
        # Convert to response format
        wiki_history = [
            WikiListResponse(
                id=wiki.id,
                title=wiki.title,
                repo_id=wiki.repo_id,
                created_at=wiki.created_at,
                updated_at=wiki.updated_at
            )
            for wiki in wikis
        ]
        
        # Sort by creation date (newest first)
        wiki_history.sort(key=lambda w: w.created_at, reverse=True)
        
        logger.info(f"Retrieved {len(wiki_history)} wikis for repo {repo_id}")
        return wiki_history
        
    except Exception as e:
        logger.error(f"Error getting wiki history: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve wiki history")


@router.post("/{repo_id}/trend-analysis", response_model=Dict[str, Any])
async def analyze_security_trends(
    repo_id: str,
    request: TrendAnalysisRequest,
    user_id: str = Depends(get_current_user)
):
    """
    Analyze security trends over time for a repository
    
    Args:
        repo_id: Repository ID
        request: Trend analysis parameters
        user_id: Current user ID for access control
        
    Returns:
        Security trend analysis over time
    """
    try:
        logger.info(f"Analyzing security trends for repo: {repo_id}")
        
        # Validate period
        try:
            period = TrendPeriod(request.period.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid period: {request.period}")
        
        # Perform trend analysis
        analysis = trend_analyzer.analyze_security_trends(
            repo_id=repo_id,
            period=period,
            lookback_days=request.lookback_days
        )
        
        if not analysis:
            return {
                "repo_id": repo_id,
                "message": "Insufficient data for trend analysis",
                "trend_data": None,
                "key_insights": [],
                "regression_alerts": [],
                "improvement_highlights": [],
                "recommendations": []
            }
        
        # Convert to dictionary for JSON response
        result = {
            "repo_id": analysis.repo_id,
            "analysis_timestamp": analysis.analysis_timestamp.isoformat(),
            "trend_data": {
                "repo_id": analysis.trend_data.repo_id,
                "period": analysis.trend_data.period,
                "data_points": [
                    {
                        "timestamp": point.timestamp.isoformat(),
                        "wiki_id": point.wiki_id,
                        "maturity_score": point.maturity_score,
                        "threat_count": point.threat_count,
                        "mitigation_count": point.mitigation_count,
                        "compliance_score": point.compliance_score,
                        "critical_threats": point.critical_threats,
                        "high_threats": point.high_threats,
                        "medium_threats": point.medium_threats,
                        "low_threats": point.low_threats,
                        "owasp_coverage": point.owasp_coverage,
                        "regression_detected": point.regression_detected,
                        "improvement_detected": point.improvement_detected
                    }
                    for point in analysis.trend_data.data_points
                ],
                "trend_direction": analysis.trend_data.trend_direction,
                "trend_strength": analysis.trend_data.trend_strength,
                "volatility": analysis.trend_data.volatility,
                "analysis_period": [
                    analysis.trend_data.analysis_period[0].isoformat(),
                    analysis.trend_data.analysis_period[1].isoformat()
                ],
                "duration_days": analysis.trend_data.duration_days,
                "latest_score": analysis.trend_data.latest_score,
                "score_change": analysis.trend_data.score_change
            },
            "key_insights": analysis.key_insights,
            "regression_alerts": [
                {
                    "timestamp": alert.timestamp.isoformat(),
                    "repo_id": alert.repo_id,
                    "wiki_id": alert.wiki_id,
                    "severity": alert.severity,
                    "regression_type": alert.regression_type,
                    "description": alert.description,
                    "impact_score": alert.impact_score,
                    "recommended_actions": alert.recommended_actions,
                    "affected_owasp_categories": alert.affected_owasp_categories
                }
                for alert in analysis.regression_alerts
            ],
            "improvement_highlights": analysis.improvement_highlights,
            "recommendations": analysis.recommendations,
            "forecast": analysis.forecast
        }
        
        logger.info(f"Security trend analysis completed for repo {repo_id}: {analysis.trend_data.trend_direction}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error analyzing security trends: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze security trends")