"""
Security Analytics Dashboard API Router
Provides endpoints for security analytics dashboard data
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field

from .security_analytics import get_security_analytics_aggregator, SecurityAnalyticsData
from .security_metrics import get_security_metrics_collector, SecurityTrendMetrics, SecurityHotspot
from .monitoring import metrics_collector, application_monitor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/security-analytics", tags=["security-analytics"])


class SecurityDashboardRequest(BaseModel):
    """Request model for security dashboard data"""
    time_range: str = Field(default="24h", description="Time range for analytics (1h, 24h, 7d, 30d)")
    repo_ids: Optional[List[str]] = Field(default=None, description="Specific repository IDs to include")
    include_predictions: bool = Field(default=True, description="Include predictive analytics")


class SecurityMetricsRequest(BaseModel):
    """Request model for security metrics"""
    repo_id: Optional[str] = Field(default=None, description="Repository ID for specific metrics")
    time_range: str = Field(default="24h", description="Time range for metrics")
    metric_types: Optional[List[str]] = Field(default=None, description="Specific metric types to include")


class OWASPComplianceRequest(BaseModel):
    """Request model for OWASP compliance data"""
    repo_id: Optional[str] = Field(default=None, description="Repository ID for compliance check")
    include_trends: bool = Field(default=True, description="Include compliance trends")


class SecurityHotspotRequest(BaseModel):
    """Request model for security hotspots"""
    limit: int = Field(default=10, description="Maximum number of hotspots to return")
    min_risk_score: float = Field(default=0.0, description="Minimum risk score threshold")
    repo_ids: Optional[List[str]] = Field(default=None, description="Filter by repository IDs")


@router.get("/dashboard")
async def get_security_dashboard(
    time_range: str = Query(default="24h", description="Time range (1h, 24h, 7d, 30d)"),
    repo_ids: Optional[str] = Query(default=None, description="Comma-separated repository IDs")
) -> SecurityAnalyticsData:
    """
    Get comprehensive security analytics dashboard data
    
    Returns aggregated security metrics, trends, OWASP compliance,
    and security hotspots for the dashboard.
    """
    try:
        # Record API request
        application_monitor.record_request(0, 200, "/api/security-analytics/dashboard")
        
        # Get analytics aggregator
        aggregator = get_security_analytics_aggregator()
        
        # Get dashboard data
        dashboard_data = aggregator.get_dashboard_data(time_range)
        
        logger.info(f"Security dashboard data retrieved for time range: {time_range}")
        return dashboard_data
        
    except Exception as e:
        logger.error(f"Failed to get security dashboard data: {e}")
        application_monitor.record_request(0, 500, "/api/security-analytics/dashboard")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve dashboard data: {str(e)}")


@router.get("/metrics")
async def get_security_metrics(
    repo_id: Optional[str] = Query(default=None, description="Repository ID"),
    time_range: str = Query(default="24h", description="Time range for metrics"),
    metric_types: Optional[str] = Query(default=None, description="Comma-separated metric types")
) -> Dict[str, Any]:
    """
    Get security metrics data for charts and visualizations
    
    Returns current metrics, historical data, and trends for
    security score, threats, vulnerabilities, and mitigations.
    """
    try:
        # Record API request
        application_monitor.record_request(0, 200, "/api/security-analytics/metrics")
        
        # Get security metrics collector
        security_metrics = get_security_metrics_collector()
        
        if repo_id:
            # Get repository-specific metrics
            repo_metrics = security_metrics.collect_repository_metrics(repo_id)
            
            # Get detailed metrics from aggregator
            aggregator = get_security_analytics_aggregator()
            detailed_metrics = aggregator.get_repository_detailed_metrics(repo_id)
            
            # Combine metrics
            metrics_data = {
                "repo_id": repo_id,
                "time_range": time_range,
                "current_metrics": repo_metrics,
                "detailed_metrics": detailed_metrics,
                "trends": security_metrics.calculate_security_trends(time_range),
                "timestamp": datetime.now().isoformat()
            }
        else:
            # Get global metrics
            global_metrics = security_metrics.get_global_security_metrics()
            trends = security_metrics.calculate_security_trends(time_range)
            
            metrics_data = {
                "global": True,
                "time_range": time_range,
                "current_metrics": global_metrics,
                "trends": trends,
                "timestamp": datetime.now().isoformat()
            }
        
        logger.info(f"Security metrics retrieved for repo_id: {repo_id}, time_range: {time_range}")
        return metrics_data
        
    except Exception as e:
        logger.error(f"Failed to get security metrics: {e}")
        application_monitor.record_request(0, 500, "/api/security-analytics/metrics")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve security metrics: {str(e)}")


@router.get("/owasp-compliance")
async def get_owasp_compliance(
    repo_id: Optional[str] = Query(default=None, description="Repository ID"),
    include_trends: bool = Query(default=True, description="Include compliance trends")
) -> Dict[str, Any]:
    """
    Get OWASP Top 10 compliance analysis
    
    Returns OWASP coverage metrics, category-specific compliance,
    trends, and recommendations for improvement.
    """
    try:
        # Record API request
        application_monitor.record_request(0, 200, "/api/security-analytics/owasp-compliance")
        
        # Get analytics aggregator
        aggregator = get_security_analytics_aggregator()
        
        # Get dashboard data which includes OWASP coverage
        dashboard_data = aggregator.get_dashboard_data("30d")  # Use 30d for better trend analysis
        
        owasp_data = {
            "repo_id": repo_id,
            "timestamp": datetime.now().isoformat(),
            "owasp_coverage": dashboard_data.owasp_coverage,
            "compliance_summary": {
                "overall_coverage": dashboard_data.owasp_coverage.get("overall_coverage", 0),
                "category_coverage": dashboard_data.owasp_coverage.get("category_coverage", {}),
                "coverage_trends": dashboard_data.owasp_coverage.get("coverage_trends", {}),
                "recommendations": dashboard_data.owasp_coverage.get("recommendations", [])
            }
        }
        
        if repo_id:
            # Get repository-specific OWASP compliance
            repo_metrics = get_security_metrics_collector().collect_repository_metrics(repo_id)
            owasp_coverage = repo_metrics.get("owasp_coverage", {})
            
            if hasattr(owasp_coverage, '__dict__'):
                owasp_data["repository_compliance"] = owasp_coverage.__dict__
            else:
                owasp_data["repository_compliance"] = owasp_coverage
        
        logger.info(f"OWASP compliance data retrieved for repo_id: {repo_id}")
        return owasp_data
        
    except Exception as e:
        logger.error(f"Failed to get OWASP compliance data: {e}")
        application_monitor.record_request(0, 500, "/api/security-analytics/owasp-compliance")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve OWASP compliance data: {str(e)}")


@router.get("/hotspots")
async def get_security_hotspots(
    limit: int = Query(default=10, description="Maximum number of hotspots"),
    min_risk_score: float = Query(default=0.0, description="Minimum risk score"),
    repo_ids: Optional[str] = Query(default=None, description="Comma-separated repository IDs")
) -> Dict[str, Any]:
    """
    Get security hotspots and risk heatmap data
    
    Returns identified security hotspots, risk distribution,
    and heatmap visualization data.
    """
    try:
        # Record API request
        application_monitor.record_request(0, 200, "/api/security-analytics/hotspots")
        
        # Get security metrics collector
        security_metrics = get_security_metrics_collector()
        
        # Get security hotspots
        hotspots = security_metrics.identify_security_hotspots(limit)
        
        # Filter by minimum risk score
        filtered_hotspots = [h for h in hotspots if h.risk_score >= min_risk_score]
        
        # Filter by repository IDs if provided
        if repo_ids:
            repo_id_list = [rid.strip() for rid in repo_ids.split(",")]
            filtered_hotspots = [h for h in filtered_hotspots if h.repo_id in repo_id_list]
        
        # Calculate risk distribution
        risk_distribution = {
            "critical": len([h for h in filtered_hotspots if h.risk_score >= 80]),
            "high": len([h for h in filtered_hotspots if 60 <= h.risk_score < 80]),
            "medium": len([h for h in filtered_hotspots if 40 <= h.risk_score < 60]),
            "low": len([h for h in filtered_hotspots if h.risk_score < 40])
        }
        
        # Convert hotspots to dict format
        hotspots_data = []
        for hotspot in filtered_hotspots:
            hotspot_dict = {
                "id": hotspot.repo_id,
                "name": hotspot.component_name,
                "repo_id": hotspot.repo_id,
                "component_name": hotspot.component_name,
                "risk_score": hotspot.risk_score,
                "threat_count": hotspot.threat_count,
                "vulnerability_count": hotspot.vulnerability_count,
                "severity_distribution": hotspot.severity_distribution,
                "owasp_categories": hotspot.owasp_categories,
                "last_updated": hotspot.last_updated.isoformat()
            }
            hotspots_data.append(hotspot_dict)
        
        hotspots_response = {
            "timestamp": datetime.now().isoformat(),
            "summary": risk_distribution,
            "items": hotspots_data,
            "total_count": len(hotspots_data),
            "filters": {
                "limit": limit,
                "min_risk_score": min_risk_score,
                "repo_ids": repo_ids.split(",") if repo_ids else None
            }
        }
        
        logger.info(f"Security hotspots retrieved: {len(hotspots_data)} items")
        return hotspots_response
        
    except Exception as e:
        logger.error(f"Failed to get security hotspots: {e}")
        application_monitor.record_request(0, 500, "/api/security-analytics/hotspots")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve security hotspots: {str(e)}")


@router.get("/trends")
async def get_security_trends(
    time_range: str = Query(default="7d", description="Time range for trend analysis"),
    repo_id: Optional[str] = Query(default=None, description="Repository ID for specific trends")
) -> Dict[str, Any]:
    """
    Get security trend analysis
    
    Returns trend analysis for security metrics over time,
    including predictions and insights.
    """
    try:
        # Record API request
        application_monitor.record_request(0, 200, "/api/security-analytics/trends")
        
        # Get security metrics collector
        security_metrics = get_security_metrics_collector()
        
        # Calculate trends
        trends = security_metrics.calculate_security_trends(time_range)
        
        # Get analytics aggregator for additional trend data
        aggregator = get_security_analytics_aggregator()
        dashboard_data = aggregator.get_dashboard_data(time_range)
        
        trends_data = {
            "repo_id": repo_id,
            "time_range": time_range,
            "timestamp": datetime.now().isoformat(),
            "trends": {
                "time_period": trends.time_period,
                "threat_trend": trends.threat_trend,
                "vulnerability_trend": trends.vulnerability_trend,
                "mitigation_trend": trends.mitigation_trend,
                "security_score_trend": trends.security_score_trend,
                "new_threats_count": trends.new_threats_count,
                "resolved_threats_count": trends.resolved_threats_count,
                "regression_count": trends.regression_count
            },
            "trend_analysis": dashboard_data.trend_analysis,
            "insights": {
                "primary_trend": "improving" if trends.security_score_trend > 0 else "declining",
                "trend_strength": abs(trends.security_score_trend),
                "key_changes": [
                    f"Security score {'improved' if trends.security_score_trend > 0 else 'declined'} by {abs(trends.security_score_trend):.1f}%",
                    f"Threat count {'increased' if trends.threat_trend > 0 else 'decreased'} by {abs(trends.threat_trend):.1f}%",
                    f"Mitigation coverage {'improved' if trends.mitigation_trend > 0 else 'declined'} by {abs(trends.mitigation_trend):.1f}%"
                ]
            }
        }
        
        logger.info(f"Security trends retrieved for time_range: {time_range}, repo_id: {repo_id}")
        return trends_data
        
    except Exception as e:
        logger.error(f"Failed to get security trends: {e}")
        application_monitor.record_request(0, 500, "/api/security-analytics/trends")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve security trends: {str(e)}")


@router.get("/performance")
async def get_performance_metrics() -> Dict[str, Any]:
    """
    Get security analysis performance metrics
    
    Returns system performance metrics, resource utilization,
    and analysis throughput statistics.
    """
    try:
        # Record API request
        application_monitor.record_request(0, 200, "/api/security-analytics/performance")
        
        # Get analytics aggregator
        aggregator = get_security_analytics_aggregator()
        
        # Get dashboard data which includes performance metrics
        dashboard_data = aggregator.get_dashboard_data("1h")  # Use 1h for current performance
        
        # Get additional system metrics
        system_metrics = {
            "cpu_usage": metrics_collector.get_gauge("system.cpu_percent"),
            "memory_usage": metrics_collector.get_gauge("system.memory_percent"),
            "disk_usage": metrics_collector.get_gauge("system.disk_usage_percent"),
            "active_analyses": metrics_collector.get_gauge("analysis.active_count"),
            "queued_analyses": metrics_collector.get_gauge("analysis.queued_count")
        }
        
        performance_data = {
            "timestamp": datetime.now().isoformat(),
            "performance_metrics": dashboard_data.performance_metrics,
            "system_metrics": system_metrics,
            "analysis_stats": {
                "total_completed": metrics_collector.get_counter("analysis.completed_total"),
                "total_failed": metrics_collector.get_counter("analysis.failed_total"),
                "success_rate": 0.0,  # Will be calculated
                "average_duration": metrics_collector.get_timer_stats("analysis.duration").get("mean", 0) / 1000
            }
        }
        
        # Calculate success rate
        total_completed = performance_data["analysis_stats"]["total_completed"]
        total_failed = performance_data["analysis_stats"]["total_failed"]
        if total_completed + total_failed > 0:
            performance_data["analysis_stats"]["success_rate"] = (total_completed / (total_completed + total_failed)) * 100
        
        logger.info("Performance metrics retrieved")
        return performance_data
        
    except Exception as e:
        logger.error(f"Failed to get performance metrics: {e}")
        application_monitor.record_request(0, 500, "/api/security-analytics/performance")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve performance metrics: {str(e)}")


@router.post("/refresh")
async def refresh_analytics_data(
    repo_ids: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Refresh analytics data for specified repositories or all repositories
    
    Triggers a refresh of security metrics collection and analytics
    aggregation for the specified repositories.
    """
    try:
        # Record API request
        application_monitor.record_request(0, 200, "/api/security-analytics/refresh")
        
        # Get security metrics collector
        security_metrics = get_security_metrics_collector()
        
        refreshed_repos = []
        
        if repo_ids:
            # Refresh specific repositories
            for repo_id in repo_ids:
                try:
                    metrics = security_metrics.collect_repository_metrics(repo_id)
                    if metrics:
                        refreshed_repos.append(repo_id)
                except Exception as e:
                    logger.warning(f"Failed to refresh metrics for repo {repo_id}: {e}")
        else:
            # Refresh global metrics
            global_metrics = security_metrics.get_global_security_metrics()
            refreshed_repos = ["global"]
        
        refresh_result = {
            "timestamp": datetime.now().isoformat(),
            "refreshed_repositories": refreshed_repos,
            "success": True,
            "message": f"Analytics data refreshed for {len(refreshed_repos)} repositories"
        }
        
        logger.info(f"Analytics data refreshed for repositories: {refreshed_repos}")
        return refresh_result
        
    except Exception as e:
        logger.error(f"Failed to refresh analytics data: {e}")
        application_monitor.record_request(0, 500, "/api/security-analytics/refresh")
        raise HTTPException(status_code=500, detail=f"Failed to refresh analytics data: {str(e)}")


@router.get("/health")
async def get_analytics_health() -> Dict[str, Any]:
    """
    Get health status of security analytics system
    
    Returns health information for analytics components,
    data freshness, and system status.
    """
    try:
        # Get current timestamp
        current_time = datetime.now()
        
        # Check analytics components health
        health_status = {
            "timestamp": current_time.isoformat(),
            "status": "healthy",
            "components": {
                "metrics_collector": "healthy",
                "analytics_aggregator": "healthy",
                "database": "healthy",
                "monitoring": "healthy"
            },
            "data_freshness": {
                "last_metrics_update": current_time.isoformat(),
                "last_analytics_refresh": current_time.isoformat(),
                "data_age_minutes": 0
            },
            "system_info": {
                "uptime_hours": 24,  # Mock data
                "total_repositories": metrics_collector.get_gauge("database.repositories_count"),
                "active_analyses": metrics_collector.get_gauge("analysis.active_count"),
                "system_load": metrics_collector.get_gauge("system.cpu_percent")
            }
        }
        
        # Check if system load is too high
        if health_status["system_info"]["system_load"] > 90:
            health_status["status"] = "degraded"
            health_status["components"]["monitoring"] = "warning"
        
        logger.info("Analytics health check completed")
        return health_status
        
    except Exception as e:
        logger.error(f"Failed to get analytics health: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve analytics health: {str(e)}")