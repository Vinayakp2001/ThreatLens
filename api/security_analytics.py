"""
Security Analytics Data Aggregation System
Provides data aggregation and analysis for security analytics dashboard
"""
import logging
import sqlite3
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict

from .database import DatabaseManager
from .security_metrics import SecurityMetricsCollector, SecurityTrendMetrics, SecurityHotspot, OWASPCoverageMetrics
from .monitoring import metrics_collector

logger = logging.getLogger(__name__)


@dataclass
class SecurityAnalyticsData:
    """Aggregated security analytics data"""
    timestamp: str
    global_metrics: Dict[str, Any]
    repository_metrics: List[Dict[str, Any]]
    trend_analysis: Dict[str, Any]
    owasp_coverage: Dict[str, Any]
    security_hotspots: List[Dict[str, Any]]
    performance_metrics: Dict[str, Any]


class SecurityAnalyticsAggregator:
    """Aggregates security data for analytics dashboard"""
    
    def __init__(self, db_manager: DatabaseManager, security_metrics: SecurityMetricsCollector):
        self.db_manager = db_manager
        self.security_metrics = security_metrics
        self.cache_duration = timedelta(minutes=5)  # Cache results for 5 minutes
        self._cache = {}
        self._cache_timestamps = {}
    
    def get_dashboard_data(self, time_range: str = "24h") -> SecurityAnalyticsData:
        """Get comprehensive dashboard data"""
        cache_key = f"dashboard_{time_range}"
        
        # Check cache
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]
        
        try:
            # Collect all dashboard data
            dashboard_data = SecurityAnalyticsData(
                timestamp=datetime.now().isoformat(),
                global_metrics=self._get_global_metrics(),
                repository_metrics=self._get_repository_metrics(),
                trend_analysis=self._get_trend_analysis(time_range),
                owasp_coverage=self._get_owasp_coverage_analysis(),
                security_hotspots=self._get_security_hotspots_data(),
                performance_metrics=self._get_performance_metrics()
            )
            
            # Cache the result
            self._cache[cache_key] = dashboard_data
            self._cache_timestamps[cache_key] = datetime.now()
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Failed to get dashboard data: {e}")
            # Return empty data structure
            return SecurityAnalyticsData(
                timestamp=datetime.now().isoformat(),
                global_metrics={},
                repository_metrics=[],
                trend_analysis={},
                owasp_coverage={},
                security_hotspots=[],
                performance_metrics={}
            )
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached data is still valid"""
        if cache_key not in self._cache or cache_key not in self._cache_timestamps:
            return False
        
        cache_time = self._cache_timestamps[cache_key]
        return datetime.now() - cache_time < self.cache_duration
    
    def _get_global_metrics(self) -> Dict[str, Any]:
        """Get global security metrics"""
        try:
            # Get from security metrics collector
            global_metrics = self.security_metrics.get_global_security_metrics()
            
            # Add database statistics
            db_stats = self._get_database_security_stats()
            global_metrics.update(db_stats)
            
            # Add system health metrics
            health_metrics = self._get_security_health_metrics()
            global_metrics.update(health_metrics)
            
            return global_metrics
            
        except Exception as e:
            logger.error(f"Failed to get global metrics: {e}")
            return {"error": str(e)}
    
    def _get_database_security_stats(self) -> Dict[str, Any]:
        """Get security-related database statistics"""
        try:
            stats = {
                "total_security_wikis": 0,
                "total_security_documents": 0,
                "total_pr_analyses": 0,
                "recent_analyses": 0
            }
            
            with sqlite3.connect(self.db_manager.db_path) as conn:
                # Count security wikis
                cursor = conn.execute("SELECT COUNT(*) FROM security_wikis")
                stats["total_security_wikis"] = cursor.fetchone()[0]
                
                # Count security documents
                cursor = conn.execute("SELECT COUNT(*) FROM security_documents WHERE is_current = 1")
                stats["total_security_documents"] = cursor.fetchone()[0]
                
                # Count PR analyses
                cursor = conn.execute("SELECT COUNT(*) FROM pr_analyses")
                stats["total_pr_analyses"] = cursor.fetchone()[0]
                
                # Count recent analyses (last 24 hours)
                yesterday = (datetime.now() - timedelta(hours=24)).isoformat()
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM security_documents WHERE created_at > ? AND is_current = 1",
                    (yesterday,)
                )
                stats["recent_analyses"] = cursor.fetchone()[0]
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get database security stats: {e}")
            return {}
    
    def _get_security_health_metrics(self) -> Dict[str, Any]:
        """Get security system health metrics"""
        try:
            health_metrics = {
                "analysis_success_rate": 0.0,
                "average_analysis_time": 0.0,
                "system_load": 0.0,
                "error_rate": 0.0
            }
            
            # Get from monitoring system
            analysis_success = metrics_collector.get_counter("analysis.completed_total")
            analysis_failed = metrics_collector.get_counter("analysis.failed_total")
            
            if analysis_success + analysis_failed > 0:
                health_metrics["analysis_success_rate"] = (analysis_success / (analysis_success + analysis_failed)) * 100
            
            # Get average analysis time
            timer_stats = metrics_collector.get_timer_stats("analysis.duration")
            health_metrics["average_analysis_time"] = timer_stats.get("mean", 0.0) / 1000  # Convert to seconds
            
            # Get system load
            health_metrics["system_load"] = metrics_collector.get_gauge("system.cpu_percent")
            
            # Get error rate
            total_requests = metrics_collector.get_counter("api.requests_total")
            total_errors = metrics_collector.get_counter("api.errors_total")
            
            if total_requests > 0:
                health_metrics["error_rate"] = (total_errors / total_requests) * 100
            
            return health_metrics
            
        except Exception as e:
            logger.error(f"Failed to get security health metrics: {e}")
            return {}
    
    def _get_repository_metrics(self) -> List[Dict[str, Any]]:
        """Get metrics for all repositories"""
        try:
            repo_metrics = []
            
            # Get all repositories from database
            with sqlite3.connect(self.db_manager.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("SELECT id, url, analysis_status, created_at FROM repositories")
                
                for row in cursor:
                    repo_id = row["id"]
                    
                    # Get security metrics for this repository
                    security_data = self.security_metrics.collect_repository_metrics(repo_id)
                    
                    repo_metric = {
                        "repo_id": repo_id,
                        "repo_url": row["url"],
                        "analysis_status": row["analysis_status"],
                        "created_at": row["created_at"],
                        "security_metrics": security_data
                    }
                    
                    repo_metrics.append(repo_metric)
            
            return repo_metrics
            
        except Exception as e:
            logger.error(f"Failed to get repository metrics: {e}")
            return []
    
    def _get_trend_analysis(self, time_range: str) -> Dict[str, Any]:
        """Get security trend analysis"""
        try:
            # Get trends from security metrics collector
            trends = self.security_metrics.calculate_security_trends(time_range)
            
            # Convert to dictionary for JSON serialization
            trend_data = asdict(trends)
            
            # Add historical data points
            trend_data["historical_data"] = self._get_historical_trend_data(time_range)
            
            # Add predictive insights
            trend_data["predictions"] = self._generate_trend_predictions(trends)
            
            return trend_data
            
        except Exception as e:
            logger.error(f"Failed to get trend analysis: {e}")
            return {}
    
    def _get_historical_trend_data(self, time_range: str) -> List[Dict[str, Any]]:
        """Get historical data points for trend visualization"""
        try:
            # Parse time range to determine data points
            if time_range == "1h":
                intervals = 12  # 5-minute intervals
                interval_minutes = 5
            elif time_range == "24h":
                intervals = 24  # 1-hour intervals
                interval_minutes = 60
            elif time_range == "7d":
                intervals = 7   # 1-day intervals
                interval_minutes = 1440
            elif time_range == "30d":
                intervals = 30  # 1-day intervals
                interval_minutes = 1440
            else:
                intervals = 24
                interval_minutes = 60
            
            historical_data = []
            current_time = datetime.now()
            
            for i in range(intervals):
                point_time = current_time - timedelta(minutes=interval_minutes * i)
                
                # Get metrics for this time point (simplified - would need more sophisticated querying)
                data_point = {
                    "timestamp": point_time.isoformat(),
                    "threats": self._get_metric_at_time("threats", point_time),
                    "vulnerabilities": self._get_metric_at_time("vulnerabilities", point_time),
                    "security_score": self._get_metric_at_time("security_score", point_time),
                    "mitigations": self._get_metric_at_time("mitigations", point_time)
                }
                
                historical_data.append(data_point)
            
            return list(reversed(historical_data))  # Chronological order
            
        except Exception as e:
            logger.error(f"Failed to get historical trend data: {e}")
            return []
    
    def _get_metric_at_time(self, metric_type: str, timestamp: datetime) -> float:
        """Get metric value at specific time (simplified implementation)"""
        # This is a simplified implementation - in reality would query stored metrics
        # For now, return mock data based on current metrics with some variation
        base_values = {
            "threats": 15,
            "vulnerabilities": 8,
            "security_score": 75,
            "mitigations": 12
        }
        
        # Add some time-based variation
        import random
        variation = random.uniform(0.8, 1.2)
        return base_values.get(metric_type, 0) * variation
    
    def _generate_trend_predictions(self, trends: SecurityTrendMetrics) -> Dict[str, Any]:
        """Generate predictive insights based on trends"""
        try:
            predictions = {
                "threat_forecast": "stable",
                "security_score_forecast": "improving",
                "risk_level": "medium",
                "recommendations": []
            }
            
            # Analyze threat trends
            if trends.threat_trend > 20:
                predictions["threat_forecast"] = "increasing"
                predictions["risk_level"] = "high"
                predictions["recommendations"].append("Immediate threat assessment recommended")
            elif trends.threat_trend < -10:
                predictions["threat_forecast"] = "decreasing"
            
            # Analyze security score trends
            if trends.security_score_trend > 10:
                predictions["security_score_forecast"] = "improving"
            elif trends.security_score_trend < -10:
                predictions["security_score_forecast"] = "declining"
                predictions["recommendations"].append("Security posture review needed")
            
            # Risk level assessment
            if trends.regression_count > 5:
                predictions["risk_level"] = "high"
                predictions["recommendations"].append("Multiple security regressions detected")
            
            return predictions
            
        except Exception as e:
            logger.error(f"Failed to generate trend predictions: {e}")
            return {}
    
    def _get_owasp_coverage_analysis(self) -> Dict[str, Any]:
        """Get OWASP coverage analysis"""
        try:
            # Get OWASP coverage from all repositories
            total_coverage = OWASPCoverageMetrics()
            repo_count = 0
            
            # This would integrate with actual OWASP analysis
            # For now, return mock analysis
            coverage_analysis = {
                "overall_coverage": 65.5,
                "category_coverage": {
                    "A01_broken_access_control": 70.0,
                    "A02_cryptographic_failures": 45.0,
                    "A03_injection": 80.0,
                    "A04_insecure_design": 55.0,
                    "A05_security_misconfiguration": 60.0,
                    "A06_vulnerable_components": 75.0,
                    "A07_identification_failures": 50.0,
                    "A08_software_integrity_failures": 40.0,
                    "A09_logging_failures": 85.0,
                    "A10_server_side_request_forgery": 65.0
                },
                "coverage_trends": {
                    "improving_categories": ["A03", "A09"],
                    "declining_categories": ["A02", "A08"],
                    "stable_categories": ["A01", "A04", "A05", "A06", "A07", "A10"]
                },
                "recommendations": [
                    "Focus on cryptographic failures (A02) - lowest coverage",
                    "Improve software integrity failures (A08) monitoring",
                    "Maintain strong injection (A03) protection practices"
                ]
            }
            
            return coverage_analysis
            
        except Exception as e:
            logger.error(f"Failed to get OWASP coverage analysis: {e}")
            return {}
    
    def _get_security_hotspots_data(self) -> List[Dict[str, Any]]:
        """Get security hotspots data"""
        try:
            hotspots = self.security_metrics.identify_security_hotspots(10)
            
            # Convert to dictionary format
            hotspots_data = []
            for hotspot in hotspots:
                hotspot_dict = asdict(hotspot)
                hotspot_dict["last_updated"] = hotspot.last_updated.isoformat()
                hotspots_data.append(hotspot_dict)
            
            return hotspots_data
            
        except Exception as e:
            logger.error(f"Failed to get security hotspots data: {e}")
            return []
    
    def _get_performance_metrics(self) -> Dict[str, Any]:
        """Get security analysis performance metrics"""
        try:
            performance_metrics = {
                "analysis_throughput": 0.0,
                "average_processing_time": 0.0,
                "queue_length": 0,
                "resource_utilization": {
                    "cpu_usage": 0.0,
                    "memory_usage": 0.0,
                    "storage_usage": 0.0
                },
                "cache_performance": {
                    "hit_rate": 0.0,
                    "miss_rate": 0.0
                }
            }
            
            # Get analysis throughput (analyses per hour)
            completed_analyses = metrics_collector.get_counter("analysis.completed_total")
            # Simplified calculation - would need time-based analysis
            performance_metrics["analysis_throughput"] = completed_analyses / 24  # per hour
            
            # Get average processing time
            timer_stats = metrics_collector.get_timer_stats("analysis.duration")
            performance_metrics["average_processing_time"] = timer_stats.get("mean", 0.0) / 1000
            
            # Get queue length
            performance_metrics["queue_length"] = int(metrics_collector.get_gauge("analysis.queued_count"))
            
            # Get resource utilization
            performance_metrics["resource_utilization"]["cpu_usage"] = metrics_collector.get_gauge("system.cpu_percent")
            performance_metrics["resource_utilization"]["memory_usage"] = metrics_collector.get_gauge("system.memory_percent")
            performance_metrics["resource_utilization"]["storage_usage"] = metrics_collector.get_gauge("system.disk_usage_percent")
            
            return performance_metrics
            
        except Exception as e:
            logger.error(f"Failed to get performance metrics: {e}")
            return {}
    
    def get_repository_detailed_metrics(self, repo_id: str) -> Dict[str, Any]:
        """Get detailed metrics for a specific repository"""
        try:
            detailed_metrics = {
                "repo_id": repo_id,
                "timestamp": datetime.now().isoformat(),
                "security_overview": {},
                "threat_analysis": {},
                "vulnerability_analysis": {},
                "owasp_compliance": {},
                "trend_analysis": {},
                "recommendations": []
            }
            
            # Get repository security metrics
            security_data = self.security_metrics.collect_repository_metrics(repo_id)
            detailed_metrics["security_overview"] = security_data
            
            # Get repository-specific database data
            repo_db_data = self._get_repository_database_data(repo_id)
            detailed_metrics.update(repo_db_data)
            
            # Generate repository-specific recommendations
            detailed_metrics["recommendations"] = self._generate_repository_recommendations(repo_id, security_data)
            
            return detailed_metrics
            
        except Exception as e:
            logger.error(f"Failed to get detailed metrics for repo {repo_id}: {e}")
            return {"error": str(e), "repo_id": repo_id}
    
    def _get_repository_database_data(self, repo_id: str) -> Dict[str, Any]:
        """Get repository data from database"""
        try:
            repo_data = {}
            
            with sqlite3.connect(self.db_manager.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get repository info
                cursor = conn.execute("SELECT * FROM repositories WHERE id = ?", (repo_id,))
                repo_row = cursor.fetchone()
                
                if repo_row:
                    repo_data["repository_info"] = dict(repo_row)
                
                # Get security documents count
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM security_documents WHERE repo_id = ? AND is_current = 1",
                    (repo_id,)
                )
                repo_data["security_documents_count"] = cursor.fetchone()[0]
                
                # Get PR analyses count
                cursor = conn.execute("SELECT COUNT(*) FROM pr_analyses WHERE repo_id = ?", (repo_id,))
                repo_data["pr_analyses_count"] = cursor.fetchone()[0]
                
                # Get recent activity
                cursor = conn.execute("""
                    SELECT created_at FROM security_documents 
                    WHERE repo_id = ? AND is_current = 1 
                    ORDER BY created_at DESC LIMIT 1
                """, (repo_id,))
                
                last_analysis = cursor.fetchone()
                if last_analysis:
                    repo_data["last_analysis"] = last_analysis[0]
            
            return repo_data
            
        except Exception as e:
            logger.error(f"Failed to get repository database data for {repo_id}: {e}")
            return {}
    
    def _generate_repository_recommendations(self, repo_id: str, security_data: Dict[str, Any]) -> List[str]:
        """Generate recommendations for a specific repository"""
        recommendations = []
        
        try:
            # Analyze security score
            security_score = security_data.get("security_score", 0)
            if security_score < 50:
                recommendations.append("Critical: Security score is below 50% - immediate review required")
            elif security_score < 70:
                recommendations.append("Warning: Security score could be improved - consider additional mitigations")
            
            # Analyze threat metrics
            threat_metrics = security_data.get("threat_metrics", {})
            critical_threats = threat_metrics.get("critical_threats", 0)
            if critical_threats > 0:
                recommendations.append(f"Address {critical_threats} critical threats immediately")
            
            # Analyze vulnerability metrics
            vuln_metrics = security_data.get("vulnerability_metrics", {})
            critical_vulns = vuln_metrics.get("critical_vulnerabilities", 0)
            if critical_vulns > 0:
                recommendations.append(f"Patch {critical_vulns} critical vulnerabilities")
            
            # Analyze OWASP coverage
            owasp_coverage = security_data.get("owasp_coverage", {})
            if hasattr(owasp_coverage, 'overall_coverage') and owasp_coverage.overall_coverage < 60:
                recommendations.append("Improve OWASP Top 10 coverage - currently below 60%")
            
            # Default recommendation if no specific issues
            if not recommendations:
                recommendations.append("Security posture is good - maintain current practices")
            
        except Exception as e:
            logger.error(f"Failed to generate recommendations for repo {repo_id}: {e}")
            recommendations.append("Unable to generate recommendations - manual review suggested")
        
        return recommendations


# Global analytics aggregator instance
security_analytics_aggregator = None

def get_security_analytics_aggregator() -> SecurityAnalyticsAggregator:
    """Get or create global security analytics aggregator"""
    global security_analytics_aggregator
    
    if security_analytics_aggregator is None:
        from .database import DatabaseManager
        from .security_metrics import get_security_metrics_collector
        
        db_manager = DatabaseManager()
        security_metrics = get_security_metrics_collector()
        security_analytics_aggregator = SecurityAnalyticsAggregator(db_manager, security_metrics)
    
    return security_analytics_aggregator