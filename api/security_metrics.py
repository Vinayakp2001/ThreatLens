"""
Security Metrics Collection System
Implements comprehensive security metrics collection for analytics dashboard
"""
import time
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from enum import Enum

from .monitoring import MetricsCollector, MetricType
from .database import DatabaseManager
from .models import SecurityWiki, SecurityFinding

logger = logging.getLogger(__name__)


class SecurityMetricType(str, Enum):
    """Types of security metrics"""
    THREAT_COUNT = "threat_count"
    VULNERABILITY_COUNT = "vulnerability_count"
    MITIGATION_COUNT = "mitigation_count"
    OWASP_COVERAGE = "owasp_coverage"
    SECURITY_SCORE = "security_score"
    RISK_LEVEL = "risk_level"
    COMPLIANCE_SCORE = "compliance_score"
    PATTERN_DETECTION = "pattern_detection"


@dataclass
class SecurityMetricPoint:
    """Security-specific metric data point"""
    metric_type: SecurityMetricType
    value: float
    repo_id: Optional[str] = None
    owasp_category: Optional[str] = None
    severity_level: Optional[str] = None
    timestamp: datetime = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.metadata is None:
            self.metadata = {}


@dataclass
class OWASPCoverageMetrics:
    """OWASP Top 10 coverage metrics"""
    a01_broken_access_control: float = 0.0
    a02_cryptographic_failures: float = 0.0
    a03_injection: float = 0.0
    a04_insecure_design: float = 0.0
    a05_security_misconfiguration: float = 0.0
    a06_vulnerable_components: float = 0.0
    a07_identification_failures: float = 0.0
    a08_software_integrity_failures: float = 0.0
    a09_logging_failures: float = 0.0
    a10_server_side_request_forgery: float = 0.0
    overall_coverage: float = 0.0
    
    def calculate_overall_coverage(self) -> float:
        """Calculate overall OWASP coverage percentage"""
        categories = [
            self.a01_broken_access_control, self.a02_cryptographic_failures,
            self.a03_injection, self.a04_insecure_design,
            self.a05_security_misconfiguration, self.a06_vulnerable_components,
            self.a07_identification_failures, self.a08_software_integrity_failures,
            self.a09_logging_failures, self.a10_server_side_request_forgery
        ]
        self.overall_coverage = sum(categories) / len(categories)
        return self.overall_coverage


@dataclass
class SecurityTrendMetrics:
    """Security trend analysis metrics"""
    time_period: str  # "1h", "24h", "7d", "30d"
    threat_trend: float  # percentage change
    vulnerability_trend: float
    mitigation_trend: float
    security_score_trend: float
    new_threats_count: int
    resolved_threats_count: int
    regression_count: int


@dataclass
class SecurityHotspot:
    """Security hotspot identification"""
    repo_id: str
    component_name: str
    risk_score: float
    threat_count: int
    vulnerability_count: int
    severity_distribution: Dict[str, int]
    owasp_categories: List[str]
    last_updated: datetime


class SecurityMetricsCollector:
    """Collects and aggregates security-specific metrics"""
    
    def __init__(self, metrics_collector: MetricsCollector, db_manager: DatabaseManager):
        self.metrics_collector = metrics_collector
        self.db_manager = db_manager
        self.security_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.owasp_mappings = self._initialize_owasp_mappings()
        self.lock = threading.Lock()
        
        # Start background collection
        self.collection_active = False
        self.collection_thread = None
    
    def _initialize_owasp_mappings(self) -> Dict[str, str]:
        """Initialize OWASP Top 10 category mappings"""
        return {
            "A01": "broken_access_control",
            "A02": "cryptographic_failures", 
            "A03": "injection",
            "A04": "insecure_design",
            "A05": "security_misconfiguration",
            "A06": "vulnerable_components",
            "A07": "identification_failures",
            "A08": "software_integrity_failures",
            "A09": "logging_failures",
            "A10": "server_side_request_forgery"
        }
    
    def start_collection(self, interval_seconds: int = 300):
        """Start automated security metrics collection"""
        if self.collection_active:
            return
        
        self.collection_active = True
        self.collection_thread = threading.Thread(
            target=self._collection_loop,
            args=(interval_seconds,),
            daemon=True
        )
        self.collection_thread.start()
        logger.info(f"Security metrics collection started with {interval_seconds}s interval")
    
    def stop_collection(self):
        """Stop automated collection"""
        self.collection_active = False
        if self.collection_thread:
            self.collection_thread.join(timeout=10)
        logger.info("Security metrics collection stopped")
    
    def record_security_metric(self, metric: SecurityMetricPoint):
        """Record a security metric point"""
        with self.lock:
            # Store in security metrics
            key = f"{metric.metric_type.value}_{metric.repo_id or 'global'}"
            self.security_metrics[key].append(metric)
            
            # Also record in general metrics collector
            labels = {
                "repo_id": metric.repo_id or "global",
                "metric_type": metric.metric_type.value
            }
            
            if metric.owasp_category:
                labels["owasp_category"] = metric.owasp_category
            if metric.severity_level:
                labels["severity"] = metric.severity_level
            
            self.metrics_collector.record_metric(
                f"security.{metric.metric_type.value}",
                metric.value,
                MetricType.GAUGE,
                labels
            )
    
    def collect_repository_metrics(self, repo_id: str) -> Dict[str, Any]:
        """Collect comprehensive security metrics for a repository"""
        try:
            # Get security wiki data
            wiki_data = self._get_repository_wiki_data(repo_id)
            if not wiki_data:
                return {}
            
            metrics = {
                "repo_id": repo_id,
                "timestamp": datetime.now().isoformat(),
                "threat_metrics": self._calculate_threat_metrics(wiki_data),
                "owasp_coverage": self._calculate_owasp_coverage(wiki_data),
                "security_score": self._calculate_security_score(wiki_data),
                "vulnerability_metrics": self._calculate_vulnerability_metrics(wiki_data),
                "mitigation_metrics": self._calculate_mitigation_metrics(wiki_data)
            }
            
            # Record individual metrics
            self._record_repository_metrics(repo_id, metrics)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to collect metrics for repo {repo_id}: {e}")
            return {}
    
    def _get_repository_wiki_data(self, repo_id: str) -> Optional[Dict[str, Any]]:
        """Get security wiki data for repository"""
        try:
            # This would integrate with the wiki storage system
            # For now, return mock data structure
            return {
                "sections": {},
                "security_findings": [],
                "owasp_mappings": [],
                "threats": [],
                "mitigations": []
            }
        except Exception as e:
            logger.error(f"Failed to get wiki data for repo {repo_id}: {e}")
            return None
    
    def _calculate_threat_metrics(self, wiki_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate threat-related metrics"""
        threats = wiki_data.get("threats", [])
        
        # Count by severity
        severity_counts = defaultdict(int)
        for threat in threats:
            severity = threat.get("severity", "unknown")
            severity_counts[severity] += 1
        
        # Count by STRIDE category
        stride_counts = defaultdict(int)
        for threat in threats:
            stride = threat.get("stride_category", "unknown")
            stride_counts[stride] += 1
        
        return {
            "total_threats": len(threats),
            "severity_distribution": dict(severity_counts),
            "stride_distribution": dict(stride_counts),
            "critical_threats": severity_counts.get("critical", 0),
            "high_threats": severity_counts.get("high", 0),
            "medium_threats": severity_counts.get("medium", 0),
            "low_threats": severity_counts.get("low", 0)
        }
    
    def _calculate_owasp_coverage(self, wiki_data: Dict[str, Any]) -> OWASPCoverageMetrics:
        """Calculate OWASP Top 10 coverage metrics"""
        owasp_mappings = wiki_data.get("owasp_mappings", [])
        
        # Count coverage for each OWASP category
        coverage_counts = defaultdict(int)
        total_possible = 10  # OWASP Top 10
        
        for mapping in owasp_mappings:
            category = mapping.get("owasp_category", "")
            if category.startswith("A"):
                coverage_counts[category] += 1
        
        # Calculate percentages (simplified - in reality would be more complex)
        coverage = OWASPCoverageMetrics()
        coverage.a01_broken_access_control = min(100.0, coverage_counts.get("A01", 0) * 20)
        coverage.a02_cryptographic_failures = min(100.0, coverage_counts.get("A02", 0) * 20)
        coverage.a03_injection = min(100.0, coverage_counts.get("A03", 0) * 20)
        coverage.a04_insecure_design = min(100.0, coverage_counts.get("A04", 0) * 20)
        coverage.a05_security_misconfiguration = min(100.0, coverage_counts.get("A05", 0) * 20)
        coverage.a06_vulnerable_components = min(100.0, coverage_counts.get("A06", 0) * 20)
        coverage.a07_identification_failures = min(100.0, coverage_counts.get("A07", 0) * 20)
        coverage.a08_software_integrity_failures = min(100.0, coverage_counts.get("A08", 0) * 20)
        coverage.a09_logging_failures = min(100.0, coverage_counts.get("A09", 0) * 20)
        coverage.a10_server_side_request_forgery = min(100.0, coverage_counts.get("A10", 0) * 20)
        
        coverage.calculate_overall_coverage()
        return coverage
    
    def _calculate_security_score(self, wiki_data: Dict[str, Any]) -> float:
        """Calculate overall security score (0-100)"""
        threats = wiki_data.get("threats", [])
        mitigations = wiki_data.get("mitigations", [])
        
        if not threats:
            return 100.0  # No threats identified
        
        # Calculate based on threat/mitigation ratio and severity
        total_threats = len(threats)
        total_mitigations = len(mitigations)
        
        # Weight by severity
        severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        weighted_threats = sum(severity_weights.get(t.get("severity", "low"), 1) for t in threats)
        weighted_mitigations = sum(severity_weights.get(m.get("effectiveness", "low"), 1) for m in mitigations)
        
        # Calculate score (simplified algorithm)
        if weighted_threats == 0:
            return 100.0
        
        mitigation_ratio = min(1.0, weighted_mitigations / weighted_threats)
        base_score = mitigation_ratio * 100
        
        # Penalty for critical/high severity threats
        critical_penalty = len([t for t in threats if t.get("severity") == "critical"]) * 10
        high_penalty = len([t for t in threats if t.get("severity") == "high"]) * 5
        
        final_score = max(0.0, base_score - critical_penalty - high_penalty)
        return min(100.0, final_score)
    
    def _calculate_vulnerability_metrics(self, wiki_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate vulnerability-related metrics"""
        security_findings = wiki_data.get("security_findings", [])
        vulnerabilities = [f for f in security_findings if f.get("type") == "vulnerability"]
        
        # Count by severity
        severity_counts = defaultdict(int)
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown")
            severity_counts[severity] += 1
        
        # Count by CWE category
        cwe_counts = defaultdict(int)
        for vuln in vulnerabilities:
            cwe = vuln.get("cwe_id", "unknown")
            cwe_counts[cwe] += 1
        
        return {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_distribution": dict(severity_counts),
            "cwe_distribution": dict(cwe_counts),
            "critical_vulnerabilities": severity_counts.get("critical", 0),
            "high_vulnerabilities": severity_counts.get("high", 0)
        }
    
    def _calculate_mitigation_metrics(self, wiki_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate mitigation-related metrics"""
        mitigations = wiki_data.get("mitigations", [])
        
        # Count by status
        status_counts = defaultdict(int)
        for mitigation in mitigations:
            status = mitigation.get("status", "unknown")
            status_counts[status] += 1
        
        # Count by effectiveness
        effectiveness_counts = defaultdict(int)
        for mitigation in mitigations:
            effectiveness = mitigation.get("effectiveness", "unknown")
            effectiveness_counts[effectiveness] += 1
        
        return {
            "total_mitigations": len(mitigations),
            "status_distribution": dict(status_counts),
            "effectiveness_distribution": dict(effectiveness_counts),
            "implemented_mitigations": status_counts.get("implemented", 0),
            "planned_mitigations": status_counts.get("planned", 0)
        }
    
    def _record_repository_metrics(self, repo_id: str, metrics: Dict[str, Any]):
        """Record repository metrics as individual metric points"""
        timestamp = datetime.now()
        
        # Record threat metrics
        threat_metrics = metrics.get("threat_metrics", {})
        self.record_security_metric(SecurityMetricPoint(
            SecurityMetricType.THREAT_COUNT,
            threat_metrics.get("total_threats", 0),
            repo_id=repo_id,
            timestamp=timestamp
        ))
        
        # Record vulnerability metrics
        vuln_metrics = metrics.get("vulnerability_metrics", {})
        self.record_security_metric(SecurityMetricPoint(
            SecurityMetricType.VULNERABILITY_COUNT,
            vuln_metrics.get("total_vulnerabilities", 0),
            repo_id=repo_id,
            timestamp=timestamp
        ))
        
        # Record mitigation metrics
        mitigation_metrics = metrics.get("mitigation_metrics", {})
        self.record_security_metric(SecurityMetricPoint(
            SecurityMetricType.MITIGATION_COUNT,
            mitigation_metrics.get("total_mitigations", 0),
            repo_id=repo_id,
            timestamp=timestamp
        ))
        
        # Record security score
        self.record_security_metric(SecurityMetricPoint(
            SecurityMetricType.SECURITY_SCORE,
            metrics.get("security_score", 0),
            repo_id=repo_id,
            timestamp=timestamp
        ))
        
        # Record OWASP coverage
        owasp_coverage = metrics.get("owasp_coverage", {})
        if hasattr(owasp_coverage, 'overall_coverage'):
            self.record_security_metric(SecurityMetricPoint(
                SecurityMetricType.OWASP_COVERAGE,
                owasp_coverage.overall_coverage,
                repo_id=repo_id,
                timestamp=timestamp
            ))
    
    def calculate_security_trends(self, time_period: str = "24h") -> SecurityTrendMetrics:
        """Calculate security trends over time period"""
        try:
            # Parse time period
            if time_period == "1h":
                delta = timedelta(hours=1)
            elif time_period == "24h":
                delta = timedelta(hours=24)
            elif time_period == "7d":
                delta = timedelta(days=7)
            elif time_period == "30d":
                delta = timedelta(days=30)
            else:
                delta = timedelta(hours=24)
            
            cutoff_time = datetime.now() - delta
            
            # Get metrics from the time period
            current_metrics = self._get_aggregated_metrics(datetime.now() - timedelta(hours=1), datetime.now())
            previous_metrics = self._get_aggregated_metrics(cutoff_time, cutoff_time + timedelta(hours=1))
            
            # Calculate trends (percentage change)
            threat_trend = self._calculate_percentage_change(
                previous_metrics.get("total_threats", 0),
                current_metrics.get("total_threats", 0)
            )
            
            vulnerability_trend = self._calculate_percentage_change(
                previous_metrics.get("total_vulnerabilities", 0),
                current_metrics.get("total_vulnerabilities", 0)
            )
            
            mitigation_trend = self._calculate_percentage_change(
                previous_metrics.get("total_mitigations", 0),
                current_metrics.get("total_mitigations", 0)
            )
            
            security_score_trend = self._calculate_percentage_change(
                previous_metrics.get("avg_security_score", 0),
                current_metrics.get("avg_security_score", 0)
            )
            
            return SecurityTrendMetrics(
                time_period=time_period,
                threat_trend=threat_trend,
                vulnerability_trend=vulnerability_trend,
                mitigation_trend=mitigation_trend,
                security_score_trend=security_score_trend,
                new_threats_count=current_metrics.get("new_threats", 0),
                resolved_threats_count=current_metrics.get("resolved_threats", 0),
                regression_count=current_metrics.get("regressions", 0)
            )
            
        except Exception as e:
            logger.error(f"Failed to calculate security trends: {e}")
            return SecurityTrendMetrics(time_period, 0, 0, 0, 0, 0, 0, 0)
    
    def _get_aggregated_metrics(self, start_time: datetime, end_time: datetime) -> Dict[str, float]:
        """Get aggregated metrics for time range"""
        aggregated = {
            "total_threats": 0,
            "total_vulnerabilities": 0,
            "total_mitigations": 0,
            "avg_security_score": 0,
            "new_threats": 0,
            "resolved_threats": 0,
            "regressions": 0
        }
        
        with self.lock:
            # Aggregate from stored metrics
            for key, metrics_deque in self.security_metrics.items():
                for metric in metrics_deque:
                    if start_time <= metric.timestamp <= end_time:
                        if metric.metric_type == SecurityMetricType.THREAT_COUNT:
                            aggregated["total_threats"] += metric.value
                        elif metric.metric_type == SecurityMetricType.VULNERABILITY_COUNT:
                            aggregated["total_vulnerabilities"] += metric.value
                        elif metric.metric_type == SecurityMetricType.MITIGATION_COUNT:
                            aggregated["total_mitigations"] += metric.value
                        elif metric.metric_type == SecurityMetricType.SECURITY_SCORE:
                            aggregated["avg_security_score"] += metric.value
        
        # Calculate averages where appropriate
        repo_count = len(set(key.split('_')[-1] for key in self.security_metrics.keys() if key.split('_')[-1] != 'global'))
        if repo_count > 0:
            aggregated["avg_security_score"] /= repo_count
        
        return aggregated
    
    def _calculate_percentage_change(self, old_value: float, new_value: float) -> float:
        """Calculate percentage change between two values"""
        if old_value == 0:
            return 100.0 if new_value > 0 else 0.0
        return ((new_value - old_value) / old_value) * 100
    
    def identify_security_hotspots(self, limit: int = 10) -> List[SecurityHotspot]:
        """Identify top security hotspots across repositories"""
        try:
            hotspots = []
            
            # Get all repositories with metrics
            repo_metrics = {}
            with self.lock:
                for key, metrics_deque in self.security_metrics.items():
                    if not metrics_deque:
                        continue
                    
                    parts = key.split('_')
                    if len(parts) >= 2:
                        repo_id = parts[-1]
                        if repo_id != 'global':
                            if repo_id not in repo_metrics:
                                repo_metrics[repo_id] = {
                                    "threats": 0,
                                    "vulnerabilities": 0,
                                    "security_score": 0,
                                    "owasp_categories": set()
                                }
                            
                            # Get latest metric
                            latest_metric = metrics_deque[-1]
                            if latest_metric.metric_type == SecurityMetricType.THREAT_COUNT:
                                repo_metrics[repo_id]["threats"] = latest_metric.value
                            elif latest_metric.metric_type == SecurityMetricType.VULNERABILITY_COUNT:
                                repo_metrics[repo_id]["vulnerabilities"] = latest_metric.value
                            elif latest_metric.metric_type == SecurityMetricType.SECURITY_SCORE:
                                repo_metrics[repo_id]["security_score"] = latest_metric.value
                            
                            if latest_metric.owasp_category:
                                repo_metrics[repo_id]["owasp_categories"].add(latest_metric.owasp_category)
            
            # Calculate risk scores and create hotspots
            for repo_id, metrics in repo_metrics.items():
                # Calculate risk score (higher is worse)
                threat_weight = metrics["threats"] * 2
                vuln_weight = metrics["vulnerabilities"] * 3
                score_penalty = (100 - metrics["security_score"]) * 0.5
                
                risk_score = threat_weight + vuln_weight + score_penalty
                
                if risk_score > 0:  # Only include repos with actual risks
                    hotspot = SecurityHotspot(
                        repo_id=repo_id,
                        component_name=f"Repository {repo_id}",
                        risk_score=risk_score,
                        threat_count=int(metrics["threats"]),
                        vulnerability_count=int(metrics["vulnerabilities"]),
                        severity_distribution={"high": int(metrics["threats"] * 0.3), "medium": int(metrics["threats"] * 0.5), "low": int(metrics["threats"] * 0.2)},
                        owasp_categories=list(metrics["owasp_categories"]),
                        last_updated=datetime.now()
                    )
                    hotspots.append(hotspot)
            
            # Sort by risk score and return top N
            hotspots.sort(key=lambda x: x.risk_score, reverse=True)
            return hotspots[:limit]
            
        except Exception as e:
            logger.error(f"Failed to identify security hotspots: {e}")
            return []
    
    def get_global_security_metrics(self) -> Dict[str, Any]:
        """Get aggregated global security metrics"""
        try:
            current_time = datetime.now()
            
            # Aggregate metrics across all repositories
            global_metrics = {
                "timestamp": current_time.isoformat(),
                "total_repositories": 0,
                "total_threats": 0,
                "total_vulnerabilities": 0,
                "total_mitigations": 0,
                "average_security_score": 0,
                "owasp_coverage_average": 0,
                "security_hotspots_count": 0,
                "trend_analysis": self.calculate_security_trends("24h")
            }
            
            repo_scores = []
            repo_ids = set()
            
            with self.lock:
                for key, metrics_deque in self.security_metrics.items():
                    if not metrics_deque:
                        continue
                    
                    parts = key.split('_')
                    if len(parts) >= 2:
                        repo_id = parts[-1]
                        if repo_id != 'global':
                            repo_ids.add(repo_id)
                            
                            # Get latest metrics
                            latest_metric = metrics_deque[-1]
                            if latest_metric.metric_type == SecurityMetricType.THREAT_COUNT:
                                global_metrics["total_threats"] += latest_metric.value
                            elif latest_metric.metric_type == SecurityMetricType.VULNERABILITY_COUNT:
                                global_metrics["total_vulnerabilities"] += latest_metric.value
                            elif latest_metric.metric_type == SecurityMetricType.MITIGATION_COUNT:
                                global_metrics["total_mitigations"] += latest_metric.value
                            elif latest_metric.metric_type == SecurityMetricType.SECURITY_SCORE:
                                repo_scores.append(latest_metric.value)
            
            global_metrics["total_repositories"] = len(repo_ids)
            
            if repo_scores:
                global_metrics["average_security_score"] = sum(repo_scores) / len(repo_scores)
            
            # Get security hotspots count
            hotspots = self.identify_security_hotspots(100)  # Get all hotspots
            global_metrics["security_hotspots_count"] = len([h for h in hotspots if h.risk_score > 10])
            
            return global_metrics
            
        except Exception as e:
            logger.error(f"Failed to get global security metrics: {e}")
            return {"error": str(e), "timestamp": datetime.now().isoformat()}
    
    def _collection_loop(self, interval_seconds: int):
        """Main collection loop for automated metrics gathering"""
        while self.collection_active:
            try:
                # Collect metrics for all repositories
                # This would integrate with the repository management system
                # For now, we'll just update global metrics
                
                global_metrics = self.get_global_security_metrics()
                
                # Record global metrics
                self.record_security_metric(SecurityMetricPoint(
                    SecurityMetricType.THREAT_COUNT,
                    global_metrics.get("total_threats", 0),
                    metadata={"scope": "global"}
                ))
                
                self.record_security_metric(SecurityMetricPoint(
                    SecurityMetricType.SECURITY_SCORE,
                    global_metrics.get("average_security_score", 0),
                    metadata={"scope": "global"}
                ))
                
                time.sleep(interval_seconds)
                
            except Exception as e:
                logger.error(f"Error in security metrics collection loop: {e}")
                time.sleep(60)  # Sleep 1 minute on error


# Global security metrics collector instance
security_metrics_collector = None

def get_security_metrics_collector() -> SecurityMetricsCollector:
    """Get or create global security metrics collector"""
    global security_metrics_collector
    
    if security_metrics_collector is None:
        from .monitoring import metrics_collector
        from .database import DatabaseManager
        
        db_manager = DatabaseManager()
        security_metrics_collector = SecurityMetricsCollector(metrics_collector, db_manager)
    
    return security_metrics_collector