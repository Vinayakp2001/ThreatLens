"""
Security trend analysis system for tracking security posture evolution over time
"""
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import statistics

from .models import SecurityWiki, SecurityFinding
from .wiki_storage import WikiStorage
from .wiki_comparison import WikiComparisonEngine, SecurityComparison, SecurityMaturityScore

logger = logging.getLogger(__name__)


class TrendDirection(str, Enum):
    IMPROVING = "improving"
    DECLINING = "declining"
    STABLE = "stable"
    VOLATILE = "volatile"


class TrendPeriod(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"


@dataclass
class SecurityMetricPoint:
    """Single point in time for security metrics"""
    timestamp: datetime
    wiki_id: str
    maturity_score: float
    threat_count: int
    mitigation_count: int
    compliance_score: float
    critical_threats: int
    high_threats: int
    medium_threats: int
    low_threats: int
    owasp_coverage: Dict[str, float]
    regression_detected: bool = False
    improvement_detected: bool = False


@dataclass
class SecurityTrendData:
    """Time-series data for security trends"""
    repo_id: str
    period: TrendPeriod
    data_points: List[SecurityMetricPoint]
    trend_direction: TrendDirection
    trend_strength: float  # 0.0 to 1.0
    volatility: float  # 0.0 to 1.0
    analysis_period: Tuple[datetime, datetime]
    
    @property
    def duration_days(self) -> int:
        """Get the duration of the analysis period in days"""
        return (self.analysis_period[1] - self.analysis_period[0]).days
    
    @property
    def latest_score(self) -> float:
        """Get the latest maturity score"""
        return self.data_points[-1].maturity_score if self.data_points else 0.0
    
    @property
    def score_change(self) -> float:
        """Get the change in maturity score from first to last point"""
        if len(self.data_points) < 2:
            return 0.0
        return self.data_points[-1].maturity_score - self.data_points[0].maturity_score


@dataclass
class SecurityRegressionAlert:
    """Alert for detected security regression"""
    timestamp: datetime
    repo_id: str
    wiki_id: str
    severity: str  # low, medium, high, critical
    regression_type: str  # threat_increase, mitigation_decrease, compliance_drop
    description: str
    impact_score: float
    recommended_actions: List[str]
    affected_owasp_categories: List[str]


@dataclass
class SecurityTrendAnalysis:
    """Complete security trend analysis results"""
    repo_id: str
    analysis_timestamp: datetime
    trend_data: SecurityTrendData
    key_insights: List[str]
    regression_alerts: List[SecurityRegressionAlert]
    improvement_highlights: List[str]
    recommendations: List[str]
    forecast: Optional[Dict[str, Any]] = None


class SecurityTrendAnalyzer:
    """Analyzer for security trends and regression detection"""
    
    def __init__(self, wiki_storage: Optional[WikiStorage] = None, 
                 comparison_engine: Optional[WikiComparisonEngine] = None):
        self.wiki_storage = wiki_storage or WikiStorage()
        self.comparison_engine = comparison_engine or WikiComparisonEngine()
        
        # Thresholds for trend analysis
        self.regression_thresholds = {
            'maturity_score_drop': 0.1,  # 10% drop in maturity score
            'compliance_drop': 0.15,     # 15% drop in compliance
            'threat_increase': 0.2,      # 20% increase in threats
            'mitigation_decrease': 0.15   # 15% decrease in mitigations
        }
        
        self.volatility_thresholds = {
            'low': 0.1,
            'medium': 0.25,
            'high': 0.4
        }
    
    def analyze_security_trends(self, repo_id: str, 
                              period: TrendPeriod = TrendPeriod.WEEKLY,
                              lookback_days: int = 90) -> Optional[SecurityTrendAnalysis]:
        """
        Analyze security trends for a repository over time
        
        Args:
            repo_id: Repository ID to analyze
            period: Time period granularity for analysis
            lookback_days: Number of days to look back for analysis
            
        Returns:
            SecurityTrendAnalysis with comprehensive trend data
        """
        try:
            logger.info(f"Analyzing security trends for repo {repo_id} over {lookback_days} days")
            
            # Get wiki history for the repository
            wikis = self.wiki_storage.get_wikis_by_repo(repo_id)
            
            if len(wikis) < 2:
                logger.warning(f"Insufficient data for trend analysis: {len(wikis)} wikis found")
                return None
            
            # Filter wikis within the lookback period
            cutoff_date = datetime.now() - timedelta(days=lookback_days)
            recent_wikis = [w for w in wikis if w.created_at >= cutoff_date]
            
            if len(recent_wikis) < 2:
                logger.warning(f"Insufficient recent data: {len(recent_wikis)} wikis in last {lookback_days} days")
                return None
            
            # Sort by creation date
            recent_wikis.sort(key=lambda w: w.created_at)
            
            # Generate metric points
            metric_points = self._generate_metric_points(recent_wikis)
            
            # Analyze trends
            trend_data = self._analyze_trend_data(repo_id, metric_points, period)
            
            # Detect regressions
            regression_alerts = self._detect_regressions(metric_points, repo_id)
            
            # Generate insights and recommendations
            key_insights = self._generate_key_insights(trend_data, metric_points)
            improvement_highlights = self._identify_improvements(metric_points)
            recommendations = self._generate_recommendations(trend_data, regression_alerts)
            
            # Generate forecast (simplified)
            forecast = self._generate_forecast(metric_points)
            
            analysis = SecurityTrendAnalysis(
                repo_id=repo_id,
                analysis_timestamp=datetime.now(),
                trend_data=trend_data,
                key_insights=key_insights,
                regression_alerts=regression_alerts,
                improvement_highlights=improvement_highlights,
                recommendations=recommendations,
                forecast=forecast
            )
            
            logger.info(f"Security trend analysis completed: {trend_data.trend_direction} trend detected")
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing security trends: {e}")
            return None
    
    def _generate_metric_points(self, wikis: List[SecurityWiki]) -> List[SecurityMetricPoint]:
        """Generate security metric points from wiki history"""
        metric_points = []
        
        for i, wiki in enumerate(wikis):
            # Calculate maturity score
            maturity_score = self.comparison_engine.calculate_security_maturity_score(wiki)
            
            # Extract security findings
            all_findings = []
            for section in wiki.sections.values():
                all_findings.extend(section.security_findings)
            
            # Count threats by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for finding in all_findings:
                severity = finding.severity.lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Calculate OWASP coverage
            owasp_coverage = self._calculate_owasp_coverage(wiki)
            
            # Calculate compliance score
            compliance_score = self._calculate_compliance_score(wiki)
            
            # Count mitigations
            mitigation_count = self._count_mitigations(wiki)
            
            # Check for regression/improvement if not first wiki
            regression_detected = False
            improvement_detected = False
            
            if i > 0:
                previous_wiki = wikis[i-1]
                comparison = self.comparison_engine.compare_wikis(previous_wiki.id, wiki.id)
                if comparison:
                    regression_detected = comparison.regression_detected
                    improvement_detected = comparison.improvement_detected
            
            metric_point = SecurityMetricPoint(
                timestamp=wiki.created_at,
                wiki_id=wiki.id,
                maturity_score=maturity_score.overall_score,
                threat_count=len(all_findings),
                mitigation_count=mitigation_count,
                compliance_score=compliance_score,
                critical_threats=severity_counts["critical"],
                high_threats=severity_counts["high"],
                medium_threats=severity_counts["medium"],
                low_threats=severity_counts["low"],
                owasp_coverage=owasp_coverage,
                regression_detected=regression_detected,
                improvement_detected=improvement_detected
            )
            
            metric_points.append(metric_point)
        
        return metric_points
    
    def _analyze_trend_data(self, repo_id: str, metric_points: List[SecurityMetricPoint], 
                          period: TrendPeriod) -> SecurityTrendData:
        """Analyze trend direction and characteristics"""
        if len(metric_points) < 2:
            return SecurityTrendData(
                repo_id=repo_id,
                period=period,
                data_points=metric_points,
                trend_direction=TrendDirection.STABLE,
                trend_strength=0.0,
                volatility=0.0,
                analysis_period=(metric_points[0].timestamp, metric_points[-1].timestamp)
            )
        
        # Calculate trend direction based on maturity scores
        scores = [point.maturity_score for point in metric_points]
        
        # Linear regression to determine trend
        n = len(scores)
        x_values = list(range(n))
        
        # Calculate slope
        x_mean = statistics.mean(x_values)
        y_mean = statistics.mean(scores)
        
        numerator = sum((x_values[i] - x_mean) * (scores[i] - y_mean) for i in range(n))
        denominator = sum((x_values[i] - x_mean) ** 2 for i in range(n))
        
        slope = numerator / denominator if denominator != 0 else 0
        
        # Determine trend direction
        if abs(slope) < 0.01:
            trend_direction = TrendDirection.STABLE
        elif slope > 0:
            trend_direction = TrendDirection.IMPROVING
        else:
            trend_direction = TrendDirection.DECLINING
        
        # Calculate trend strength (normalized slope)
        trend_strength = min(1.0, abs(slope) * 10)  # Scale slope to 0-1 range
        
        # Calculate volatility (standard deviation of scores)
        volatility = statistics.stdev(scores) if len(scores) > 1 else 0.0
        
        # Check for high volatility
        if volatility > self.volatility_thresholds['high']:
            trend_direction = TrendDirection.VOLATILE
        
        return SecurityTrendData(
            repo_id=repo_id,
            period=period,
            data_points=metric_points,
            trend_direction=trend_direction,
            trend_strength=trend_strength,
            volatility=volatility,
            analysis_period=(metric_points[0].timestamp, metric_points[-1].timestamp)
        )
    
    def _detect_regressions(self, metric_points: List[SecurityMetricPoint], 
                          repo_id: str) -> List[SecurityRegressionAlert]:
        """Detect security regressions in the trend data"""
        alerts = []
        
        if len(metric_points) < 2:
            return alerts
        
        for i in range(1, len(metric_points)):
            current = metric_points[i]
            previous = metric_points[i-1]
            
            # Check for maturity score drop
            score_change = current.maturity_score - previous.maturity_score
            if score_change < -self.regression_thresholds['maturity_score_drop']:
                alert = SecurityRegressionAlert(
                    timestamp=current.timestamp,
                    repo_id=repo_id,
                    wiki_id=current.wiki_id,
                    severity="high" if score_change < -0.2 else "medium",
                    regression_type="maturity_drop",
                    description=f"Security maturity score dropped by {abs(score_change):.1%}",
                    impact_score=abs(score_change),
                    recommended_actions=[
                        "Review recent code changes for security issues",
                        "Conduct security assessment of new features",
                        "Update security documentation and mitigations"
                    ],
                    affected_owasp_categories=[]
                )
                alerts.append(alert)
            
            # Check for compliance drop
            compliance_change = current.compliance_score - previous.compliance_score
            if compliance_change < -self.regression_thresholds['compliance_drop']:
                alert = SecurityRegressionAlert(
                    timestamp=current.timestamp,
                    repo_id=repo_id,
                    wiki_id=current.wiki_id,
                    severity="medium",
                    regression_type="compliance_drop",
                    description=f"OWASP compliance score dropped by {abs(compliance_change):.1%}",
                    impact_score=abs(compliance_change),
                    recommended_actions=[
                        "Review OWASP compliance requirements",
                        "Update security controls and documentation",
                        "Implement missing security guidelines"
                    ],
                    affected_owasp_categories=[]
                )
                alerts.append(alert)
            
            # Check for threat increase
            threat_change_pct = (current.threat_count - previous.threat_count) / max(1, previous.threat_count)
            if threat_change_pct > self.regression_thresholds['threat_increase']:
                alert = SecurityRegressionAlert(
                    timestamp=current.timestamp,
                    repo_id=repo_id,
                    wiki_id=current.wiki_id,
                    severity="high" if current.critical_threats > previous.critical_threats else "medium",
                    regression_type="threat_increase",
                    description=f"Security threats increased by {threat_change_pct:.1%}",
                    impact_score=threat_change_pct,
                    recommended_actions=[
                        "Investigate new security vulnerabilities",
                        "Prioritize mitigation of critical threats",
                        "Review security testing processes"
                    ],
                    affected_owasp_categories=[]
                )
                alerts.append(alert)
            
            # Check for mitigation decrease
            mitigation_change_pct = (current.mitigation_count - previous.mitigation_count) / max(1, previous.mitigation_count)
            if mitigation_change_pct < -self.regression_thresholds['mitigation_decrease']:
                alert = SecurityRegressionAlert(
                    timestamp=current.timestamp,
                    repo_id=repo_id,
                    wiki_id=current.wiki_id,
                    severity="medium",
                    regression_type="mitigation_decrease",
                    description=f"Security mitigations decreased by {abs(mitigation_change_pct):.1%}",
                    impact_score=abs(mitigation_change_pct),
                    recommended_actions=[
                        "Review removed security controls",
                        "Restore critical security mitigations",
                        "Update security implementation guidelines"
                    ],
                    affected_owasp_categories=[]
                )
                alerts.append(alert)
        
        return alerts
    
    def _generate_key_insights(self, trend_data: SecurityTrendData, 
                             metric_points: List[SecurityMetricPoint]) -> List[str]:
        """Generate key insights from trend analysis"""
        insights = []
        
        if not metric_points:
            return insights
        
        # Overall trend insight
        if trend_data.trend_direction == TrendDirection.IMPROVING:
            insights.append(f"Security posture is improving with {trend_data.trend_strength:.1%} strength")
        elif trend_data.trend_direction == TrendDirection.DECLINING:
            insights.append(f"Security posture is declining with {trend_data.trend_strength:.1%} strength")
        elif trend_data.trend_direction == TrendDirection.VOLATILE:
            insights.append(f"Security posture shows high volatility ({trend_data.volatility:.2f})")
        else:
            insights.append("Security posture remains stable")
        
        # Score change insight
        if len(metric_points) >= 2:
            score_change = metric_points[-1].maturity_score - metric_points[0].maturity_score
            if abs(score_change) > 0.05:
                direction = "increased" if score_change > 0 else "decreased"
                insights.append(f"Security maturity score {direction} by {abs(score_change):.1%} over the analysis period")
        
        # Threat trend insight
        if len(metric_points) >= 2:
            threat_change = metric_points[-1].threat_count - metric_points[0].threat_count
            if threat_change > 0:
                insights.append(f"{threat_change} new security threats identified")
            elif threat_change < 0:
                insights.append(f"{abs(threat_change)} security threats resolved")
        
        # Critical threat insight
        latest_critical = metric_points[-1].critical_threats
        if latest_critical > 0:
            insights.append(f"{latest_critical} critical security threats require immediate attention")
        
        # OWASP coverage insight
        latest_coverage = metric_points[-1].owasp_coverage
        avg_coverage = statistics.mean(latest_coverage.values()) if latest_coverage else 0
        if avg_coverage < 0.5:
            insights.append(f"OWASP coverage is below 50% ({avg_coverage:.1%}) - consider improving security guidelines compliance")
        
        return insights
    
    def _identify_improvements(self, metric_points: List[SecurityMetricPoint]) -> List[str]:
        """Identify security improvements from the trend data"""
        improvements = []
        
        if len(metric_points) < 2:
            return improvements
        
        latest = metric_points[-1]
        previous = metric_points[-2]
        
        # Check for score improvements
        if latest.maturity_score > previous.maturity_score:
            improvements.append(f"Security maturity score improved by {(latest.maturity_score - previous.maturity_score):.1%}")
        
        # Check for threat reductions
        if latest.threat_count < previous.threat_count:
            improvements.append(f"Reduced security threats by {previous.threat_count - latest.threat_count}")
        
        # Check for mitigation increases
        if latest.mitigation_count > previous.mitigation_count:
            improvements.append(f"Added {latest.mitigation_count - previous.mitigation_count} new security mitigations")
        
        # Check for compliance improvements
        if latest.compliance_score > previous.compliance_score:
            improvements.append(f"OWASP compliance improved by {(latest.compliance_score - previous.compliance_score):.1%}")
        
        # Check for critical threat reductions
        if latest.critical_threats < previous.critical_threats:
            improvements.append(f"Resolved {previous.critical_threats - latest.critical_threats} critical security threats")
        
        return improvements
    
    def _generate_recommendations(self, trend_data: SecurityTrendData, 
                                regression_alerts: List[SecurityRegressionAlert]) -> List[str]:
        """Generate actionable recommendations based on trend analysis"""
        recommendations = []
        
        # Trend-based recommendations
        if trend_data.trend_direction == TrendDirection.DECLINING:
            recommendations.extend([
                "Conduct comprehensive security review to identify root causes of decline",
                "Implement additional security controls and monitoring",
                "Review and update security development practices"
            ])
        elif trend_data.trend_direction == TrendDirection.VOLATILE:
            recommendations.extend([
                "Establish consistent security practices to reduce volatility",
                "Implement automated security testing in CI/CD pipeline",
                "Create security guidelines for development team"
            ])
        elif trend_data.trend_direction == TrendDirection.STABLE:
            recommendations.extend([
                "Consider implementing advanced security measures to improve posture",
                "Explore proactive security testing and threat modeling",
                "Review industry best practices for security enhancements"
            ])
        
        # Alert-based recommendations
        if regression_alerts:
            recommendations.append("Address security regression alerts immediately")
            
            # Add specific recommendations based on alert types
            alert_types = set(alert.regression_type for alert in regression_alerts)
            if "threat_increase" in alert_types:
                recommendations.append("Investigate and mitigate newly identified security threats")
            if "compliance_drop" in alert_types:
                recommendations.append("Review and restore OWASP compliance requirements")
            if "mitigation_decrease" in alert_types:
                recommendations.append("Restore removed security controls and mitigations")
        
        # Score-based recommendations
        if trend_data.latest_score < 0.5:
            recommendations.extend([
                "Security maturity is below average - prioritize security improvements",
                "Implement comprehensive security training for development team",
                "Consider security consulting or external security assessment"
            ])
        
        return recommendations
    
    def _generate_forecast(self, metric_points: List[SecurityMetricPoint]) -> Dict[str, Any]:
        """Generate simple forecast based on trend data"""
        if len(metric_points) < 3:
            return {"message": "Insufficient data for forecasting"}
        
        # Simple linear projection
        scores = [point.maturity_score for point in metric_points[-5:]]  # Use last 5 points
        
        # Calculate trend
        n = len(scores)
        x_values = list(range(n))
        
        x_mean = statistics.mean(x_values)
        y_mean = statistics.mean(scores)
        
        numerator = sum((x_values[i] - x_mean) * (scores[i] - y_mean) for i in range(n))
        denominator = sum((x_values[i] - x_mean) ** 2 for i in range(n))
        
        slope = numerator / denominator if denominator != 0 else 0
        intercept = y_mean - slope * x_mean
        
        # Project next 3 periods
        next_periods = []
        for i in range(1, 4):
            projected_score = intercept + slope * (n + i - 1)
            projected_score = max(0.0, min(1.0, projected_score))  # Clamp to valid range
            next_periods.append({
                "period": i,
                "projected_score": projected_score,
                "confidence": max(0.3, 1.0 - abs(slope) * 2)  # Lower confidence for steep trends
            })
        
        return {
            "method": "linear_projection",
            "trend_slope": slope,
            "projections": next_periods,
            "disclaimer": "Projections are estimates based on historical trends and may not reflect future changes"
        }
    
    def _calculate_owasp_coverage(self, wiki: SecurityWiki) -> Dict[str, float]:
        """Calculate OWASP category coverage for a wiki"""
        owasp_categories = [
            "A01", "A02", "A03", "A04", "A05", 
            "A06", "A07", "A08", "A09", "A10"
        ]
        
        coverage = {}
        for category in owasp_categories:
            coverage[category] = self._calculate_category_coverage(wiki, category)
        
        return coverage
    
    def _calculate_category_coverage(self, wiki: SecurityWiki, category: str) -> float:
        """Calculate coverage for a specific OWASP category"""
        relevant_content = 0
        total_sections = len(wiki.sections)
        
        for section in wiki.sections.values():
            # Check OWASP mappings
            for mapping in section.owasp_mappings:
                if category.lower() in mapping.lower():
                    relevant_content += 1
                    break
            else:
                # Check security findings
                for finding in section.security_findings:
                    if finding.owasp_category and category.lower() in finding.owasp_category.lower():
                        relevant_content += 1
                        break
        
        return relevant_content / max(1, total_sections)
    
    def _calculate_compliance_score(self, wiki: SecurityWiki) -> float:
        """Calculate overall compliance score for a wiki"""
        owasp_categories = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]
        
        category_scores = []
        for category in owasp_categories:
            score = self._calculate_category_coverage(wiki, category)
            category_scores.append(score)
        
        return statistics.mean(category_scores) if category_scores else 0.0
    
    def _count_mitigations(self, wiki: SecurityWiki) -> int:
        """Count total mitigations in a wiki"""
        mitigation_count = 0
        
        for section in wiki.sections.values():
            mitigation_count += len(section.recommendations)
            for finding in section.security_findings:
                mitigation_count += len(finding.recommendations)
        
        return mitigation_count


# Global trend analyzer instance
security_trend_analyzer = SecurityTrendAnalyzer()