"""
Wiki comparison engine for security posture analysis and benchmarking
"""
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from .models import SecurityWiki, WikiSection, SecurityFinding, OWASPMapping
from .wiki_storage import WikiStorage
from .owasp_retriever import OWASPRetriever

logger = logging.getLogger(__name__)


class ComparisonType(str, Enum):
    THREAT_LANDSCAPE = "threat_landscape"
    MITIGATION_COVERAGE = "mitigation_coverage"
    OWASP_COMPLIANCE = "owasp_compliance"
    SECURITY_MATURITY = "security_maturity"


class ChangeType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


@dataclass
class SecurityChange:
    """Represents a security-related change between wiki versions"""
    change_type: ChangeType
    section_id: str
    section_title: str
    old_content: Optional[str] = None
    new_content: Optional[str] = None
    impact_level: str = "medium"  # low, medium, high, critical
    description: str = ""
    owasp_categories: List[str] = None
    
    def __post_init__(self):
        if self.owasp_categories is None:
            self.owasp_categories = []


@dataclass
class ThreatComparison:
    """Comparison of threat landscapes between wikis"""
    baseline_threats: int
    current_threats: int
    new_threats: List[SecurityFinding]
    resolved_threats: List[SecurityFinding]
    modified_threats: List[Tuple[SecurityFinding, SecurityFinding]]
    threat_severity_distribution: Dict[str, int]
    owasp_category_changes: Dict[str, int]


@dataclass
class MitigationComparison:
    """Comparison of mitigation coverage between wikis"""
    baseline_mitigations: int
    current_mitigations: int
    new_mitigations: List[str]
    removed_mitigations: List[str]
    coverage_by_owasp: Dict[str, float]
    effectiveness_changes: Dict[str, float]


@dataclass
class ComplianceComparison:
    """Comparison of OWASP compliance between wikis"""
    baseline_compliance_score: float
    current_compliance_score: float
    compliance_changes: Dict[str, float]
    missing_guidelines: List[str]
    new_guidelines_covered: List[str]
    compliance_trend: str  # improving, declining, stable


@dataclass
class SecurityMaturityScore:
    """Security maturity scoring based on OWASP criteria"""
    overall_score: float
    category_scores: Dict[str, float]
    maturity_level: str  # basic, developing, defined, managed, optimizing
    improvement_areas: List[str]
    strengths: List[str]


@dataclass
class SecurityComparison:
    """Complete security comparison between two wikis"""
    baseline_wiki_id: str
    current_wiki_id: str
    comparison_timestamp: datetime
    threat_comparison: ThreatComparison
    mitigation_comparison: MitigationComparison
    compliance_comparison: ComplianceComparison
    security_changes: List[SecurityChange]
    regression_detected: bool
    improvement_detected: bool
    summary: str


class WikiComparisonEngine:
    """Engine for comparing security wikis and analyzing security posture changes"""
    
    def __init__(self, wiki_storage: Optional[WikiStorage] = None, owasp_retriever: Optional[OWASPRetriever] = None):
        self.wiki_storage = wiki_storage or WikiStorage()
        self.owasp_retriever = owasp_retriever or OWASPRetriever()
        
        # OWASP Top 10 categories for compliance scoring
        self.owasp_categories = [
            "A01:2021 – Broken Access Control",
            "A02:2021 – Cryptographic Failures", 
            "A03:2021 – Injection",
            "A04:2021 – Insecure Design",
            "A05:2021 – Security Misconfiguration",
            "A06:2021 – Vulnerable and Outdated Components",
            "A07:2021 – Identification and Authentication Failures",
            "A08:2021 – Software and Data Integrity Failures",
            "A09:2021 – Security Logging and Monitoring Failures",
            "A10:2021 – Server-Side Request Forgery"
        ]
    
    def compare_wikis(self, baseline_wiki_id: str, current_wiki_id: str) -> Optional[SecurityComparison]:
        """
        Compare two security wikis for security posture analysis
        
        Args:
            baseline_wiki_id: ID of the baseline wiki for comparison
            current_wiki_id: ID of the current wiki to compare against baseline
            
        Returns:
            SecurityComparison object with detailed comparison results
        """
        try:
            # Load wikis
            baseline_wiki = self.wiki_storage.load_wiki(baseline_wiki_id)
            current_wiki = self.wiki_storage.load_wiki(current_wiki_id)
            
            if not baseline_wiki or not current_wiki:
                logger.error(f"Failed to load wikis for comparison: {baseline_wiki_id}, {current_wiki_id}")
                return None
            
            logger.info(f"Comparing wikis: {baseline_wiki_id} vs {current_wiki_id}")
            
            # Perform detailed comparisons
            threat_comparison = self._compare_threat_landscapes(baseline_wiki, current_wiki)
            mitigation_comparison = self._compare_mitigation_coverage(baseline_wiki, current_wiki)
            compliance_comparison = self._compare_owasp_compliance(baseline_wiki, current_wiki)
            security_changes = self._detect_security_changes(baseline_wiki, current_wiki)
            
            # Detect regressions and improvements
            regression_detected = self._detect_security_regression(threat_comparison, mitigation_comparison, compliance_comparison)
            improvement_detected = self._detect_security_improvement(threat_comparison, mitigation_comparison, compliance_comparison)
            
            # Generate summary
            summary = self._generate_comparison_summary(
                threat_comparison, mitigation_comparison, compliance_comparison,
                regression_detected, improvement_detected
            )
            
            comparison = SecurityComparison(
                baseline_wiki_id=baseline_wiki_id,
                current_wiki_id=current_wiki_id,
                comparison_timestamp=datetime.now(),
                threat_comparison=threat_comparison,
                mitigation_comparison=mitigation_comparison,
                compliance_comparison=compliance_comparison,
                security_changes=security_changes,
                regression_detected=regression_detected,
                improvement_detected=improvement_detected,
                summary=summary
            )
            
            logger.info(f"Wiki comparison completed: {len(security_changes)} changes detected")
            return comparison
            
        except Exception as e:
            logger.error(f"Error comparing wikis: {e}")
            return None
    
    def _compare_threat_landscapes(self, baseline_wiki: SecurityWiki, current_wiki: SecurityWiki) -> ThreatComparison:
        """Compare threat landscapes between two wikis"""
        # Extract all security findings from both wikis
        baseline_threats = self._extract_security_findings(baseline_wiki)
        current_threats = self._extract_security_findings(current_wiki)
        
        # Create threat maps for comparison
        baseline_threat_map = {self._get_threat_key(t): t for t in baseline_threats}
        current_threat_map = {self._get_threat_key(t): t for t in current_threats}
        
        # Find new, resolved, and modified threats
        new_threats = [t for key, t in current_threat_map.items() if key not in baseline_threat_map]
        resolved_threats = [t for key, t in baseline_threat_map.items() if key not in current_threat_map]
        
        modified_threats = []
        for key in baseline_threat_map:
            if key in current_threat_map:
                baseline_threat = baseline_threat_map[key]
                current_threat = current_threat_map[key]
                if self._threat_modified(baseline_threat, current_threat):
                    modified_threats.append((baseline_threat, current_threat))
        
        # Calculate severity distributions
        current_severity_dist = self._calculate_severity_distribution(current_threats)
        
        # Calculate OWASP category changes
        owasp_changes = self._calculate_owasp_category_changes(baseline_threats, current_threats)
        
        return ThreatComparison(
            baseline_threats=len(baseline_threats),
            current_threats=len(current_threats),
            new_threats=new_threats,
            resolved_threats=resolved_threats,
            modified_threats=modified_threats,
            threat_severity_distribution=current_severity_dist,
            owasp_category_changes=owasp_changes
        )
    
    def _compare_mitigation_coverage(self, baseline_wiki: SecurityWiki, current_wiki: SecurityWiki) -> MitigationComparison:
        """Compare mitigation coverage between two wikis"""
        # Extract mitigations from both wikis
        baseline_mitigations = self._extract_mitigations(baseline_wiki)
        current_mitigations = self._extract_mitigations(current_wiki)
        
        # Find new and removed mitigations
        new_mitigations = list(set(current_mitigations) - set(baseline_mitigations))
        removed_mitigations = list(set(baseline_mitigations) - set(current_mitigations))
        
        # Calculate coverage by OWASP categories
        coverage_by_owasp = self._calculate_owasp_coverage(current_wiki)
        
        # Calculate effectiveness changes (simplified for now)
        effectiveness_changes = {}
        for category in self.owasp_categories:
            baseline_coverage = self._calculate_category_coverage(baseline_wiki, category)
            current_coverage = self._calculate_category_coverage(current_wiki, category)
            effectiveness_changes[category] = current_coverage - baseline_coverage
        
        return MitigationComparison(
            baseline_mitigations=len(baseline_mitigations),
            current_mitigations=len(current_mitigations),
            new_mitigations=new_mitigations,
            removed_mitigations=removed_mitigations,
            coverage_by_owasp=coverage_by_owasp,
            effectiveness_changes=effectiveness_changes
        )
    
    def _compare_owasp_compliance(self, baseline_wiki: SecurityWiki, current_wiki: SecurityWiki) -> ComplianceComparison:
        """Compare OWASP compliance between two wikis"""
        # Calculate compliance scores
        baseline_score = self._calculate_compliance_score(baseline_wiki)
        current_score = self._calculate_compliance_score(current_wiki)
        
        # Calculate compliance changes by category
        compliance_changes = {}
        for category in self.owasp_categories:
            baseline_cat_score = self._calculate_category_compliance(baseline_wiki, category)
            current_cat_score = self._calculate_category_compliance(current_wiki, category)
            compliance_changes[category] = current_cat_score - baseline_cat_score
        
        # Identify missing and new guidelines
        baseline_guidelines = self._extract_covered_guidelines(baseline_wiki)
        current_guidelines = self._extract_covered_guidelines(current_wiki)
        
        missing_guidelines = list(set(baseline_guidelines) - set(current_guidelines))
        new_guidelines_covered = list(set(current_guidelines) - set(baseline_guidelines))
        
        # Determine compliance trend
        score_diff = current_score - baseline_score
        if score_diff > 0.05:
            trend = "improving"
        elif score_diff < -0.05:
            trend = "declining"
        else:
            trend = "stable"
        
        return ComplianceComparison(
            baseline_compliance_score=baseline_score,
            current_compliance_score=current_score,
            compliance_changes=compliance_changes,
            missing_guidelines=missing_guidelines,
            new_guidelines_covered=new_guidelines_covered,
            compliance_trend=trend
        )
    
    def calculate_security_maturity_score(self, wiki: SecurityWiki) -> SecurityMaturityScore:
        """
        Calculate security maturity score based on OWASP criteria
        
        Args:
            wiki: SecurityWiki to analyze
            
        Returns:
            SecurityMaturityScore with detailed maturity analysis
        """
        try:
            # Calculate category scores
            category_scores = {}
            for category in self.owasp_categories:
                category_scores[category] = self._calculate_category_maturity(wiki, category)
            
            # Calculate overall score
            overall_score = sum(category_scores.values()) / len(category_scores)
            
            # Determine maturity level
            if overall_score >= 0.9:
                maturity_level = "optimizing"
            elif overall_score >= 0.7:
                maturity_level = "managed"
            elif overall_score >= 0.5:
                maturity_level = "defined"
            elif overall_score >= 0.3:
                maturity_level = "developing"
            else:
                maturity_level = "basic"
            
            # Identify improvement areas and strengths
            improvement_areas = [cat for cat, score in category_scores.items() if score < 0.6]
            strengths = [cat for cat, score in category_scores.items() if score >= 0.8]
            
            return SecurityMaturityScore(
                overall_score=overall_score,
                category_scores=category_scores,
                maturity_level=maturity_level,
                improvement_areas=improvement_areas,
                strengths=strengths
            )
            
        except Exception as e:
            logger.error(f"Error calculating security maturity score: {e}")
            return SecurityMaturityScore(
                overall_score=0.0,
                category_scores={},
                maturity_level="basic",
                improvement_areas=list(self.owasp_categories),
                strengths=[]
            )
    
    def _extract_security_findings(self, wiki: SecurityWiki) -> List[SecurityFinding]:
        """Extract all security findings from a wiki"""
        findings = []
        for section in wiki.sections.values():
            findings.extend(section.security_findings)
        return findings
    
    def _extract_mitigations(self, wiki: SecurityWiki) -> List[str]:
        """Extract all mitigations from a wiki"""
        mitigations = []
        for section in wiki.sections.values():
            mitigations.extend(section.recommendations)
            # Also extract mitigations from security findings
            for finding in section.security_findings:
                mitigations.extend(finding.recommendations)
        return list(set(mitigations))  # Remove duplicates
    
    def _get_threat_key(self, threat: SecurityFinding) -> str:
        """Generate a unique key for threat comparison"""
        return f"{threat.type}_{threat.description[:50]}_{threat.severity}"
    
    def _threat_modified(self, baseline: SecurityFinding, current: SecurityFinding) -> bool:
        """Check if a threat has been modified"""
        return (baseline.severity != current.severity or 
                baseline.description != current.description or
                baseline.recommendations != current.recommendations)
    
    def _calculate_severity_distribution(self, threats: List[SecurityFinding]) -> Dict[str, int]:
        """Calculate distribution of threat severities"""
        distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for threat in threats:
            severity = threat.severity.lower()
            if severity in distribution:
                distribution[severity] += 1
        return distribution
    
    def _calculate_owasp_category_changes(self, baseline_threats: List[SecurityFinding], 
                                        current_threats: List[SecurityFinding]) -> Dict[str, int]:
        """Calculate changes in OWASP category coverage"""
        baseline_categories = {}
        current_categories = {}
        
        for threat in baseline_threats:
            if threat.owasp_category:
                baseline_categories[threat.owasp_category] = baseline_categories.get(threat.owasp_category, 0) + 1
        
        for threat in current_threats:
            if threat.owasp_category:
                current_categories[threat.owasp_category] = current_categories.get(threat.owasp_category, 0) + 1
        
        changes = {}
        all_categories = set(baseline_categories.keys()) | set(current_categories.keys())
        for category in all_categories:
            baseline_count = baseline_categories.get(category, 0)
            current_count = current_categories.get(category, 0)
            changes[category] = current_count - baseline_count
        
        return changes
    
    def _calculate_owasp_coverage(self, wiki: SecurityWiki) -> Dict[str, float]:
        """Calculate OWASP coverage by category"""
        coverage = {}
        for category in self.owasp_categories:
            coverage[category] = self._calculate_category_coverage(wiki, category)
        return coverage
    
    def _calculate_category_coverage(self, wiki: SecurityWiki, category: str) -> float:
        """Calculate coverage for a specific OWASP category"""
        # Count relevant security findings and mitigations for this category
        relevant_findings = 0
        total_mitigations = 0
        
        for section in wiki.sections.values():
            for finding in section.security_findings:
                if finding.owasp_category and category.split(':')[0] in finding.owasp_category:
                    relevant_findings += 1
                    total_mitigations += len(finding.recommendations)
            
            # Check OWASP mappings in section
            for mapping in section.owasp_mappings:
                if category.split(':')[0] in mapping:
                    total_mitigations += len(section.recommendations)
        
        # Simple coverage calculation (can be enhanced)
        if relevant_findings == 0:
            return 0.0
        
        return min(1.0, total_mitigations / (relevant_findings * 2))  # Assume 2 mitigations per finding is good coverage
    
    def _calculate_compliance_score(self, wiki: SecurityWiki) -> float:
        """Calculate overall OWASP compliance score"""
        category_scores = []
        for category in self.owasp_categories:
            score = self._calculate_category_compliance(wiki, category)
            category_scores.append(score)
        
        return sum(category_scores) / len(category_scores) if category_scores else 0.0
    
    def _calculate_category_compliance(self, wiki: SecurityWiki, category: str) -> float:
        """Calculate compliance score for a specific OWASP category"""
        # Check for relevant content in wiki sections
        relevant_content = 0
        total_sections = len(wiki.sections)
        
        category_key = category.split(':')[0].lower()  # e.g., "a01" from "A01:2021 – Broken Access Control"
        
        for section in wiki.sections.values():
            # Check if section addresses this OWASP category
            section_content = (section.title + " " + section.content).lower()
            
            # Check OWASP mappings
            for mapping in section.owasp_mappings:
                if category_key in mapping.lower():
                    relevant_content += 1
                    break
            else:
                # Check security findings
                for finding in section.security_findings:
                    if finding.owasp_category and category_key in finding.owasp_category.lower():
                        relevant_content += 1
                        break
        
        return relevant_content / max(1, total_sections)
    
    def _extract_covered_guidelines(self, wiki: SecurityWiki) -> List[str]:
        """Extract OWASP guidelines covered by the wiki"""
        guidelines = set()
        
        for section in wiki.sections.values():
            guidelines.update(section.owasp_mappings)
            for finding in section.security_findings:
                if finding.owasp_category:
                    guidelines.add(finding.owasp_category)
        
        return list(guidelines)
    
    def _calculate_category_maturity(self, wiki: SecurityWiki, category: str) -> float:
        """Calculate maturity score for a specific OWASP category"""
        # Factors for maturity scoring
        factors = {
            'threat_identification': 0.0,
            'mitigation_coverage': 0.0,
            'implementation_guidance': 0.0,
            'monitoring_controls': 0.0
        }
        
        category_key = category.split(':')[0].lower()
        
        for section in wiki.sections.values():
            # Check threat identification
            for finding in section.security_findings:
                if finding.owasp_category and category_key in finding.owasp_category.lower():
                    factors['threat_identification'] = 1.0
                    
                    # Check mitigation coverage
                    if finding.recommendations:
                        factors['mitigation_coverage'] = min(1.0, len(finding.recommendations) / 3)
            
            # Check implementation guidance
            if any(category_key in mapping.lower() for mapping in section.owasp_mappings):
                if section.recommendations:
                    factors['implementation_guidance'] = min(1.0, len(section.recommendations) / 2)
            
            # Check for monitoring/logging content
            if 'monitor' in section.content.lower() or 'log' in section.content.lower():
                factors['monitoring_controls'] = 0.5
        
        return sum(factors.values()) / len(factors)
    
    def _detect_security_changes(self, baseline_wiki: SecurityWiki, current_wiki: SecurityWiki) -> List[SecurityChange]:
        """Detect detailed security changes between wikis"""
        changes = []
        
        # Get all section IDs from both wikis
        baseline_sections = set(baseline_wiki.sections.keys())
        current_sections = set(current_wiki.sections.keys())
        
        # Detect added sections
        for section_id in current_sections - baseline_sections:
            section = current_wiki.sections[section_id]
            change = SecurityChange(
                change_type=ChangeType.ADDED,
                section_id=section_id,
                section_title=section.title,
                new_content=section.content[:200] + "..." if len(section.content) > 200 else section.content,
                impact_level=self._assess_change_impact(section),
                description=f"New security section added: {section.title}",
                owasp_categories=section.owasp_mappings
            )
            changes.append(change)
        
        # Detect removed sections
        for section_id in baseline_sections - current_sections:
            section = baseline_wiki.sections[section_id]
            change = SecurityChange(
                change_type=ChangeType.REMOVED,
                section_id=section_id,
                section_title=section.title,
                old_content=section.content[:200] + "..." if len(section.content) > 200 else section.content,
                impact_level=self._assess_change_impact(section),
                description=f"Security section removed: {section.title}",
                owasp_categories=section.owasp_mappings
            )
            changes.append(change)
        
        # Detect modified sections
        for section_id in baseline_sections & current_sections:
            baseline_section = baseline_wiki.sections[section_id]
            current_section = current_wiki.sections[section_id]
            
            if self._section_modified(baseline_section, current_section):
                change = SecurityChange(
                    change_type=ChangeType.MODIFIED,
                    section_id=section_id,
                    section_title=current_section.title,
                    old_content=baseline_section.content[:200] + "..." if len(baseline_section.content) > 200 else baseline_section.content,
                    new_content=current_section.content[:200] + "..." if len(current_section.content) > 200 else current_section.content,
                    impact_level=self._assess_modification_impact(baseline_section, current_section),
                    description=f"Security section modified: {current_section.title}",
                    owasp_categories=current_section.owasp_mappings
                )
                changes.append(change)
        
        return changes
    
    def _section_modified(self, baseline: WikiSection, current: WikiSection) -> bool:
        """Check if a wiki section has been modified"""
        return (baseline.content != current.content or
                baseline.security_findings != current.security_findings or
                baseline.recommendations != current.recommendations or
                baseline.owasp_mappings != current.owasp_mappings)
    
    def _assess_change_impact(self, section: WikiSection) -> str:
        """Assess the impact level of a section change"""
        # High impact if section has critical security findings
        for finding in section.security_findings:
            if finding.severity.lower() == "critical":
                return "critical"
            elif finding.severity.lower() == "high":
                return "high"
        
        # Medium impact if section has OWASP mappings
        if section.owasp_mappings:
            return "medium"
        
        return "low"
    
    def _assess_modification_impact(self, baseline: WikiSection, current: WikiSection) -> str:
        """Assess the impact level of section modifications"""
        # Check if security findings changed
        baseline_findings = len(baseline.security_findings)
        current_findings = len(current.security_findings)
        
        if current_findings < baseline_findings:
            return "high"  # Removing security findings is high impact
        elif current_findings > baseline_findings:
            return "medium"  # Adding security findings is medium impact
        
        # Check if recommendations changed
        if len(current.recommendations) < len(baseline.recommendations):
            return "medium"  # Removing recommendations is medium impact
        
        return "low"
    
    def _detect_security_regression(self, threat_comp: ThreatComparison, 
                                  mitigation_comp: MitigationComparison,
                                  compliance_comp: ComplianceComparison) -> bool:
        """Detect if there's a security regression"""
        # Regression indicators
        regression_indicators = [
            len(threat_comp.new_threats) > len(threat_comp.resolved_threats),
            len(mitigation_comp.removed_mitigations) > len(mitigation_comp.new_mitigations),
            compliance_comp.current_compliance_score < compliance_comp.baseline_compliance_score - 0.05,
            compliance_comp.compliance_trend == "declining"
        ]
        
        return any(regression_indicators)
    
    def _detect_security_improvement(self, threat_comp: ThreatComparison,
                                   mitigation_comp: MitigationComparison,
                                   compliance_comp: ComplianceComparison) -> bool:
        """Detect if there's a security improvement"""
        # Improvement indicators
        improvement_indicators = [
            len(threat_comp.resolved_threats) > len(threat_comp.new_threats),
            len(mitigation_comp.new_mitigations) > len(mitigation_comp.removed_mitigations),
            compliance_comp.current_compliance_score > compliance_comp.baseline_compliance_score + 0.05,
            compliance_comp.compliance_trend == "improving"
        ]
        
        return any(improvement_indicators)
    
    def _generate_comparison_summary(self, threat_comp: ThreatComparison,
                                   mitigation_comp: MitigationComparison,
                                   compliance_comp: ComplianceComparison,
                                   regression_detected: bool,
                                   improvement_detected: bool) -> str:
        """Generate a human-readable summary of the comparison"""
        summary_parts = []
        
        # Threat landscape summary
        threat_change = threat_comp.current_threats - threat_comp.baseline_threats
        if threat_change > 0:
            summary_parts.append(f"{threat_change} new threats identified")
        elif threat_change < 0:
            summary_parts.append(f"{abs(threat_change)} threats resolved")
        else:
            summary_parts.append("No change in threat count")
        
        # Mitigation summary
        mitigation_change = mitigation_comp.current_mitigations - mitigation_comp.baseline_mitigations
        if mitigation_change > 0:
            summary_parts.append(f"{mitigation_change} new mitigations added")
        elif mitigation_change < 0:
            summary_parts.append(f"{abs(mitigation_change)} mitigations removed")
        
        # Compliance summary
        compliance_change = compliance_comp.current_compliance_score - compliance_comp.baseline_compliance_score
        if compliance_change > 0.05:
            summary_parts.append(f"OWASP compliance improved by {compliance_change:.1%}")
        elif compliance_change < -0.05:
            summary_parts.append(f"OWASP compliance declined by {abs(compliance_change):.1%}")
        
        # Overall assessment
        if regression_detected:
            summary_parts.append("⚠️ Security regression detected")
        elif improvement_detected:
            summary_parts.append("✅ Security improvement detected")
        else:
            summary_parts.append("Security posture stable")
        
        return ". ".join(summary_parts) + "."


# Global comparison engine instance
wiki_comparison_engine = WikiComparisonEngine()