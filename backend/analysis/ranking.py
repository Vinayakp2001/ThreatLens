"""Threat scoring and prioritization using likelihood × impact calculation with business considerations."""

from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

from ..models.threats import (
    Threat, StrideCategory, LikelihoodLevel, ImpactLevel, ThreatResponse
)
from ..models.system_model import System, DataClassification, ComponentType, TrustLevel


class EffortLevel(Enum):
    """Effort required to mitigate a threat."""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class BusinessPriority(Enum):
    """Business priority for addressing threats."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    DEFERRED = "deferred"


@dataclass
class ThreatScore:
    """Complete threat scoring information."""
    threat_id: str
    base_risk_score: float
    adjusted_risk_score: float
    likelihood_score: int
    impact_score: int
    effort_score: int
    business_priority_score: int
    final_priority_score: float
    ranking_position: int
    rationale: str


@dataclass
class RankingContext:
    """Context information for threat ranking."""
    system: System
    business_criticality: Dict[str, float]  # Component/asset ID to criticality mapping
    compliance_requirements: List[str]
    available_resources: EffortLevel
    time_constraints: str


class ThreatRanker:
    """Threat scoring and prioritization engine."""
    
    def __init__(self):
        self.likelihood_weights = {
            LikelihoodLevel.VERY_LOW: 1,
            LikelihoodLevel.LOW: 2,
            LikelihoodLevel.MEDIUM: 3,
            LikelihoodLevel.HIGH: 4,
            LikelihoodLevel.VERY_HIGH: 5
        }
        
        self.impact_weights = {
            ImpactLevel.VERY_LOW: 1,
            ImpactLevel.LOW: 2,
            ImpactLevel.MEDIUM: 3,
            ImpactLevel.HIGH: 4,
            ImpactLevel.VERY_HIGH: 5
        }
        
        self.effort_weights = {
            EffortLevel.VERY_LOW: 5,  # Inverted - lower effort = higher score
            EffortLevel.LOW: 4,
            EffortLevel.MEDIUM: 3,
            EffortLevel.HIGH: 2,
            EffortLevel.VERY_HIGH: 1
        }
        
        self.business_priority_weights = {
            BusinessPriority.CRITICAL: 5,
            BusinessPriority.HIGH: 4,
            BusinessPriority.MEDIUM: 3,
            BusinessPriority.LOW: 2,
            BusinessPriority.DEFERRED: 1
        }

    def rank_threats(self, threats: List[Threat], system: System, 
                    context: Optional[RankingContext] = None) -> List[ThreatScore]:
        """Rank threats based on risk, effort, and business priority."""
        if context is None:
            context = self._create_default_context(system)
        
        threat_scores = []
        
        for threat in threats:
            score = self._calculate_threat_score(threat, system, context)
            threat_scores.append(score)
        
        # Sort by final priority score (descending)
        threat_scores.sort(key=lambda x: x.final_priority_score, reverse=True)
        
        # Assign ranking positions
        for i, score in enumerate(threat_scores):
            score.ranking_position = i + 1
        
        return threat_scores

    def _create_default_context(self, system: System) -> RankingContext:
        """Create default ranking context."""
        # Default business criticality based on component types and trust levels
        business_criticality = {}
        
        for component in system.components:
            if component.type == ComponentType.WEB_SERVICE:
                criticality = 0.9 if component.trust_level == TrustLevel.HIGH else 0.7
            elif component.type == ComponentType.API_GATEWAY:
                criticality = 0.8
            elif component.type == ComponentType.MICROSERVICE:
                criticality = 0.6
            else:
                criticality = 0.5
            
            business_criticality[component.id] = criticality
        
        for data_store in system.data_stores:
            if data_store.data_classification == DataClassification.SENSITIVE:
                criticality = 0.9
            elif data_store.data_classification == DataClassification.INTERNAL:
                criticality = 0.7
            else:
                criticality = 0.5
            
            business_criticality[data_store.id] = criticality
        
        return RankingContext(
            system=system,
            business_criticality=business_criticality,
            compliance_requirements=system.cloud_context.compliance_requirements,
            available_resources=EffortLevel.MEDIUM,
            time_constraints="normal"
        )

    def _calculate_threat_score(self, threat: Threat, system: System, 
                               context: RankingContext) -> ThreatScore:
        """Calculate comprehensive threat score."""
        # Base risk score (likelihood × impact)
        likelihood_score = self.likelihood_weights[threat.likelihood]
        impact_score = self.impact_weights[threat.impact]
        base_risk_score = likelihood_score * impact_score
        
        # Adjust for business criticality of affected assets
        business_impact_multiplier = self._calculate_business_impact_multiplier(
            threat, context.business_criticality
        )
        
        # Adjust for compliance requirements
        compliance_multiplier = self._calculate_compliance_multiplier(
            threat, context.compliance_requirements
        )
        
        # Calculate adjusted risk score
        adjusted_risk_score = base_risk_score * business_impact_multiplier * compliance_multiplier
        
        # Estimate mitigation effort
        effort_level = self._estimate_mitigation_effort(threat, system)
        effort_score = self.effort_weights[effort_level]
        
        # Determine business priority
        business_priority = self._determine_business_priority(
            threat, system, context, adjusted_risk_score
        )
        business_priority_score = self.business_priority_weights[business_priority]
        
        # Calculate final priority score
        # Formula: (Adjusted Risk Score × Business Priority) / (Effort Factor)
        effort_factor = max(1, 6 - effort_score)  # Convert to penalty factor
        final_priority_score = (adjusted_risk_score * business_priority_score) / effort_factor
        
        # Generate rationale
        rationale = self._generate_ranking_rationale(
            threat, base_risk_score, adjusted_risk_score, effort_level, 
            business_priority, business_impact_multiplier, compliance_multiplier
        )
        
        return ThreatScore(
            threat_id=threat.id,
            base_risk_score=base_risk_score,
            adjusted_risk_score=adjusted_risk_score,
            likelihood_score=likelihood_score,
            impact_score=impact_score,
            effort_score=effort_score,
            business_priority_score=business_priority_score,
            final_priority_score=final_priority_score,
            ranking_position=0,  # Will be set after sorting
            rationale=rationale
        )

    def _calculate_business_impact_multiplier(self, threat: Threat, 
                                            business_criticality: Dict[str, float]) -> float:
        """Calculate business impact multiplier based on affected assets."""
        if not threat.affected_assets:
            return 1.0
        
        # Use the highest criticality among affected assets
        max_criticality = max(
            business_criticality.get(asset_id, 0.5) 
            for asset_id in threat.affected_assets
        )
        
        # Convert criticality (0-1) to multiplier (0.5-2.0)
        return 0.5 + (max_criticality * 1.5)

    def _calculate_compliance_multiplier(self, threat: Threat, 
                                       compliance_requirements: List[str]) -> float:
        """Calculate compliance impact multiplier."""
        if not compliance_requirements:
            return 1.0
        
        # Check if threat affects compliance-sensitive areas
        compliance_sensitive_cwe = [
            "CWE-311",  # Missing Encryption
            "CWE-312",  # Cleartext Storage
            "CWE-319",  # Cleartext Transmission
            "CWE-287",  # Improper Authentication
            "CWE-285",  # Improper Authorization
            "CWE-778",  # Insufficient Logging
        ]
        
        has_compliance_impact = any(
            cwe in threat.cwe_ids for cwe in compliance_sensitive_cwe
        )
        
        if has_compliance_impact:
            # Higher multiplier for compliance-critical threats
            if any(req in ["PCI_DSS", "HIPAA", "SOX"] for req in compliance_requirements):
                return 1.5
            elif any(req in ["GDPR", "CCPA"] for req in compliance_requirements):
                return 1.3
            else:
                return 1.1
        
        return 1.0

    def _estimate_mitigation_effort(self, threat: Threat, system: System) -> EffortLevel:
        """Estimate effort required to mitigate the threat."""
        # Base effort estimation on threat category and affected components
        stride_effort_mapping = {
            StrideCategory.SPOOFING: EffortLevel.MEDIUM,  # Auth/session fixes
            StrideCategory.TAMPERING: EffortLevel.HIGH,   # Input validation, crypto
            StrideCategory.REPUDIATION: EffortLevel.LOW,  # Logging improvements
            StrideCategory.INFORMATION_DISCLOSURE: EffortLevel.MEDIUM,  # Access controls, crypto
            StrideCategory.DENIAL_OF_SERVICE: EffortLevel.HIGH,  # Infrastructure changes
            StrideCategory.ELEVATION_OF_PRIVILEGE: EffortLevel.HIGH  # Authorization overhaul
        }
        
        base_effort = stride_effort_mapping.get(threat.stride_category, EffortLevel.MEDIUM)
        
        # Adjust based on number of affected assets
        if len(threat.affected_assets) > 3:
            base_effort = self._increase_effort_level(base_effort)
        
        # Adjust based on CWE complexity
        complex_cwes = ["CWE-89", "CWE-78", "CWE-94", "CWE-400"]  # Injection, DoS
        if any(cwe in threat.cwe_ids for cwe in complex_cwes):
            base_effort = self._increase_effort_level(base_effort)
        
        # Adjust based on system complexity
        if len(system.components) > 10 or len(system.data_stores) > 5:
            base_effort = self._increase_effort_level(base_effort)
        
        return base_effort

    def _increase_effort_level(self, current_level: EffortLevel) -> EffortLevel:
        """Increase effort level by one step."""
        effort_progression = [
            EffortLevel.VERY_LOW,
            EffortLevel.LOW,
            EffortLevel.MEDIUM,
            EffortLevel.HIGH,
            EffortLevel.VERY_HIGH
        ]
        
        try:
            current_index = effort_progression.index(current_level)
            if current_index < len(effort_progression) - 1:
                return effort_progression[current_index + 1]
        except ValueError:
            pass
        
        return current_level

    def _determine_business_priority(self, threat: Threat, system: System, 
                                   context: RankingContext, adjusted_risk_score: float) -> BusinessPriority:
        """Determine business priority for addressing the threat."""
        # High-risk threats get higher priority
        if adjusted_risk_score >= 20:
            return BusinessPriority.CRITICAL
        elif adjusted_risk_score >= 15:
            return BusinessPriority.HIGH
        elif adjusted_risk_score >= 10:
            return BusinessPriority.MEDIUM
        elif adjusted_risk_score >= 5:
            return BusinessPriority.LOW
        else:
            return BusinessPriority.DEFERRED

    def _generate_ranking_rationale(self, threat: Threat, base_risk_score: float,
                                   adjusted_risk_score: float, effort_level: EffortLevel,
                                   business_priority: BusinessPriority,
                                   business_multiplier: float, compliance_multiplier: float) -> str:
        """Generate human-readable rationale for threat ranking."""
        rationale_parts = []
        
        # Base risk explanation
        rationale_parts.append(
            f"Base risk score: {base_risk_score:.1f} "
            f"({threat.likelihood.value} likelihood × {threat.impact.value} impact)"
        )
        
        # Business impact adjustment
        if business_multiplier != 1.0:
            rationale_parts.append(
                f"Business impact multiplier: {business_multiplier:.1f} "
                f"(affects critical business assets)"
            )
        
        # Compliance adjustment
        if compliance_multiplier != 1.0:
            rationale_parts.append(
                f"Compliance multiplier: {compliance_multiplier:.1f} "
                f"(impacts regulatory compliance)"
            )
        
        # Adjusted risk
        if adjusted_risk_score != base_risk_score:
            rationale_parts.append(f"Adjusted risk score: {adjusted_risk_score:.1f}")
        
        # Effort consideration
        rationale_parts.append(f"Mitigation effort: {effort_level.value}")
        
        # Business priority
        rationale_parts.append(f"Business priority: {business_priority.value}")
        
        # STRIDE category context
        stride_context = {
            StrideCategory.SPOOFING: "Authentication/identity threats require immediate attention",
            StrideCategory.TAMPERING: "Data integrity threats can cause significant business impact",
            StrideCategory.REPUDIATION: "Audit trail threats affect compliance and forensics",
            StrideCategory.INFORMATION_DISCLOSURE: "Confidentiality breaches can cause regulatory issues",
            StrideCategory.DENIAL_OF_SERVICE: "Availability threats directly impact business operations",
            StrideCategory.ELEVATION_OF_PRIVILEGE: "Authorization bypasses can lead to complete system compromise"
        }
        
        if threat.stride_category in stride_context:
            rationale_parts.append(stride_context[threat.stride_category])
        
        return ". ".join(rationale_parts) + "."

    def get_threat_priority_matrix(self, threat_scores: List[ThreatScore]) -> Dict[str, List[str]]:
        """Generate priority matrix grouping threats by priority levels."""
        priority_matrix = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "deferred": []
        }
        
        for score in threat_scores:
            if score.final_priority_score >= 20:
                priority_matrix["critical"].append(score.threat_id)
            elif score.final_priority_score >= 15:
                priority_matrix["high"].append(score.threat_id)
            elif score.final_priority_score >= 10:
                priority_matrix["medium"].append(score.threat_id)
            elif score.final_priority_score >= 5:
                priority_matrix["low"].append(score.threat_id)
            else:
                priority_matrix["deferred"].append(score.threat_id)
        
        return priority_matrix

    def get_quick_wins(self, threat_scores: List[ThreatScore], max_count: int = 5) -> List[ThreatScore]:
        """Identify quick wins - high impact, low effort threats."""
        quick_wins = []
        
        for score in threat_scores:
            # Quick wins: high adjusted risk score but low effort (high effort score)
            if score.adjusted_risk_score >= 10 and score.effort_score >= 4:
                quick_wins.append(score)
        
        # Sort by priority score and return top N
        quick_wins.sort(key=lambda x: x.final_priority_score, reverse=True)
        return quick_wins[:max_count]

    def get_risk_distribution(self, threat_scores: List[ThreatScore]) -> Dict[str, int]:
        """Get distribution of threats across risk levels."""
        distribution = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "very_low": 0
        }
        
        for score in threat_scores:
            if score.adjusted_risk_score >= 20:
                distribution["critical"] += 1
            elif score.adjusted_risk_score >= 15:
                distribution["high"] += 1
            elif score.adjusted_risk_score >= 10:
                distribution["medium"] += 1
            elif score.adjusted_risk_score >= 5:
                distribution["low"] += 1
            else:
                distribution["very_low"] += 1
        
        return distribution

    def filter_threats_by_stride(self, threat_scores: List[ThreatScore], 
                                threats: List[Threat], 
                                stride_categories: List[StrideCategory]) -> List[ThreatScore]:
        """Filter threat scores by STRIDE categories."""
        threat_map = {threat.id: threat for threat in threats}
        
        filtered_scores = []
        for score in threat_scores:
            threat = threat_map.get(score.threat_id)
            if threat and threat.stride_category in stride_categories:
                filtered_scores.append(score)
        
        return filtered_scores

    def get_mitigation_roadmap(self, threat_scores: List[ThreatScore], 
                              threats: List[Threat]) -> Dict[str, List[str]]:
        """Generate mitigation roadmap based on threat priorities and effort."""
        threat_map = {threat.id: threat for threat in threats}
        
        roadmap = {
            "immediate": [],      # Critical threats, low effort
            "short_term": [],     # High priority, medium effort
            "medium_term": [],    # Medium priority or high effort
            "long_term": []       # Low priority or very high effort
        }
        
        for score in threat_scores:
            threat = threat_map.get(score.threat_id)
            if not threat:
                continue
            
            if (score.final_priority_score >= 20 and score.effort_score >= 4):
                roadmap["immediate"].append(score.threat_id)
            elif (score.final_priority_score >= 15 and score.effort_score >= 3):
                roadmap["short_term"].append(score.threat_id)
            elif (score.final_priority_score >= 10 or score.effort_score >= 2):
                roadmap["medium_term"].append(score.threat_id)
            else:
                roadmap["long_term"].append(score.threat_id)
        
        return roadmap