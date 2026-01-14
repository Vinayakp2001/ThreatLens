"""
Security Review and Assessment System

This module provides comprehensive security review and assessment capabilities,
including security methodology validation for threat modeling, mitigation mapping
to OWASP categories, and security control effectiveness assessment.
"""

import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import json
from pathlib import Path

from models import (
    SecurityModel, SecurityDocument, Component, DataStore, Flow,
    StrideCategory, ImpactLevel, LikelihoodLevel, ComponentType, Threat, Mitigation
)
from owasp_compliance import OWASPCategory, ComplianceLevel, ValidationSeverity


class ThreatModelingMethodology(Enum):
    """Supported threat modeling methodologies"""
    STRIDE = "stride"
    PASTA = "pasta"
    LINDDUN = "linddun"
    OCTAVE = "octave"
    TRIKE = "trike"


class SecurityControlType(Enum):
    """Types of security controls"""
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    DETERRENT = "deterrent"
    RECOVERY = "recovery"
    COMPENSATING = "compensating"


class ControlEffectiveness(Enum):
    """Security control effectiveness levels"""
    HIGHLY_EFFECTIVE = "highly_effective"
    EFFECTIVE = "effective"
    PARTIALLY_EFFECTIVE = "partially_effective"
    INEFFECTIVE = "ineffective"
    NOT_IMPLEMENTED = "not_implemented"


@dataclass
class MethodologyValidationResult:
    """Result of threat modeling methodology validation"""
    methodology: ThreatModelingMethodology
    is_valid: bool
    completeness_score: float
    coverage_analysis: Dict[str, Any]
    gaps_identified: List[str]
    recommendations: List[str]
    validation_details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MitigationMapping:
    """Mapping of mitigation to OWASP categories"""
    mitigation_id: str
    mitigation_description: str
    primary_owasp_category: OWASPCategory
    secondary_owasp_categories: List[OWASPCategory] = field(default_factory=list)
    mapping_confidence: float = 0.0
    mapping_rationale: str = ""
    control_types: List[SecurityControlType] = field(default_factory=list)


@dataclass
class SecurityControlAssessment:
    """Assessment of security control effectiveness"""
    control_id: str
    control_name: str
    control_description: str
    control_type: SecurityControlType
    owasp_category: OWASPCategory
    effectiveness: ControlEffectiveness
    effectiveness_score: float
    implementation_status: str
    coverage_areas: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


@dataclass
class SecurityReviewReport:
    """Comprehensive security review report"""
    review_id: str
    security_model_id: str
    timestamp: datetime
    methodology_validation: MethodologyValidationResult
    mitigation_mappings: List[MitigationMapping]
    control_assessments: List[SecurityControlAssessment]
    overall_assessment: Dict[str, Any]
    recommendations: List[str] = field(default_factory=list)
    action_items: List[Dict[str, Any]] = field(default_factory=list)


class SecurityReviewSystem:
    """
    Comprehensive security review and assessment system that validates security
    methodology implementation, maps mitigations to OWASP categories, and
    assesses security control effectiveness.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.owasp_mapping_rules = self._load_owasp_mapping_rules()
        self.control_assessment_criteria = self._load_control_assessment_criteria()
    
    def _load_owasp_mapping_rules(self) -> Dict[str, List[OWASPCategory]]:
        """Load rules for mapping mitigations to OWASP categories"""
        return {
            # Access Control mappings
            "authentication": [OWASPCategory.BROKEN_ACCESS_CONTROL, OWASPCategory.IDENTIFICATION_FAILURES],
            "authorization": [OWASPCategory.BROKEN_ACCESS_CONTROL],
            "access control": [OWASPCategory.BROKEN_ACCESS_CONTROL],
            "privilege": [OWASPCategory.BROKEN_ACCESS_CONTROL],
            "rbac": [OWASPCategory.BROKEN_ACCESS_CONTROL],
            "session": [OWASPCategory.IDENTIFICATION_FAILURES],
            
            # Cryptographic mappings
            "encryption": [OWASPCategory.CRYPTOGRAPHIC_FAILURES],
            "crypto": [OWASPCategory.CRYPTOGRAPHIC_FAILURES],
            "tls": [OWASPCategory.CRYPTOGRAPHIC_FAILURES],
            "ssl": [OWASPCategory.CRYPTOGRAPHIC_FAILURES],
            "hash": [OWASPCategory.CRYPTOGRAPHIC_FAILURES],
            "key management": [OWASPCategory.CRYPTOGRAPHIC_FAILURES],
            
            # Injection mappings
            "sql injection": [OWASPCategory.INJECTION],
            "xss": [OWASPCategory.INJECTION],
            "cross-site scripting": [OWASPCategory.INJECTION],
            "input validation": [OWASPCategory.INJECTION],
            "sanitization": [OWASPCategory.INJECTION],
            "parameterized": [OWASPCategory.INJECTION],
            
            # Design mappings
            "threat modeling": [OWASPCategory.INSECURE_DESIGN],
            "security design": [OWASPCategory.INSECURE_DESIGN],
            "secure architecture": [OWASPCategory.INSECURE_DESIGN],
            
            # Configuration mappings
            "configuration": [OWASPCategory.SECURITY_MISCONFIGURATION],
            "default": [OWASPCategory.SECURITY_MISCONFIGURATION],
            "hardening": [OWASPCategory.SECURITY_MISCONFIGURATION],
            
            # Component mappings
            "vulnerability": [OWASPCategory.VULNERABLE_COMPONENTS],
            "patch": [OWASPCategory.VULNERABLE_COMPONENTS],
            "update": [OWASPCategory.VULNERABLE_COMPONENTS],
            "dependency": [OWASPCategory.VULNERABLE_COMPONENTS, OWASPCategory.SOFTWARE_INTEGRITY_FAILURES],
            
            # Integrity mappings
            "integrity": [OWASPCategory.SOFTWARE_INTEGRITY_FAILURES],
            "supply chain": [OWASPCategory.SOFTWARE_INTEGRITY_FAILURES],
            "code signing": [OWASPCategory.SOFTWARE_INTEGRITY_FAILURES],
            
            # Logging mappings
            "logging": [OWASPCategory.LOGGING_FAILURES],
            "monitoring": [OWASPCategory.LOGGING_FAILURES],
            "audit": [OWASPCategory.LOGGING_FAILURES],
            "alerting": [OWASPCategory.LOGGING_FAILURES],
            
            # SSRF mappings
            "ssrf": [OWASPCategory.SSRF],
            "server-side request forgery": [OWASPCategory.SSRF],
            "url validation": [OWASPCategory.SSRF],
            "network segmentation": [OWASPCategory.SSRF]
        }
    
    def _load_control_assessment_criteria(self) -> Dict[SecurityControlType, Dict[str, Any]]:
        """Load criteria for assessing security control effectiveness"""
        return {
            SecurityControlType.PREVENTIVE: {
                "description": "Controls that prevent security incidents from occurring",
                "effectiveness_factors": ["implementation_completeness", "coverage_scope", "bypass_resistance"],
                "assessment_questions": [
                    "Is the control properly implemented?",
                    "Does it cover all relevant attack vectors?",
                    "Can it be easily bypassed?"
                ]
            },
            SecurityControlType.DETECTIVE: {
                "description": "Controls that detect security incidents when they occur",
                "effectiveness_factors": ["detection_accuracy", "response_time", "false_positive_rate"],
                "assessment_questions": [
                    "Does it accurately detect threats?",
                    "How quickly does it detect incidents?",
                    "What is the false positive rate?"
                ]
            },
            SecurityControlType.CORRECTIVE: {
                "description": "Controls that correct or mitigate security incidents",
                "effectiveness_factors": ["response_effectiveness", "recovery_time", "damage_limitation"],
                "assessment_questions": [
                    "How effectively does it respond to incidents?",
                    "How quickly can it restore normal operations?",
                    "Does it limit damage from incidents?"
                ]
            },
            SecurityControlType.DETERRENT: {
                "description": "Controls that deter potential attackers",
                "effectiveness_factors": ["visibility", "perceived_difficulty", "consequence_severity"],
                "assessment_questions": [
                    "Is the control visible to potential attackers?",
                    "Does it increase perceived attack difficulty?",
                    "Are consequences severe enough to deter?"
                ]
            },
            SecurityControlType.RECOVERY: {
                "description": "Controls that help recover from security incidents",
                "effectiveness_factors": ["recovery_speed", "data_integrity", "business_continuity"],
                "assessment_questions": [
                    "How quickly can it restore operations?",
                    "Does it maintain data integrity?",
                    "Does it ensure business continuity?"
                ]
            },
            SecurityControlType.COMPENSATING: {
                "description": "Controls that provide alternative protection when primary controls fail",
                "effectiveness_factors": ["alternative_coverage", "independence", "reliability"],
                "assessment_questions": [
                    "Does it provide adequate alternative protection?",
                    "Is it independent of primary controls?",
                    "Is it reliable when needed?"
                ]
            }
        }
    
    def conduct_security_review(self, security_model: SecurityModel) -> SecurityReviewReport:
        """
        Conduct comprehensive security review and assessment
        
        Args:
            security_model: The security model to review
            
        Returns:
            SecurityReviewReport with detailed assessment results
        """
        self.logger.info(f"Starting security review for model {security_model.id}")
        
        review_id = f"review_{security_model.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Validate threat modeling methodology
        methodology_validation = self.validate_threat_modeling_methodology(security_model)
        
        # Map mitigations to OWASP categories
        mitigation_mappings = self.map_mitigations_to_owasp(security_model)
        
        # Assess security control effectiveness
        control_assessments = self.assess_security_controls(security_model, mitigation_mappings)
        
        # Generate overall assessment
        overall_assessment = self._generate_overall_assessment(
            methodology_validation, mitigation_mappings, control_assessments
        )
        
        # Generate recommendations and action items
        recommendations = self._generate_review_recommendations(
            methodology_validation, mitigation_mappings, control_assessments
        )
        action_items = self._generate_action_items(
            methodology_validation, mitigation_mappings, control_assessments
        )
        
        report = SecurityReviewReport(
            review_id=review_id,
            security_model_id=security_model.id,
            timestamp=datetime.now(),
            methodology_validation=methodology_validation,
            mitigation_mappings=mitigation_mappings,
            control_assessments=control_assessments,
            overall_assessment=overall_assessment,
            recommendations=recommendations,
            action_items=action_items
        )
        
        self.logger.info(f"Completed security review. Overall score: {overall_assessment.get('overall_score', 0):.1f}")
        return report
    
    def validate_threat_modeling_methodology(self, security_model: SecurityModel) -> MethodologyValidationResult:
        """
        Validate threat modeling methodology implementation
        
        Args:
            security_model: The security model to validate
            
        Returns:
            MethodologyValidationResult with validation details
        """
        self.logger.info("Validating threat modeling methodology")
        
        # Determine methodology used (currently focusing on STRIDE)
        methodology = ThreatModelingMethodology.STRIDE
        
        # Analyze STRIDE coverage
        stride_coverage = self._analyze_stride_coverage(security_model)
        
        # Check threat modeling completeness
        completeness_analysis = self._analyze_threat_modeling_completeness(security_model)
        
        # Identify gaps
        gaps = self._identify_methodology_gaps(security_model, stride_coverage, completeness_analysis)
        
        # Calculate completeness score
        completeness_score = self._calculate_methodology_completeness_score(
            stride_coverage, completeness_analysis
        )
        
        # Generate recommendations
        recommendations = self._generate_methodology_recommendations(gaps, stride_coverage)
        
        # Determine if methodology is valid
        is_valid = completeness_score >= 70.0 and len(gaps) <= 3
        
        return MethodologyValidationResult(
            methodology=methodology,
            is_valid=is_valid,
            completeness_score=completeness_score,
            coverage_analysis=stride_coverage,
            gaps_identified=gaps,
            recommendations=recommendations,
            validation_details=completeness_analysis
        )
    
    def _analyze_stride_coverage(self, security_model: SecurityModel) -> Dict[str, Any]:
        """Analyze STRIDE methodology coverage"""
        stride_categories = {
            StrideCategory.SPOOFING: [],
            StrideCategory.TAMPERING: [],
            StrideCategory.REPUDIATION: [],
            StrideCategory.INFORMATION_DISCLOSURE: [],
            StrideCategory.DENIAL_OF_SERVICE: [],
            StrideCategory.ELEVATION_OF_PRIVILEGE: []
        }
        
        # Categorize threats by STRIDE
        for threat in security_model.threats:
            if threat.stride_category in stride_categories:
                stride_categories[threat.stride_category].append(threat)
        
        # Calculate coverage metrics
        coverage_analysis = {}
        for category, threats in stride_categories.items():
            coverage_analysis[category.value] = {
                "threat_count": len(threats),
                "mitigation_count": sum(len(threat.mitigations) for threat in threats),
                "avg_mitigations_per_threat": (
                    sum(len(threat.mitigations) for threat in threats) / len(threats)
                    if threats else 0
                ),
                "coverage_score": min(100, len(threats) * 20)  # Max 100% with 5+ threats per category
            }
        
        # Overall STRIDE coverage
        covered_categories = len([cat for cat, analysis in coverage_analysis.items() 
                                if analysis["threat_count"] > 0])
        
        coverage_analysis["overall"] = {
            "categories_covered": covered_categories,
            "total_categories": len(stride_categories),
            "coverage_percentage": (covered_categories / len(stride_categories)) * 100,
            "total_threats": len(security_model.threats),
            "total_mitigations": sum(len(threat.mitigations) for threat in security_model.threats)
        }
        
        return coverage_analysis
    
    def _analyze_threat_modeling_completeness(self, security_model: SecurityModel) -> Dict[str, Any]:
        """Analyze threat modeling completeness"""
        analysis = {
            "component_coverage": self._analyze_component_threat_coverage(security_model),
            "dataflow_coverage": self._analyze_dataflow_threat_coverage(security_model),
            "threat_quality": self._analyze_threat_quality(security_model),
            "mitigation_quality": self._analyze_mitigation_quality(security_model)
        }
        
        return analysis
    
    def _analyze_component_threat_coverage(self, security_model: SecurityModel) -> Dict[str, Any]:
        """Analyze threat coverage for components"""
        component_threats = {}
        
        # Map threats to components (simplified - would need more sophisticated mapping)
        for component in security_model.components:
            component_threats[component.id] = []
            
        # Count threats that might affect each component type
        for threat in security_model.threats:
            # Simple heuristic - more sophisticated analysis would be needed
            if threat.stride_category in [StrideCategory.SPOOFING, StrideCategory.ELEVATION_OF_PRIVILEGE]:
                # These typically affect process components
                for component in security_model.components:
                    if component.component_type == ComponentType.PROCESS:
                        component_threats[component.id].append(threat)
        
        coverage_analysis = {
            "total_components": len(security_model.components),
            "components_with_threats": len([cid for cid, threats in component_threats.items() if threats]),
            "coverage_percentage": (
                len([cid for cid, threats in component_threats.items() if threats]) / 
                len(security_model.components) * 100
                if security_model.components else 0
            )
        }
        
        return coverage_analysis
    
    def _analyze_dataflow_threat_coverage(self, security_model: SecurityModel) -> Dict[str, Any]:
        """Analyze threat coverage for data flows"""
        flow_threats = {}
        
        # Map threats to flows
        for flow in security_model.flows:
            flow_threats[flow.id] = []
        
        # Count threats that might affect each flow
        for threat in security_model.threats:
            if threat.stride_category in [StrideCategory.TAMPERING, StrideCategory.INFORMATION_DISCLOSURE]:
                # These typically affect data flows
                for flow in security_model.flows:
                    flow_threats[flow.id].append(threat)
        
        coverage_analysis = {
            "total_flows": len(security_model.flows),
            "flows_with_threats": len([fid for fid, threats in flow_threats.items() if threats]),
            "coverage_percentage": (
                len([fid for fid, threats in flow_threats.items() if threats]) / 
                len(security_model.flows) * 100
                if security_model.flows else 0
            )
        }
        
        return coverage_analysis
    
    def _analyze_threat_quality(self, security_model: SecurityModel) -> Dict[str, Any]:
        """Analyze quality of threat descriptions"""
        quality_metrics = {
            "total_threats": len(security_model.threats),
            "detailed_threats": 0,
            "threats_with_impact": 0,
            "threats_with_likelihood": 0,
            "avg_description_length": 0
        }
        
        if security_model.threats:
            total_length = 0
            for threat in security_model.threats:
                # Check description quality
                if len(threat.description) > 50:  # Detailed description
                    quality_metrics["detailed_threats"] += 1
                
                # Check if impact is assessed
                if threat.impact != ImpactLevel.UNKNOWN:
                    quality_metrics["threats_with_impact"] += 1
                
                # Check if likelihood is assessed
                if threat.likelihood != LikelihoodLevel.UNKNOWN:
                    quality_metrics["threats_with_likelihood"] += 1
                
                total_length += len(threat.description)
            
            quality_metrics["avg_description_length"] = total_length / len(security_model.threats)
            quality_metrics["quality_score"] = (
                (quality_metrics["detailed_threats"] / len(security_model.threats)) * 40 +
                (quality_metrics["threats_with_impact"] / len(security_model.threats)) * 30 +
                (quality_metrics["threats_with_likelihood"] / len(security_model.threats)) * 30
            )
        
        return quality_metrics
    
    def _analyze_mitigation_quality(self, security_model: SecurityModel) -> Dict[str, Any]:
        """Analyze quality of mitigation descriptions"""
        all_mitigations = []
        for threat in security_model.threats:
            all_mitigations.extend(threat.mitigations)
        
        quality_metrics = {
            "total_mitigations": len(all_mitigations),
            "detailed_mitigations": 0,
            "actionable_mitigations": 0,
            "avg_description_length": 0
        }
        
        if all_mitigations:
            total_length = 0
            actionable_keywords = ["implement", "configure", "enable", "disable", "use", "apply", "install"]
            
            for mitigation in all_mitigations:
                # Check description quality
                if len(mitigation.description) > 30:
                    quality_metrics["detailed_mitigations"] += 1
                
                # Check if mitigation is actionable
                if any(keyword in mitigation.description.lower() for keyword in actionable_keywords):
                    quality_metrics["actionable_mitigations"] += 1
                
                total_length += len(mitigation.description)
            
            quality_metrics["avg_description_length"] = total_length / len(all_mitigations)
            quality_metrics["quality_score"] = (
                (quality_metrics["detailed_mitigations"] / len(all_mitigations)) * 50 +
                (quality_metrics["actionable_mitigations"] / len(all_mitigations)) * 50
            )
        
        return quality_metrics
    
    def _identify_methodology_gaps(self, security_model: SecurityModel, 
                                 stride_coverage: Dict[str, Any], 
                                 completeness_analysis: Dict[str, Any]) -> List[str]:
        """Identify gaps in threat modeling methodology"""
        gaps = []
        
        # Check STRIDE coverage gaps
        overall_coverage = stride_coverage.get("overall", {})
        if overall_coverage.get("coverage_percentage", 0) < 100:
            missing_categories = []
            for category, analysis in stride_coverage.items():
                if category != "overall" and analysis.get("threat_count", 0) == 0:
                    missing_categories.append(category)
            
            if missing_categories:
                gaps.append(f"Missing STRIDE categories: {', '.join(missing_categories)}")
        
        # Check component coverage gaps
        component_coverage = completeness_analysis.get("component_coverage", {})
        if component_coverage.get("coverage_percentage", 0) < 80:
            gaps.append("Insufficient threat coverage for system components")
        
        # Check dataflow coverage gaps
        dataflow_coverage = completeness_analysis.get("dataflow_coverage", {})
        if dataflow_coverage.get("coverage_percentage", 0) < 80:
            gaps.append("Insufficient threat coverage for data flows")
        
        # Check threat quality gaps
        threat_quality = completeness_analysis.get("threat_quality", {})
        if threat_quality.get("quality_score", 0) < 70:
            gaps.append("Threat descriptions lack sufficient detail or risk assessment")
        
        # Check mitigation quality gaps
        mitigation_quality = completeness_analysis.get("mitigation_quality", {})
        if mitigation_quality.get("quality_score", 0) < 70:
            gaps.append("Mitigation descriptions lack sufficient detail or actionability")
        
        # Check overall threat count
        if len(security_model.threats) < 5:
            gaps.append("Insufficient number of threats identified for comprehensive analysis")
        
        return gaps
    
    def _calculate_methodology_completeness_score(self, stride_coverage: Dict[str, Any], 
                                                completeness_analysis: Dict[str, Any]) -> float:
        """Calculate overall methodology completeness score"""
        scores = []
        
        # STRIDE coverage score (30%)
        overall_coverage = stride_coverage.get("overall", {})
        stride_score = overall_coverage.get("coverage_percentage", 0)
        scores.append(stride_score * 0.3)
        
        # Component coverage score (20%)
        component_coverage = completeness_analysis.get("component_coverage", {})
        component_score = component_coverage.get("coverage_percentage", 0)
        scores.append(component_score * 0.2)
        
        # Dataflow coverage score (20%)
        dataflow_coverage = completeness_analysis.get("dataflow_coverage", {})
        dataflow_score = dataflow_coverage.get("coverage_percentage", 0)
        scores.append(dataflow_score * 0.2)
        
        # Threat quality score (15%)
        threat_quality = completeness_analysis.get("threat_quality", {})
        threat_score = threat_quality.get("quality_score", 0)
        scores.append(threat_score * 0.15)
        
        # Mitigation quality score (15%)
        mitigation_quality = completeness_analysis.get("mitigation_quality", {})
        mitigation_score = mitigation_quality.get("quality_score", 0)
        scores.append(mitigation_score * 0.15)
        
        return sum(scores)
    
    def _generate_methodology_recommendations(self, gaps: List[str], 
                                           stride_coverage: Dict[str, Any]) -> List[str]:
        """Generate recommendations for methodology improvement"""
        recommendations = []
        
        # Address specific gaps
        for gap in gaps:
            if "Missing STRIDE categories" in gap:
                recommendations.append("Conduct additional threat analysis for missing STRIDE categories")
            elif "component coverage" in gap:
                recommendations.append("Analyze threats for each system component systematically")
            elif "data flow coverage" in gap:
                recommendations.append("Identify threats for each data flow in the system")
            elif "Threat descriptions" in gap:
                recommendations.append("Enhance threat descriptions with detailed impact and likelihood assessments")
            elif "Mitigation descriptions" in gap:
                recommendations.append("Provide more specific and actionable mitigation strategies")
            elif "Insufficient number of threats" in gap:
                recommendations.append("Expand threat analysis to identify additional security risks")
        
        # General recommendations based on coverage
        overall_coverage = stride_coverage.get("overall", {})
        if overall_coverage.get("total_threats", 0) < 10:
            recommendations.append("Consider conducting additional threat brainstorming sessions")
        
        if overall_coverage.get("total_mitigations", 0) < overall_coverage.get("total_threats", 0):
            recommendations.append("Ensure each identified threat has appropriate mitigations")
        
        return recommendations    
    d
ef map_mitigations_to_owasp(self, security_model: SecurityModel) -> List[MitigationMapping]:
        """
        Map mitigations to OWASP categories
        
        Args:
            security_model: The security model containing mitigations
            
        Returns:
            List of MitigationMapping objects
        """
        self.logger.info("Mapping mitigations to OWASP categories")
        
        mappings = []
        mitigation_id = 1
        
        for threat in security_model.threats:
            for mitigation in threat.mitigations:
                mapping = self._map_single_mitigation(mitigation, mitigation_id)
                mappings.append(mapping)
                mitigation_id += 1
        
        self.logger.info(f"Mapped {len(mappings)} mitigations to OWASP categories")
        return mappings
    
    def _map_single_mitigation(self, mitigation: Mitigation, mitigation_id: int) -> MitigationMapping:
        """Map a single mitigation to OWASP categories"""
        description_lower = mitigation.description.lower()
        
        # Find matching OWASP categories
        primary_category = None
        secondary_categories = []
        mapping_confidence = 0.0
        mapping_rationale = ""
        control_types = []
        
        # Check against mapping rules
        matched_categories = set()
        for keyword, categories in self.owasp_mapping_rules.items():
            if keyword in description_lower:
                matched_categories.update(categories)
                mapping_confidence += 0.2  # Increase confidence for each match
        
        # Determine primary and secondary categories
        if matched_categories:
            # Sort by frequency in mapping rules (simplified approach)
            category_scores = {}
            for category in matched_categories:
                category_scores[category] = sum(
                    1 for keyword, cats in self.owasp_mapping_rules.items() 
                    if category in cats and keyword in description_lower
                )
            
            sorted_categories = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)
            primary_category = sorted_categories[0][0]
            secondary_categories = [cat for cat, _ in sorted_categories[1:3]]  # Top 2 secondary
            
            mapping_rationale = f"Mapped based on keywords: {', '.join([k for k in self.owasp_mapping_rules.keys() if k in description_lower])}"
        else:
            # Default mapping based on common patterns
            primary_category = self._determine_default_owasp_category(description_lower)
            mapping_confidence = 0.1
            mapping_rationale = "Default mapping based on general security patterns"
        
        # Determine control types
        control_types = self._determine_control_types(description_lower)
        
        # Cap confidence at 1.0
        mapping_confidence = min(1.0, mapping_confidence)
        
        return MitigationMapping(
            mitigation_id=str(mitigation_id),
            mitigation_description=mitigation.description,
            primary_owasp_category=primary_category,
            secondary_owasp_categories=secondary_categories,
            mapping_confidence=mapping_confidence,
            mapping_rationale=mapping_rationale,
            control_types=control_types
        )
    
    def _determine_default_owasp_category(self, description_lower: str) -> OWASPCategory:
        """Determine default OWASP category for unmapped mitigations"""
        # Simple heuristics for default mapping
        if any(word in description_lower for word in ["prevent", "block", "filter"]):
            return OWASPCategory.SECURITY_MISCONFIGURATION
        elif any(word in description_lower for word in ["detect", "monitor", "log"]):
            return OWASPCategory.LOGGING_FAILURES
        elif any(word in description_lower for word in ["secure", "protect", "safe"]):
            return OWASPCategory.INSECURE_DESIGN
        else:
            return OWASPCategory.SECURITY_MISCONFIGURATION  # Most general category
    
    def _determine_control_types(self, description_lower: str) -> List[SecurityControlType]:
        """Determine security control types based on mitigation description"""
        control_types = []
        
        # Preventive controls
        if any(word in description_lower for word in ["prevent", "block", "filter", "validate", "sanitize"]):
            control_types.append(SecurityControlType.PREVENTIVE)
        
        # Detective controls
        if any(word in description_lower for word in ["detect", "monitor", "log", "audit", "alert"]):
            control_types.append(SecurityControlType.DETECTIVE)
        
        # Corrective controls
        if any(word in description_lower for word in ["correct", "fix", "patch", "update", "remediate"]):
            control_types.append(SecurityControlType.CORRECTIVE)
        
        # Recovery controls
        if any(word in description_lower for word in ["backup", "restore", "recover", "failover"]):
            control_types.append(SecurityControlType.RECOVERY)
        
        # Deterrent controls
        if any(word in description_lower for word in ["warn", "notice", "deter", "discourage"]):
            control_types.append(SecurityControlType.DETERRENT)
        
        # Compensating controls
        if any(word in description_lower for word in ["alternative", "compensate", "substitute"]):
            control_types.append(SecurityControlType.COMPENSATING)
        
        # Default to preventive if no specific type identified
        if not control_types:
            control_types.append(SecurityControlType.PREVENTIVE)
        
        return control_types
    
    def assess_security_controls(self, security_model: SecurityModel, 
                               mitigation_mappings: List[MitigationMapping]) -> List[SecurityControlAssessment]:
        """
        Assess security control effectiveness
        
        Args:
            security_model: The security model
            mitigation_mappings: Mapped mitigations to assess
            
        Returns:
            List of SecurityControlAssessment objects
        """
        self.logger.info("Assessing security control effectiveness")
        
        assessments = []
        
        for mapping in mitigation_mappings:
            for control_type in mapping.control_types:
                assessment = self._assess_single_control(mapping, control_type, security_model)
                assessments.append(assessment)
        
        self.logger.info(f"Assessed {len(assessments)} security controls")
        return assessments
    
    def _assess_single_control(self, mapping: MitigationMapping, 
                             control_type: SecurityControlType,
                             security_model: SecurityModel) -> SecurityControlAssessment:
        """Assess effectiveness of a single security control"""
        
        control_id = f"{mapping.mitigation_id}_{control_type.value}"
        control_name = f"{control_type.value.replace('_', ' ').title()} Control"
        
        # Assess implementation status
        implementation_status = self._assess_implementation_status(mapping, control_type)
        
        # Assess effectiveness
        effectiveness, effectiveness_score = self._assess_control_effectiveness(
            mapping, control_type, implementation_status
        )
        
        # Identify coverage areas
        coverage_areas = self._identify_coverage_areas(mapping, control_type)
        
        # Identify gaps
        gaps = self._identify_control_gaps(mapping, control_type, effectiveness)
        
        # Generate recommendations
        recommendations = self._generate_control_recommendations(mapping, control_type, gaps)
        
        # Collect evidence
        evidence = self._collect_control_evidence(mapping, control_type, security_model)
        
        return SecurityControlAssessment(
            control_id=control_id,
            control_name=control_name,
            control_description=mapping.mitigation_description,
            control_type=control_type,
            owasp_category=mapping.primary_owasp_category,
            effectiveness=effectiveness,
            effectiveness_score=effectiveness_score,
            implementation_status=implementation_status,
            coverage_areas=coverage_areas,
            gaps=gaps,
            recommendations=recommendations,
            evidence=evidence
        )
    
    def _assess_implementation_status(self, mapping: MitigationMapping, 
                                   control_type: SecurityControlType) -> str:
        """Assess implementation status of a control"""
        description_lower = mapping.mitigation_description.lower()
        
        # Check for implementation indicators
        implemented_indicators = ["implemented", "configured", "enabled", "deployed", "active"]
        planned_indicators = ["plan", "will", "should", "consider", "recommend"]
        
        if any(indicator in description_lower for indicator in implemented_indicators):
            return "Implemented"
        elif any(indicator in description_lower for indicator in planned_indicators):
            return "Planned"
        else:
            return "Proposed"
    
    def _assess_control_effectiveness(self, mapping: MitigationMapping, 
                                    control_type: SecurityControlType,
                                    implementation_status: str) -> Tuple[ControlEffectiveness, float]:
        """Assess control effectiveness and calculate score"""
        
        # Base effectiveness on implementation status
        if implementation_status == "Proposed":
            return ControlEffectiveness.NOT_IMPLEMENTED, 0.0
        
        # Assess based on description quality and specificity
        description_lower = mapping.mitigation_description.lower()
        score = 0.0
        
        # Check for specific implementation details
        if len(mapping.mitigation_description) > 50:
            score += 20  # Detailed description
        
        # Check for specific technologies or methods
        specific_indicators = ["aes", "tls", "https", "oauth", "saml", "rbac", "mfa", "sql injection", "xss"]
        if any(indicator in description_lower for indicator in specific_indicators):
            score += 30  # Specific technology mentioned
        
        # Check for measurable criteria
        measurable_indicators = ["all", "every", "100%", "complete", "comprehensive"]
        if any(indicator in description_lower for indicator in measurable_indicators):
            score += 20  # Measurable implementation
        
        # Check mapping confidence
        score += mapping.mapping_confidence * 30  # Up to 30 points for mapping confidence
        
        # Determine effectiveness level
        if score >= 80:
            effectiveness = ControlEffectiveness.HIGHLY_EFFECTIVE
        elif score >= 60:
            effectiveness = ControlEffectiveness.EFFECTIVE
        elif score >= 40:
            effectiveness = ControlEffectiveness.PARTIALLY_EFFECTIVE
        elif score >= 20:
            effectiveness = ControlEffectiveness.INEFFECTIVE
        else:
            effectiveness = ControlEffectiveness.NOT_IMPLEMENTED
        
        return effectiveness, score
    
    def _identify_coverage_areas(self, mapping: MitigationMapping, 
                               control_type: SecurityControlType) -> List[str]:
        """Identify areas covered by the control"""
        coverage_areas = []
        description_lower = mapping.mitigation_description.lower()
        
        # Map keywords to coverage areas
        coverage_mapping = {
            "authentication": "User Authentication",
            "authorization": "Access Control",
            "encryption": "Data Protection",
            "validation": "Input Security",
            "logging": "Security Monitoring",
            "backup": "Data Recovery",
            "firewall": "Network Security",
            "patch": "Vulnerability Management",
            "session": "Session Management",
            "audit": "Compliance Monitoring"
        }
        
        for keyword, area in coverage_mapping.items():
            if keyword in description_lower:
                coverage_areas.append(area)
        
        # Add OWASP category as coverage area
        coverage_areas.append(f"OWASP {mapping.primary_owasp_category.value}")
        
        return list(set(coverage_areas))  # Remove duplicates
    
    def _identify_control_gaps(self, mapping: MitigationMapping, 
                             control_type: SecurityControlType,
                             effectiveness: ControlEffectiveness) -> List[str]:
        """Identify gaps in control implementation"""
        gaps = []
        
        # Check for common gaps based on effectiveness
        if effectiveness == ControlEffectiveness.NOT_IMPLEMENTED:
            gaps.append("Control not implemented")
        elif effectiveness == ControlEffectiveness.INEFFECTIVE:
            gaps.append("Control implementation lacks detail")
            gaps.append("Control effectiveness cannot be verified")
        elif effectiveness == ControlEffectiveness.PARTIALLY_EFFECTIVE:
            gaps.append("Control implementation may be incomplete")
        
        # Check for specific gaps based on control type
        description_lower = mapping.mitigation_description.lower()
        
        if control_type == SecurityControlType.PREVENTIVE:
            if "validate" in description_lower and "sanitize" not in description_lower:
                gaps.append("Input sanitization not explicitly mentioned")
        elif control_type == SecurityControlType.DETECTIVE:
            if "monitor" in description_lower and "alert" not in description_lower:
                gaps.append("Alerting mechanism not specified")
        elif control_type == SecurityControlType.CORRECTIVE:
            if "fix" in description_lower and "test" not in description_lower:
                gaps.append("Testing of corrective actions not mentioned")
        
        # Check for missing implementation details
        if len(mapping.mitigation_description) < 30:
            gaps.append("Insufficient implementation details")
        
        if mapping.mapping_confidence < 0.5:
            gaps.append("Unclear mapping to security requirements")
        
        return gaps
    
    def _generate_control_recommendations(self, mapping: MitigationMapping, 
                                        control_type: SecurityControlType,
                                        gaps: List[str]) -> List[str]:
        """Generate recommendations for control improvement"""
        recommendations = []
        
        # Address specific gaps
        for gap in gaps:
            if "not implemented" in gap:
                recommendations.append("Implement the security control as described")
            elif "lacks detail" in gap:
                recommendations.append("Provide more specific implementation details")
            elif "incomplete" in gap:
                recommendations.append("Review and complete control implementation")
            elif "sanitization" in gap:
                recommendations.append("Add input sanitization to validation controls")
            elif "alerting" in gap:
                recommendations.append("Implement alerting for monitoring controls")
            elif "testing" in gap:
                recommendations.append("Add testing procedures for corrective controls")
        
        # General recommendations based on control type
        criteria = self.control_assessment_criteria.get(control_type, {})
        assessment_questions = criteria.get("assessment_questions", [])
        
        if assessment_questions:
            recommendations.append(f"Evaluate control against: {assessment_questions[0]}")
        
        # OWASP-specific recommendations
        owasp_category = mapping.primary_owasp_category
        if owasp_category == OWASPCategory.BROKEN_ACCESS_CONTROL:
            recommendations.append("Ensure principle of least privilege is implemented")
        elif owasp_category == OWASPCategory.CRYPTOGRAPHIC_FAILURES:
            recommendations.append("Use industry-standard encryption algorithms")
        elif owasp_category == OWASPCategory.INJECTION:
            recommendations.append("Implement parameterized queries and input validation")
        
        return recommendations
    
    def _collect_control_evidence(self, mapping: MitigationMapping, 
                                control_type: SecurityControlType,
                                security_model: SecurityModel) -> List[str]:
        """Collect evidence for control assessment"""
        evidence = []
        
        # Add mitigation description as primary evidence
        evidence.append(f"Mitigation: {mapping.mitigation_description}")
        
        # Add mapping information
        evidence.append(f"OWASP Category: {mapping.primary_owasp_category.value}")
        evidence.append(f"Control Type: {control_type.value}")
        evidence.append(f"Mapping Confidence: {mapping.mapping_confidence:.2f}")
        
        # Add related threats as context
        description_keywords = set(mapping.mitigation_description.lower().split())
        related_threats = []
        
        for threat in security_model.threats:
            threat_keywords = set(threat.description.lower().split())
            if description_keywords.intersection(threat_keywords):
                related_threats.append(threat.description[:100] + "...")
        
        if related_threats:
            evidence.append(f"Related threats: {len(related_threats)} identified")
        
        return evidence
    
    def _generate_overall_assessment(self, methodology_validation: MethodologyValidationResult,
                                   mitigation_mappings: List[MitigationMapping],
                                   control_assessments: List[SecurityControlAssessment]) -> Dict[str, Any]:
        """Generate overall security assessment"""
        
        # Calculate overall scores
        methodology_score = methodology_validation.completeness_score
        
        # Mitigation mapping quality
        mapping_scores = [m.mapping_confidence for m in mitigation_mappings]
        avg_mapping_confidence = sum(mapping_scores) / len(mapping_scores) if mapping_scores else 0
        mapping_score = avg_mapping_confidence * 100
        
        # Control effectiveness
        effectiveness_scores = [c.effectiveness_score for c in control_assessments]
        avg_effectiveness = sum(effectiveness_scores) / len(effectiveness_scores) if effectiveness_scores else 0
        
        # Overall score (weighted average)
        overall_score = (
            methodology_score * 0.4 +  # 40% methodology
            mapping_score * 0.3 +      # 30% mapping quality
            avg_effectiveness * 0.3     # 30% control effectiveness
        )
        
        # Count controls by effectiveness
        effectiveness_counts = {}
        for effectiveness in ControlEffectiveness:
            effectiveness_counts[effectiveness.value] = len([
                c for c in control_assessments if c.effectiveness == effectiveness
            ])
        
        # Count controls by OWASP category
        owasp_counts = {}
        for category in OWASPCategory:
            owasp_counts[category.value] = len([
                c for c in control_assessments if c.owasp_category == category
            ])
        
        return {
            "overall_score": overall_score,
            "methodology_score": methodology_score,
            "mapping_score": mapping_score,
            "control_effectiveness_score": avg_effectiveness,
            "total_controls": len(control_assessments),
            "total_mitigations": len(mitigation_mappings),
            "effectiveness_distribution": effectiveness_counts,
            "owasp_category_distribution": owasp_counts,
            "assessment_summary": {
                "methodology_valid": methodology_validation.is_valid,
                "high_confidence_mappings": len([m for m in mitigation_mappings if m.mapping_confidence > 0.7]),
                "effective_controls": len([c for c in control_assessments 
                                         if c.effectiveness in [ControlEffectiveness.EFFECTIVE, ControlEffectiveness.HIGHLY_EFFECTIVE]])
            }
        }
    
    def _generate_review_recommendations(self, methodology_validation: MethodologyValidationResult,
                                       mitigation_mappings: List[MitigationMapping],
                                       control_assessments: List[SecurityControlAssessment]) -> List[str]:
        """Generate overall review recommendations"""
        recommendations = []
        
        # Methodology recommendations
        if not methodology_validation.is_valid:
            recommendations.extend(methodology_validation.recommendations[:3])  # Top 3
        
        # Mapping recommendations
        low_confidence_mappings = [m for m in mitigation_mappings if m.mapping_confidence < 0.5]
        if low_confidence_mappings:
            recommendations.append(f"Review {len(low_confidence_mappings)} mitigations with unclear OWASP mapping")
        
        # Control effectiveness recommendations
        ineffective_controls = [c for c in control_assessments 
                              if c.effectiveness in [ControlEffectiveness.INEFFECTIVE, ControlEffectiveness.NOT_IMPLEMENTED]]
        if ineffective_controls:
            recommendations.append(f"Improve {len(ineffective_controls)} ineffective or unimplemented controls")
        
        # OWASP category coverage recommendations
        owasp_coverage = {}
        for assessment in control_assessments:
            if assessment.owasp_category not in owasp_coverage:
                owasp_coverage[assessment.owasp_category] = []
            owasp_coverage[assessment.owasp_category].append(assessment)
        
        uncovered_categories = [cat for cat in OWASPCategory if cat not in owasp_coverage]
        if uncovered_categories:
            recommendations.append(f"Address uncovered OWASP categories: {', '.join([cat.value for cat in uncovered_categories[:3]])}")
        
        return recommendations
    
    def _generate_action_items(self, methodology_validation: MethodologyValidationResult,
                             mitigation_mappings: List[MitigationMapping],
                             control_assessments: List[SecurityControlAssessment]) -> List[Dict[str, Any]]:
        """Generate prioritized action items"""
        action_items = []
        priority = 1
        
        # High priority: Critical gaps in methodology
        if not methodology_validation.is_valid:
            for gap in methodology_validation.gaps_identified[:2]:  # Top 2 gaps
                action_items.append({
                    "priority": priority,
                    "category": "Threat Modeling",
                    "description": f"Address methodology gap: {gap}",
                    "effort": "Medium",
                    "impact": "High"
                })
                priority += 1
        
        # Medium priority: Ineffective controls
        critical_controls = [c for c in control_assessments 
                           if c.effectiveness == ControlEffectiveness.NOT_IMPLEMENTED 
                           and c.owasp_category in [OWASPCategory.BROKEN_ACCESS_CONTROL, 
                                                  OWASPCategory.CRYPTOGRAPHIC_FAILURES,
                                                  OWASPCategory.INJECTION]]
        
        for control in critical_controls[:3]:  # Top 3 critical controls
            action_items.append({
                "priority": priority,
                "category": "Security Controls",
                "description": f"Implement {control.control_name}: {control.control_description[:100]}...",
                "effort": "High",
                "impact": "High"
            })
            priority += 1
        
        # Lower priority: Improve mapping confidence
        low_confidence_mappings = [m for m in mitigation_mappings if m.mapping_confidence < 0.3]
        if low_confidence_mappings:
            action_items.append({
                "priority": priority,
                "category": "Documentation",
                "description": f"Clarify {len(low_confidence_mappings)} mitigations with unclear security purpose",
                "effort": "Low",
                "impact": "Medium"
            })
        
        return action_items