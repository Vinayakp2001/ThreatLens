"""
OWASP Compliance and Security Review Router

This module provides API endpoints for OWASP compliance validation and
security review functionality.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field

from api.owasp_compliance import (
    OWASPComplianceValidator, ComplianceReport, ComplianceTracking,
    OWASPCategory, ComplianceLevel, ValidationSeverity
)
from api.security_review_system import (
    SecurityReviewSystem, SecurityReviewReport, MethodologyValidationResult,
    MitigationMapping, SecurityControlAssessment, ThreatModelingMethodology,
    SecurityControlType, ControlEffectiveness
)
from api.models import SecurityModel
from api.database import get_db_session
from api.user_utils import get_current_user

# Initialize router
router = APIRouter(prefix="/api/owasp-compliance", tags=["OWASP Compliance"])
logger = logging.getLogger(__name__)

# Initialize services
compliance_validator = OWASPComplianceValidator()
security_review_system = SecurityReviewSystem()


# Pydantic models for API requests/responses
class ComplianceValidationRequest(BaseModel):
    security_model_id: str
    include_tracking: bool = Field(default=True, description="Include compliance tracking data")


class ComplianceValidationResponse(BaseModel):
    assessment_id: str
    security_model_id: str
    timestamp: str
    overall_score: float
    compliance_level: str
    total_findings: int
    critical_findings: int
    high_findings: int
    category_scores: Dict[str, float]
    recommendations: List[str]
    improvement_plan: List[Dict[str, Any]]


class SecurityReviewRequest(BaseModel):
    security_model_id: str
    include_methodology_validation: bool = Field(default=True)
    include_mitigation_mapping: bool = Field(default=True)
    include_control_assessment: bool = Field(default=True)


class SecurityReviewResponse(BaseModel):
    review_id: str
    security_model_id: str
    timestamp: str
    methodology_validation: Dict[str, Any]
    mitigation_mappings_count: int
    control_assessments_count: int
    overall_assessment: Dict[str, Any]
    recommendations: List[str]
    action_items: List[Dict[str, Any]]


class ComplianceTrackingResponse(BaseModel):
    security_model_id: str
    assessment_count: int
    latest_score: float
    trend_analysis: Dict[str, Any]
    improvement_metrics: Dict[str, Any]


@router.post("/validate", response_model=ComplianceValidationResponse)
async def validate_compliance(
    request: ComplianceValidationRequest,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db_session = Depends(get_db_session)
):
    """
    Perform OWASP compliance validation on a security model
    
    This endpoint validates a security model against OWASP guidelines and
    provides detailed compliance assessment with findings and recommendations.
    """
    try:
        logger.info(f"Starting OWASP compliance validation for model {request.security_model_id}")
        
        # Retrieve security model from database
        security_model = await _get_security_model(request.security_model_id, db_session)
        if not security_model:
            raise HTTPException(status_code=404, detail="Security model not found")
        
        # Perform compliance validation
        compliance_report = compliance_validator.validate_security_model(security_model)
        
        # Count findings by severity
        critical_findings = len([f for f in compliance_report.findings 
                               if f.severity == ValidationSeverity.CRITICAL and f.status != ComplianceLevel.COMPLIANT])
        high_findings = len([f for f in compliance_report.findings 
                           if f.severity == ValidationSeverity.HIGH and f.status != ComplianceLevel.COMPLIANT])
        
        # Prepare response
        response = ComplianceValidationResponse(
            assessment_id=compliance_report.assessment_id,
            security_model_id=compliance_report.security_model_id,
            timestamp=compliance_report.timestamp.isoformat(),
            overall_score=compliance_report.overall_score,
            compliance_level=compliance_report.compliance_level.value,
            total_findings=len(compliance_report.findings),
            critical_findings=critical_findings,
            high_findings=high_findings,
            category_scores={cat.value: score for cat, score in compliance_report.category_scores.items()},
            recommendations=compliance_report.recommendations,
            improvement_plan=compliance_report.improvement_plan
        )
        
        # Store compliance report in background
        if request.include_tracking:
            background_tasks.add_task(_store_compliance_report, compliance_report, db_session)
        
        logger.info(f"Completed compliance validation. Score: {compliance_report.overall_score:.1f}%")
        return response
        
    except Exception as e:
        logger.error(f"Error in compliance validation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Compliance validation failed: {str(e)}")


@router.post("/security-review", response_model=SecurityReviewResponse)
async def conduct_security_review(
    request: SecurityReviewRequest,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db_session = Depends(get_db_session)
):
    """
    Conduct comprehensive security review and assessment
    
    This endpoint performs security methodology validation, mitigation mapping
    to OWASP categories, and security control effectiveness assessment.
    """
    try:
        logger.info(f"Starting security review for model {request.security_model_id}")
        
        # Retrieve security model from database
        security_model = await _get_security_model(request.security_model_id, db_session)
        if not security_model:
            raise HTTPException(status_code=404, detail="Security model not found")
        
        # Conduct security review
        review_report = security_review_system.conduct_security_review(security_model)
        
        # Prepare methodology validation response
        methodology_validation = {
            "methodology": review_report.methodology_validation.methodology.value,
            "is_valid": review_report.methodology_validation.is_valid,
            "completeness_score": review_report.methodology_validation.completeness_score,
            "gaps_count": len(review_report.methodology_validation.gaps_identified),
            "recommendations_count": len(review_report.methodology_validation.recommendations)
        }
        
        # Prepare response
        response = SecurityReviewResponse(
            review_id=review_report.review_id,
            security_model_id=review_report.security_model_id,
            timestamp=review_report.timestamp.isoformat(),
            methodology_validation=methodology_validation,
            mitigation_mappings_count=len(review_report.mitigation_mappings),
            control_assessments_count=len(review_report.control_assessments),
            overall_assessment=review_report.overall_assessment,
            recommendations=review_report.recommendations,
            action_items=review_report.action_items
        )
        
        # Store review report in background
        background_tasks.add_task(_store_security_review, review_report, db_session)
        
        logger.info(f"Completed security review. Overall score: {review_report.overall_assessment.get('overall_score', 0):.1f}")
        return response
        
    except Exception as e:
        logger.error(f"Error in security review: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Security review failed: {str(e)}")


@router.get("/tracking/{security_model_id}", response_model=ComplianceTrackingResponse)
async def get_compliance_tracking(
    security_model_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db_session = Depends(get_db_session)
):
    """
    Get compliance tracking data for a security model
    
    This endpoint returns historical compliance data, trend analysis,
    and improvement metrics for a specific security model.
    """
    try:
        logger.info(f"Retrieving compliance tracking for model {security_model_id}")
        
        # Get compliance tracking data
        tracking = compliance_validator.get_compliance_tracking(security_model_id)
        if not tracking:
            raise HTTPException(status_code=404, detail="No compliance tracking data found")
        
        # Get latest assessment
        latest_assessment = tracking.assessments[-1] if tracking.assessments else None
        latest_score = latest_assessment.overall_score if latest_assessment else 0.0
        
        response = ComplianceTrackingResponse(
            security_model_id=security_model_id,
            assessment_count=len(tracking.assessments),
            latest_score=latest_score,
            trend_analysis=tracking.trend_analysis,
            improvement_metrics=tracking.improvement_metrics
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving compliance tracking: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve compliance tracking: {str(e)}")


@router.get("/summary/{security_model_id}")
async def get_compliance_summary(
    security_model_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db_session = Depends(get_db_session)
):
    """
    Get compliance summary for a security model
    
    This endpoint returns a comprehensive summary of the latest compliance
    assessment including scores, findings, and recommendations.
    """
    try:
        logger.info(f"Generating compliance summary for model {security_model_id}")
        
        # Generate compliance summary
        summary = compliance_validator.generate_compliance_summary(security_model_id)
        
        if "error" in summary:
            raise HTTPException(status_code=404, detail=summary["error"])
        
        return summary
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating compliance summary: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate compliance summary: {str(e)}")


@router.get("/categories")
async def get_owasp_categories():
    """
    Get list of OWASP Top 10 categories
    
    This endpoint returns the complete list of OWASP Top 10 2021 categories
    used for compliance validation and mitigation mapping.
    """
    try:
        categories = [
            {
                "id": category.name,
                "name": category.value,
                "description": _get_category_description(category)
            }
            for category in OWASPCategory
        ]
        
        return {"categories": categories}
        
    except Exception as e:
        logger.error(f"Error retrieving OWASP categories: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve OWASP categories: {str(e)}")


@router.get("/validation-rules")
async def get_validation_rules(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get list of OWASP validation rules
    
    This endpoint returns the validation rules used for compliance assessment,
    including rule descriptions, severity levels, and remediation guidance.
    """
    try:
        rules = []
        for rule in compliance_validator.validation_rules:
            rules.append({
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "owasp_category": rule.owasp_category.value,
                "severity": rule.severity.value,
                "remediation_guidance": rule.remediation_guidance,
                "references": rule.references
            })
        
        return {"validation_rules": rules}
        
    except Exception as e:
        logger.error(f"Error retrieving validation rules: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve validation rules: {str(e)}")


# Helper functions
async def _get_security_model(security_model_id: str, db_session) -> Optional[SecurityModel]:
    """Retrieve security model from database"""
    # This would typically query the database
    # For now, return a placeholder - would need actual database implementation
    try:
        # Placeholder implementation - replace with actual database query
        return SecurityModel(
            id=security_model_id,
            name=f"Security Model {security_model_id}",
            description="Security model for compliance validation",
            components=[],
            data_stores=[],
            flows=[],
            threats=[],
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
    except Exception as e:
        logger.error(f"Error retrieving security model {security_model_id}: {str(e)}")
        return None


async def _store_compliance_report(compliance_report: ComplianceReport, db_session):
    """Store compliance report in database"""
    try:
        # Placeholder implementation - replace with actual database storage
        logger.info(f"Storing compliance report {compliance_report.assessment_id}")
        # Would implement actual database storage here
    except Exception as e:
        logger.error(f"Error storing compliance report: {str(e)}")


async def _store_security_review(review_report: SecurityReviewReport, db_session):
    """Store security review report in database"""
    try:
        # Placeholder implementation - replace with actual database storage
        logger.info(f"Storing security review {review_report.review_id}")
        # Would implement actual database storage here
    except Exception as e:
        logger.error(f"Error storing security review: {str(e)}")


def _get_category_description(category: OWASPCategory) -> str:
    """Get description for OWASP category"""
    descriptions = {
        OWASPCategory.BROKEN_ACCESS_CONTROL: "Restrictions on what authenticated users are allowed to do are often not properly enforced.",
        OWASPCategory.CRYPTOGRAPHIC_FAILURES: "Failures related to cryptography which often leads to sensitive data exposure.",
        OWASPCategory.INJECTION: "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.",
        OWASPCategory.INSECURE_DESIGN: "A broad category representing different weaknesses, expressed as 'missing or ineffective control design'.",
        OWASPCategory.SECURITY_MISCONFIGURATION: "Security misconfiguration is commonly a result of insecure default configurations.",
        OWASPCategory.VULNERABLE_COMPONENTS: "Components with known vulnerabilities that may undermine application defenses.",
        OWASPCategory.IDENTIFICATION_FAILURES: "Confirmation of the user's identity, authentication, and session management is critical.",
        OWASPCategory.SOFTWARE_INTEGRITY_FAILURES: "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.",
        OWASPCategory.LOGGING_FAILURES: "Logging and monitoring failures couple with missing or ineffective integration with incident response.",
        OWASPCategory.SSRF: "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL."
    }
    
    return descriptions.get(category, "OWASP Top 10 security category")