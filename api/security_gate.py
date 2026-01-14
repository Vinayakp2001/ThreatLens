"""
Security Gate Validation System

Implements security criteria validation for deployment gates, automated security 
regression detection, and security blocking and approval workflows for CI/CD pipelines.
"""
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, asdict

from pydantic import BaseModel, Field

from api.database import DatabaseManager
from api.security_analytics import SecurityAnalytics
from api.wiki_storage import WikiStorage
from api.monitoring import metrics_collector

logger = logging.getLogger(__name__)

class SecurityGateType(str, Enum):
    """Types of security gates"""
    DEPLOYMENT = "deployment"
    MERGE = "merge"
    RELEASE = "release"
    PROMOTION = "promotion"

class ApprovalStatus(str, Enum):
    """Security gate approval status"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"

class RegressionSeverity(str, Enum):
    """Security regression severity levels"""
    MINOR = "minor"
    MODERATE = "moderate"
    MAJOR = "major"
    CRITICAL = "critical"

@dataclass
class SecurityRegression:
    """Security regression detection result"""
    regression_id: str
    repository_id: str
    severity: RegressionSeverity
    regression_type: str
    description: str
    current_value: float
    previous_value: float
    threshold_breached: float
    detected_at: datetime
    affected_components: List[str]
    
class SecurityGatePolicy(BaseModel):
    """Security gate policy configuration"""
    policy_id: str = Field(description="Unique policy identifier")
    name: str = Field(description="Policy name")
    gate_type: SecurityGateType
    criteria: Dict[str, Any] = Field(description="Security criteria configuration")
    approval_required: bool = Field(default=False, description="Whether manual approval is required")
    auto_approve_threshold: float = Field(default=9.0, description="Auto-approve if score above threshold")
    block_on_regression: bool = Field(default=True, description="Block on security regression")
    regression_threshold: float = Field(default=0.5, description="Regression detection threshold")
    expiry_hours: int = Field(default=24, description="Approval expiry time in hours")
    notification_channels: List[str] = Field(default_factory=list, description="Notification channels")
    
class SecurityGateValidation(BaseModel):
    """Security gate validation result"""
    validation_id: str
    repository_id: str
    gate_type: SecurityGateType
    policy_id: str
    status: str  # passed, failed, warning, pending_approval
    security_score: float
    risk_level: str
    validation_timestamp: datetime
    expiry_timestamp: Optional[datetime] = None
    
    # Detailed results
    criteria_results: Dict[str, Any]
    regressions_detected: List[SecurityRegression]
    blockers: List[Dict[str, Any]]
    warnings: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]
    
    # Approval workflow
    requires_approval: bool = False
    approval_status: Optional[ApprovalStatus] = None
    approved_by: Optional[str] = None
    approval_timestamp: Optional[datetime] = None
    approval_comments: Optional[str] = None

class SecurityGateValidator:
    """Security gate validation engine"""
    
    def __init__(self, db_manager: DatabaseManager, wiki_storage: WikiStorage):
        self.db_manager = db_manager
        self.wiki_storage = wiki_storage
        self.security_analytics = SecurityAnalytics(db_manager)
        self.policies: Dict[str, SecurityGatePolicy] = {}
        self.active_validations: Dict[str, SecurityGateValidation] = {}
        
        # Load default policies
        self._load_default_policies()
    
    async def validate_security_gate(self, repository_id: str, gate_type: SecurityGateType,
                                   policy_id: Optional[str] = None) -> SecurityGateValidation:
        """Validate security gate against policy criteria"""
        validation_id = str(uuid.uuid4())
        
        try:
            # Get policy
            policy = self._get_policy(gate_type, policy_id)
            
            # Get current security data
            security_data = await self.security_analytics.get_repository_security_summary(repository_id)
            
            if not security_data:
                return self._create_error_validation(
                    validation_id, repository_id, gate_type, policy.policy_id,
                    "No security analysis data available"
                )
            
            # Validate criteria
            criteria_results = await self._validate_criteria(security_data, policy.criteria)
            
            # Detect regressions
            regressions = []
            if policy.block_on_regression:
                regressions = await self._detect_regressions(
                    repository_id, security_data, policy.regression_threshold
                )
            
            # Determine overall status
            status, blockers, warnings = self._determine_validation_status(
                criteria_results, regressions, policy
            )
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(
                security_data, criteria_results, regressions
            )
            
            # Check if approval is required
            requires_approval = self._requires_approval(status, policy, security_data)
            
            # Create validation result
            validation = SecurityGateValidation(
                validation_id=validation_id,
                repository_id=repository_id,
                gate_type=gate_type,
                policy_id=policy.policy_id,
                status=status,
                security_score=security_data.get('security_score', 0.0),
                risk_level=security_data.get('risk_level', 'unknown'),
                validation_timestamp=datetime.now(),
                expiry_timestamp=datetime.now() + timedelta(hours=policy.expiry_hours) if requires_approval else None,
                criteria_results=criteria_results,
                regressions_detected=regressions,
                blockers=blockers,
                warnings=warnings,
                recommendations=recommendations,
                requires_approval=requires_approval,
                approval_status=ApprovalStatus.PENDING if requires_approval else None
            )
            
            # Store validation
            self.active_validations[validation_id] = validation
            await self._store_validation(validation)
            
            # Record metrics
            metrics_collector.record_security_gate_validation(
                repository_id=repository_id,
                status=status,
                security_score=validation.security_score,
                environment=gate_type.value
            )
            
            logger.info(f"Security gate validation {validation_id} completed: {status}")
            
            return validation
            
        except Exception as e:
            logger.error(f"Security gate validation failed: {e}")
            return self._create_error_validation(
                validation_id, repository_id, gate_type, 
                policy_id or "default", str(e)
            )
    
    async def approve_security_gate(self, validation_id: str, approver: str, 
                                  comments: Optional[str] = None) -> bool:
        """Manually approve a security gate validation"""
        if validation_id not in self.active_validations:
            raise ValueError(f"Validation {validation_id} not found")
        
        validation = self.active_validations[validation_id]
        
        if not validation.requires_approval:
            raise ValueError("Validation does not require approval")
        
        if validation.approval_status != ApprovalStatus.PENDING:
            raise ValueError(f"Validation already {validation.approval_status.value}")
        
        # Check if not expired
        if validation.expiry_timestamp and datetime.now() > validation.expiry_timestamp:
            validation.approval_status = ApprovalStatus.EXPIRED
            await self._update_validation(validation)
            raise ValueError("Validation has expired")
        
        # Approve
        validation.approval_status = ApprovalStatus.APPROVED
        validation.approved_by = approver
        validation.approval_timestamp = datetime.now()
        validation.approval_comments = comments
        validation.status = "approved"
        
        await self._update_validation(validation)
        
        logger.info(f"Security gate {validation_id} approved by {approver}")
        
        return True
    
    async def reject_security_gate(self, validation_id: str, rejector: str,
                                 comments: Optional[str] = None) -> bool:
        """Manually reject a security gate validation"""
        if validation_id not in self.active_validations:
            raise ValueError(f"Validation {validation_id} not found")
        
        validation = self.active_validations[validation_id]
        
        if not validation.requires_approval:
            raise ValueError("Validation does not require approval")
        
        if validation.approval_status != ApprovalStatus.PENDING:
            raise ValueError(f"Validation already {validation.approval_status.value}")
        
        # Reject
        validation.approval_status = ApprovalStatus.REJECTED
        validation.approved_by = rejector
        validation.approval_timestamp = datetime.now()
        validation.approval_comments = comments
        validation.status = "rejected"
        
        await self._update_validation(validation)
        
        logger.info(f"Security gate {validation_id} rejected by {rejector}")
        
        return True
    
    async def get_validation_status(self, validation_id: str) -> Optional[SecurityGateValidation]:
        """Get security gate validation status"""
        if validation_id in self.active_validations:
            return self.active_validations[validation_id]
        
        # Try to load from database
        return await self._load_validation(validation_id)
    
    async def _validate_criteria(self, security_data: Dict[str, Any], 
                               criteria: Dict[str, Any]) -> Dict[str, Any]:
        """Validate security data against criteria"""
        results = {}
        
        # Check issue counts
        issues_by_severity = security_data.get('issues_by_severity', {})
        
        for severity in ['critical', 'high', 'medium', 'low']:
            max_allowed = criteria.get(f'max_{severity}_issues', float('inf'))
            actual_count = issues_by_severity.get(severity, 0)
            
            results[f'{severity}_issues'] = {
                'actual': actual_count,
                'max_allowed': max_allowed,
                'passed': actual_count <= max_allowed,
                'severity': severity
            }
        
        # Check security score
        min_score = criteria.get('min_security_score', 0.0)
        actual_score = security_data.get('security_score', 0.0)
        
        results['security_score'] = {
            'actual': actual_score,
            'min_required': min_score,
            'passed': actual_score >= min_score
        }
        
        # Check OWASP compliance
        if criteria.get('require_owasp_compliance', False):
            owasp_data = security_data.get('owasp_compliance', {})
            compliance_score = owasp_data.get('overall_score', 0.0)
            min_compliance = criteria.get('min_owasp_compliance', 0.8)
            
            results['owasp_compliance'] = {
                'actual': compliance_score,
                'min_required': min_compliance,
                'passed': compliance_score >= min_compliance
            }
        
        # Check coverage metrics
        if 'min_threat_coverage' in criteria:
            threat_coverage = security_data.get('threat_coverage', 0.0)
            min_coverage = criteria['min_threat_coverage']
            
            results['threat_coverage'] = {
                'actual': threat_coverage,
                'min_required': min_coverage,
                'passed': threat_coverage >= min_coverage
            }
        
        if 'min_mitigation_coverage' in criteria:
            mitigation_coverage = security_data.get('mitigation_coverage', 0.0)
            min_coverage = criteria['min_mitigation_coverage']
            
            results['mitigation_coverage'] = {
                'actual': mitigation_coverage,
                'min_required': min_coverage,
                'passed': mitigation_coverage >= min_coverage
            }
        
        return results
    
    async def _detect_regressions(self, repository_id: str, current_data: Dict[str, Any],
                                threshold: float) -> List[SecurityRegression]:
        """Detect security regressions by comparing with previous analysis"""
        regressions = []
        
        try:
            # Get previous security data
            previous_data = await self.security_analytics.get_previous_security_summary(repository_id)
            
            if not previous_data:
                return regressions
            
            # Compare security scores
            current_score = current_data.get('security_score', 0.0)
            previous_score = previous_data.get('security_score', 0.0)
            
            if current_score < (previous_score - threshold):
                severity = self._determine_regression_severity(previous_score - current_score)
                
                regressions.append(SecurityRegression(
                    regression_id=str(uuid.uuid4()),
                    repository_id=repository_id,
                    severity=severity,
                    regression_type="security_score",
                    description=f"Security score decreased from {previous_score:.2f} to {current_score:.2f}",
                    current_value=current_score,
                    previous_value=previous_score,
                    threshold_breached=threshold,
                    detected_at=datetime.now(),
                    affected_components=["overall_security"]
                ))
            
            # Compare issue counts
            current_issues = current_data.get('issues_by_severity', {})
            previous_issues = previous_data.get('issues_by_severity', {})
            
            for severity in ['critical', 'high']:
                current_count = current_issues.get(severity, 0)
                previous_count = previous_issues.get(severity, 0)
                
                if current_count > previous_count:
                    regression_severity = RegressionSeverity.CRITICAL if severity == 'critical' else RegressionSeverity.MAJOR
                    
                    regressions.append(SecurityRegression(
                        regression_id=str(uuid.uuid4()),
                        repository_id=repository_id,
                        severity=regression_severity,
                        regression_type=f"{severity}_issues_increase",
                        description=f"New {severity} severity issues detected: {current_count - previous_count}",
                        current_value=current_count,
                        previous_value=previous_count,
                        threshold_breached=0,  # Any increase is a regression
                        detected_at=datetime.now(),
                        affected_components=[f"{severity}_security_issues"]
                    ))
            
            # Compare OWASP compliance
            current_owasp = current_data.get('owasp_compliance', {}).get('overall_score', 0.0)
            previous_owasp = previous_data.get('owasp_compliance', {}).get('overall_score', 0.0)
            
            if current_owasp < (previous_owasp - 0.1):  # 10% decrease threshold
                regressions.append(SecurityRegression(
                    regression_id=str(uuid.uuid4()),
                    repository_id=repository_id,
                    severity=RegressionSeverity.MODERATE,
                    regression_type="owasp_compliance",
                    description=f"OWASP compliance decreased from {previous_owasp:.2f} to {current_owasp:.2f}",
                    current_value=current_owasp,
                    previous_value=previous_owasp,
                    threshold_breached=0.1,
                    detected_at=datetime.now(),
                    affected_components=["owasp_compliance"]
                ))
            
        except Exception as e:
            logger.warning(f"Could not detect regressions for {repository_id}: {e}")
        
        return regressions
    
    def _determine_regression_severity(self, score_decrease: float) -> RegressionSeverity:
        """Determine regression severity based on score decrease"""
        if score_decrease >= 2.0:
            return RegressionSeverity.CRITICAL
        elif score_decrease >= 1.0:
            return RegressionSeverity.MAJOR
        elif score_decrease >= 0.5:
            return RegressionSeverity.MODERATE
        else:
            return RegressionSeverity.MINOR
    
    def _determine_validation_status(self, criteria_results: Dict[str, Any], 
                                   regressions: List[SecurityRegression],
                                   policy: SecurityGatePolicy) -> Tuple[str, List[Dict], List[Dict]]:
        """Determine overall validation status"""
        blockers = []
        warnings = []
        
        # Check criteria failures
        for criterion, result in criteria_results.items():
            if not result.get('passed', True):
                if criterion in ['critical_issues', 'security_score']:
                    blockers.append({
                        'type': 'criteria_failure',
                        'criterion': criterion,
                        'message': f"{criterion} validation failed",
                        'details': result
                    })
                else:
                    warnings.append({
                        'type': 'criteria_warning',
                        'criterion': criterion,
                        'message': f"{criterion} below recommended threshold",
                        'details': result
                    })
        
        # Check regressions
        for regression in regressions:
            if regression.severity in [RegressionSeverity.CRITICAL, RegressionSeverity.MAJOR]:
                blockers.append({
                    'type': 'security_regression',
                    'severity': regression.severity.value,
                    'message': regression.description,
                    'regression_id': regression.regression_id
                })
            else:
                warnings.append({
                    'type': 'security_regression',
                    'severity': regression.severity.value,
                    'message': regression.description,
                    'regression_id': regression.regression_id
                })
        
        # Determine status
        if blockers:
            return "failed", blockers, warnings
        elif warnings:
            return "warning", blockers, warnings
        else:
            return "passed", blockers, warnings
    
    def _requires_approval(self, status: str, policy: SecurityGatePolicy, 
                         security_data: Dict[str, Any]) -> bool:
        """Determine if manual approval is required"""
        if not policy.approval_required:
            return False
        
        if status == "failed":
            return True
        
        if status == "warning":
            # Check if score is above auto-approve threshold
            security_score = security_data.get('security_score', 0.0)
            return security_score < policy.auto_approve_threshold
        
        return False
    
    async def _generate_recommendations(self, security_data: Dict[str, Any],
                                      criteria_results: Dict[str, Any],
                                      regressions: List[SecurityRegression]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on validation results"""
        recommendations = []
        
        # Recommendations for failed criteria
        for criterion, result in criteria_results.items():
            if not result.get('passed', True):
                if criterion == 'security_score':
                    recommendations.append({
                        'type': 'security_score_improvement',
                        'priority': 'high',
                        'message': 'Improve overall security score by addressing high-priority security issues',
                        'actions': [
                            'Review and fix critical and high severity security issues',
                            'Implement additional security controls',
                            'Enhance input validation and sanitization'
                        ]
                    })
                elif 'issues' in criterion:
                    severity = criterion.replace('_issues', '')
                    recommendations.append({
                        'type': f'{severity}_issues_reduction',
                        'priority': 'high' if severity in ['critical', 'high'] else 'medium',
                        'message': f'Reduce {severity} severity security issues',
                        'actions': [
                            f'Review and fix {severity} severity security vulnerabilities',
                            'Implement security best practices',
                            'Add security testing to CI/CD pipeline'
                        ]
                    })
        
        # Recommendations for regressions
        for regression in regressions:
            recommendations.append({
                'type': 'regression_remediation',
                'priority': 'high' if regression.severity in [RegressionSeverity.CRITICAL, RegressionSeverity.MAJOR] else 'medium',
                'message': f'Address security regression: {regression.description}',
                'actions': [
                    'Review recent changes that may have introduced security issues',
                    'Revert problematic changes if necessary',
                    'Implement additional security controls'
                ]
            })
        
        return recommendations
    
    def _get_policy(self, gate_type: SecurityGateType, policy_id: Optional[str] = None) -> SecurityGatePolicy:
        """Get security gate policy"""
        if policy_id and policy_id in self.policies:
            return self.policies[policy_id]
        
        # Return default policy for gate type
        default_policy_id = f"default_{gate_type.value}"
        if default_policy_id in self.policies:
            return self.policies[default_policy_id]
        
        # Create minimal default policy
        return SecurityGatePolicy(
            policy_id=default_policy_id,
            name=f"Default {gate_type.value} policy",
            gate_type=gate_type,
            criteria={
                'max_critical_issues': 0,
                'max_high_issues': 5,
                'min_security_score': 7.0,
                'require_owasp_compliance': True
            }
        )
    
    def _load_default_policies(self):
        """Load default security gate policies"""
        # Deployment gate policy
        self.policies["default_deployment"] = SecurityGatePolicy(
            policy_id="default_deployment",
            name="Default Deployment Gate",
            gate_type=SecurityGateType.DEPLOYMENT,
            criteria={
                'max_critical_issues': 0,
                'max_high_issues': 3,
                'max_medium_issues': 15,
                'min_security_score': 8.0,
                'require_owasp_compliance': True,
                'min_owasp_compliance': 0.85
            },
            approval_required=True,
            auto_approve_threshold=9.0,
            block_on_regression=True,
            regression_threshold=0.5
        )
        
        # Merge gate policy
        self.policies["default_merge"] = SecurityGatePolicy(
            policy_id="default_merge",
            name="Default Merge Gate",
            gate_type=SecurityGateType.MERGE,
            criteria={
                'max_critical_issues': 0,
                'max_high_issues': 5,
                'max_medium_issues': 20,
                'min_security_score': 7.0,
                'require_owasp_compliance': True,
                'min_owasp_compliance': 0.8
            },
            approval_required=False,
            block_on_regression=True,
            regression_threshold=0.3
        )
        
        # Release gate policy
        self.policies["default_release"] = SecurityGatePolicy(
            policy_id="default_release",
            name="Default Release Gate",
            gate_type=SecurityGateType.RELEASE,
            criteria={
                'max_critical_issues': 0,
                'max_high_issues': 2,
                'max_medium_issues': 10,
                'min_security_score': 8.5,
                'require_owasp_compliance': True,
                'min_owasp_compliance': 0.9
            },
            approval_required=True,
            auto_approve_threshold=9.5,
            block_on_regression=True,
            regression_threshold=0.2
        )
    
    def _create_error_validation(self, validation_id: str, repository_id: str,
                               gate_type: SecurityGateType, policy_id: str,
                               error_message: str) -> SecurityGateValidation:
        """Create error validation result"""
        return SecurityGateValidation(
            validation_id=validation_id,
            repository_id=repository_id,
            gate_type=gate_type,
            policy_id=policy_id,
            status="error",
            security_score=0.0,
            risk_level="unknown",
            validation_timestamp=datetime.now(),
            criteria_results={},
            regressions_detected=[],
            blockers=[{
                'type': 'validation_error',
                'message': error_message
            }],
            warnings=[],
            recommendations=[]
        )
    
    async def _store_validation(self, validation: SecurityGateValidation):
        """Store validation result in database"""
        # Implementation would store validation in database
        pass
    
    async def _update_validation(self, validation: SecurityGateValidation):
        """Update validation result in database"""
        # Implementation would update validation in database
        pass
    
    async def _load_validation(self, validation_id: str) -> Optional[SecurityGateValidation]:
        """Load validation result from database"""
        # Implementation would load validation from database
        return None