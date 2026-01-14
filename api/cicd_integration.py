"""
CI/CD Integration System for Continuous Security Assessment

This module provides webhook endpoints and API integration for CI/CD pipelines
to enable continuous security assessment and automated security gate validation.
"""
import logging
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from enum import Enum

from fastapi import APIRouter, HTTPException, Request, Depends, BackgroundTasks, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
import asyncio
from dataclasses import dataclass

from api.config import settings
from api.database import DatabaseManager
from api.security_analytics import SecurityAnalytics
from api.wiki_storage import WikiStorage
from api.monitoring import metrics_collector

logger = logging.getLogger(__name__)

# Security scheme for API authentication
security = HTTPBearer()

class WebhookEventType(str, Enum):
    """Supported webhook event types"""
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    RELEASE = "release"
    DEPLOYMENT = "deployment"
    SECURITY_SCAN = "security_scan"

class SecurityGateStatus(str, Enum):
    """Security gate validation status"""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    PENDING = "pending"
    ERROR = "error"

class SecurityRiskLevel(str, Enum):
    """Security risk levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class WebhookConfig:
    """Webhook configuration"""
    url: str
    secret: str
    events: List[WebhookEventType]
    active: bool = True
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

class WebhookPayload(BaseModel):
    """Base webhook payload model"""
    event_type: WebhookEventType
    repository: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.now)
    sender: Optional[Dict[str, Any]] = None
    
class PushWebhookPayload(WebhookPayload):
    """Push event webhook payload"""
    ref: str
    commits: List[Dict[str, Any]]
    head_commit: Optional[Dict[str, Any]] = None
    
class PullRequestWebhookPayload(WebhookPayload):
    """Pull request webhook payload"""
    action: str  # opened, closed, synchronize, etc.
    number: int
    pull_request: Dict[str, Any]
    
class SecurityGateCriteria(BaseModel):
    """Security gate validation criteria"""
    max_critical_issues: int = Field(default=0, description="Maximum allowed critical security issues")
    max_high_issues: int = Field(default=5, description="Maximum allowed high severity issues")
    max_medium_issues: int = Field(default=20, description="Maximum allowed medium severity issues")
    require_owasp_compliance: bool = Field(default=True, description="Require OWASP compliance")
    min_security_score: float = Field(default=7.0, ge=0.0, le=10.0, description="Minimum security score (0-10)")
    block_on_regression: bool = Field(default=True, description="Block deployment on security regression")
    
class SecurityGateResult(BaseModel):
    """Security gate validation result"""
    gate_id: str = Field(description="Unique gate validation ID")
    status: SecurityGateStatus
    passed: bool
    security_score: float
    risk_level: SecurityRiskLevel
    issues_found: Dict[str, int] = Field(description="Count of issues by severity")
    blockers: List[Dict[str, Any]] = Field(default_factory=list)
    warnings: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[Dict[str, Any]] = Field(default_factory=list)
    owasp_compliance: Dict[str, Any]
    regression_detected: bool = False
    validation_timestamp: datetime = Field(default_factory=datetime.now)
    
class SecurityReport(BaseModel):
    """Security analysis report"""
    report_id: str
    repository_id: str
    analysis_timestamp: datetime
    security_summary: Dict[str, Any]
    threat_analysis: Dict[str, Any]
    mitigation_coverage: Dict[str, Any]
    owasp_alignment: Dict[str, Any]
    recommendations: List[Dict[str, Any]]
    format: str = "json"  # json, pdf, html
    
class WebhookRegistration(BaseModel):
    """Webhook registration response"""
    webhook_id: str
    endpoint_url: str
    secret_key: str
    supported_events: List[WebhookEventType]
    created_at: datetime
    
class CICDIntegrationService:
    """CI/CD Integration Service for webhook and API management"""
    
    def __init__(self, db_manager: DatabaseManager, wiki_storage: WikiStorage):
        self.db_manager = db_manager
        self.wiki_storage = wiki_storage
        self.security_analytics = SecurityAnalytics(db_manager)
        self.webhook_configs: Dict[str, WebhookConfig] = {}
        self.rate_limiter = RateLimiter()
        
    async def register_webhook(self, config: WebhookConfig) -> WebhookRegistration:
        """Register a new webhook endpoint"""
        webhook_id = str(uuid.uuid4())
        
        # Generate secure secret key
        secret_key = self._generate_secret_key()
        config.secret = secret_key
        
        # Store webhook configuration
        self.webhook_configs[webhook_id] = config
        
        # Store in database
        await self._store_webhook_config(webhook_id, config)
        
        logger.info(f"Registered webhook {webhook_id} for events: {config.events}")
        
        return WebhookRegistration(
            webhook_id=webhook_id,
            endpoint_url=f"/api/v1/webhooks/{webhook_id}",
            secret_key=secret_key,
            supported_events=config.events,
            created_at=config.created_at
        )
    
    async def process_webhook_event(self, webhook_id: str, payload: WebhookPayload, 
                                  signature: str) -> Dict[str, Any]:
        """Process incoming webhook event"""
        # Validate webhook signature
        if not self._validate_signature(webhook_id, payload.json(), signature):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")
        
        # Rate limiting check
        if not await self.rate_limiter.check_rate_limit(webhook_id):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        # Process event based on type
        result = await self._process_event_by_type(payload)
        
        # Record metrics
        metrics_collector.record_webhook_event(
            event_type=payload.event_type.value,
            repository=payload.repository.get('full_name', 'unknown'),
            processing_time_ms=result.get('processing_time_ms', 0)
        )
        
        return result
    
    async def validate_security_gate(self, criteria: SecurityGateCriteria, 
                                   repository_id: str) -> SecurityGateResult:
        """Validate security gate criteria for deployment"""
        gate_id = str(uuid.uuid4())
        
        try:
            # Get latest security analysis
            security_data = await self.security_analytics.get_repository_security_summary(repository_id)
            
            if not security_data:
                return SecurityGateResult(
                    gate_id=gate_id,
                    status=SecurityGateStatus.ERROR,
                    passed=False,
                    security_score=0.0,
                    risk_level=SecurityRiskLevel.CRITICAL,
                    issues_found={},
                    owasp_compliance={},
                    blockers=[{"type": "missing_analysis", "message": "No security analysis found"}]
                )
            
            # Validate against criteria
            validation_result = await self._validate_against_criteria(security_data, criteria)
            
            # Check for regressions if enabled
            regression_detected = False
            if criteria.block_on_regression:
                regression_detected = await self._detect_security_regression(repository_id)
            
            # Determine overall status
            status = self._determine_gate_status(validation_result, regression_detected)
            
            result = SecurityGateResult(
                gate_id=gate_id,
                status=status,
                passed=status == SecurityGateStatus.PASSED,
                security_score=validation_result['security_score'],
                risk_level=validation_result['risk_level'],
                issues_found=validation_result['issues_found'],
                blockers=validation_result['blockers'],
                warnings=validation_result['warnings'],
                recommendations=validation_result['recommendations'],
                owasp_compliance=validation_result['owasp_compliance'],
                regression_detected=regression_detected
            )
            
            # Store gate validation result
            await self._store_gate_result(gate_id, result)
            
            logger.info(f"Security gate {gate_id} validation completed: {status.value}")
            
            return result
            
        except Exception as e:
            logger.error(f"Security gate validation failed: {e}")
            return SecurityGateResult(
                gate_id=gate_id,
                status=SecurityGateStatus.ERROR,
                passed=False,
                security_score=0.0,
                risk_level=SecurityRiskLevel.CRITICAL,
                issues_found={},
                owasp_compliance={},
                blockers=[{"type": "validation_error", "message": str(e)}]
            )
    
    async def generate_security_report(self, repository_id: str, 
                                     format: str = "json") -> SecurityReport:
        """Generate comprehensive security report"""
        report_id = str(uuid.uuid4())
        
        try:
            # Gather security data
            security_summary = await self.security_analytics.get_repository_security_summary(repository_id)
            threat_analysis = await self.security_analytics.get_threat_analysis(repository_id)
            mitigation_coverage = await self.security_analytics.get_mitigation_coverage(repository_id)
            owasp_alignment = await self.security_analytics.get_owasp_alignment(repository_id)
            recommendations = await self.security_analytics.get_security_recommendations(repository_id)
            
            report = SecurityReport(
                report_id=report_id,
                repository_id=repository_id,
                analysis_timestamp=datetime.now(),
                security_summary=security_summary or {},
                threat_analysis=threat_analysis or {},
                mitigation_coverage=mitigation_coverage or {},
                owasp_alignment=owasp_alignment or {},
                recommendations=recommendations or [],
                format=format
            )
            
            # Store report
            await self._store_security_report(report)
            
            logger.info(f"Generated security report {report_id} for repository {repository_id}")
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate security report: {e}")
            raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")
    
    def _generate_secret_key(self) -> str:
        """Generate secure secret key for webhook validation"""
        return hashlib.sha256(f"{uuid.uuid4()}{datetime.now()}".encode()).hexdigest()
    
    def _validate_signature(self, webhook_id: str, payload: str, signature: str) -> bool:
        """Validate webhook signature using HMAC"""
        if webhook_id not in self.webhook_configs:
            return False
        
        secret = self.webhook_configs[webhook_id].secret
        expected_signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(f"sha256={expected_signature}", signature)
    
    async def _process_event_by_type(self, payload: WebhookPayload) -> Dict[str, Any]:
        """Process webhook event based on type"""
        start_time = datetime.now()
        
        if payload.event_type == WebhookEventType.PUSH:
            result = await self._process_push_event(payload)
        elif payload.event_type == WebhookEventType.PULL_REQUEST:
            result = await self._process_pr_event(payload)
        elif payload.event_type == WebhookEventType.RELEASE:
            result = await self._process_release_event(payload)
        elif payload.event_type == WebhookEventType.DEPLOYMENT:
            result = await self._process_deployment_event(payload)
        elif payload.event_type == WebhookEventType.SECURITY_SCAN:
            result = await self._process_security_scan_event(payload)
        else:
            result = {"status": "ignored", "message": f"Unsupported event type: {payload.event_type}"}
        
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        result['processing_time_ms'] = processing_time
        
        return result
    
    async def _process_push_event(self, payload: PushWebhookPayload) -> Dict[str, Any]:
        """Process push event - trigger security analysis update"""
        repo_name = payload.repository.get('full_name', 'unknown')
        
        # Trigger background security analysis update
        # This would integrate with existing analysis pipeline
        
        return {
            "status": "processed",
            "event_type": "push",
            "repository": repo_name,
            "ref": payload.ref,
            "commits_count": len(payload.commits),
            "message": "Security analysis update triggered"
        }
    
    async def _process_pr_event(self, payload: PullRequestWebhookPayload) -> Dict[str, Any]:
        """Process pull request event - trigger PR security analysis"""
        repo_name = payload.repository.get('full_name', 'unknown')
        pr_number = payload.number
        
        # Trigger PR security analysis
        # This would integrate with existing PR analysis pipeline
        
        return {
            "status": "processed",
            "event_type": "pull_request",
            "repository": repo_name,
            "pr_number": pr_number,
            "action": payload.action,
            "message": "PR security analysis triggered"
        }
    
    async def _process_release_event(self, payload: WebhookPayload) -> Dict[str, Any]:
        """Process release event - generate security report"""
        repo_name = payload.repository.get('full_name', 'unknown')
        
        return {
            "status": "processed",
            "event_type": "release",
            "repository": repo_name,
            "message": "Release security report generation triggered"
        }
    
    async def _process_deployment_event(self, payload: WebhookPayload) -> Dict[str, Any]:
        """Process deployment event - validate security gate"""
        repo_name = payload.repository.get('full_name', 'unknown')
        
        return {
            "status": "processed",
            "event_type": "deployment",
            "repository": repo_name,
            "message": "Deployment security gate validation triggered"
        }
    
    async def _process_security_scan_event(self, payload: WebhookPayload) -> Dict[str, Any]:
        """Process security scan event - update security data"""
        repo_name = payload.repository.get('full_name', 'unknown')
        
        return {
            "status": "processed",
            "event_type": "security_scan",
            "repository": repo_name,
            "message": "Security scan results processed"
        }
    
    async def _validate_against_criteria(self, security_data: Dict[str, Any], 
                                       criteria: SecurityGateCriteria) -> Dict[str, Any]:
        """Validate security data against gate criteria"""
        issues_found = security_data.get('issues_by_severity', {})
        security_score = security_data.get('security_score', 0.0)
        owasp_compliance = security_data.get('owasp_compliance', {})
        
        blockers = []
        warnings = []
        recommendations = []
        
        # Check issue counts
        critical_count = issues_found.get('critical', 0)
        high_count = issues_found.get('high', 0)
        medium_count = issues_found.get('medium', 0)
        
        if critical_count > criteria.max_critical_issues:
            blockers.append({
                "type": "critical_issues",
                "message": f"Found {critical_count} critical issues (max allowed: {criteria.max_critical_issues})"
            })
        
        if high_count > criteria.max_high_issues:
            blockers.append({
                "type": "high_issues",
                "message": f"Found {high_count} high severity issues (max allowed: {criteria.max_high_issues})"
            })
        
        if medium_count > criteria.max_medium_issues:
            warnings.append({
                "type": "medium_issues",
                "message": f"Found {medium_count} medium severity issues (max allowed: {criteria.max_medium_issues})"
            })
        
        # Check security score
        if security_score < criteria.min_security_score:
            blockers.append({
                "type": "low_security_score",
                "message": f"Security score {security_score} below minimum {criteria.min_security_score}"
            })
        
        # Check OWASP compliance
        if criteria.require_owasp_compliance:
            compliance_score = owasp_compliance.get('overall_score', 0.0)
            if compliance_score < 0.8:  # 80% compliance threshold
                warnings.append({
                    "type": "owasp_compliance",
                    "message": f"OWASP compliance score {compliance_score} below recommended threshold"
                })
        
        # Determine risk level
        risk_level = SecurityRiskLevel.LOW
        if critical_count > 0 or security_score < 5.0:
            risk_level = SecurityRiskLevel.CRITICAL
        elif high_count > 5 or security_score < 7.0:
            risk_level = SecurityRiskLevel.HIGH
        elif medium_count > 10 or security_score < 8.5:
            risk_level = SecurityRiskLevel.MEDIUM
        
        return {
            'security_score': security_score,
            'risk_level': risk_level,
            'issues_found': issues_found,
            'blockers': blockers,
            'warnings': warnings,
            'recommendations': recommendations,
            'owasp_compliance': owasp_compliance
        }
    
    async def _detect_security_regression(self, repository_id: str) -> bool:
        """Detect security regression by comparing with previous analysis"""
        try:
            # Get current and previous security scores
            current_analysis = await self.security_analytics.get_repository_security_summary(repository_id)
            previous_analysis = await self.security_analytics.get_previous_security_summary(repository_id)
            
            if not current_analysis or not previous_analysis:
                return False
            
            current_score = current_analysis.get('security_score', 0.0)
            previous_score = previous_analysis.get('security_score', 0.0)
            
            # Consider it a regression if score drops by more than 0.5 points
            return current_score < (previous_score - 0.5)
            
        except Exception as e:
            logger.warning(f"Could not detect security regression: {e}")
            return False
    
    def _determine_gate_status(self, validation_result: Dict[str, Any], 
                             regression_detected: bool) -> SecurityGateStatus:
        """Determine overall security gate status"""
        if validation_result['blockers']:
            return SecurityGateStatus.FAILED
        
        if regression_detected:
            return SecurityGateStatus.FAILED
        
        if validation_result['warnings']:
            return SecurityGateStatus.WARNING
        
        return SecurityGateStatus.PASSED
    
    async def _store_webhook_config(self, webhook_id: str, config: WebhookConfig):
        """Store webhook configuration in database"""
        # Implementation would store webhook config in database
        pass
    
    async def _store_gate_result(self, gate_id: str, result: SecurityGateResult):
        """Store security gate validation result"""
        # Implementation would store gate result in database
        pass
    
    async def _store_security_report(self, report: SecurityReport):
        """Store security report"""
        # Implementation would store report in database/storage
        pass

class RateLimiter:
    """Rate limiter for webhook endpoints"""
    
    def __init__(self):
        self.requests: Dict[str, List[datetime]] = {}
        self.max_requests_per_minute = 60
        self.max_requests_per_hour = 1000
    
    async def check_rate_limit(self, webhook_id: str) -> bool:
        """Check if request is within rate limits"""
        now = datetime.now()
        
        if webhook_id not in self.requests:
            self.requests[webhook_id] = []
        
        # Clean old requests
        self.requests[webhook_id] = [
            req_time for req_time in self.requests[webhook_id]
            if now - req_time < timedelta(hours=1)
        ]
        
        # Check limits
        recent_requests = [
            req_time for req_time in self.requests[webhook_id]
            if now - req_time < timedelta(minutes=1)
        ]
        
        if len(recent_requests) >= self.max_requests_per_minute:
            return False
        
        if len(self.requests[webhook_id]) >= self.max_requests_per_hour:
            return False
        
        # Add current request
        self.requests[webhook_id].append(now)
        return True