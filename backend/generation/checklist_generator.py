"""
Checklist generator for security review and validation.

This module generates customized security review checklists based on:
- OWASP review and validation guidance
- Detected technologies and frameworks
- Component types and security requirements
- Identified threats and mitigations
"""

from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass
from enum import Enum

from ..models.system_model import System, Component, ComponentType
from ..models.threats import Threat, StrideCategory
from ..models.mitigations import Mitigation


class ChecklistCategory(Enum):
    """Categories for organizing checklist items."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    OUTPUT_ENCODING = "output_encoding"
    CRYPTOGRAPHY = "cryptography"
    ERROR_HANDLING = "error_handling"
    LOGGING = "logging"
    SESSION_MANAGEMENT = "session_management"
    DATA_PROTECTION = "data_protection"
    COMMUNICATION_SECURITY = "communication_security"
    CONFIGURATION = "configuration"
    ARCHITECTURE = "architecture"
    TESTING = "testing"
    DEPLOYMENT = "deployment"


@dataclass
class ChecklistItem:
    """Individual checklist item with context and guidance."""
    id: str
    title: str
    description: str
    category: ChecklistCategory
    priority: str  # Critical, High, Medium, Low
    owasp_reference: str
    verification_method: str
    applicable_components: List[str]
    technology_specific: bool = False
    threat_related: List[str] = None  # Related threat IDs


@dataclass
class ChecklistConfig:
    """Configuration for checklist generation."""
    include_technology_specific: bool = True
    include_threat_specific: bool = True
    include_owasp_references: bool = True
    priority_filter: List[str] = None  # Filter by priority levels
    category_filter: List[ChecklistCategory] = None  # Filter by categories


class SecurityChecklistGenerator:
    """
    Generates customized security review checklists based on system analysis.
    """
    
    def __init__(self, config: ChecklistConfig = None):
        self.config = config or ChecklistConfig()
        self._initialize_base_checklists()
    
    def _initialize_base_checklists(self):
        """Initialize base OWASP-aligned checklist items."""
        self.base_items = {
            # Authentication items
            ChecklistCategory.AUTHENTICATION: [
                ChecklistItem(
                    id="auth-001",
                    title="Multi-factor authentication implemented for privileged accounts",
                    description="Verify that multi-factor authentication is required for all administrative and privileged user accounts.",
                    category=ChecklistCategory.AUTHENTICATION,
                    priority="Critical",
                    owasp_reference="authentication-cheat-sheet",
                    verification_method="Review authentication configuration and test login flows",
                    applicable_components=["web_service", "api", "admin_interface"]
                ),
                ChecklistItem(
                    id="auth-002",
                    title="Password policies meet security requirements",
                    description="Verify password complexity, length, and rotation requirements align with organizational policy.",
                    category=ChecklistCategory.AUTHENTICATION,
                    priority="High",
                    owasp_reference="authentication-cheat-sheet",
                    verification_method="Review password policy configuration and test enforcement",
                    applicable_components=["web_service", "api", "user_interface"]
                ),
                ChecklistItem(
                    id="auth-003",
                    title="Account lockout mechanisms prevent brute force attacks",
                    description="Verify that account lockout or rate limiting prevents automated password guessing attacks.",
                    category=ChecklistCategory.AUTHENTICATION,
                    priority="High",
                    owasp_reference="authentication-cheat-sheet",
                    verification_method="Test failed login attempts and verify lockout behavior",
                    applicable_components=["web_service", "api", "user_interface"]
                ),
                ChecklistItem(
                    id="auth-004",
                    title="Session tokens are securely generated and managed",
                    description="Verify that session tokens use cryptographically secure random generation and proper lifecycle management.",
                    category=ChecklistCategory.AUTHENTICATION,
                    priority="Critical",
                    owasp_reference="session-management-cheat-sheet",
                    verification_method="Review session token generation and test session handling",
                    applicable_components=["web_service", "api"]
                )
            ],
            
            # Authorization items
            ChecklistCategory.AUTHORIZATION: [
                ChecklistItem(
                    id="authz-001",
                    title="Principle of least privilege enforced",
                    description="Verify that users and services have only the minimum permissions necessary for their function.",
                    category=ChecklistCategory.AUTHORIZATION,
                    priority="Critical",
                    owasp_reference="access-control-cheat-sheet",
                    verification_method="Review role definitions and test access controls",
                    applicable_components=["web_service", "api", "database", "admin_interface"]
                ),
                ChecklistItem(
                    id="authz-002",
                    title="Authorization checks performed on server side",
                    description="Verify that all authorization decisions are made on the server side and cannot be bypassed by client manipulation.",
                    category=ChecklistCategory.AUTHORIZATION,
                    priority="Critical",
                    owasp_reference="access-control-cheat-sheet",
                    verification_method="Test authorization bypass attempts and review server-side code",
                    applicable_components=["web_service", "api"]
                ),
                ChecklistItem(
                    id="authz-003",
                    title="Direct object references are protected",
                    description="Verify that direct object references (URLs, file paths, database keys) are protected against unauthorized access.",
                    category=ChecklistCategory.AUTHORIZATION,
                    priority="High",
                    owasp_reference="access-control-cheat-sheet",
                    verification_method="Test parameter manipulation and object access controls",
                    applicable_components=["web_service", "api", "database"]
                )
            ],
            
            # Input Validation items
            ChecklistCategory.INPUT_VALIDATION: [
                ChecklistItem(
                    id="input-001",
                    title="All input is validated using positive validation",
                    description="Verify that all user input is validated using allow-lists rather than deny-lists.",
                    category=ChecklistCategory.INPUT_VALIDATION,
                    priority="Critical",
                    owasp_reference="input-validation-cheat-sheet",
                    verification_method="Review input validation code and test with malicious inputs",
                    applicable_components=["web_service", "api", "user_interface"]
                ),
                ChecklistItem(
                    id="input-002",
                    title="SQL injection prevention implemented",
                    description="Verify that parameterized queries or prepared statements are used for all database interactions.",
                    category=ChecklistCategory.INPUT_VALIDATION,
                    priority="Critical",
                    owasp_reference="sql-injection-prevention-cheat-sheet",
                    verification_method="Review database query code and test for SQL injection vulnerabilities",
                    applicable_components=["web_service", "api", "database"]
                ),
                ChecklistItem(
                    id="input-003",
                    title="File upload security controls implemented",
                    description="Verify that file uploads are restricted by type, size, and content, and stored securely.",
                    category=ChecklistCategory.INPUT_VALIDATION,
                    priority="High",
                    owasp_reference="file-upload-cheat-sheet",
                    verification_method="Test file upload functionality with various file types and malicious content",
                    applicable_components=["web_service", "api", "file_storage"]
                )
            ],
            
            # Output Encoding items
            ChecklistCategory.OUTPUT_ENCODING: [
                ChecklistItem(
                    id="output-001",
                    title="Output encoding prevents XSS attacks",
                    description="Verify that all dynamic content is properly encoded for the output context (HTML, JavaScript, CSS, URL).",
                    category=ChecklistCategory.OUTPUT_ENCODING,
                    priority="Critical",
                    owasp_reference="cross-site-scripting-prevention-cheat-sheet",
                    verification_method="Review output encoding implementation and test for XSS vulnerabilities",
                    applicable_components=["web_service", "user_interface"]
                ),
                ChecklistItem(
                    id="output-002",
                    title="Content Security Policy (CSP) implemented",
                    description="Verify that a restrictive Content Security Policy is implemented to prevent XSS and data injection attacks.",
                    category=ChecklistCategory.OUTPUT_ENCODING,
                    priority="High",
                    owasp_reference="content-security-policy-cheat-sheet",
                    verification_method="Review CSP headers and test policy effectiveness",
                    applicable_components=["web_service", "user_interface"]
                )
            ],
            
            # Cryptography items
            ChecklistCategory.CRYPTOGRAPHY: [
                ChecklistItem(
                    id="crypto-001",
                    title="Strong cryptographic algorithms used",
                    description="Verify that only approved, strong cryptographic algorithms are used (AES-256, RSA-2048+, etc.).",
                    category=ChecklistCategory.CRYPTOGRAPHY,
                    priority="Critical",
                    owasp_reference="cryptographic-storage-cheat-sheet",
                    verification_method="Review cryptographic implementations and algorithm choices",
                    applicable_components=["web_service", "api", "database", "file_storage"]
                ),
                ChecklistItem(
                    id="crypto-002",
                    title="Sensitive data encrypted at rest",
                    description="Verify that sensitive data is encrypted when stored in databases, files, or other persistent storage.",
                    category=ChecklistCategory.CRYPTOGRAPHY,
                    priority="Critical",
                    owasp_reference="cryptographic-storage-cheat-sheet",
                    verification_method="Review data storage encryption and key management",
                    applicable_components=["database", "file_storage"]
                ),
                ChecklistItem(
                    id="crypto-003",
                    title="Data encrypted in transit",
                    description="Verify that all sensitive data is encrypted during transmission using TLS 1.2 or higher.",
                    category=ChecklistCategory.CRYPTOGRAPHY,
                    priority="Critical",
                    owasp_reference="transport-layer-protection-cheat-sheet",
                    verification_method="Test TLS configuration and verify encryption of data in transit",
                    applicable_components=["web_service", "api", "external_service"]
                )
            ],
            
            # Error Handling items
            ChecklistCategory.ERROR_HANDLING: [
                ChecklistItem(
                    id="error-001",
                    title="Error messages do not leak sensitive information",
                    description="Verify that error messages do not reveal system details, stack traces, or sensitive data.",
                    category=ChecklistCategory.ERROR_HANDLING,
                    priority="High",
                    owasp_reference="error-handling-cheat-sheet",
                    verification_method="Test error conditions and review error message content",
                    applicable_components=["web_service", "api", "user_interface"]
                ),
                ChecklistItem(
                    id="error-002",
                    title="Proper exception handling implemented",
                    description="Verify that all exceptions are properly caught and handled without exposing system internals.",
                    category=ChecklistCategory.ERROR_HANDLING,
                    priority="Medium",
                    owasp_reference="error-handling-cheat-sheet",
                    verification_method="Review exception handling code and test error scenarios",
                    applicable_components=["web_service", "api"]
                )
            ],
            
            # Logging items
            ChecklistCategory.LOGGING: [
                ChecklistItem(
                    id="log-001",
                    title="Security events are logged",
                    description="Verify that authentication, authorization, and other security-relevant events are logged.",
                    category=ChecklistCategory.LOGGING,
                    priority="High",
                    owasp_reference="logging-cheat-sheet",
                    verification_method="Review logging configuration and test log generation",
                    applicable_components=["web_service", "api", "database"]
                ),
                ChecklistItem(
                    id="log-002",
                    title="Logs do not contain sensitive data",
                    description="Verify that log files do not contain passwords, session tokens, or other sensitive information.",
                    category=ChecklistCategory.LOGGING,
                    priority="High",
                    owasp_reference="logging-cheat-sheet",
                    verification_method="Review log content and test logging of sensitive operations",
                    applicable_components=["web_service", "api", "database"]
                ),
                ChecklistItem(
                    id="log-003",
                    title="Log integrity protection implemented",
                    description="Verify that logs are protected against tampering and unauthorized modification.",
                    category=ChecklistCategory.LOGGING,
                    priority="Medium",
                    owasp_reference="logging-cheat-sheet",
                    verification_method="Review log storage security and access controls",
                    applicable_components=["logging_service", "monitoring"]
                )
            ]
        }
        
        # Technology-specific items
        self.technology_items = {
            "react": [
                ChecklistItem(
                    id="react-001",
                    title="React components sanitize props and state",
                    description="Verify that React components properly sanitize props and state to prevent XSS through JSX injection.",
                    category=ChecklistCategory.OUTPUT_ENCODING,
                    priority="High",
                    owasp_reference="cross-site-scripting-prevention-cheat-sheet",
                    verification_method="Review React component code for unsafe prop usage",
                    applicable_components=["user_interface"],
                    technology_specific=True
                ),
                ChecklistItem(
                    id="react-002",
                    title="Dangerous HTML rendering is avoided",
                    description="Verify that dangerouslySetInnerHTML is not used or is properly sanitized when necessary.",
                    category=ChecklistCategory.OUTPUT_ENCODING,
                    priority="Critical",
                    owasp_reference="cross-site-scripting-prevention-cheat-sheet",
                    verification_method="Search codebase for dangerouslySetInnerHTML usage",
                    applicable_components=["user_interface"],
                    technology_specific=True
                )
            ],
            
            "node.js": [
                ChecklistItem(
                    id="node-001",
                    title="Node.js dependencies are up to date and secure",
                    description="Verify that all Node.js dependencies are current and free of known vulnerabilities.",
                    category=ChecklistCategory.CONFIGURATION,
                    priority="High",
                    owasp_reference="dependency-check",
                    verification_method="Run npm audit and review dependency versions",
                    applicable_components=["web_service", "api"],
                    technology_specific=True
                ),
                ChecklistItem(
                    id="node-002",
                    title="Prototype pollution prevention implemented",
                    description="Verify that the application is protected against prototype pollution attacks.",
                    category=ChecklistCategory.INPUT_VALIDATION,
                    priority="High",
                    owasp_reference="nodejs-security-cheat-sheet",
                    verification_method="Review object merging and JSON parsing code",
                    applicable_components=["web_service", "api"],
                    technology_specific=True
                )
            ],
            
            "python": [
                ChecklistItem(
                    id="python-001",
                    title="Python pickle deserialization is secure",
                    description="Verify that pickle or other unsafe deserialization is not used with untrusted data.",
                    category=ChecklistCategory.INPUT_VALIDATION,
                    priority="Critical",
                    owasp_reference="deserialization-cheat-sheet",
                    verification_method="Search for pickle usage and review deserialization code",
                    applicable_components=["web_service", "api"],
                    technology_specific=True
                ),
                ChecklistItem(
                    id="python-002",
                    title="Template injection prevention implemented",
                    description="Verify that template engines (Jinja2, Django) are configured to prevent template injection.",
                    category=ChecklistCategory.OUTPUT_ENCODING,
                    priority="High",
                    owasp_reference="template-injection-prevention",
                    verification_method="Review template usage and test for injection vulnerabilities",
                    applicable_components=["web_service"],
                    technology_specific=True
                )
            ],
            
            "docker": [
                ChecklistItem(
                    id="docker-001",
                    title="Docker images use minimal base images",
                    description="Verify that Docker images use minimal, security-hardened base images without unnecessary packages.",
                    category=ChecklistCategory.CONFIGURATION,
                    priority="Medium",
                    owasp_reference="docker-security-cheat-sheet",
                    verification_method="Review Dockerfile and scan images for vulnerabilities",
                    applicable_components=["container"],
                    technology_specific=True
                ),
                ChecklistItem(
                    id="docker-002",
                    title="Container runs as non-root user",
                    description="Verify that containers run as non-root users and use appropriate user namespaces.",
                    category=ChecklistCategory.CONFIGURATION,
                    priority="High",
                    owasp_reference="docker-security-cheat-sheet",
                    verification_method="Review Dockerfile USER directive and runtime configuration",
                    applicable_components=["container"],
                    technology_specific=True
                )
            ],
            
            "kubernetes": [
                ChecklistItem(
                    id="k8s-001",
                    title="Kubernetes RBAC properly configured",
                    description="Verify that Role-Based Access Control (RBAC) is properly configured with least privilege principles.",
                    category=ChecklistCategory.AUTHORIZATION,
                    priority="Critical",
                    owasp_reference="kubernetes-security-cheat-sheet",
                    verification_method="Review RBAC configurations and test access controls",
                    applicable_components=["orchestration"],
                    technology_specific=True
                ),
                ChecklistItem(
                    id="k8s-002",
                    title="Pod security standards enforced",
                    description="Verify that Pod Security Standards are enforced to prevent privileged containers and unsafe configurations.",
                    category=ChecklistCategory.CONFIGURATION,
                    priority="High",
                    owasp_reference="kubernetes-security-cheat-sheet",
                    verification_method="Review Pod Security Policy or Pod Security Standards configuration",
                    applicable_components=["orchestration"],
                    technology_specific=True
                )
            ],
            
            "aws": [
                ChecklistItem(
                    id="aws-001",
                    title="AWS IAM follows least privilege principle",
                    description="Verify that IAM policies grant only the minimum permissions necessary for each role and user.",
                    category=ChecklistCategory.AUTHORIZATION,
                    priority="Critical",
                    owasp_reference="cloud-security-cheat-sheet",
                    verification_method="Review IAM policies and test access permissions",
                    applicable_components=["cloud_service"],
                    technology_specific=True
                ),
                ChecklistItem(
                    id="aws-002",
                    title="S3 buckets are properly secured",
                    description="Verify that S3 buckets have appropriate access controls and are not publicly accessible unless intended.",
                    category=ChecklistCategory.DATA_PROTECTION,
                    priority="Critical",
                    owasp_reference="cloud-security-cheat-sheet",
                    verification_method="Review S3 bucket policies and test public access",
                    applicable_components=["file_storage"],
                    technology_specific=True
                )
            ]
        }
    
    def generate_pr_review_checklist(
        self,
        system: System,
        threats: List[Threat],
        mitigations: List[Mitigation],
        technology_stack: List[str] = None,
        files_changed: List[str] = None
    ) -> str:
        """
        Generate a PR review checklist based on system analysis and detected technologies.
        
        Args:
            system: System model
            threats: Identified threats
            mitigations: Planned mitigations
            technology_stack: Detected technologies
            files_changed: List of files changed in the PR
            
        Returns:
            Markdown-formatted PR review checklist
        """
        checklist_items = self._select_relevant_items(
            system, threats, mitigations, technology_stack, files_changed
        )
        
        checklist = f"""# Pull Request Security Review Checklist

**Review Date**: {self._get_current_date()}
**Reviewer**: _[Name]_
**PR**: _[PR Number/Title]_

## Overview

This checklist is customized based on the system components, identified threats, and technologies used in this pull request. Complete all applicable items before approving the PR.

### Risk Summary
- **Components Affected**: {len(system.components)}
- **Security-Relevant Changes**: {len([f for f in (files_changed or []) if self._is_security_relevant_file(f)])}
- **High-Risk Threats**: {len([t for t in threats if t.risk_score >= 7.0])}

"""
        
        # Group items by category
        categories = {}
        for item in checklist_items:
            if item.category not in categories:
                categories[item.category] = []
            categories[item.category].append(item)
        
        # Generate checklist by category
        for category, items in categories.items():
            category_name = category.value.replace('_', ' ').title()
            checklist += f"""## {category_name} ({len(items)} items)

"""
            
            # Sort items by priority
            priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            sorted_items = sorted(items, key=lambda x: priority_order.get(x.priority, 4))
            
            for item in sorted_items:
                priority_emoji = self._get_priority_emoji(item.priority)
                tech_indicator = " 🔧" if item.technology_specific else ""
                
                checklist += f"""### {priority_emoji} {item.title}{tech_indicator}

**Priority**: {item.priority}  
**Applicable Components**: {', '.join(item.applicable_components)}

{item.description}

**Verification Method**: {item.verification_method}

**OWASP Reference**: [{item.owasp_reference}](https://cheatsheetseries.owasp.org/cheatsheets/{item.owasp_reference.replace('-', '_').title()}_Cheat_Sheet.html)

- [ ] **Verified** - This requirement has been checked and meets security standards
- [ ] **Not Applicable** - This requirement does not apply to the current changes
- [ ] **Needs Attention** - This requirement needs to be addressed before approval

**Notes**: _[Add any specific notes or findings]_

---

"""
        
        # Add threat-specific items
        if threats:
            high_risk_threats = [t for t in threats if t.risk_score >= 7.0]
            if high_risk_threats:
                checklist += """## Threat-Specific Review Items

The following items are based on high-risk threats identified in the system:

"""
                
                for threat in high_risk_threats:
                    checklist += f"""### 🔴 {threat.title}

**Risk Score**: {threat.risk_score:.1f} | **STRIDE**: {threat.stride_category.value}

{threat.description}

**Review Actions**:
- [ ] Verify that changes do not introduce or worsen this threat
- [ ] Confirm that existing mitigations remain effective
- [ ] Check that new code follows secure coding practices for this threat type

**Affected Assets**: {', '.join(threat.affected_assets)}

---

"""
        
        # Add technology-specific guidance
        if technology_stack and self.config.include_technology_specific:
            tech_items = []
            for tech in technology_stack:
                tech_lower = tech.lower()
                for tech_key, items in self.technology_items.items():
                    if tech_key in tech_lower:
                        tech_items.extend(items)
            
            if tech_items:
                checklist += """## Technology-Specific Items

These items are specific to the technologies detected in your system:

"""
                
                for item in tech_items:
                    priority_emoji = self._get_priority_emoji(item.priority)
                    checklist += f"""### {priority_emoji} {item.title}

{item.description}

**Verification**: {item.verification_method}

- [ ] **Completed**
- [ ] **Not Applicable**
- [ ] **Needs Work**

---

"""
        
        # Add final review section
        checklist += """## Final Review

### Overall Assessment
- [ ] **All critical and high-priority items have been addressed**
- [ ] **No new security vulnerabilities have been introduced**
- [ ] **Existing security controls remain effective**
- [ ] **Code follows secure coding best practices**
- [ ] **Documentation has been updated if needed**

### Security Approval
- [ ] **Approved** - This PR meets security requirements and can be merged
- [ ] **Approved with Conditions** - This PR can be merged with the following conditions: _[List conditions]_
- [ ] **Rejected** - This PR has security issues that must be resolved before merging

**Reviewer Signature**: _[Name and Date]_

### Additional Notes
_[Add any additional security considerations, recommendations, or follow-up items]_

---

*This checklist was generated using ThreatLens based on OWASP security review guidance.*
*For questions about specific items, consult the referenced OWASP cheat sheets or contact the security team.*
"""
        
        return checklist
    
    def generate_component_security_checklist(
        self,
        component: Component,
        threats: List[Threat],
        mitigations: List[Mitigation]
    ) -> str:
        """
        Generate a security checklist specific to a component.
        
        Args:
            component: Component to generate checklist for
            threats: Threats affecting this component
            mitigations: Mitigations for this component
            
        Returns:
            Markdown-formatted component security checklist
        """
        component_threats = [t for t in threats if component.name in t.affected_assets]
        
        checklist = f"""# Security Checklist: {component.name}

**Component Type**: {component.type.value}
**Trust Level**: {component.trust_level.value}
**Last Updated**: {self._get_current_date()}

## Component Overview

{component.description}

### Security Context
- **Interfaces**: {len(component.interfaces)} endpoints
- **Trust Level**: {component.trust_level.value}
- **Threats Identified**: {len(component_threats)}
- **Risk Level**: {self._calculate_component_risk_level(component_threats)}

"""
        
        # Get relevant checklist items for this component type
        relevant_items = []
        for category_items in self.base_items.values():
            for item in category_items:
                if component.type.value.lower() in item.applicable_components:
                    relevant_items.append(item)
        
        # Group by category
        categories = {}
        for item in relevant_items:
            if item.category not in categories:
                categories[item.category] = []
            categories[item.category].append(item)
        
        # Generate checklist sections
        for category, items in categories.items():
            category_name = category.value.replace('_', ' ').title()
            checklist += f"""## {category_name}

"""
            
            for item in items:
                priority_emoji = self._get_priority_emoji(item.priority)
                checklist += f"""### {priority_emoji} {item.title}

{item.description}

**Verification**: {item.verification_method}
**OWASP Reference**: {item.owasp_reference}

- [ ] **Implemented**
- [ ] **Not Applicable**
- [ ] **Needs Implementation**

---

"""
        
        # Add component-specific threat items
        if component_threats:
            checklist += """## Component-Specific Threats

Review the following threats that specifically affect this component:

"""
            
            for threat in sorted(component_threats, key=lambda t: t.risk_score, reverse=True):
                risk_emoji = "🔴" if threat.risk_score >= 7.0 else "🟡" if threat.risk_score >= 4.0 else "🟢"
                checklist += f"""### {risk_emoji} {threat.title}

**Risk Score**: {threat.risk_score:.1f}
**STRIDE Category**: {threat.stride_category.value}

{threat.description}

**Mitigation Status**:
- [ ] **Mitigated** - Appropriate controls are in place
- [ ] **Partially Mitigated** - Some controls exist but additional work needed
- [ ] **Not Mitigated** - No controls in place, requires immediate attention

---

"""
        
        checklist += """## Implementation Verification

### Code Review Items
- [ ] Input validation is implemented for all user inputs
- [ ] Output encoding is applied consistently
- [ ] Error handling doesn't leak sensitive information
- [ ] Authentication and authorization are properly implemented
- [ ] Cryptographic functions use approved algorithms
- [ ] Logging captures security-relevant events

### Testing Items
- [ ] Security unit tests are implemented
- [ ] Integration tests cover security scenarios
- [ ] Penetration testing has been conducted
- [ ] Static code analysis has been performed
- [ ] Dependency scanning has been completed

### Deployment Items
- [ ] Security configuration is properly set
- [ ] Monitoring and alerting are configured
- [ ] Incident response procedures are documented
- [ ] Security documentation is up to date

---

*This checklist is based on OWASP security guidance and component-specific threat analysis.*
"""
        
        return checklist
    
    def generate_deployment_security_checklist(
        self,
        system: System,
        environment: str = "production"
    ) -> str:
        """
        Generate a security checklist for system deployment.
        
        Args:
            system: System model
            environment: Target environment (development, staging, production)
            
        Returns:
            Markdown-formatted deployment security checklist
        """
        checklist = f"""# Deployment Security Checklist: {system.name}

**Environment**: {environment.title()}
**Deployment Date**: {self._get_current_date()}
**System Version**: _[Version Number]_

## Pre-Deployment Security Verification

### Infrastructure Security
- [ ] **Network Security**: Firewalls and network segmentation properly configured
- [ ] **Access Controls**: Administrative access restricted to authorized personnel
- [ ] **Monitoring**: Security monitoring and logging systems are operational
- [ ] **Backup Systems**: Secure backup and recovery procedures are in place

### Application Security
- [ ] **Security Testing**: All security tests have passed
- [ ] **Vulnerability Scanning**: No critical or high-severity vulnerabilities remain
- [ ] **Code Review**: Security-focused code review has been completed
- [ ] **Configuration Review**: Security configuration has been verified

"""
        
        if system.cloud_context:
            checklist += f"""### Cloud Security ({system.cloud_context.provider.value})
- [ ] **IAM Configuration**: Identity and access management properly configured
- [ ] **Encryption**: Data encryption at rest and in transit is enabled
- [ ] **Network Security**: VPC, security groups, and network ACLs properly configured
- [ ] **Compliance**: Configuration meets compliance requirements: {', '.join(system.cloud_context.compliance_requirements)}

"""
        
        # Environment-specific items
        if environment.lower() == "production":
            checklist += """### Production-Specific Items
- [ ] **Security Hardening**: All systems are hardened according to security baselines
- [ ] **Certificate Management**: SSL/TLS certificates are valid and properly configured
- [ ] **Incident Response**: Incident response procedures are documented and tested
- [ ] **Security Contacts**: Security team contact information is documented and accessible
- [ ] **Change Management**: Security change management procedures are in place

"""
        
        checklist += """## Post-Deployment Verification

### Operational Security
- [ ] **Monitoring Active**: Security monitoring systems are actively monitoring the deployment
- [ ] **Alerting Functional**: Security alerts are being generated and routed correctly
- [ ] **Log Collection**: Security logs are being collected and stored securely
- [ ] **Access Verification**: User and system access is working as expected

### Security Testing
- [ ] **Smoke Tests**: Basic security functionality tests have passed
- [ ] **Integration Tests**: Security integration tests have passed
- [ ] **Performance Impact**: Security controls are not negatively impacting performance
- [ ] **User Acceptance**: Security features are working from user perspective

## Ongoing Security Requirements

### Regular Activities
- [ ] **Security Monitoring**: Continuous monitoring for security events and anomalies
- [ ] **Vulnerability Management**: Regular vulnerability scanning and patching
- [ ] **Access Review**: Periodic review of user access and permissions
- [ ] **Security Updates**: Timely application of security updates and patches

### Periodic Reviews
- [ ] **Monthly**: Review security logs and incident reports
- [ ] **Quarterly**: Conduct security assessment and update threat model
- [ ] **Annually**: Comprehensive security audit and penetration testing

## Sign-off

### Security Team Approval
- [ ] **Security Architect**: _[Name and Date]_
- [ ] **Security Engineer**: _[Name and Date]_
- [ ] **Compliance Officer**: _[Name and Date]_ (if applicable)

### Operations Team Approval
- [ ] **DevOps Lead**: _[Name and Date]_
- [ ] **System Administrator**: _[Name and Date]_
- [ ] **Monitoring Team**: _[Name and Date]_

---

*This deployment checklist ensures that security requirements are met before and after system deployment.*
*Contact the security team if any items cannot be completed or if issues are discovered.*
"""
        
        return checklist
    
    def _select_relevant_items(
        self,
        system: System,
        threats: List[Threat],
        mitigations: List[Mitigation],
        technology_stack: List[str] = None,
        files_changed: List[str] = None
    ) -> List[ChecklistItem]:
        """Select checklist items relevant to the current context."""
        relevant_items = []
        
        # Get component types in the system
        component_types = set(comp.type.value.lower() for comp in system.components)
        
        # Add base items that match component types
        for category_items in self.base_items.values():
            for item in category_items:
                if any(comp_type in item.applicable_components for comp_type in component_types):
                    relevant_items.append(item)
        
        # Add technology-specific items
        if technology_stack and self.config.include_technology_specific:
            for tech in technology_stack:
                tech_lower = tech.lower()
                for tech_key, tech_items in self.technology_items.items():
                    if tech_key in tech_lower:
                        relevant_items.extend(tech_items)
        
        # Filter by priority if configured
        if self.config.priority_filter:
            relevant_items = [item for item in relevant_items if item.priority in self.config.priority_filter]
        
        # Filter by category if configured
        if self.config.category_filter:
            relevant_items = [item for item in relevant_items if item.category in self.config.category_filter]
        
        return relevant_items
    
    def _get_priority_emoji(self, priority: str) -> str:
        """Get emoji for priority level."""
        priority_emojis = {
            "Critical": "🔴",
            "High": "🟡",
            "Medium": "🔵",
            "Low": "⚪"
        }
        return priority_emojis.get(priority, "⚪")
    
    def _get_current_date(self) -> str:
        """Get current date in YYYY-MM-DD format."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d")
    
    def _is_security_relevant_file(self, filename: str) -> bool:
        """Check if a file is security-relevant based on its path/name."""
        security_patterns = [
            'auth', 'login', 'password', 'token', 'session', 'security',
            'crypto', 'encrypt', 'hash', 'validate', 'sanitize', 'permission',
            'role', 'access', 'config', 'env', 'secret'
        ]
        
        filename_lower = filename.lower()
        return any(pattern in filename_lower for pattern in security_patterns)
    
    def _calculate_component_risk_level(self, threats: List[Threat]) -> str:
        """Calculate overall risk level for a component based on its threats."""
        if not threats:
            return "Low"
        
        max_risk = max(threat.risk_score for threat in threats)
        
        if max_risk >= 7.0:
            return "High"
        elif max_risk >= 4.0:
            return "Medium"
        else:
            return "Low"