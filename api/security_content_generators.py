"""
Security-focused content generators for comprehensive security analysis
Replaces rigid threat document templates with flexible, DeepWiki-style content generation
"""
import logging
from typing import List, Dict, Any, Optional

from .models import SecurityModel, Component, Flow, DataStore
from .llm_client import LLMManager


logger = logging.getLogger(__name__)


class SecurityContentGenerators:
    """
    Content generators for different aspects of security analysis
    Each generator focuses on a specific security domain
    """
    
    def __init__(self):
        self.llm_manager = LLMManager()
    
    async def generate_security_overview(self, security_model: SecurityModel) -> str:
        """Generate comprehensive security overview similar to DeepWiki's system overview"""
        
        components_summary = self._create_components_summary(security_model.components)
        data_stores_summary = self._create_data_stores_summary(security_model.data_stores)
        flows_summary = self._create_flows_summary(security_model.flows)
        security_patterns = security_model.security_patterns
        
        prompt = f"""Generate a comprehensive Security Overview for this application, similar to how DeepWiki creates system documentation but focused on security aspects.

## System Components Analysis
{components_summary}

## Data Stores Analysis  
{data_stores_summary}

## Data Flows Analysis
{flows_summary}

## Detected Security Patterns
- Authentication Mechanisms: {', '.join(security_patterns.authentication_mechanisms[:5])}
- Authorization Patterns: {', '.join(security_patterns.authorization_patterns[:5])}
- Input Validation: {', '.join(security_patterns.input_validation_patterns[:5])}
- Encryption Usage: {', '.join(security_patterns.encryption_usage[:5])}
- Logging Patterns: {', '.join(security_patterns.logging_patterns[:5])}

## Trust Boundaries
{len(security_model.trust_boundaries)} trust boundaries identified across the system

Create a comprehensive Security Overview that covers:

1. **System Security Architecture**
   - Overall security design and approach
   - Key security components and their roles
   - Security boundaries and isolation mechanisms

2. **Data Security Landscape**
   - Critical data assets and their protection
   - Data classification and handling procedures
   - Data flow security controls

3. **Authentication & Authorization Framework**
   - Identity management approach
   - Access control mechanisms
   - Session management and security

4. **Attack Surface Analysis**
   - External interfaces and exposure points
   - Input validation and sanitization coverage
   - API security posture

5. **Security Controls Inventory**
   - Implemented security measures
   - Monitoring and logging capabilities
   - Incident response readiness

6. **Risk Assessment Summary**
   - Key security strengths
   - Potential vulnerability areas
   - Overall security maturity level

Format as comprehensive markdown documentation with clear sections and actionable insights."""
        
        try:
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_security_analysis_system_prompt(),
                temperature=0.3,
                max_tokens=4000
            )
            return response.content
        except Exception as e:
            logger.error(f"Failed to generate security overview: {e}")
            return f"# Security Overview\n\nError generating security overview: {str(e)}"
    
    async def generate_authentication_analysis(self, security_model: SecurityModel) -> str:
        """Generate detailed authentication mechanism analysis"""
        
        auth_components = [comp for comp in security_model.components if comp.auth_mechanisms]
        auth_endpoints = []
        for comp in security_model.components:
            auth_endpoints.extend([ep for ep in comp.endpoints if ep.requires_auth])
        
        prompt = f"""Generate a detailed Authentication Analysis for this application.

## Authentication Components
{self._format_auth_components(auth_components)}

## Authentication-Required Endpoints
{self._format_auth_endpoints(auth_endpoints)}

## Detected Authentication Patterns
{', '.join(security_model.security_patterns.authentication_mechanisms)}

Create a comprehensive Authentication Analysis covering:

1. **Authentication Architecture**
   - Authentication flow and mechanisms
   - Identity providers and integration
   - Multi-factor authentication implementation

2. **Session Management**
   - Session creation and lifecycle
   - Session security controls
   - Session termination procedures

3. **Credential Management**
   - Password policies and storage
   - API key management
   - Certificate handling

4. **Authentication Security Assessment**
   - Strength of authentication mechanisms
   - Vulnerability analysis (brute force, credential stuffing, etc.)
   - Compliance with security standards

5. **Recommendations**
   - Authentication improvements
   - Security hardening measures
   - Best practice implementation

Format as detailed markdown with specific security recommendations."""
        
        try:
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_security_analysis_system_prompt(),
                temperature=0.3,
                max_tokens=3000
            )
            return response.content
        except Exception as e:
            logger.error(f"Failed to generate authentication analysis: {e}")
            return f"# Authentication Analysis\n\nError generating authentication analysis: {str(e)}"
    
    async def generate_authorization_analysis(self, security_model: SecurityModel) -> str:
        """Generate detailed authorization and access control analysis"""
        
        prompt = f"""Generate a comprehensive Authorization Analysis for this application.

## Authorization Patterns Detected
{', '.join(security_model.security_patterns.authorization_patterns)}

## Components with Access Control
{self._format_components_with_access_control(security_model.components)}

## Data Access Patterns
{self._format_data_access_patterns(security_model.data_stores)}

Create a detailed Authorization Analysis covering:

1. **Access Control Architecture**
   - Authorization model (RBAC, ABAC, etc.)
   - Permission management system
   - Role and privilege definitions

2. **Resource Protection**
   - Protected resources and endpoints
   - Access control enforcement points
   - Data-level access controls

3. **Privilege Management**
   - User role assignments
   - Permission inheritance
   - Privilege escalation controls

4. **Authorization Security Assessment**
   - Access control bypass vulnerabilities
   - Privilege escalation risks
   - Horizontal/vertical access control issues

5. **Compliance and Standards**
   - Adherence to access control principles
   - Regulatory compliance considerations
   - Industry best practices alignment

6. **Recommendations**
   - Access control improvements
   - Zero-trust implementation
   - Monitoring and auditing enhancements

Format as comprehensive markdown with actionable security recommendations."""
        
        try:
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_security_analysis_system_prompt(),
                temperature=0.3,
                max_tokens=3000
            )
            return response.content
        except Exception as e:
            logger.error(f"Failed to generate authorization analysis: {e}")
            return f"# Authorization Analysis\n\nError generating authorization analysis: {str(e)}"
    
    async def generate_data_flow_analysis(self, security_model: SecurityModel) -> str:
        """Generate comprehensive data flow security analysis"""
        
        sensitive_flows = [flow for flow in security_model.flows 
                          if flow.data_sensitivity.value in ["confidential", "restricted"]]
        
        prompt = f"""Generate a comprehensive Data Flow Security Analysis for this application.

## Sensitive Data Flows
{self._format_sensitive_flows(sensitive_flows)}

## Trust Boundary Crossings
{len(security_model.trust_boundaries)} trust boundaries with multiple data flows crossing security perimeters

## Data Stores with Sensitive Data
{self._format_sensitive_data_stores(security_model.data_stores)}

Create a detailed Data Flow Security Analysis covering:

1. **Data Flow Architecture**
   - Data movement patterns across the system
   - Trust boundary crossings and security implications
   - Data transformation and processing points

2. **Data Classification and Handling**
   - Sensitive data identification and classification
   - Data protection requirements by sensitivity level
   - Data lifecycle management

3. **Data in Transit Security**
   - Encryption and protection mechanisms
   - Secure communication protocols
   - Man-in-the-middle attack prevention

4. **Data at Rest Security**
   - Storage encryption and protection
   - Access controls for stored data
   - Backup and recovery security

5. **Data Processing Security**
   - Input validation and sanitization
   - Data transformation security
   - Memory protection and secure processing

6. **Privacy and Compliance**
   - Personal data handling
   - Regulatory compliance (GDPR, CCPA, etc.)
   - Data retention and deletion policies

7. **Security Recommendations**
   - Data flow security improvements
   - Encryption and protection enhancements
   - Monitoring and detection capabilities

Format as comprehensive markdown with specific data protection recommendations."""
        
        try:
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_security_analysis_system_prompt(),
                temperature=0.3,
                max_tokens=4000
            )
            return response.content
        except Exception as e:
            logger.error(f"Failed to generate data flow analysis: {e}")
            return f"# Data Flow Security Analysis\n\nError generating data flow analysis: {str(e)}"
    
    async def generate_api_security_analysis(self, security_model: SecurityModel) -> str:
        """Generate comprehensive API security analysis"""
        
        all_endpoints = []
        for comp in security_model.components:
            all_endpoints.extend(comp.endpoints)
        
        prompt = f"""Generate a comprehensive API Security Analysis for this application.

## API Endpoints Analysis
{self._format_api_endpoints(all_endpoints)}

## API Security Patterns
- Input Validation: {', '.join(security_model.security_patterns.input_validation_patterns)}
- Authentication: {', '.join(security_model.security_patterns.authentication_mechanisms)}

Create a detailed API Security Analysis covering:

1. **API Attack Surface**
   - Exposed endpoints and methods
   - Input vectors and validation points
   - Authentication and authorization requirements

2. **API Security Controls**
   - Input validation and sanitization
   - Output encoding and response security
   - Rate limiting and throttling

3. **API Authentication & Authorization**
   - API key management
   - Token-based authentication
   - OAuth/JWT implementation

4. **API Vulnerability Assessment**
   - OWASP API Security Top 10 analysis
   - Injection vulnerabilities (SQL, NoSQL, etc.)
   - Broken authentication and authorization

5. **Data Exposure Risks**
   - Sensitive data in API responses
   - Information disclosure vulnerabilities
   - Mass assignment and over-posting

6. **API Monitoring and Logging**
   - Security event logging
   - Anomaly detection
   - Rate limiting and abuse prevention

7. **Security Recommendations**
   - API security hardening
   - Security testing strategies
   - Monitoring and alerting improvements

Format as comprehensive markdown with specific API security recommendations."""
        
        try:
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_security_analysis_system_prompt(),
                temperature=0.3,
                max_tokens=3500
            )
            return response.content
        except Exception as e:
            logger.error(f"Failed to generate API security analysis: {e}")
            return f"# API Security Analysis\n\nError generating API security analysis: {str(e)}"
    
    async def generate_vulnerability_assessment(self, security_model: SecurityModel) -> str:
        """Generate comprehensive vulnerability assessment"""
        
        prompt = f"""Generate a comprehensive Vulnerability Assessment for this application.

## System Components for Assessment
{len(security_model.components)} components analyzed for security vulnerabilities

## Security Patterns Analysis
- Authentication: {', '.join(security_model.security_patterns.authentication_mechanisms)}
- Input Validation: {', '.join(security_model.security_patterns.input_validation_patterns)}
- Encryption: {', '.join(security_model.security_patterns.encryption_usage)}

## High-Risk Areas Identified
{self._identify_high_risk_areas(security_model)}

Create a comprehensive Vulnerability Assessment covering:

1. **OWASP Top 10 Analysis**
   - Injection vulnerabilities assessment
   - Broken authentication analysis
   - Sensitive data exposure risks
   - XML external entities (XXE) vulnerabilities
   - Broken access control assessment
   - Security misconfiguration analysis
   - Cross-site scripting (XSS) risks
   - Insecure deserialization vulnerabilities
   - Known vulnerable components
   - Insufficient logging and monitoring

2. **Application-Specific Vulnerabilities**
   - Business logic flaws
   - Race conditions and concurrency issues
   - File upload vulnerabilities
   - Server-side request forgery (SSRF)

3. **Infrastructure Vulnerabilities**
   - Network security assessment
   - Server configuration analysis
   - Database security evaluation
   - Third-party service integration risks

4. **Risk Prioritization**
   - Critical vulnerabilities requiring immediate attention
   - High-risk issues for near-term remediation
   - Medium and low-risk findings

5. **Remediation Roadmap**
   - Immediate fixes and patches
   - Short-term security improvements
   - Long-term security architecture changes

6. **Security Testing Recommendations**
   - Automated security testing integration
   - Penetration testing scope and frequency
   - Code review security focus areas

Format as comprehensive markdown with prioritized vulnerability findings and remediation guidance."""
        
        try:
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_security_analysis_system_prompt(),
                temperature=0.3,
                max_tokens=4000
            )
            return response.content
        except Exception as e:
            logger.error(f"Failed to generate vulnerability assessment: {e}")
            return f"# Vulnerability Assessment\n\nError generating vulnerability assessment: {str(e)}"
    
    async def generate_security_recommendations(self, security_model: SecurityModel) -> str:
        """Generate comprehensive security recommendations and action plan"""
        
        prompt = f"""Generate comprehensive Security Recommendations and Action Plan for this application.

## Current Security Posture
- Components: {len(security_model.components)} analyzed
- Data Stores: {len(security_model.data_stores)} with varying sensitivity levels
- Data Flows: {len(security_model.flows)} including sensitive data transfers
- Trust Boundaries: {len(security_model.trust_boundaries)} security perimeters

## Security Patterns Implemented
- Authentication: {', '.join(security_model.security_patterns.authentication_mechanisms)}
- Authorization: {', '.join(security_model.security_patterns.authorization_patterns)}
- Input Validation: {', '.join(security_model.security_patterns.input_validation_patterns)}

Create comprehensive Security Recommendations covering:

1. **Immediate Actions (Critical Priority)**
   - Security vulnerabilities requiring immediate fixes
   - Critical misconfigurations to address
   - Emergency security patches needed

2. **Short-term Improvements (High Priority)**
   - Authentication and authorization enhancements
   - Input validation and output encoding improvements
   - Logging and monitoring upgrades

3. **Medium-term Security Initiatives**
   - Security architecture improvements
   - Advanced threat detection implementation
   - Security automation and tooling

4. **Long-term Security Strategy**
   - Zero-trust architecture migration
   - Security culture and training programs
   - Compliance and governance frameworks

5. **Implementation Roadmap**
   - Phased implementation approach
   - Resource requirements and timelines
   - Success metrics and KPIs

6. **Security Operations**
   - Incident response procedures
   - Security monitoring and alerting
   - Regular security assessments

7. **Compliance and Standards**
   - Industry standard alignment
   - Regulatory compliance requirements
   - Security certification pathways

Format as actionable markdown with specific implementation guidance, timelines, and success criteria."""
        
        try:
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_security_analysis_system_prompt(),
                temperature=0.3,
                max_tokens=4000
            )
            return response.content
        except Exception as e:
            logger.error(f"Failed to generate security recommendations: {e}")
            return f"# Security Recommendations\n\nError generating security recommendations: {str(e)}"
    
    # PR-specific content generators
    
    async def generate_pr_security_overview(
        self, 
        security_model: SecurityModel, 
        changed_files: List[str],
        repo_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate security overview focused on PR changes"""
        
        context_info = "No repository context available" if not repo_context else "Repository security context available"
        
        prompt = f"""Generate a PR Security Overview for changes in this pull request.

## Changed Files
{self._format_changed_files(changed_files)}

## Repository Context
{context_info}

## Components Affected by Changes
{self._identify_affected_components(security_model, changed_files)}

Create a PR Security Overview covering:

1. **Change Summary**
   - Overview of files and components modified
   - Security-relevant changes identified
   - Scope and impact of modifications

2. **Security Impact Assessment**
   - Authentication/authorization changes
   - Data handling modifications
   - API endpoint changes

3. **Context Analysis**
   - How changes fit into overall security architecture
   - Dependencies and integration impacts
   - Trust boundary implications

4. **Risk Summary**
   - Security risks introduced by changes
   - Mitigation measures in place
   - Recommended additional protections

Format as focused markdown analysis specific to PR changes."""
        
        try:
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_pr_security_system_prompt(),
                temperature=0.3,
                max_tokens=2000
            )
            return response.content
        except Exception as e:
            logger.error(f"Failed to generate PR security overview: {e}")
            return f"# PR Security Overview\n\nError generating PR security overview: {str(e)}"
    
    async def generate_change_impact_analysis(
        self, 
        security_model: SecurityModel, 
        changed_files: List[str],
        repo_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate detailed analysis of security impact from changes"""
        
        prompt = f"""Generate a detailed Change Impact Analysis for the security implications of this PR.

## Files Modified
{chr(10).join(f'- {file}' for file in changed_files)}

## Security Model Analysis
{self._analyze_security_changes(security_model, changed_files)}

Create a Change Impact Analysis covering:

1. **Direct Security Changes**
   - Authentication mechanism modifications
   - Authorization rule changes
   - Input validation updates

2. **Indirect Security Implications**
   - Data flow modifications
   - Component interaction changes
   - Trust boundary impacts

3. **Risk Assessment**
   - New attack vectors introduced
   - Existing protections affected
   - Overall security posture impact

4. **Testing Recommendations**
   - Security tests needed for changes
   - Integration testing requirements
   - Regression testing focus areas

Format as detailed markdown with specific change analysis."""
        
        try:
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_pr_security_system_prompt(),
                temperature=0.3,
                max_tokens=2500
            )
            return response.content
        except Exception as e:
            logger.error(f"Failed to generate change impact analysis: {e}")
            return f"# Change Impact Analysis\n\nError generating change impact analysis: {str(e)}"
    
    async def generate_security_risk_assessment(
        self, 
        security_model: SecurityModel, 
        changed_files: List[str],
        repo_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate security risk assessment for PR changes"""
        
        prompt = f"""Generate a Security Risk Assessment for this PR's changes.

## Risk Factors Analysis
- Files changed: {len(changed_files)}
- Security-sensitive components affected: {self._count_security_sensitive_changes(security_model, changed_files)}
- Repository context available: {'Yes' if repo_context else 'No'}

Create a Security Risk Assessment covering:

1. **Risk Identification**
   - Security risks introduced by changes
   - Existing risks potentially amplified
   - New attack surface exposure

2. **Risk Quantification**
   - Likelihood and impact assessment
   - Risk severity ratings
   - Business impact evaluation

3. **Risk Mitigation**
   - Existing controls effectiveness
   - Additional protections needed
   - Monitoring and detection requirements

4. **Approval Recommendations**
   - Security approval status
   - Conditions for safe deployment
   - Post-deployment monitoring needs

Format as structured risk assessment with clear recommendations."""
        
        try:
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_pr_security_system_prompt(),
                temperature=0.3,
                max_tokens=2000
            )
            return response.content
        except Exception as e:
            logger.error(f"Failed to generate security risk assessment: {e}")
            return f"# Security Risk Assessment\n\nError generating security risk assessment: {str(e)}"
    
    async def generate_pr_recommendations(
        self, 
        security_model: SecurityModel, 
        changed_files: List[str],
        repo_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate specific recommendations for PR security"""
        
        prompt = f"""Generate specific Security Recommendations for this PR.

## PR Context
- Changed files: {len(changed_files)}
- Security components affected: {self._identify_security_component_changes(security_model, changed_files)}

Create PR Security Recommendations covering:

1. **Pre-Merge Requirements**
   - Security tests to run
   - Code review focus areas
   - Additional validations needed

2. **Implementation Improvements**
   - Security hardening suggestions
   - Best practice implementations
   - Code quality enhancements

3. **Post-Merge Actions**
   - Monitoring and alerting setup
   - Security validation steps
   - Rollback procedures if needed

4. **Future Considerations**
   - Long-term security improvements
   - Architecture recommendations
   - Process improvements

Format as actionable recommendations with clear next steps."""
        
        try:
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=self._get_pr_security_system_prompt(),
                temperature=0.3,
                max_tokens=2000
            )
            return response.content
        except Exception as e:
            logger.error(f"Failed to generate PR recommendations: {e}")
            return f"# PR Security Recommendations\n\nError generating PR recommendations: {str(e)}"
    
    # Helper methods for formatting and analysis
    
    def _create_components_summary(self, components: List[Component]) -> str:
        """Create formatted summary of components"""
        if not components:
            return "No components detected"
        
        summary_lines = []
        for comp in components[:10]:  # Limit to avoid token overflow
            security_info = []
            if comp.handles_sensitive_data:
                security_info.append("handles sensitive data")
            if comp.auth_mechanisms:
                security_info.append(f"auth: {', '.join(comp.auth_mechanisms[:2])}")
            if comp.endpoints:
                auth_endpoints = sum(1 for ep in comp.endpoints if ep.requires_auth)
                security_info.append(f"{len(comp.endpoints)} endpoints ({auth_endpoints} auth required)")
            
            security_desc = f" - {', '.join(security_info)}" if security_info else ""
            summary_lines.append(f"- {comp.name} ({comp.type.value}){security_desc}")
        
        return "\n".join(summary_lines)
    
    def _create_data_stores_summary(self, data_stores: List[DataStore]) -> str:
        """Create formatted summary of data stores"""
        if not data_stores:
            return "No data stores detected"
        
        summary_lines = []
        for ds in data_stores[:5]:
            sensitive_data = f" - Sensitive data: {', '.join(ds.sensitive_data_types[:3])}" if ds.sensitive_data_types else ""
            summary_lines.append(f"- {ds.name} ({ds.type.value}){sensitive_data}")
        
        return "\n".join(summary_lines)
    
    def _create_flows_summary(self, flows: List[Flow]) -> str:
        """Create formatted summary of data flows"""
        if not flows:
            return "No data flows detected"
        
        summary_lines = []
        for flow in flows[:5]:
            boundary_info = f" - Crosses {len(flow.trust_boundary_crossings)} trust boundaries" if flow.trust_boundary_crossings else ""
            summary_lines.append(f"- {flow.name} ({flow.flow_type.value}, {flow.data_sensitivity.value}){boundary_info}")
        
        return "\n".join(summary_lines)
    
    def _format_auth_components(self, components: List[Component]) -> str:
        """Format components with authentication mechanisms"""
        if not components:
            return "No authentication components detected"
        
        lines = []
        for comp in components:
            auth_info = ", ".join(comp.auth_mechanisms)
            lines.append(f"- {comp.name}: {auth_info}")
        
        return "\n".join(lines)
    
    def _format_auth_endpoints(self, endpoints: List) -> str:
        """Format endpoints requiring authentication"""
        if not endpoints:
            return "No authentication-required endpoints detected"
        
        lines = []
        for ep in endpoints[:10]:  # Limit to avoid overflow
            sensitive_info = " (handles sensitive data)" if ep.sensitive_data else ""
            lines.append(f"- {ep.method} {ep.path}{sensitive_info}")
        
        return "\n".join(lines)
    
    def _format_components_with_access_control(self, components: List[Component]) -> str:
        """Format components with access control mechanisms"""
        access_control_components = [comp for comp in components if comp.auth_mechanisms or any(ep.requires_auth for ep in comp.endpoints)]
        
        if not access_control_components:
            return "No components with explicit access control detected"
        
        lines = []
        for comp in access_control_components[:10]:
            auth_endpoints = sum(1 for ep in comp.endpoints if ep.requires_auth)
            lines.append(f"- {comp.name}: {auth_endpoints} protected endpoints")
        
        return "\n".join(lines)
    
    def _format_data_access_patterns(self, data_stores: List[DataStore]) -> str:
        """Format data access patterns"""
        if not data_stores:
            return "No data access patterns detected"
        
        lines = []
        for ds in data_stores:
            access_info = ", ".join(ds.access_patterns) if ds.access_patterns else "No specific patterns detected"
            lines.append(f"- {ds.name}: {access_info}")
        
        return "\n".join(lines)
    
    def _format_sensitive_flows(self, flows: List[Flow]) -> str:
        """Format sensitive data flows"""
        if not flows:
            return "No sensitive data flows detected"
        
        lines = []
        for flow in flows:
            components_info = f" (involves {len(flow.components_involved)} components)"
            lines.append(f"- {flow.name} ({flow.data_sensitivity.value}){components_info}")
        
        return "\n".join(lines)
    
    def _format_sensitive_data_stores(self, data_stores: List[DataStore]) -> str:
        """Format data stores with sensitive data"""
        sensitive_stores = [ds for ds in data_stores if ds.sensitive_data_types]
        
        if not sensitive_stores:
            return "No data stores with sensitive data detected"
        
        lines = []
        for ds in sensitive_stores:
            data_types = ", ".join(ds.sensitive_data_types[:3])
            lines.append(f"- {ds.name}: {data_types}")
        
        return "\n".join(lines)
    
    def _format_api_endpoints(self, endpoints: List) -> str:
        """Format API endpoints for analysis"""
        if not endpoints:
            return "No API endpoints detected"
        
        lines = []
        for ep in endpoints[:15]:  # Limit to avoid overflow
            auth_info = " (auth required)" if ep.requires_auth else ""
            sensitive_info = " (sensitive data)" if ep.sensitive_data else ""
            lines.append(f"- {ep.method} {ep.path}{auth_info}{sensitive_info}")
        
        return "\n".join(lines)
    
    def _identify_high_risk_areas(self, security_model: SecurityModel) -> str:
        """Identify high-risk areas in the system"""
        risk_areas = []
        
        # Components handling sensitive data without auth
        for comp in security_model.components:
            if comp.handles_sensitive_data and not comp.auth_mechanisms:
                risk_areas.append(f"- {comp.name}: Handles sensitive data without explicit authentication")
        
        # Endpoints with sensitive data but no auth
        for comp in security_model.components:
            for ep in comp.endpoints:
                if ep.sensitive_data and not ep.requires_auth:
                    risk_areas.append(f"- {ep.method} {ep.path}: Sensitive data endpoint without authentication")
        
        # High-sensitivity flows crossing trust boundaries
        for flow in security_model.flows:
            if flow.data_sensitivity.value in ["confidential", "restricted"] and flow.trust_boundary_crossings:
                risk_areas.append(f"- {flow.name}: High-sensitivity flow crossing {len(flow.trust_boundary_crossings)} trust boundaries")
        
        return "\n".join(risk_areas) if risk_areas else "No obvious high-risk areas identified"
    
    def _format_changed_files(self, changed_files: List[str]) -> str:
        """Format changed files for PR analysis"""
        return "\n".join(f"- {file}" for file in changed_files)
    
    def _identify_affected_components(self, security_model: SecurityModel, changed_files: List[str]) -> str:
        """Identify components affected by file changes"""
        affected_components = []
        for comp in security_model.components:
            if comp.file_path in changed_files:
                security_info = []
                if comp.handles_sensitive_data:
                    security_info.append("sensitive data")
                if comp.auth_mechanisms:
                    security_info.append("authentication")
                if comp.endpoints:
                    security_info.append(f"{len(comp.endpoints)} endpoints")
                
                info_str = f" ({', '.join(security_info)})" if security_info else ""
                affected_components.append(f"- {comp.name}{info_str}")
        
        return "\n".join(affected_components) if affected_components else "No security-relevant components directly affected"
    
    def _analyze_security_changes(self, security_model: SecurityModel, changed_files: List[str]) -> str:
        """Analyze security implications of changed files"""
        analysis = []
        
        affected_components = [comp for comp in security_model.components if comp.file_path in changed_files]
        
        if affected_components:
            analysis.append(f"Components affected: {len(affected_components)}")
            
            auth_components = [comp for comp in affected_components if comp.auth_mechanisms]
            if auth_components:
                analysis.append(f"Authentication components: {len(auth_components)}")
            
            sensitive_components = [comp for comp in affected_components if comp.handles_sensitive_data]
            if sensitive_components:
                analysis.append(f"Sensitive data components: {len(sensitive_components)}")
        
        return "\n".join(f"- {item}" for item in analysis) if analysis else "No direct security component changes detected"
    
    def _count_security_sensitive_changes(self, security_model: SecurityModel, changed_files: List[str]) -> int:
        """Count security-sensitive components affected by changes"""
        count = 0
        for comp in security_model.components:
            if comp.file_path in changed_files:
                if (comp.handles_sensitive_data or 
                    comp.auth_mechanisms or 
                    any(ep.requires_auth for ep in comp.endpoints)):
                    count += 1
        return count
    
    def _identify_security_component_changes(self, security_model: SecurityModel, changed_files: List[str]) -> str:
        """Identify specific security component changes"""
        changes = []
        
        for comp in security_model.components:
            if comp.file_path in changed_files:
                if comp.auth_mechanisms:
                    changes.append(f"Authentication component: {comp.name}")
                if comp.handles_sensitive_data:
                    changes.append(f"Sensitive data component: {comp.name}")
                if any(ep.requires_auth for ep in comp.endpoints):
                    changes.append(f"Protected endpoints component: {comp.name}")
        
        return "\n".join(f"- {change}" for change in changes) if changes else "No security-specific component changes"
    
    def _get_security_analysis_system_prompt(self) -> str:
        """Get system prompt for security analysis"""
        return """You are a senior security architect and analyst specializing in comprehensive application security assessment. 
Your task is to generate detailed, actionable security analysis similar to how DeepWiki creates comprehensive system documentation, but focused entirely on security aspects.

Key principles:
- Provide comprehensive, DeepWiki-style security analysis covering all aspects of application security
- Focus on practical, implementable security recommendations
- Reference industry standards (OWASP, NIST, CWE) where applicable
- Identify specific vulnerabilities and provide concrete mitigation strategies
- Consider both technical and business context in security recommendations
- Structure analysis in clear, logical sections with actionable insights

Always format responses in well-structured markdown with clear headings, bullet points, and specific recommendations."""
    
    def _get_pr_security_system_prompt(self) -> str:
        """Get system prompt for PR security analysis"""
        return """You are a security reviewer specializing in pull request security analysis. 
Your task is to provide focused, actionable security analysis for code changes in pull requests.

Key principles:
- Focus specifically on security implications of the changes being made
- Provide context-aware analysis when repository security knowledge is available
- Identify new security risks introduced by changes
- Assess impact on existing security controls
- Provide specific, actionable recommendations for secure implementation
- Consider both immediate and long-term security implications

Always format responses in clear markdown with specific focus on the changes being reviewed."""