"""
ThreatAnalysisProvider - Wrapper for ThreatDocGenerator to provide wiki-compatible content
"""
import asyncio
import logging
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    # Try relative imports first (for package usage)
    from .models import (
        SecurityModel, Component, Flow, WikiSectionContent, 
        SecurityFinding, CodeReference
    )
    from .task_llm_router import get_task_router, TaskType
    from .llm_client import LLMError
    from .prompt_templates import PromptTemplates, ResponseParser
except ImportError:
    # Fall back to absolute imports (for direct testing)
    from models import (
        SecurityModel, Component, Flow, WikiSectionContent, 
        SecurityFinding, CodeReference
    )
    from llm_client import LLMManager, LLMError
    from prompt_templates import PromptTemplates, ResponseParser


logger = logging.getLogger(__name__)


class ThreatAnalysisProvider:
    """
    Wrapper for existing ThreatDocGenerator functionality to provide content for wiki sections
    Preserves all existing analysis capabilities while changing output format
    """
    
    def __init__(self, settings):
        self.settings = settings
        self.task_router = get_task_router()
        # Reuse existing prompt templates and response parsing
        self.prompt_templates = PromptTemplates()
        self.response_parser = ResponseParser()
    
    async def generate_threat_content_for_wiki(
        self, 
        security_model: SecurityModel,
        section_type: str,
        component: Optional[Component] = None,
        flow: Optional[Flow] = None
    ) -> WikiSectionContent:
        """
        Generate threat analysis content for specific wiki sections
        Instead of separate documents, creates content for wiki integration
        """
        logger.info(f"Generating wiki content for section type: {section_type}")
        
        try:
            if section_type == "threat_landscape":
                return await self._generate_stride_analysis_content(security_model)
            elif section_type == "vulnerability_analysis":
                return await self._generate_owasp_top10_content(security_model)
            elif section_type == "component_analysis":
                if not component:
                    raise ValueError("Component required for component analysis")
                return await self._generate_component_security_content(component, security_model)
            elif section_type == "flow_analysis":
                if not flow:
                    raise ValueError("Flow required for flow analysis")
                return await self._generate_flow_security_content(flow, security_model)
            elif section_type == "system_overview":
                return await self._generate_system_overview_content(security_model)
            elif section_type == "mitigations":
                return await self._generate_mitigations_content(security_model)
            else:
                raise ValueError(f"Unsupported section type: {section_type}")
                
        except Exception as e:
            logger.error(f"Failed to generate wiki content for {section_type}: {e}")
            raise
    
    async def _generate_stride_analysis_content(self, security_model: SecurityModel) -> WikiSectionContent:
        """
        Use existing STRIDE analysis but format for wiki integration
        """
        logger.info("Generating STRIDE analysis content for threat landscape section")
        
        try:
            # Use existing flow threat model prompt templates but adapt for wiki format
            prompt = self._create_stride_wiki_prompt(security_model)
            
            response_content, metadata = await self.task_router.route_task(
                task_type=TaskType.THREAT_BRAINSTORMING,
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt()
            )
            
            # Parse and format for wiki instead of separate document
            content = self.response_parser.parse_for_wiki_section(response_content, "threat_landscape")
            
            # Extract security findings from the content
            security_findings = self._extract_security_findings_from_content(
                content, "threat", security_model
            )
            
            # Extract code references
            code_references = self._extract_code_references_for_threats(security_model)
            
            return WikiSectionContent(
                title="Threat Landscape Analysis",
                content=content,
                cross_references=self._extract_cross_references(content),
                owasp_mappings=["STRIDE", "Threat_Modeling"],
                code_snippets=code_references,
                recommendations=self._extract_recommendations_from_content(content)
            )
            
        except Exception as e:
            logger.error(f"Failed to generate STRIDE analysis content: {e}")
            raise
    
    async def _generate_owasp_top10_content(self, security_model: SecurityModel) -> WikiSectionContent:
        """
        Generate OWASP Top 10 vulnerability analysis content for wiki
        """
        logger.info("Generating OWASP Top 10 analysis content for vulnerability section")
        
        try:
            prompt = self._create_owasp_top10_wiki_prompt(security_model)
            
            response_content, metadata = await self.task_router.route_task(
                task_type=TaskType.COMPLIANCE_ANALYSIS,
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt()
            )
            
            content = self.response_parser.parse_for_wiki_section(response_content, "vulnerability_analysis")
            
            # Extract security findings focused on vulnerabilities
            security_findings = self._extract_security_findings_from_content(
                content, "vulnerability", security_model
            )
            
            code_references = self._extract_code_references_for_vulnerabilities(security_model)
            
            return WikiSectionContent(
                title="Vulnerability Analysis (OWASP Top 10)",
                content=content,
                cross_references=self._extract_cross_references(content),
                owasp_mappings=["OWASP_Top_10", "Vulnerability_Assessment"],
                code_snippets=code_references,
                recommendations=self._extract_recommendations_from_content(content)
            )
            
        except Exception as e:
            logger.error(f"Failed to generate OWASP Top 10 content: {e}")
            raise
    
    async def _generate_component_security_content(
        self, 
        component: Component, 
        security_model: SecurityModel
    ) -> WikiSectionContent:
        """
        Generate component-specific security analysis content for wiki
        Reuses existing component analysis logic but formats for wiki integration
        """
        logger.info(f"Generating component security content for: {component.name}")
        
        try:
            # Use existing component profile prompt but adapt for wiki format
            prompt = self._create_component_wiki_prompt(component, security_model)
            
            response_content, metadata = await self.task_router.route_task(
                task_type=TaskType.COMPONENT_ANALYSIS,
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt()
            )
            
            content = self.response_parser.parse_for_wiki_section(response_content, "component_analysis")
            
            # Extract component-specific security findings
            security_findings = self._extract_security_findings_from_content(
                content, "component", security_model, component
            )
            
            # Create code reference for the component
            code_references = [
                CodeReference(
                    id=str(uuid.uuid4()),
                    file_path=component.file_path,
                    line_start=1,
                    function_name=component.name,
                    code_snippet=f"Component: {component.name} ({component.type.value})"
                )
            ]
            
            return WikiSectionContent(
                title=f"Component Analysis: {component.name}",
                content=content,
                cross_references=self._extract_cross_references(content),
                owasp_mappings=["Component_Security", "ASVS"],
                code_snippets=code_references,
                recommendations=self._extract_recommendations_from_content(content)
            )
            
        except Exception as e:
            logger.error(f"Failed to generate component security content for {component.name}: {e}")
            raise
    
    async def _generate_flow_security_content(
        self, 
        flow: Flow, 
        security_model: SecurityModel
    ) -> WikiSectionContent:
        """
        Generate flow-specific security analysis content for wiki
        """
        logger.info(f"Generating flow security content for: {flow.name}")
        
        try:
            prompt = self._create_flow_wiki_prompt(flow, security_model)
            
            response_content, metadata = await self.task_router.route_task(
                task_type=TaskType.THREAT_BRAINSTORMING,
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt()
            )
            
            content = self.response_parser.parse_for_wiki_section(response_content, "flow_analysis")
            
            # Extract flow-specific security findings
            security_findings = self._extract_security_findings_from_content(
                content, "flow", security_model, flow=flow
            )
            
            # Extract code references from flow components
            code_references = self._extract_code_references_for_flow(flow, security_model)
            
            return WikiSectionContent(
                title=f"Data Flow Analysis: {flow.name}",
                content=content,
                cross_references=self._extract_cross_references(content),
                owasp_mappings=["Data_Flow_Security", "STRIDE"],
                code_snippets=code_references,
                recommendations=self._extract_recommendations_from_content(content)
            )
            
        except Exception as e:
            logger.error(f"Failed to generate flow security content for {flow.name}: {e}")
            raise
    
    async def _generate_system_overview_content(self, security_model: SecurityModel) -> WikiSectionContent:
        """
        Generate system overview content for wiki
        """
        logger.info("Generating system overview content for wiki")
        
        try:
            prompt = self._create_system_overview_wiki_prompt(security_model)
            
            response_content, metadata = await self.task_router.route_task(
                task_type=TaskType.COMPONENT_ANALYSIS,
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt()
            )
            
            content = self.response_parser.parse_for_wiki_section(response_content, "system_overview")
            
            # Extract high-level security findings
            security_findings = self._extract_security_findings_from_content(
                content, "system", security_model
            )
            
            code_references = self._extract_code_references_for_overview(security_model)
            
            return WikiSectionContent(
                title="System Security Overview",
                content=content,
                cross_references=self._extract_cross_references(content),
                owasp_mappings=["System_Architecture", "Security_Design"],
                code_snippets=code_references,
                recommendations=self._extract_recommendations_from_content(content)
            )
            
        except Exception as e:
            logger.error(f"Failed to generate system overview content: {e}")
            raise
    
    async def _generate_mitigations_content(self, security_model: SecurityModel) -> WikiSectionContent:
        """
        Generate mitigations and recommendations content for wiki
        """
        logger.info("Generating mitigations content for wiki")
        
        try:
            prompt = self._create_mitigations_wiki_prompt(security_model)
            
            response_content, metadata = await self.task_router.route_task(
                task_type=TaskType.MITIGATION_RECOMMENDATIONS,
                prompt=prompt,
                system_prompt=self._get_wiki_system_prompt()
            )
            
            content = self.response_parser.parse_for_wiki_section(response_content, "mitigations")
            
            # Extract mitigation-focused security findings
            security_findings = self._extract_security_findings_from_content(
                content, "mitigation", security_model
            )
            
            code_references = self._extract_code_references_for_mitigations(security_model)
            
            return WikiSectionContent(
                title="Security Controls & Mitigations",
                content=content,
                cross_references=self._extract_cross_references(content),
                owasp_mappings=["Security_Controls", "ASVS", "Mitigations"],
                code_snippets=code_references,
                recommendations=self._extract_recommendations_from_content(content)
            )
            
        except Exception as e:
            logger.error(f"Failed to generate mitigations content: {e}")
            raise
    
    def _get_wiki_system_prompt(self) -> str:
        """Get system prompt optimized for wiki content generation"""
        return """You are a security expert generating content for a comprehensive security wiki. 
Your task is to create well-structured, interconnected security documentation that will be part of a larger security knowledge base.

Key principles:
- Write content that flows naturally and can be cross-referenced with other wiki sections
- Use clear, professional language suitable for security documentation
- Include specific, actionable recommendations
- Reference OWASP guidelines and standards where applicable
- Structure content with clear headings and bullet points for easy navigation
- Focus on practical security insights that help developers and security teams

Format your response in clean markdown that will integrate seamlessly into a wiki structure."""
    
    # Helper methods for prompt creation - wiki-compatible content generation methods
    def _create_stride_wiki_prompt(self, security_model: SecurityModel) -> str:
        """Create STRIDE analysis prompt optimized for wiki format"""
        
        components_summary = "\n".join([
            f"- {comp.name} ({comp.type.value}): {comp.description or 'Security-relevant component'}"
            for comp in security_model.components[:8]  # Limit to avoid token overflow
        ])
        
        flows_summary = "\n".join([
            f"- {flow.name} ({flow.flow_type.value}): {flow.data_sensitivity.value} sensitivity, "
            f"{len(flow.trust_boundary_crossings)} boundary crossings"
            for flow in security_model.flows[:5]
        ])
        
        auth_mechanisms = ", ".join(security_model.security_patterns.authentication_mechanisms[:5])
        
        return f"""Generate a comprehensive STRIDE-based threat landscape analysis for this security wiki section.

## System Context
### Components
{components_summary}

### Data Flows
{flows_summary}

### Security Patterns
- Authentication: {auth_mechanisms}
- Authorization: {', '.join(security_model.security_patterns.authorization_patterns[:3])}
- Input Validation: {', '.join(security_model.security_patterns.input_validation_patterns[:3])}

### Trust Boundaries
{len(security_model.trust_boundaries)} trust boundaries identified across the system

Create a **Threat Landscape Analysis** wiki section that includes:

## STRIDE Threat Categories

### Spoofing Threats
- Identity verification weaknesses across components
- Authentication bypass opportunities in flows
- Impersonation risks at trust boundaries
- Component-specific spoofing vectors

### Tampering Threats  
- Data integrity vulnerabilities in flows
- Message modification risks between components
- Parameter tampering opportunities at endpoints
- File/database tampering possibilities

### Repudiation Threats
- Logging and audit gaps across the system
- Non-repudiation weaknesses in critical flows
- Evidence preservation issues
- Transaction integrity concerns

### Information Disclosure Threats
- Data leakage opportunities in components
- Unauthorized access risks in flows
- Information inference attacks
- Sensitive data exposure vectors

### Denial of Service Threats
- Resource exhaustion vulnerabilities
- Availability disruption risks per component
- Performance degradation attack vectors
- System bottlenecks and failure points

### Elevation of Privilege Threats
- Authorization bypass opportunities
- Privilege escalation risks in components
- Access control weaknesses in flows
- Administrative function abuse

## Cross-Component Threat Analysis
- Threats that span multiple components
- Inter-service communication risks
- Trust boundary violation scenarios
- Cascading failure possibilities

## Risk Prioritization
- High-impact, high-likelihood threats
- Critical system vulnerabilities
- Immediate attention required threats

Format as clear, well-structured markdown suitable for a security wiki. Focus on actionable threat intelligence that security teams can use for risk assessment and mitigation planning."""
    
    def _create_owasp_top10_wiki_prompt(self, security_model: SecurityModel) -> str:
        """Create OWASP Top 10 analysis prompt optimized for wiki format"""
        
        endpoints_summary = []
        for comp in security_model.components[:5]:
            if comp.endpoints:
                for ep in comp.endpoints[:2]:  # Limit endpoints per component
                    endpoints_summary.append(
                        f"- {ep.method} {ep.path} (Component: {comp.name}, "
                        f"Auth: {'Yes' if ep.requires_auth else 'No'}, "
                        f"Sensitive: {'Yes' if ep.sensitive_data else 'No'})"
                    )
        
        endpoints_info = "\n".join(endpoints_summary[:10])  # Limit total endpoints
        
        data_stores_info = "\n".join([
            f"- {ds.name} ({ds.type.value}): {', '.join(ds.sensitive_data_types[:3])}"
            for ds in security_model.data_stores[:5]
        ])
        
        return f"""Generate a comprehensive OWASP Top 10 vulnerability analysis for this security wiki section.

## System Attack Surface
### API Endpoints
{endpoints_info if endpoints_info.strip() else 'No endpoints detected'}

### Data Stores
{data_stores_info if data_stores_info.strip() else 'No data stores detected'}

### Security Patterns
- Authentication: {', '.join(security_model.security_patterns.authentication_mechanisms[:3])}
- Authorization: {', '.join(security_model.security_patterns.authorization_patterns[:3])}
- Input Validation: {', '.join(security_model.security_patterns.input_validation_patterns[:3])}
- Encryption: {', '.join(security_model.security_patterns.encryption_usage[:3])}

Create a **Vulnerability Analysis (OWASP Top 10)** wiki section that includes:

## OWASP Top 10 2021 Analysis

### A01:2021 – Broken Access Control
- Access control implementation analysis
- Authorization bypass opportunities
- Privilege escalation risks
- Component-specific access control issues

### A02:2021 – Cryptographic Failures
- Encryption implementation review
- Data protection in transit and at rest
- Key management practices
- Cryptographic algorithm usage

### A03:2021 – Injection
- SQL injection vulnerabilities
- Command injection risks
- LDAP/NoSQL injection possibilities
- Input validation effectiveness

### A04:2021 – Insecure Design
- Security design flaws
- Threat modeling gaps
- Secure development practices
- Architecture security weaknesses

### A05:2021 – Security Misconfiguration
- Default configuration issues
- Unnecessary features enabled
- Security header analysis
- Error handling and information disclosure

### A06:2021 – Vulnerable and Outdated Components
- Third-party dependency analysis
- Known vulnerability assessment
- Component update practices
- Supply chain security

### A07:2021 – Identification and Authentication Failures
- Authentication mechanism analysis
- Session management review
- Multi-factor authentication implementation
- Password policy and storage

### A08:2021 – Software and Data Integrity Failures
- Code integrity verification
- Data integrity protection
- CI/CD pipeline security
- Update mechanism security

### A09:2021 – Security Logging and Monitoring Failures
- Logging implementation analysis
- Monitoring coverage assessment
- Incident detection capabilities
- Audit trail completeness

### A10:2021 – Server-Side Request Forgery (SSRF)
- SSRF vulnerability assessment
- URL validation implementation
- Network segmentation effectiveness
- External service interaction security

## Vulnerability Risk Matrix
- Critical vulnerabilities requiring immediate attention
- High-risk issues for near-term remediation
- Medium and low-risk findings for planning

## Component-Specific Vulnerabilities
- Per-component vulnerability analysis
- Endpoint-specific security issues
- Data flow vulnerability assessment

Format as comprehensive, actionable markdown suitable for a security wiki. Include specific examples and remediation guidance where applicable."""
    
    def _create_component_wiki_prompt(self, component: Component, security_model: SecurityModel) -> str:
        """Create component analysis prompt optimized for wiki format"""
        
        endpoints_info = "\n".join([
            f"- {ep.method} {ep.path} (Auth: {'Yes' if ep.requires_auth else 'No'}, "
            f"Sensitive: {'Yes' if ep.sensitive_data else 'No'}, "
            f"Handler: {ep.handler_function or 'Unknown'})"
            for ep in component.endpoints[:8]
        ])
        
        dependencies_info = "\n".join([f"- {dep}" for dep in component.dependencies[:8]])
        
        # Find flows involving this component
        related_flows = [
            flow for flow in security_model.flows 
            if component.id in flow.components_involved
        ][:3]
        
        flows_info = "\n".join([
            f"- {flow.name} ({flow.flow_type.value}): {flow.data_sensitivity.value} sensitivity"
            for flow in related_flows
        ])
        
        return f"""Generate a detailed component security analysis for this security wiki section.

## Component Details
- **Name**: {component.name}
- **Type**: {component.type.value}
- **File Path**: {component.file_path}
- **Handles Sensitive Data**: {'Yes' if component.handles_sensitive_data else 'No'}
- **Authentication Mechanisms**: {', '.join(component.auth_mechanisms) if component.auth_mechanisms else 'None detected'}

## Endpoints
{endpoints_info if endpoints_info.strip() else 'No endpoints detected'}

## Dependencies
{dependencies_info if dependencies_info.strip() else 'No dependencies detected'}

## Related Data Flows
{flows_info if flows_info.strip() else 'No related flows detected'}

Create a **Component Security Analysis: {component.name}** wiki section that includes:

## Component Overview
- Purpose and functionality within the system
- Role in overall security architecture
- Key responsibilities and capabilities
- Integration points with other components

## Security Profile
- Authentication and authorization mechanisms
- Input validation and sanitization approach
- Output encoding and data protection
- Error handling and logging practices

## Attack Surface Analysis
- Exposed interfaces and endpoints
- Input vectors and validation points
- Potential entry points for attackers
- Trust boundaries and security controls

## Threat Assessment
- Component-specific threats (STRIDE analysis)
- Vulnerability patterns and risks
- Potential impact of compromise
- Cascading failure scenarios

## Security Controls
- Implemented security measures
- Access control mechanisms
- Data protection controls
- Monitoring and logging capabilities

## Risk Analysis
- Security risk level assessment
- Critical vulnerabilities identified
- Potential business impact
- Likelihood of successful attacks

## Recommendations
- Immediate security improvements needed
- Long-term security enhancements
- Configuration recommendations
- Monitoring and alerting suggestions

## Cross-References
- Related components and dependencies
- Relevant data flows and trust boundaries
- Applicable OWASP guidelines and standards
- Related security policies and procedures

Format as detailed, actionable markdown suitable for a security wiki. Focus on practical security insights that help developers and security teams understand and secure this component."""
    
    def _create_flow_wiki_prompt(self, flow: Flow, security_model: SecurityModel) -> str:
        """Create flow analysis prompt optimized for wiki format"""
        
        steps_info = "\n".join([
            f"{step.step_number}. {step.description} (Component: {step.component_id})"
            + (f" - **Trust Boundary Crossing**: {step.trust_boundary_crossing}" if step.trust_boundary_crossing else "")
            + (f" - **Data Processed**: {', '.join(step.data_processed[:3])}" if step.data_processed else "")
            for step in flow.steps[:8]
        ])
        
        # Get component details for involved components
        involved_components = []
        for comp_id in flow.components_involved[:5]:
            comp = next((c for c in security_model.components if c.id == comp_id), None)
            if comp:
                involved_components.append(f"- {comp.name} ({comp.type.value}) - {comp.file_path}")
        
        components_info = "\n".join(involved_components)
        
        return f"""Generate a comprehensive data flow security analysis for this security wiki section.

## Flow Details
- **Name**: {flow.name}
- **Type**: {flow.flow_type.value}
- **Data Sensitivity**: {flow.data_sensitivity.value}
- **Trust Boundary Crossings**: {len(flow.trust_boundary_crossings)} boundaries crossed
- **Description**: {flow.description or 'No description provided'}

## Flow Steps
{steps_info}

## Involved Components
{components_info}

## Trust Boundaries
{len(flow.trust_boundary_crossings)} trust boundaries are crossed in this flow

Create a **Data Flow Security Analysis: {flow.name}** wiki section that includes:

## Flow Overview
- Business purpose and context
- Trigger conditions and frequency
- Success and failure scenarios
- Data transformation and processing

## Data Flow Diagram Analysis
- Step-by-step data movement description
- Component interaction patterns
- Trust boundary crossing points
- Data validation and transformation points

## Security Architecture
- Authentication requirements at each step
- Authorization checks and access controls
- Data encryption and protection measures
- Input validation and output encoding

## Threat Analysis (STRIDE)
### Spoofing Threats
- Identity verification weaknesses in the flow
- Authentication bypass opportunities
- Impersonation risks at each step

### Tampering Threats
- Data integrity vulnerabilities during transit
- Message modification opportunities
- Parameter tampering risks

### Repudiation Threats
- Logging and audit gaps in the flow
- Non-repudiation weaknesses
- Evidence preservation issues

### Information Disclosure Threats
- Data leakage opportunities
- Unauthorized access risks
- Information inference possibilities

### Denial of Service Threats
- Resource exhaustion vulnerabilities
- Availability disruption risks
- Performance bottlenecks

### Elevation of Privilege Threats
- Authorization bypass opportunities
- Privilege escalation risks
- Access control weaknesses

## Trust Boundary Analysis
- Security controls at each boundary
- Data validation and sanitization
- Authentication and authorization requirements
- Potential boundary violation scenarios

## Risk Assessment
- Flow-specific risk level
- Critical security controls required
- Potential business impact of compromise
- Likelihood assessment

## Security Requirements
- Authentication and authorization needs
- Data protection requirements
- Logging and monitoring needs
- Input validation specifications

## Recommendations
- Immediate security improvements
- Long-term security enhancements
- Monitoring and alerting requirements
- Testing and validation needs

## Cross-References
- Related components and their security profiles
- Other flows with similar security requirements
- Applicable OWASP guidelines and standards
- Related security controls and mitigations

Format as comprehensive, actionable markdown suitable for a security wiki. Focus on practical security insights for securing this specific data flow."""
    
    def _create_system_overview_wiki_prompt(self, security_model: SecurityModel) -> str:
        """Create system overview prompt optimized for wiki format"""
        
        components_summary = "\n".join([
            f"- **{comp.name}** ({comp.type.value}): "
            f"{'Handles sensitive data' if comp.handles_sensitive_data else 'Standard component'}, "
            f"{len(comp.endpoints)} endpoints, "
            f"Auth: {', '.join(comp.auth_mechanisms[:2]) if comp.auth_mechanisms else 'None'}"
            for comp in security_model.components[:8]
        ])
        
        data_stores_summary = "\n".join([
            f"- **{ds.name}** ({ds.type.value}): {', '.join(ds.sensitive_data_types[:3])}"
            for ds in security_model.data_stores[:5]
        ])
        
        flows_summary = "\n".join([
            f"- **{flow.name}** ({flow.flow_type.value}): {flow.data_sensitivity.value} sensitivity, "
            f"{len(flow.components_involved)} components, {len(flow.trust_boundary_crossings)} boundaries"
            for flow in security_model.flows[:5]
        ])
        
        return f"""Generate a comprehensive system security overview for this security wiki.

## System Analysis Results
### Components ({len(security_model.components)} total)
{components_summary}

### Data Stores ({len(security_model.data_stores)} total)
{data_stores_summary if data_stores_summary.strip() else 'No data stores detected'}

### Data Flows ({len(security_model.flows)} total)
{flows_summary}

### Security Patterns Detected
- **Authentication**: {', '.join(security_model.security_patterns.authentication_mechanisms[:5])}
- **Authorization**: {', '.join(security_model.security_patterns.authorization_patterns[:3])}
- **Input Validation**: {', '.join(security_model.security_patterns.input_validation_patterns[:3])}
- **Encryption**: {', '.join(security_model.security_patterns.encryption_usage[:3])}
- **Logging**: {', '.join(security_model.security_patterns.logging_patterns[:3])}

### Trust Boundaries
{len(security_model.trust_boundaries)} trust boundaries identified across the system

Create a **System Security Overview** wiki section that includes:

## System Purpose and Architecture
- Application purpose and business context
- Key business functions and user types
- High-level system architecture
- Component relationships and dependencies

## Security Architecture Overview
- Overall security design approach
- Trust boundaries and security zones
- Authentication and authorization strategy
- Data protection and encryption approach

## Asset Inventory
- Critical data assets and sensitivity levels
- Key system components and their roles
- External dependencies and integrations
- High-value targets for attackers

## Attack Surface Analysis
- External-facing components and endpoints
- Input vectors and validation points
- Network exposure and access points
- Third-party integration risks

## Security Control Framework
- Implemented security controls by category
- Authentication and identity management
- Access control and authorization
- Data protection and encryption
- Logging, monitoring, and incident response

## Risk Profile
- Overall system risk assessment
- Critical security concerns
- High-priority vulnerabilities
- Compliance and regulatory considerations

## Security Governance
- Security policies and procedures
- Development security practices
- Change management and deployment security
- Security training and awareness

## Threat Landscape
- Primary threat actors and motivations
- Common attack vectors for this system type
- Industry-specific security concerns
- Emerging threats and vulnerabilities

## Compliance and Standards
- Applicable security standards (OWASP, NIST, etc.)
- Regulatory compliance requirements
- Industry best practices alignment
- Security certification considerations

## Cross-References
- Detailed component security analyses
- Specific threat and vulnerability assessments
- Security control implementation details
- Risk mitigation strategies and plans

Format as comprehensive, executive-level markdown suitable for a security wiki. Focus on providing a clear, high-level understanding of the system's security posture for both technical and non-technical stakeholders."""
    
    def _create_mitigations_wiki_prompt(self, security_model: SecurityModel) -> str:
        """Create mitigations prompt optimized for wiki format"""
        
        high_risk_components = [
            comp.name for comp in security_model.components 
            if comp.handles_sensitive_data or comp.endpoints or comp.auth_mechanisms
        ][:8]
        
        sensitive_flows = [
            flow.name for flow in security_model.flows
            if flow.data_sensitivity.value in ['confidential', 'restricted'] or flow.trust_boundary_crossings
        ][:5]
        
        return f"""Generate comprehensive security controls and mitigations for this security wiki section.

## System Security Context
### High-Risk Components
{', '.join(high_risk_components) if high_risk_components else 'No high-risk components identified'}

### Sensitive Data Flows
{', '.join(sensitive_flows) if sensitive_flows else 'No sensitive flows identified'}

### Current Security Patterns
- **Authentication**: {', '.join(security_model.security_patterns.authentication_mechanisms[:3])}
- **Authorization**: {', '.join(security_model.security_patterns.authorization_patterns[:3])}
- **Input Validation**: {', '.join(security_model.security_patterns.input_validation_patterns[:3])}
- **Encryption**: {', '.join(security_model.security_patterns.encryption_usage[:3])}
- **Logging**: {', '.join(security_model.security_patterns.logging_patterns[:3])}

### Trust Boundaries
{len(security_model.trust_boundaries)} trust boundaries requiring security controls

Create a **Security Controls & Mitigations** wiki section that includes:

## Executive Summary
- Overall security posture assessment
- Critical risks and immediate priorities
- Implementation roadmap and timeline
- Resource requirements and dependencies

## Security Control Framework

### Authentication Controls
- Multi-factor authentication implementation
- Password policy and management requirements
- Session management and timeout controls
- Identity verification and validation
- Single sign-on (SSO) integration considerations

### Authorization Controls
- Role-based access control (RBAC) implementation
- Attribute-based access control (ABAC) where needed
- Principle of least privilege enforcement
- Access review and certification processes
- Privileged access management (PAM)

### Input Validation and Data Protection
- Input validation and sanitization requirements
- Output encoding and XSS prevention
- SQL injection prevention measures
- Command injection protection
- Data validation at trust boundaries

### Cryptographic Controls
- Encryption requirements for data at rest
- Encryption requirements for data in transit
- Key management and rotation policies
- Digital signature and integrity protection
- Cryptographic algorithm standards

### Network Security Controls
- Network segmentation and isolation
- Firewall rules and access controls
- Intrusion detection and prevention
- VPN and secure communication channels
- Network monitoring and traffic analysis

### Application Security Controls
- Secure coding practices and standards
- Code review and static analysis requirements
- Dynamic application security testing (DAST)
- Dependency scanning and management
- Security configuration management

### Logging and Monitoring Controls
- Security event logging requirements
- Log aggregation and correlation
- Real-time monitoring and alerting
- Incident detection and response
- Audit trail and forensic capabilities

## Implementation Priorities

### Critical (Immediate - 0-30 days)
- High-impact, high-likelihood vulnerabilities
- Missing authentication controls
- Critical data protection gaps
- Immediate compliance requirements

### High (Short-term - 1-3 months)
- Important security controls
- Significant vulnerability remediation
- Enhanced monitoring capabilities
- Process improvements

### Medium (Medium-term - 3-6 months)
- Additional security enhancements
- Automation and tooling improvements
- Training and awareness programs
- Documentation and procedures

### Low (Long-term - 6-12 months)
- Advanced security capabilities
- Optimization and fine-tuning
- Emerging threat preparations
- Strategic security initiatives

## Component-Specific Mitigations
- Security controls for each high-risk component
- Endpoint-specific protection measures
- Data flow security requirements
- Integration point security controls

## Compliance and Standards Alignment
- OWASP ASVS requirement mappings
- Industry-specific compliance requirements
- Regulatory compliance considerations
- Security framework alignment (NIST, ISO 27001)

## Testing and Validation
- Security testing requirements and schedules
- Penetration testing scope and frequency
- Code review and static analysis processes
- Vulnerability assessment procedures
- Security control effectiveness validation

## Monitoring and Maintenance
- Ongoing security monitoring requirements
- Regular security assessment schedules
- Update and patch management processes
- Security metrics and KPIs
- Continuous improvement processes

## Risk Management
- Residual risk assessment and acceptance
- Risk mitigation strategies and timelines
- Business continuity and disaster recovery
- Incident response and recovery procedures
- Third-party risk management

## Cross-References
- Detailed threat and vulnerability analyses
- Component-specific security requirements
- Implementation guides and procedures
- Security policies and standards
- Training and awareness materials

Format as comprehensive, actionable markdown suitable for a security wiki. Focus on practical implementation guidance that security teams and developers can use to improve the system's security posture."""
    
    # Helper methods for content extraction and processing
    def _extract_cross_references(self, content: str) -> List[str]:
        """Extract potential cross-references from content"""
        cross_refs = []
        
        # Look for common security terms that might reference other sections
        reference_terms = [
            "authentication", "authorization", "component", "flow", "threat",
            "vulnerability", "mitigation", "control", "risk", "owasp"
        ]
        
        content_lower = content.lower()
        for term in reference_terms:
            if term in content_lower:
                cross_refs.append(term)
        
        return list(set(cross_refs))  # Remove duplicates
    
    def _extract_recommendations_from_content(self, content: str) -> List[str]:
        """Extract recommendations from generated content"""
        recommendations = []
        
        # Look for recommendation patterns in the content
        lines = content.split('\n')
        for line in lines:
            line_lower = line.lower().strip()
            if any(keyword in line_lower for keyword in ['recommend', 'should', 'must', 'implement']):
                if len(line.strip()) > 20:  # Avoid very short lines
                    recommendations.append(line.strip())
        
        return recommendations[:10]  # Limit to avoid overwhelming
    
    def _extract_security_findings_from_content(
        self, 
        content: str, 
        finding_type: str, 
        security_model: SecurityModel,
        component: Optional[Component] = None,
        flow: Optional[Flow] = None
    ) -> List[SecurityFinding]:
        """Extract security findings from generated content"""
        findings = []
        
        # This is a simplified extraction - in a real implementation,
        # you might use more sophisticated NLP or structured parsing
        content_lower = content.lower()
        
        # Look for severity indicators
        severity_keywords = {
            'critical': ['critical', 'severe', 'high risk'],
            'high': ['high', 'important', 'significant'],
            'medium': ['medium', 'moderate'],
            'low': ['low', 'minor', 'informational']
        }
        
        severity = 'medium'  # default
        for sev, keywords in severity_keywords.items():
            if any(keyword in content_lower for keyword in keywords):
                severity = sev
                break
        
        # Create a finding based on the content type
        finding = SecurityFinding(
            id=str(uuid.uuid4()),
            type=finding_type,
            severity=severity,
            description=f"Security analysis findings for {finding_type}",
            affected_components=[component.id] if component else [],
            recommendations=self._extract_recommendations_from_content(content)
        )
        
        findings.append(finding)
        return findings
    
    def _extract_code_references_for_threats(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract code references relevant to threat analysis"""
        references = []
        
        # Add references to high-risk components
        for component in security_model.components[:5]:
            if component.handles_sensitive_data or component.endpoints:
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=component.file_path,
                        line_start=1,
                        function_name=component.name,
                        code_snippet=f"Threat-relevant component: {component.name}"
                    )
                )
        
        return references
    
    def _extract_code_references_for_vulnerabilities(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract code references relevant to vulnerability analysis"""
        references = []
        
        # Add references to components with endpoints (potential attack surface)
        for component in security_model.components:
            if component.endpoints:
                for endpoint in component.endpoints[:3]:  # Limit per component
                    references.append(
                        CodeReference(
                            id=str(uuid.uuid4()),
                            file_path=component.file_path,
                            line_start=1,
                            function_name=endpoint.handler_function or f"{endpoint.method}_{endpoint.path}",
                            code_snippet=f"Endpoint: {endpoint.method} {endpoint.path}"
                        )
                    )
        
        return references[:10]  # Limit total references
    
    def _extract_code_references_for_flow(self, flow: Flow, security_model: SecurityModel) -> List[CodeReference]:
        """Extract code references for a specific flow"""
        references = []
        
        # Add references to components involved in the flow
        for component_id in flow.components_involved:
            component = next((c for c in security_model.components if c.id == component_id), None)
            if component:
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=component.file_path,
                        line_start=1,
                        function_name=component.name,
                        code_snippet=f"Flow component: {component.name}"
                    )
                )
        
        return references
    
    def _extract_code_references_for_overview(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract relevant code references for system overview"""
        references = []
        
        # Add references to key components
        for component in security_model.components[:5]:  # Limit to top 5 components
            if component.handles_sensitive_data or component.endpoints:
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=component.file_path,
                        line_start=1,
                        function_name=component.name,
                        code_snippet=f"Key component: {component.name}"
                    )
                )
        
        return references
    
    def _extract_code_references_for_mitigations(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract code references for mitigations document"""
        references = []
        
        # Add references to all security-relevant components
        for component in security_model.components:
            if (component.handles_sensitive_data or 
                component.auth_mechanisms or 
                component.endpoints):
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=component.file_path,
                        line_start=1,
                        function_name=component.name,
                        code_snippet=f"Security-relevant component: {component.name}"
                    )
                )
        
        return references[:20]  # Limit to avoid overwhelming the document
    
    async def close(self):
        """Close the threat analysis provider"""
        await self.llm_manager.close()