"""
Prompt templates for threat modeling document generation aligned with OWASP standards
"""
from typing import Dict, Any, List
from .models import SecurityModel, Component, Flow


class PromptTemplates:
    """OWASP-aligned prompt templates for threat modeling document generation"""
    
    SYSTEM_PROMPT = """You are a security expert specializing in threat modeling and security documentation. 
Your task is to generate comprehensive, accurate threat modeling documentation following OWASP Threat Modeling Cheat Sheet guidelines.

Key principles:
- Follow STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- Reference OWASP ASVS (Application Security Verification Standard) where applicable
- Include specific CWE (Common Weakness Enumeration) references
- Provide actionable, implementable security recommendations
- Focus on realistic threats based on the actual system architecture
- Use clear, professional language suitable for security documentation

Always structure your responses in well-formatted markdown with clear sections and subsections."""
    
    @staticmethod
    def system_overview_prompt(security_model: SecurityModel) -> str:
        """Generate prompt for System Security Overview document"""
        
        components_summary = "\n".join([
            f"- {comp.name} ({comp.type.value}): {comp.description or 'No description'}"
            for comp in security_model.components[:10]  # Limit to avoid token overflow
        ])
        
        data_stores_summary = "\n".join([
            f"- {ds.name} ({ds.type.value}): Handles {', '.join(ds.sensitive_data_types[:3])}"
            for ds in security_model.data_stores[:5]
        ])
        
        flows_summary = "\n".join([
            f"- {flow.name} ({flow.flow_type.value}): {flow.data_sensitivity.value} sensitivity"
            for flow in security_model.flows[:5]
        ])
        
        auth_mechanisms = ", ".join(security_model.security_patterns.authentication_mechanisms[:5])
        
        return f"""Generate a comprehensive System Security Overview document for this application based on the following security model analysis:

## System Components
{components_summary}

## Data Stores
{data_stores_summary}

## Key Data Flows
{flows_summary}

## Detected Security Patterns
- Authentication: {auth_mechanisms}
- Authorization: {', '.join(security_model.security_patterns.authorization_patterns[:3])}
- Input Validation: {', '.join(security_model.security_patterns.input_validation_patterns[:3])}

## Trust Boundaries
{len(security_model.trust_boundaries)} trust boundaries identified

Please create a System Security Overview document that includes:

1. **System Purpose and Scope**
   - Brief description of the application's purpose
   - Key business functions and user types
   - System boundaries and external dependencies

2. **Architecture Overview**
   - High-level system architecture
   - Key components and their relationships
   - Data flow between major components

3. **Data Assets**
   - Critical data types handled by the system
   - Data sensitivity classifications
   - Data storage and processing locations

4. **External Dependencies**
   - Third-party services and APIs
   - External data sources
   - Integration points

5. **Trust Boundaries**
   - Identification of trust boundaries
   - Security controls at each boundary
   - Authentication and authorization mechanisms

6. **Security Controls Overview**
   - Existing security mechanisms
   - Authentication and authorization approach
   - Input validation and output encoding
   - Logging and monitoring capabilities

Format the document in clear markdown with appropriate headers and bullet points. Focus on security-relevant aspects and avoid implementation details."""
    
    @staticmethod
    def component_profile_prompt(component: Component, security_model: SecurityModel) -> str:
        """Generate prompt for Component Security Profile document"""
        
        endpoints_info = "\n".join([
            f"- {ep.method} {ep.path} (Auth: {'Yes' if ep.requires_auth else 'No'}, Sensitive: {'Yes' if ep.sensitive_data else 'No'})"
            for ep in component.endpoints[:10]
        ])
        
        dependencies_info = "\n".join([
            f"- {dep}" for dep in component.dependencies[:5]
        ])
        
        return f"""Generate a detailed Component Security Profile for the following component:

## Component Details
- **Name**: {component.name}
- **Type**: {component.type.value}
- **File Path**: {component.file_path}
- **Handles Sensitive Data**: {'Yes' if component.handles_sensitive_data else 'No'}
- **Authentication Mechanisms**: {', '.join(component.auth_mechanisms) if component.auth_mechanisms else 'None detected'}

## Endpoints (if applicable)
{endpoints_info if endpoints_info.strip() else 'No endpoints detected'}

## Dependencies
{dependencies_info if dependencies_info.strip() else 'No dependencies detected'}

Please create a Component Security Profile that includes:

1. **Component Overview**
   - Purpose and functionality
   - Role in the overall system
   - Key responsibilities

2. **Security Characteristics**
   - Authentication requirements
   - Authorization mechanisms
   - Input validation approach
   - Output encoding/sanitization

3. **Data Handling**
   - Types of data processed
   - Data sensitivity levels
   - Data transformation or storage

4. **Attack Surface**
   - Exposed endpoints or interfaces
   - Input vectors and validation points
   - Potential entry points for attackers

5. **Threat Analysis (STRIDE)**
   - **Spoofing**: Identity-related threats
   - **Tampering**: Data integrity threats
   - **Repudiation**: Non-repudiation concerns
   - **Information Disclosure**: Confidentiality threats
   - **Denial of Service**: Availability threats
   - **Elevation of Privilege**: Authorization bypass threats

6. **Security Recommendations**
   - Specific security controls to implement
   - Configuration recommendations
   - Monitoring and logging suggestions
   - References to OWASP ASVS requirements where applicable

Format as clear markdown with specific, actionable recommendations."""
    
    @staticmethod
    def flow_threat_model_prompt(flow: Flow, security_model: SecurityModel) -> str:
        """Generate prompt for Flow Threat Model document using STRIDE methodology"""
        
        steps_info = "\n".join([
            f"{step.step_number}. {step.description} (Component: {step.component_id})"
            + (f" - Crosses trust boundary: {step.trust_boundary_crossing}" if step.trust_boundary_crossing else "")
            for step in flow.steps[:10]
        ])
        
        involved_components = []
        for comp_id in flow.components_involved[:5]:
            comp = next((c for c in security_model.components if c.id == comp_id), None)
            if comp:
                involved_components.append(f"- {comp.name} ({comp.type.value})")
        
        components_info = "\n".join(involved_components)
        
        return f"""Generate a comprehensive Flow Threat Model using STRIDE methodology for the following data flow:

## Flow Details
- **Name**: {flow.name}
- **Type**: {flow.flow_type.value}
- **Data Sensitivity**: {flow.data_sensitivity.value}
- **Trust Boundary Crossings**: {len(flow.trust_boundary_crossings)} boundaries crossed

## Flow Steps
{steps_info}

## Involved Components
{components_info}

Please create a Flow Threat Model that includes:

1. **Flow Overview**
   - Purpose and business context
   - Trigger conditions and frequency
   - Success and failure scenarios

2. **Data Flow Diagram Description**
   - Step-by-step data movement
   - Component interactions
   - Trust boundary crossings
   - Data transformations

3. **STRIDE Threat Analysis**

   ### Spoofing Threats
   - Identity verification weaknesses
   - Authentication bypass opportunities
   - Impersonation risks
   - Specific threats and mitigations

   ### Tampering Threats
   - Data integrity vulnerabilities
   - Message modification risks
   - Parameter tampering opportunities
   - Specific threats and mitigations

   ### Repudiation Threats
   - Logging and audit gaps
   - Non-repudiation weaknesses
   - Evidence preservation issues
   - Specific threats and mitigations

   ### Information Disclosure Threats
   - Data leakage opportunities
   - Unauthorized access risks
   - Information inference attacks
   - Specific threats and mitigations

   ### Denial of Service Threats
   - Resource exhaustion vulnerabilities
   - Availability disruption risks
   - Performance degradation attacks
   - Specific threats and mitigations

   ### Elevation of Privilege Threats
   - Authorization bypass opportunities
   - Privilege escalation risks
   - Access control weaknesses
   - Specific threats and mitigations

4. **Risk Assessment**
   - Threat likelihood and impact ratings
   - Overall risk level for the flow
   - Critical security controls required

5. **Security Requirements**
   - Specific security controls needed
   - Implementation recommendations
   - Testing and validation requirements
   - OWASP ASVS requirement references

Format as detailed markdown with specific threat scenarios and actionable mitigations."""
    
    @staticmethod
    def mitigations_prompt(security_model: SecurityModel, identified_threats: List[str]) -> str:
        """Generate prompt for Mitigations & Requirements document"""
        
        threats_summary = "\n".join([f"- {threat}" for threat in identified_threats[:20]])
        
        high_risk_components = [
            comp.name for comp in security_model.components 
            if comp.handles_sensitive_data or comp.endpoints
        ][:10]
        
        return f"""Generate a comprehensive Mitigations & Requirements document based on the identified threats and security analysis:

## Identified Threats Summary
{threats_summary}

## High-Risk Components
{', '.join(high_risk_components)}

## System Security Patterns
- Authentication: {', '.join(security_model.security_patterns.authentication_mechanisms[:3])}
- Authorization: {', '.join(security_model.security_patterns.authorization_patterns[:3])}
- Input Validation: {', '.join(security_model.security_patterns.input_validation_patterns[:3])}

Please create a Mitigations & Requirements document that includes:

1. **Executive Summary**
   - Overall security posture assessment
   - Critical risks and priorities
   - Implementation roadmap overview

2. **Security Requirements by Category**

   ### Authentication Requirements
   - Multi-factor authentication requirements
   - Password policy and management
   - Session management controls
   - OWASP ASVS V2 references

   ### Authorization Requirements
   - Access control mechanisms
   - Role-based access control (RBAC)
   - Attribute-based access control (ABAC)
   - OWASP ASVS V4 references

   ### Input Validation Requirements
   - Input validation strategies
   - Output encoding requirements
   - SQL injection prevention
   - XSS prevention measures
   - OWASP ASVS V5 references

   ### Data Protection Requirements
   - Encryption at rest and in transit
   - Data classification and handling
   - Privacy protection measures
   - OWASP ASVS V7 and V9 references

   ### Logging and Monitoring Requirements
   - Security event logging
   - Monitoring and alerting
   - Incident response preparation
   - OWASP ASVS V7 references

3. **Implementation Priorities**
   - Critical (implement immediately)
   - High (implement within 3 months)
   - Medium (implement within 6 months)
   - Low (implement within 12 months)

4. **Specific Mitigations by Threat Category**
   - STRIDE-based mitigation strategies
   - Technical implementation details
   - Configuration recommendations
   - Third-party tool recommendations

5. **Compliance and Standards**
   - OWASP ASVS requirement mappings
   - CWE references for identified weaknesses
   - Industry-specific compliance considerations

6. **Testing and Validation**
   - Security testing requirements
   - Penetration testing scope
   - Code review guidelines
   - Automated security testing integration

7. **Monitoring and Maintenance**
   - Ongoing security monitoring
   - Regular security assessments
   - Update and patch management
   - Security metrics and KPIs

Format as actionable markdown with specific implementation guidance and priority levels."""
    
    @staticmethod
    def get_prompt_for_doc_type(
        doc_type: str,
        security_model: SecurityModel,
        component: Component = None,
        flow: Flow = None,
        identified_threats: List[str] = None
    ) -> str:
        """Get the appropriate prompt based on document type"""
        
        if doc_type == "system_overview":
            return PromptTemplates.system_overview_prompt(security_model)
        
        elif doc_type == "component_profile":
            if not component:
                raise ValueError("Component required for component profile generation")
            return PromptTemplates.component_profile_prompt(component, security_model)
        
        elif doc_type == "flow_threat_model":
            if not flow:
                raise ValueError("Flow required for flow threat model generation")
            return PromptTemplates.flow_threat_model_prompt(flow, security_model)
        
        elif doc_type == "mitigation":
            if not identified_threats:
                identified_threats = []
            return PromptTemplates.mitigations_prompt(security_model, identified_threats)
        
        else:
            raise ValueError(f"Unsupported document type: {doc_type}")


class ResponseParser:
    """Parser for LLM responses with validation"""
    
    @staticmethod
    def parse_threat_document(response_content: str, doc_type: str) -> Dict[str, Any]:
        """Parse and validate LLM response for threat document"""
        
        # Basic validation - ensure we have content
        if not response_content or len(response_content.strip()) < 100:
            raise ValueError("Generated content is too short or empty")
        
        # Extract title from first header if present
        lines = response_content.split('\n')
        title = None
        for line in lines[:10]:  # Check first 10 lines for title
            if line.startswith('# '):
                title = line[2:].strip()
                break
        
        if not title:
            # Generate default title based on doc type
            title_map = {
                "system_overview": "System Security Overview",
                "component_profile": "Component Security Profile",
                "flow_threat_model": "Flow Threat Model",
                "mitigation": "Security Mitigations & Requirements"
            }
            title = title_map.get(doc_type, "Threat Modeling Document")
        
        # Validate content structure based on document type
        required_sections = {
            "system_overview": ["purpose", "architecture", "data", "security"],
            "component_profile": ["overview", "security", "threat", "recommendation"],
            "flow_threat_model": ["flow", "stride", "threat", "mitigation"],
            "mitigation": ["requirement", "mitigation", "implementation"]
        }
        
        content_lower = response_content.lower()
        missing_sections = []
        
        for section in required_sections.get(doc_type, []):
            if section not in content_lower:
                missing_sections.append(section)
        
        metadata = {
            "validation_status": "valid" if not missing_sections else "partial",
            "missing_sections": missing_sections,
            "content_length": len(response_content),
            "has_title": title is not None
        }
        
        return {
            "title": title,
            "content": response_content,
            "metadata": metadata
        }