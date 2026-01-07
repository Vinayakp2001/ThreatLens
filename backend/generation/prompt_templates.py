"""
Prompt templates for the four threat modeling questions.

This module provides structured prompts that implement the OWASP threat modeling
methodology based on the four key questions:
1. What are we working on?
2. What can go wrong?
3. What are we going to do about it?
4. Did we do a good enough job?
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from ..models.system_model import System, Component, DataFlow
from ..models.threats import Threat, StrideCategory
from ..models.mitigations import Mitigation


@dataclass
class PromptContext:
    """Context information for prompt generation."""
    system: System
    threats: List[Threat] = None
    mitigations: List[Mitigation] = None
    owasp_references: List[str] = None
    technology_stack: List[str] = None


class FourQuestionsPrompts:
    """
    Structured prompts for the four threat modeling questions following OWASP methodology.
    """
    
    @staticmethod
    def what_are_we_working_on(context: PromptContext) -> str:
        """
        Generate prompt for "What are we working on?" - System modeling question.
        
        This prompt helps identify and document the system architecture, components,
        data flows, and trust boundaries.
        """
        system = context.system
        
        prompt = f"""# What are we working on?

## System Overview
You are analyzing the system: **{system.name}**

{system.description}

## System Components Analysis

### Identified Components ({len(system.components)} total):
"""
        
        for component in system.components:
            prompt += f"""
- **{component.name}** ({component.type.value})
  - Trust Level: {component.trust_level.value}
  - Interfaces: {len(component.interfaces)} endpoints
  - Description: {component.description}
"""
        
        prompt += f"""
### Data Stores ({len(system.data_stores)} total):
"""
        
        for data_store in system.data_stores:
            prompt += f"""
- **{data_store.name}** ({data_store.type.value})
  - Data Classification: {data_store.data_classification.value}
  - Encryption: {'Yes' if data_store.encrypted else 'No'}
  - Access Controls: {data_store.access_controls}
"""
        
        prompt += f"""
### Data Flows ({len(system.data_flows)} total):
"""
        
        for flow in system.data_flows:
            prompt += f"""
- **{flow.source} → {flow.destination}**
  - Protocol: {flow.protocol}
  - Data Classification: {flow.data_classification.value}
  - Authentication Required: {'Yes' if flow.authentication_required else 'No'}
"""
        
        prompt += f"""
### External Entities ({len(system.external_entities)} total):
"""
        
        for entity in system.external_entities:
            prompt += f"""
- **{entity.name}** ({entity.type.value})
  - Trust Level: {entity.trust_level.value}
  - Description: {entity.description}
"""
        
        prompt += f"""
### Trust Boundaries ({len(system.trust_boundaries)} total):
"""
        
        for boundary in system.trust_boundaries:
            prompt += f"""
- **{boundary.name}**
  - Type: {boundary.type.value}
  - Components: {', '.join(boundary.components)}
  - Security Controls: {', '.join(boundary.security_controls)}
"""
        
        if system.cloud_context:
            prompt += f"""
### Cloud Context
- **Provider**: {system.cloud_context.provider.value}
- **Deployment Model**: {system.cloud_context.deployment_model.value}
- **Services Used**: {', '.join(system.cloud_context.services_used)}
- **Compliance Requirements**: {', '.join(system.cloud_context.compliance_requirements)}
- **Data Residency**: {system.cloud_context.data_residency}
"""
        
        prompt += """
## Analysis Instructions

Based on this system architecture:

1. **Validate the system model** - Are all components, data flows, and trust boundaries correctly identified?
2. **Identify missing elements** - What components, data stores, or external entities might be missing?
3. **Verify trust boundaries** - Are the trust boundaries properly defined and do they make security sense?
4. **Check data classification** - Is the data classification appropriate for each data store and flow?
5. **Review cloud context** - Are cloud-specific security considerations properly captured?

## Key Questions to Address:
- What assets are we protecting?
- Who are the users and what are their roles?
- What are the entry and exit points?
- What data is processed, stored, and transmitted?
- What are the trust relationships between components?

Please provide a comprehensive analysis of this system model and suggest any improvements or missing elements.
"""
        
        return prompt
    
    @staticmethod
    def what_can_go_wrong(context: PromptContext) -> str:
        """
        Generate prompt for "What can go wrong?" - STRIDE threat identification.
        
        This prompt guides systematic threat identification using the STRIDE methodology.
        """
        system = context.system
        threats = context.threats or []
        
        prompt = f"""# What can go wrong?

## STRIDE Threat Analysis for {system.name}

We will systematically analyze potential threats using the STRIDE methodology:
- **S**poofing (Identity)
- **T**ampering (Data)
- **R**epudiation (Actions)
- **I**nformation Disclosure (Data)
- **D**enial of Service (Availability)
- **E**levation of Privilege (Authorization)

## Current System Context
"""
        
        # Add system summary
        prompt += f"""
### System Summary:
- Components: {len(system.components)}
- Data Stores: {len(system.data_stores)}
- Data Flows: {len(system.data_flows)}
- External Entities: {len(system.external_entities)}
- Trust Boundaries: {len(system.trust_boundaries)}
"""
        
        if threats:
            prompt += f"""
### Identified Threats ({len(threats)} total):
"""
            
            # Group threats by STRIDE category
            stride_groups = {}
            for threat in threats:
                category = threat.stride_category.value
                if category not in stride_groups:
                    stride_groups[category] = []
                stride_groups[category].append(threat)
            
            for category, category_threats in stride_groups.items():
                prompt += f"""
#### {category.upper()} Threats ({len(category_threats)}):
"""
                for threat in category_threats:
                    prompt += f"""
- **{threat.title}** (Risk: {threat.risk_score:.1f})
  - Likelihood: {threat.likelihood.value}
  - Impact: {threat.impact.value}
  - Description: {threat.description}
  - Affected Assets: {', '.join(threat.affected_assets)}
"""
        
        prompt += """
## STRIDE Analysis Framework

### Spoofing Threats
Analyze each component and external entity for identity spoofing risks:
- Can an attacker impersonate a legitimate user or system?
- Are authentication mechanisms sufficient?
- Can certificates, tokens, or credentials be forged?

**Focus Areas:**
- Authentication endpoints
- API keys and tokens
- User identity verification
- Service-to-service authentication

### Tampering Threats
Examine data integrity risks across all data flows and stores:
- Can data be modified in transit or at rest?
- Are integrity checks in place?
- Can configuration files be tampered with?

**Focus Areas:**
- Data transmission channels
- Database integrity
- Configuration files
- Log files and audit trails

### Repudiation Threats
Assess non-repudiation and audit trail completeness:
- Can users deny performing actions?
- Are all security-relevant actions logged?
- Can logs be tampered with or deleted?

**Focus Areas:**
- Audit logging
- Digital signatures
- Transaction records
- User action tracking

### Information Disclosure Threats
Identify data confidentiality risks:
- Can sensitive data be accessed by unauthorized parties?
- Are there information leakage vectors?
- Is data properly classified and protected?

**Focus Areas:**
- Data encryption
- Access controls
- Error messages
- Debug information
- Backup and archive security

### Denial of Service Threats
Analyze availability risks:
- Can the system be overwhelmed or crashed?
- Are there resource exhaustion vectors?
- Can critical services be disrupted?

**Focus Areas:**
- Resource limits
- Rate limiting
- Input validation
- Dependency failures
- Infrastructure resilience

### Elevation of Privilege Threats
Examine authorization and privilege escalation risks:
- Can users gain unauthorized access to resources?
- Are privilege boundaries properly enforced?
- Can administrative functions be accessed inappropriately?

**Focus Areas:**
- Role-based access control
- Administrative interfaces
- Privilege separation
- Input validation in privileged contexts

## Analysis Instructions

For each STRIDE category:

1. **Systematically examine each component** - Consider how each threat type could affect every system component
2. **Analyze data flows** - Consider threats that could affect data in transit
3. **Review trust boundaries** - Focus on threats that cross trust boundaries
4. **Consider attack vectors** - Think about realistic attack scenarios
5. **Assess likelihood and impact** - Evaluate the probability and business impact of each threat

## Key Questions for Each Threat:
- What is the attack vector?
- What are the prerequisites for this attack?
- What assets are affected?
- What is the potential business impact?
- How likely is this threat to be exploited?

Please provide a comprehensive STRIDE analysis identifying specific threats for this system.
"""
        
        return prompt
    
    @staticmethod
    def what_are_we_going_to_do_about_it(context: PromptContext) -> str:
        """
        Generate prompt for "What are we going to do about it?" - Mitigation and response planning.
        
        This prompt guides the development of appropriate responses to identified threats.
        """
        threats = context.threats or []
        mitigations = context.mitigations or []
        system = context.system
        
        prompt = f"""# What are we going to do about it?

## Threat Response Planning for {system.name}

Now that we've identified potential threats, we need to determine appropriate responses for each threat. The four main response strategies are:

1. **Mitigate** - Reduce the likelihood or impact of the threat
2. **Transfer** - Share or shift the risk (e.g., insurance, third-party services)
3. **Accept** - Acknowledge the risk and accept the consequences
4. **Avoid** - Eliminate the threat by removing the feature or changing the design

## Identified Threats Summary
"""
        
        if threats:
            # Group threats by risk level
            high_risk = [t for t in threats if t.risk_score >= 7.0]
            medium_risk = [t for t in threats if 4.0 <= t.risk_score < 7.0]
            low_risk = [t for t in threats if t.risk_score < 4.0]
            
            prompt += f"""
### Risk Distribution:
- **High Risk** (≥7.0): {len(high_risk)} threats
- **Medium Risk** (4.0-6.9): {len(medium_risk)} threats  
- **Low Risk** (<4.0): {len(low_risk)} threats

### High Priority Threats Requiring Immediate Attention:
"""
            
            for threat in sorted(high_risk, key=lambda t: t.risk_score, reverse=True):
                prompt += f"""
#### {threat.title} (Risk: {threat.risk_score:.1f})
- **STRIDE Category**: {threat.stride_category.value}
- **Description**: {threat.description}
- **Affected Assets**: {', '.join(threat.affected_assets)}
- **Attack Vectors**: {', '.join(threat.attack_vectors)}
- **Current Mitigations**: {len([m for m in mitigations if threat.id in getattr(m, 'threat_ids', [])])} identified
"""
        
        if mitigations:
            prompt += f"""
## Current Mitigation Strategies ({len(mitigations)} total):
"""
            
            # Group mitigations by category
            mitigation_groups = {}
            for mitigation in mitigations:
                category = mitigation.category.value
                if category not in mitigation_groups:
                    mitigation_groups[category] = []
                mitigation_groups[category].append(mitigation)
            
            for category, category_mitigations in mitigation_groups.items():
                prompt += f"""
### {category.title()} Controls ({len(category_mitigations)}):
"""
                for mitigation in category_mitigations:
                    prompt += f"""
- **{mitigation.title}** (Priority: {mitigation.priority.value})
  - Description: {mitigation.description}
  - OWASP References: {', '.join(mitigation.owasp_cheatsheet_ids)}
  - Implementation Effort: {mitigation.effort_estimate.value}
"""
        
        prompt += """
## Mitigation Planning Framework

### 1. Risk-Based Prioritization
For each identified threat, determine the appropriate response strategy:

**High Risk Threats (≥7.0):**
- **Primary Strategy**: Mitigate immediately
- **Secondary Strategy**: Consider design changes to avoid the threat
- **Timeline**: Implement before production deployment

**Medium Risk Threats (4.0-6.9):**
- **Primary Strategy**: Mitigate with reasonable controls
- **Secondary Strategy**: Accept with monitoring and incident response plans
- **Timeline**: Implement within next development cycle

**Low Risk Threats (<4.0):**
- **Primary Strategy**: Accept with documentation
- **Secondary Strategy**: Mitigate if low-cost solutions are available
- **Timeline**: Address in future iterations if resources permit

### 2. OWASP-Aligned Mitigation Categories

#### Preventive Controls
- Input validation and sanitization
- Authentication and authorization mechanisms
- Secure coding practices
- Encryption and data protection

#### Detective Controls
- Logging and monitoring
- Intrusion detection systems
- Security scanning and testing
- Audit trails and forensics

#### Corrective Controls
- Incident response procedures
- Backup and recovery systems
- Patch management processes
- Security update mechanisms

#### Compensating Controls
- Network segmentation
- Rate limiting and throttling
- Web application firewalls
- Runtime application self-protection (RASP)

### 3. Implementation Guidance

For each mitigation strategy, consider:

**Technical Implementation:**
- What specific security controls need to be implemented?
- What code changes are required?
- What infrastructure changes are needed?
- What third-party tools or services should be used?

**OWASP Cheat Sheet References:**
- Which OWASP cheat sheets provide relevant guidance?
- What specific recommendations should be followed?
- Are there code examples or implementation patterns to follow?

**Verification and Testing:**
- How will the effectiveness of the mitigation be verified?
- What security tests need to be implemented?
- What metrics will be used to measure success?

**Maintenance and Updates:**
- How will the mitigation be maintained over time?
- What processes are needed for updates and patches?
- How will effectiveness be monitored ongoing?

## Response Planning Instructions

For each threat, provide:

1. **Response Strategy** - Mitigate, Transfer, Accept, or Avoid
2. **Specific Mitigations** - Detailed technical controls to implement
3. **OWASP References** - Relevant cheat sheets and guidance
4. **Implementation Priority** - High, Medium, or Low based on risk
5. **Effort Estimate** - Development effort required (Low, Medium, High)
6. **Verification Method** - How to test the mitigation effectiveness
7. **Acceptance Criteria** - When the threat response is considered complete

## Key Considerations:
- Balance security with usability and performance
- Consider implementation costs vs. risk reduction
- Ensure mitigations don't introduce new vulnerabilities
- Plan for defense in depth with multiple layers of security
- Document all decisions and rationale for future reference

Please provide comprehensive response strategies for all identified threats, prioritized by risk level and aligned with OWASP best practices.
"""
        
        return prompt
    
    @staticmethod
    def did_we_do_good_enough_job(context: PromptContext) -> str:
        """
        Generate prompt for "Did we do a good enough job?" - Review and validation.
        
        This prompt guides the review and validation of the threat modeling process.
        """
        system = context.system
        threats = context.threats or []
        mitigations = context.mitigations or []
        
        prompt = f"""# Did we do a good enough job?

## Threat Modeling Review and Validation for {system.name}

This final question ensures our threat modeling process was thorough and effective. We need to validate that we've properly identified threats, planned appropriate responses, and haven't missed critical security considerations.

## Threat Modeling Completeness Assessment

### System Model Validation
"""
        
        prompt += f"""
**System Coverage:**
- Components Identified: {len(system.components)}
- Data Stores Mapped: {len(system.data_stores)}
- Data Flows Documented: {len(system.data_flows)}
- External Entities Cataloged: {len(system.external_entities)}
- Trust Boundaries Defined: {len(system.trust_boundaries)}

**Architecture Completeness Checklist:**
- [ ] All system components have been identified and documented
- [ ] All data stores and their sensitivity levels are mapped
- [ ] All data flows between components are documented
- [ ] All external entities and their trust levels are identified
- [ ] Trust boundaries are clearly defined and justified
- [ ] Cloud context and infrastructure dependencies are documented
- [ ] Entry and exit points are clearly identified
- [ ] Authentication and authorization mechanisms are mapped
"""
        
        if threats:
            # Calculate STRIDE coverage
            stride_categories = set(threat.stride_category for threat in threats)
            stride_coverage = len(stride_categories)
            
            prompt += f"""
### Threat Identification Validation

**STRIDE Coverage Analysis:**
- Total Threats Identified: {len(threats)}
- STRIDE Categories Covered: {stride_coverage}/6
- Categories: {', '.join([cat.value for cat in stride_categories])}

**Threat Distribution by Risk Level:**
"""
            
            high_risk = len([t for t in threats if t.risk_score >= 7.0])
            medium_risk = len([t for t in threats if 4.0 <= t.risk_score < 7.0])
            low_risk = len([t for t in threats if t.risk_score < 4.0])
            
            prompt += f"""
- High Risk (≥7.0): {high_risk} threats
- Medium Risk (4.0-6.9): {medium_risk} threats
- Low Risk (<4.0): {low_risk} threats

**STRIDE Completeness Checklist:**
- [ ] Spoofing threats analyzed for all authentication points
- [ ] Tampering threats considered for all data flows and stores
- [ ] Repudiation threats assessed for all user actions
- [ ] Information disclosure threats evaluated for all sensitive data
- [ ] Denial of service threats examined for all critical services
- [ ] Elevation of privilege threats analyzed for all authorization boundaries
"""
        
        if mitigations:
            mitigation_coverage = len([m for m in mitigations if m.priority.value in ['High', 'Critical']])
            
            prompt += f"""
### Mitigation Planning Validation

**Response Strategy Coverage:**
- Total Mitigations Planned: {len(mitigations)}
- High Priority Mitigations: {mitigation_coverage}
- OWASP-Aligned Controls: {len([m for m in mitigations if m.owasp_cheatsheet_ids])}

**Mitigation Completeness Checklist:**
- [ ] All high-risk threats have defined mitigation strategies
- [ ] Mitigation strategies are aligned with OWASP best practices
- [ ] Implementation priorities are based on risk levels
- [ ] Effort estimates are realistic and justified
- [ ] Verification methods are defined for each mitigation
- [ ] Defense-in-depth principles are applied
- [ ] Compensating controls are identified where needed
"""
        
        prompt += """
## Quality Assurance Framework

### 1. Threat Model Quality Criteria

**Accuracy:**
- Are the identified threats realistic and relevant to the system?
- Are threat descriptions clear and actionable?
- Are risk assessments (likelihood × impact) justified?

**Completeness:**
- Have we covered all STRIDE categories systematically?
- Are all system components analyzed for threats?
- Are all trust boundary crossings examined?

**Consistency:**
- Are threat classifications consistent across similar components?
- Are risk ratings applied consistently?
- Are mitigation strategies aligned with threat severity?

### 2. OWASP Methodology Compliance

**Four Questions Coverage:**
- [ ] "What are we working on?" - System model is complete and accurate
- [ ] "What can go wrong?" - STRIDE analysis is systematic and thorough
- [ ] "What are we going to do about it?" - Response strategies are appropriate and prioritized
- [ ] "Did we do a good enough job?" - Review process validates completeness and quality

**OWASP Best Practice Alignment:**
- [ ] Threat modeling follows OWASP Threat Modeling Cheat Sheet guidance
- [ ] Mitigations reference relevant OWASP cheat sheets
- [ ] Security controls align with OWASP ASVS requirements
- [ ] Implementation guidance follows OWASP secure coding practices

### 3. Stakeholder Review Validation

**Technical Review:**
- [ ] Architecture team has validated the system model
- [ ] Security team has reviewed threat identification and risk ratings
- [ ] Development team has assessed mitigation feasibility
- [ ] Operations team has reviewed monitoring and response requirements

**Business Review:**
- [ ] Business stakeholders understand the risk landscape
- [ ] Risk acceptance decisions are documented and approved
- [ ] Resource allocation for mitigations is approved
- [ ] Timeline for implementation is agreed upon

### 4. Continuous Improvement Assessment

**Process Effectiveness:**
- Did the threat modeling process identify previously unknown risks?
- Were stakeholders engaged effectively throughout the process?
- Are the outputs actionable and useful for development teams?
- Can the threat model be maintained and updated efficiently?

**Knowledge Gaps Identified:**
- What areas require additional security expertise?
- What tools or resources would improve the process?
- What training needs were identified during the process?

## Validation Checklist

### Critical Success Factors:
- [ ] **Comprehensive Coverage**: All system components, data flows, and trust boundaries analyzed
- [ ] **STRIDE Completeness**: All six threat categories systematically examined
- [ ] **Risk-Based Prioritization**: Threats prioritized by realistic risk assessments
- [ ] **Actionable Mitigations**: Response strategies are specific, feasible, and OWASP-aligned
- [ ] **Stakeholder Buy-in**: Technical and business stakeholders approve the analysis and responses
- [ ] **Maintainable Documentation**: Threat model can be updated as the system evolves

### Quality Gates:
1. **System Model Accuracy** (≥90% stakeholder agreement)
2. **Threat Coverage** (All STRIDE categories addressed)
3. **High-Risk Mitigation** (100% of high-risk threats have response strategies)
4. **OWASP Alignment** (All mitigations reference appropriate cheat sheets)
5. **Implementation Feasibility** (Development team confirms feasibility)

## Final Assessment Questions:

1. **Completeness**: Have we identified all significant threats to this system?
2. **Accuracy**: Are our threat assessments realistic and well-justified?
3. **Actionability**: Can development teams implement the recommended mitigations?
4. **Sustainability**: Can this threat model be maintained as the system evolves?
5. **Value**: Does this analysis provide actionable security improvements?

## Recommendations for Improvement:

Based on this review, provide specific recommendations for:
- Areas requiring additional analysis
- Process improvements for future threat modeling
- Tools or resources that would enhance effectiveness
- Training or knowledge gaps to address
- Timeline for threat model updates and reviews

Please conduct a thorough review using this framework and provide a final assessment of the threat modeling quality and completeness.
"""
        
        return prompt


class PromptTemplateManager:
    """
    Manager class for generating and customizing threat modeling prompts.
    """
    
    def __init__(self):
        self.four_questions = FourQuestionsPrompts()
    
    def generate_full_analysis_prompt(self, context: PromptContext) -> Dict[str, str]:
        """
        Generate all four question prompts for a complete threat modeling analysis.
        
        Args:
            context: PromptContext containing system, threats, and mitigations
            
        Returns:
            Dictionary with prompts for each of the four questions
        """
        return {
            "what_are_we_working_on": self.four_questions.what_are_we_working_on(context),
            "what_can_go_wrong": self.four_questions.what_can_go_wrong(context),
            "what_are_we_going_to_do_about_it": self.four_questions.what_are_we_going_to_do_about_it(context),
            "did_we_do_good_enough_job": self.four_questions.did_we_do_good_enough_job(context)
        }
    
    def generate_incremental_prompt(self, question: str, context: PromptContext) -> str:
        """
        Generate a prompt for a specific question in the threat modeling process.
        
        Args:
            question: One of the four threat modeling questions
            context: PromptContext with relevant information
            
        Returns:
            Formatted prompt string for the specified question
        """
        question_methods = {
            "what_are_we_working_on": self.four_questions.what_are_we_working_on,
            "what_can_go_wrong": self.four_questions.what_can_go_wrong,
            "what_are_we_going_to_do_about_it": self.four_questions.what_are_we_going_to_do_about_it,
            "did_we_do_good_enough_job": self.four_questions.did_we_do_good_enough_job
        }
        
        if question not in question_methods:
            raise ValueError(f"Unknown question: {question}. Must be one of: {list(question_methods.keys())}")
        
        return question_methods[question](context)
    
    def customize_prompt_for_technology(self, base_prompt: str, technology_stack: List[str]) -> str:
        """
        Customize a prompt based on the detected technology stack.
        
        Args:
            base_prompt: The base prompt to customize
            technology_stack: List of detected technologies
            
        Returns:
            Customized prompt with technology-specific guidance
        """
        tech_guidance = {
            "react": "Consider React-specific security concerns like XSS in JSX, state management security, and component prop validation.",
            "node.js": "Focus on Node.js vulnerabilities like prototype pollution, dependency vulnerabilities, and server-side injection attacks.",
            "python": "Consider Python-specific issues like pickle deserialization, SQL injection in ORMs, and template injection.",
            "docker": "Analyze container security including image vulnerabilities, runtime security, and container escape scenarios.",
            "kubernetes": "Examine Kubernetes security including RBAC, network policies, pod security standards, and secrets management.",
            "aws": "Consider AWS-specific threats including IAM misconfigurations, S3 bucket exposure, and service-specific vulnerabilities.",
            "database": "Focus on data security including SQL injection, data encryption, access controls, and backup security."
        }
        
        if not technology_stack:
            return base_prompt
        
        customization = "\n\n## Technology-Specific Considerations\n\n"
        
        for tech in technology_stack:
            tech_lower = tech.lower()
            for key, guidance in tech_guidance.items():
                if key in tech_lower:
                    customization += f"**{tech}**: {guidance}\n\n"
        
        return base_prompt + customization