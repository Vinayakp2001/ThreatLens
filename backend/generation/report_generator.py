"""
Report generator for creating threat modeling documentation.

This module generates various types of security documentation including:
- PR security summaries using the four questions structure
- Per-component threat model documentation
- Comprehensive system threat models with OWASP references
"""

import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path

from ..models.system_model import System, Component, DataStore, DataFlow
from ..models.threats import Threat, StrideCategory
from ..models.mitigations import Mitigation
from .prompt_templates import PromptContext


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    output_directory: str = "docs/security"
    include_owasp_references: bool = True
    include_code_references: bool = True
    include_diagrams: bool = True
    format_style: str = "github"  # github, confluence, html


class ThreatModelReportGenerator:
    """
    Generates comprehensive threat modeling reports and documentation.
    """
    
    def __init__(self, config: ReportConfig = None):
        self.config = config or ReportConfig()
    
    def generate_pr_security_summary(
        self,
        pr_info: Dict[str, Any],
        system: System,
        threats: List[Threat],
        mitigations: List[Mitigation]
    ) -> str:
        """
        Generate a security summary for a pull request using the four questions structure.
        
        Args:
            pr_info: Dictionary containing PR metadata (title, description, files_changed, etc.)
            system: System model for the changes
            threats: List of identified threats
            mitigations: List of planned mitigations
            
        Returns:
            Markdown-formatted security summary
        """
        pr_title = pr_info.get('title', 'Unknown PR')
        pr_number = pr_info.get('number', 'N/A')
        files_changed = pr_info.get('files_changed', [])
        
        report = f"""# Security Analysis Summary

**Pull Request**: #{pr_number} - {pr_title}
**Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Files Changed**: {len(files_changed)} files

## Executive Summary

This security analysis follows the OWASP threat modeling methodology to assess the security implications of the proposed changes.

"""
        
        # Risk summary
        high_risk_threats = [t for t in threats if t.risk_score >= 7.0]
        medium_risk_threats = [t for t in threats if 4.0 <= t.risk_score < 7.0]
        low_risk_threats = [t for t in threats if t.risk_score < 4.0]
        
        report += f"""### Risk Assessment
- **High Risk**: {len(high_risk_threats)} threats requiring immediate attention
- **Medium Risk**: {len(medium_risk_threats)} threats requiring mitigation
- **Low Risk**: {len(low_risk_threats)} threats for monitoring

"""
        
        if high_risk_threats:
            report += "⚠️ **Action Required**: This PR introduces high-risk security concerns that must be addressed before merging.\n\n"
        elif medium_risk_threats:
            report += "⚡ **Review Recommended**: This PR introduces moderate security risks that should be mitigated.\n\n"
        else:
            report += "✅ **Low Risk**: This PR introduces minimal security concerns.\n\n"
        
        # Four Questions Analysis
        report += """## Four Questions Analysis

Following the OWASP threat modeling methodology:

### 1. What are we working on?

"""
        
        # System changes summary
        report += f"""#### Changes Overview
- **Components Modified**: {len([c for c in system.components if any(f in c.name.lower() for f in [f.lower() for f in files_changed])])}
- **New Data Flows**: {len([df for df in system.data_flows if 'new' in df.source.lower() or 'new' in df.destination.lower()])}
- **Trust Boundary Changes**: {len(system.trust_boundaries)} boundaries affected

"""
        
        # List key components
        if system.components:
            report += "#### Key Components:\n"
            for component in system.components[:5]:  # Limit to top 5
                report += f"- **{component.name}** ({component.type.value}) - Trust Level: {component.trust_level.value}\n"
            if len(system.components) > 5:
                report += f"- ... and {len(system.components) - 5} more components\n"
            report += "\n"
        
        report += """### 2. What can go wrong?

"""
        
        if threats:
            # Group threats by STRIDE category
            stride_groups = {}
            for threat in threats:
                category = threat.stride_category.value
                if category not in stride_groups:
                    stride_groups[category] = []
                stride_groups[category].append(threat)
            
            report += "#### Identified Threats by STRIDE Category:\n\n"
            
            for category, category_threats in stride_groups.items():
                report += f"**{category.upper()}** ({len(category_threats)} threats):\n"
                
                # Show top 3 threats per category
                sorted_threats = sorted(category_threats, key=lambda t: t.risk_score, reverse=True)
                for threat in sorted_threats[:3]:
                    risk_emoji = "🔴" if threat.risk_score >= 7.0 else "🟡" if threat.risk_score >= 4.0 else "🟢"
                    report += f"- {risk_emoji} **{threat.title}** (Risk: {threat.risk_score:.1f})\n"
                    report += f"  - {threat.description}\n"
                
                if len(category_threats) > 3:
                    report += f"  - ... and {len(category_threats) - 3} more {category} threats\n"
                report += "\n"
        else:
            report += "No significant threats identified for this change set.\n\n"
        
        report += """### 3. What are we going to do about it?

"""
        
        if mitigations:
            # Group mitigations by priority
            high_priority = [m for m in mitigations if m.priority.value in ['Critical', 'High']]
            medium_priority = [m for m in mitigations if m.priority.value == 'Medium']
            low_priority = [m for m in mitigations if m.priority.value == 'Low']
            
            if high_priority:
                report += "#### Immediate Actions Required:\n"
                for mitigation in high_priority:
                    report += f"- **{mitigation.title}** (Priority: {mitigation.priority.value})\n"
                    report += f"  - {mitigation.description}\n"
                    if mitigation.owasp_cheatsheet_ids:
                        report += f"  - OWASP References: {', '.join(mitigation.owasp_cheatsheet_ids)}\n"
                report += "\n"
            
            if medium_priority:
                report += "#### Recommended Mitigations:\n"
                for mitigation in medium_priority:
                    report += f"- **{mitigation.title}**\n"
                    report += f"  - {mitigation.description}\n"
                report += "\n"
            
            if low_priority:
                report += f"#### Future Considerations: {len(low_priority)} additional mitigations identified for future implementation.\n\n"
        else:
            report += "No specific mitigations required for the identified risks.\n\n"
        
        report += """### 4. Did we do a good enough job?

"""
        
        # Review checklist
        report += """#### Security Review Checklist:
- [ ] All high-risk threats have defined mitigation strategies
- [ ] Code changes follow secure coding practices
- [ ] Input validation is implemented where needed
- [ ] Authentication and authorization are properly handled
- [ ] Sensitive data is protected appropriately
- [ ] Error handling doesn't leak sensitive information
- [ ] Logging captures security-relevant events

"""
        
        # Recommendations
        if high_risk_threats:
            report += """#### Recommendations:
1. **Do not merge** until high-risk threats are mitigated
2. Implement the immediate actions listed above
3. Conduct additional security testing
4. Consider security architecture review

"""
        elif medium_risk_threats:
            report += """#### Recommendations:
1. Address medium-risk threats before or shortly after merge
2. Implement recommended mitigations
3. Monitor for security events post-deployment
4. Schedule follow-up security review

"""
        else:
            report += """#### Recommendations:
1. Proceed with merge after standard code review
2. Monitor for any unexpected security events
3. Consider the future considerations for next iteration

"""
        
        # OWASP references
        if self.config.include_owasp_references:
            owasp_refs = set()
            for mitigation in mitigations:
                owasp_refs.update(mitigation.owasp_cheatsheet_ids)
            
            if owasp_refs:
                report += """## OWASP References

This analysis references the following OWASP cheat sheets:
"""
                for ref in sorted(owasp_refs):
                    report += f"- [{ref}](https://cheatsheetseries.owasp.org/cheatsheets/{ref.replace('-', '_').title()}_Cheat_Sheet.html)\n"
                report += "\n"
        
        report += """---
*This security analysis was generated using ThreatLens following OWASP threat modeling methodology.*
"""
        
        return report
    
    def generate_component_threat_model(
        self,
        component: Component,
        threats: List[Threat],
        mitigations: List[Mitigation],
        system_context: System
    ) -> str:
        """
        Generate detailed threat model documentation for a specific component.
        
        Args:
            component: The component to analyze
            threats: Threats affecting this component
            mitigations: Mitigations for the component threats
            system_context: Overall system context
            
        Returns:
            Markdown-formatted component threat model
        """
        component_threats = [t for t in threats if component.name in t.affected_assets]
        component_mitigations = [m for m in mitigations if any(t.id in getattr(m, 'threat_ids', []) for t in component_threats)]
        
        report = f"""# Threat Model: {component.name}

**Component Type**: {component.type.value}
**Trust Level**: {component.trust_level.value}
**Last Updated**: {datetime.now().strftime('%Y-%m-%d')}

## Component Overview

### Description
{component.description}

### Interfaces
"""
        
        for interface in component.interfaces:
            report += f"""- **{interface.name}** ({interface.protocol})
  - Port: {interface.port if interface.port else 'N/A'}
  - Authentication: {'Required' if interface.authentication_required else 'Not Required'}
  - Public Facing: {'Yes' if interface.public_facing else 'No'}
"""
        
        report += f"""
### System Context
This component operates within the {system_context.name} system and interacts with:
"""
        
        # Find related data flows
        related_flows = [df for df in system_context.data_flows 
                        if component.name in df.source or component.name in df.destination]
        
        for flow in related_flows[:5]:  # Limit to top 5
            direction = "→" if component.name == flow.source else "←"
            other_component = flow.destination if component.name == flow.source else flow.source
            report += f"- {direction} **{other_component}** via {flow.protocol}\n"
        
        if len(related_flows) > 5:
            report += f"- ... and {len(related_flows) - 5} more connections\n"
        
        report += """
## Threat Analysis

"""
        
        if component_threats:
            # Group by STRIDE category
            stride_groups = {}
            for threat in component_threats:
                category = threat.stride_category.value
                if category not in stride_groups:
                    stride_groups[category] = []
                stride_groups[category].append(threat)
            
            for category, category_threats in stride_groups.items():
                report += f"""### {category.upper()} Threats

"""
                for threat in sorted(category_threats, key=lambda t: t.risk_score, reverse=True):
                    risk_level = "HIGH" if threat.risk_score >= 7.0 else "MEDIUM" if threat.risk_score >= 4.0 else "LOW"
                    report += f"""#### {threat.title}
**Risk Level**: {risk_level} ({threat.risk_score:.1f})
**Likelihood**: {threat.likelihood.value} | **Impact**: {threat.impact.value}

**Description**: {threat.description}

**Attack Vectors**:
"""
                    for attack_path in threat.attack_paths:
                        report += f"- {attack_path.name}: {attack_path.description}\n"
                    
                    report += f"""
**Prerequisites**:
"""
                    for prereq in threat.prerequisites:
                        report += f"- {prereq}\n"
                    
                    report += "\n"
        else:
            report += "No specific threats identified for this component.\n\n"
        
        report += """## Mitigation Strategies

"""
        
        if component_mitigations:
            # Group by category
            mitigation_groups = {}
            for mitigation in component_mitigations:
                category = mitigation.category.value
                if category not in mitigation_groups:
                    mitigation_groups[category] = []
                mitigation_groups[category].append(mitigation)
            
            for category, category_mitigations in mitigation_groups.items():
                report += f"""### {category.title()} Controls

"""
                for mitigation in category_mitigations:
                    report += f"""#### {mitigation.title}
**Priority**: {mitigation.priority.value} | **Effort**: {mitigation.effort_estimate.value}

**Description**: {mitigation.description}

**Implementation Guidance**:
{mitigation.implementation_guidance}

"""
                    if mitigation.code_examples:
                        report += "**Code Examples**:\n"
                        for example in mitigation.code_examples:
                            report += f"""```{example.language}
{example.code}
```

"""
                    
                    if mitigation.verification_criteria:
                        report += "**Verification Criteria**:\n"
                        for criteria in mitigation.verification_criteria:
                            report += f"- {criteria}\n"
                        report += "\n"
                    
                    if mitigation.owasp_cheatsheet_ids:
                        report += f"**OWASP References**: {', '.join(mitigation.owasp_cheatsheet_ids)}\n\n"
        else:
            report += "No specific mitigations required for this component.\n\n"
        
        report += """## Security Testing

### Recommended Tests
"""
        
        # Generate test recommendations based on component type and threats
        if component.type.value.lower() in ['web_service', 'api', 'microservice']:
            report += """- Input validation testing (fuzzing, boundary value analysis)
- Authentication bypass testing
- Authorization testing (privilege escalation)
- Injection attack testing (SQL, NoSQL, LDAP, etc.)
- Cross-site scripting (XSS) testing
- Cross-site request forgery (CSRF) testing
"""
        
        if component.type.value.lower() in ['database', 'data_store']:
            report += """- Access control testing
- Data encryption verification
- Backup security testing
- SQL injection testing
- Data leakage testing
"""
        
        if component.type.value.lower() in ['frontend', 'web_application']:
            report += """- Client-side security testing
- Content Security Policy (CSP) validation
- Secure cookie configuration
- Session management testing
- DOM-based XSS testing
"""
        
        report += """
### Monitoring and Detection
"""
        
        report += f"""- Monitor authentication failures for {component.name}
- Log and alert on suspicious access patterns
- Track data access and modifications
- Monitor for injection attack attempts
- Alert on privilege escalation attempts

## Maintenance

### Regular Reviews
- **Quarterly**: Review threat landscape and update threat model
- **After Changes**: Re-assess threats when component is modified
- **Annual**: Comprehensive security assessment

### Update Triggers
- New vulnerabilities discovered in dependencies
- Changes to component interfaces or functionality
- New attack vectors identified in threat intelligence
- Compliance requirement changes

---
*Generated by ThreatLens - Component Threat Modeling*
"""
        
        return report
    
    def generate_system_threat_model(
        self,
        system: System,
        threats: List[Threat],
        mitigations: List[Mitigation]
    ) -> str:
        """
        Generate comprehensive system-level threat model documentation.
        
        Args:
            system: Complete system model
            threats: All identified threats
            mitigations: All planned mitigations
            
        Returns:
            Markdown-formatted system threat model
        """
        report = f"""# System Threat Model: {system.name}

**System Description**: {system.description}
**Last Updated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Threat Model Version**: 1.0

## Executive Summary

This document provides a comprehensive threat model for the {system.name} system following the OWASP threat modeling methodology. The analysis identifies {len(threats)} potential threats across {len(system.components)} components and provides {len(mitigations)} mitigation strategies.

### Risk Overview
"""
        
        # Risk distribution
        high_risk = len([t for t in threats if t.risk_score >= 7.0])
        medium_risk = len([t for t in threats if 4.0 <= t.risk_score < 7.0])
        low_risk = len([t for t in threats if t.risk_score < 4.0])
        
        report += f"""- **Critical/High Risk**: {high_risk} threats requiring immediate attention
- **Medium Risk**: {medium_risk} threats requiring planned mitigation
- **Low Risk**: {low_risk} threats for monitoring and future consideration

"""
        
        # STRIDE coverage
        stride_categories = set(threat.stride_category for threat in threats)
        report += f"""### STRIDE Coverage
This analysis covers {len(stride_categories)}/6 STRIDE categories: {', '.join([cat.value for cat in stride_categories])}

"""
        
        report += """## 1. What are we working on?

### System Architecture
"""
        
        # System components overview
        report += f"""#### Components ({len(system.components)} total)
"""
        
        component_types = {}
        for component in system.components:
            comp_type = component.type.value
            if comp_type not in component_types:
                component_types[comp_type] = []
            component_types[comp_type].append(component)
        
        for comp_type, components in component_types.items():
            report += f"""
**{comp_type.title()}** ({len(components)} components):
"""
            for component in components:
                report += f"- {component.name} (Trust Level: {component.trust_level.value})\n"
        
        # Data stores
        if system.data_stores:
            report += f"""
#### Data Stores ({len(system.data_stores)} total)
"""
            for data_store in system.data_stores:
                encryption_status = "🔒 Encrypted" if data_store.encryption_at_rest else "🔓 Not Encrypted"
                report += f"- **{data_store.name}** ({data_store.type}) - {encryption_status}\n"
                report += f"  - Classification: {data_store.data_classification.value}\n"
        
        # Trust boundaries
        if system.trust_boundaries:
            report += f"""
#### Trust Boundaries ({len(system.trust_boundaries)} total)
"""
            for boundary in system.trust_boundaries:
                report += f"- **{boundary.name}** ({boundary.type.value})\n"
                report += f"  - Components: {', '.join(boundary.components)}\n"
                report += f"  - Controls: {', '.join(boundary.security_controls)}\n"
        
        # Cloud context
        if system.cloud_context:
            report += f"""
#### Cloud Context
- **Provider**: {system.cloud_context.provider.value}
- **Deployment Model**: {system.cloud_context.deployment_model.value}
- **Key Services**: {', '.join(system.cloud_context.services_used[:5])}
- **Compliance**: {', '.join(system.cloud_context.compliance_requirements)}
"""
        
        report += """
## 2. What can go wrong?

### Threat Landscape
"""
        
        if threats:
            # STRIDE analysis
            stride_groups = {}
            for threat in threats:
                category = threat.stride_category.value
                if category not in stride_groups:
                    stride_groups[category] = []
                stride_groups[category].append(threat)
            
            for category, category_threats in stride_groups.items():
                report += f"""
#### {category.upper()} Threats ({len(category_threats)} identified)
"""
                
                # Show top threats in each category
                sorted_threats = sorted(category_threats, key=lambda t: t.risk_score, reverse=True)
                for threat in sorted_threats[:3]:  # Top 3 per category
                    risk_emoji = "🔴" if threat.risk_score >= 7.0 else "🟡" if threat.risk_score >= 4.0 else "🟢"
                    report += f"""
**{threat.title}** {risk_emoji}
- **Risk Score**: {threat.risk_score:.1f} (Likelihood: {threat.likelihood.value}, Impact: {threat.impact.value})
- **Description**: {threat.description}
- **Affected Assets**: {', '.join(threat.affected_assets)}
"""
                
                if len(category_threats) > 3:
                    report += f"\n*... and {len(category_threats) - 3} additional {category} threats*\n"
        
        report += """
## 3. What are we going to do about it?

### Mitigation Strategy
"""
        
        if mitigations:
            # Group by priority
            priority_groups = {}
            for mitigation in mitigations:
                priority = mitigation.priority.value
                if priority not in priority_groups:
                    priority_groups[priority] = []
                priority_groups[priority].append(mitigation)
            
            priority_order = ['Critical', 'High', 'Medium', 'Low']
            
            for priority in priority_order:
                if priority in priority_groups:
                    priority_mitigations = priority_groups[priority]
                    report += f"""
#### {priority} Priority Mitigations ({len(priority_mitigations)} items)
"""
                    
                    for mitigation in priority_mitigations:
                        report += f"""
**{mitigation.title}**
- **Category**: {mitigation.category.value}
- **Effort**: {mitigation.effort_estimate.value}
- **Description**: {mitigation.description}
"""
                        if mitigation.owasp_cheatsheet_ids:
                            report += f"- **OWASP References**: {', '.join(mitigation.owasp_cheatsheet_ids)}\n"
        
        report += """
## 4. Did we do a good enough job?

### Quality Assessment
"""
        
        # Calculate completeness metrics
        total_components = len(system.components)
        components_with_threats = len(set(asset for threat in threats for asset in threat.affected_assets))
        coverage_percentage = (components_with_threats / total_components * 100) if total_components > 0 else 0
        
        report += f"""
#### Coverage Metrics
- **Component Coverage**: {components_with_threats}/{total_components} components analyzed ({coverage_percentage:.1f}%)
- **STRIDE Coverage**: {len(stride_categories)}/6 categories addressed
- **Threat-Mitigation Ratio**: {len(mitigations)}/{len(threats)} mitigations per threat

#### Quality Checklist
- [{'x' if len(stride_categories) >= 5 else ' '}] Comprehensive STRIDE analysis completed
- [{'x' if high_risk == 0 else ' '}] All high-risk threats have mitigation strategies
- [{'x' if coverage_percentage >= 80 else ' '}] Adequate component coverage (≥80%)
- [{'x' if len([m for m in mitigations if m.owasp_cheatsheet_ids]) > 0 else ' '}] OWASP-aligned mitigations defined
- [{'x' if system.trust_boundaries else ' '}] Trust boundaries clearly defined
"""
        
        # Recommendations
        report += """
### Recommendations

#### Immediate Actions
"""
        
        if high_risk > 0:
            report += f"1. **Address {high_risk} high-risk threats** before system deployment\n"
        
        if coverage_percentage < 80:
            report += f"2. **Expand threat analysis** to cover remaining {total_components - components_with_threats} components\n"
        
        if len(stride_categories) < 6:
            missing_categories = set(['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege']) - set(cat.value for cat in stride_categories)
            report += f"3. **Complete STRIDE analysis** for missing categories: {', '.join(missing_categories)}\n"
        
        report += """
#### Ongoing Activities
1. **Regular Reviews**: Schedule quarterly threat model reviews
2. **Continuous Monitoring**: Implement security monitoring for identified threats
3. **Incident Response**: Develop response procedures for high-risk scenarios
4. **Training**: Ensure development team understands security requirements

"""
        
        # OWASP references
        if self.config.include_owasp_references:
            all_owasp_refs = set()
            for mitigation in mitigations:
                all_owasp_refs.update(mitigation.owasp_cheatsheet_ids)
            
            if all_owasp_refs:
                report += """## OWASP References

This threat model aligns with the following OWASP guidance:

"""
                for ref in sorted(all_owasp_refs):
                    report += f"- [{ref}](https://cheatsheetseries.owasp.org/cheatsheets/{ref.replace('-', '_').title()}_Cheat_Sheet.html)\n"
        
        report += f"""
## Appendices

### A. Component Details
For detailed component-level threat models, see:
"""
        
        for component in system.components:
            report += f"- [docs/security/components/{component.name.lower().replace(' ', '-')}.md](components/{component.name.lower().replace(' ', '-')}.md)\n"
        
        report += """
### B. Threat Details
Complete threat details including attack vectors, prerequisites, and technical analysis are maintained in the threat database.

### C. Implementation Guidance
Detailed implementation guidance for each mitigation is available in the component-specific documentation.

---
*This threat model was generated using ThreatLens following OWASP threat modeling methodology.*
*For questions or updates, contact the security team.*
"""
        
        return report
    
    def generate_repository_threat_model(
        self,
        system: System,
        threats: List[Threat],
        mitigations: List[Mitigation],
        repository_path: str = None
    ) -> str:
        """
        Generate high-level repository threat model using four questions structure.
        
        Args:
            system: Complete system model for the repository
            threats: All identified threats
            mitigations: All planned mitigations
            repository_path: Path to the repository being analyzed
            
        Returns:
            Markdown-formatted repository threat model following four questions structure
        """
        repo_name = system.name or (repository_path.split('/')[-1] if repository_path else "Repository")
        
        report = f"""# Threat Model: {repo_name}

**Repository**: {repository_path or 'N/A'}
**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Methodology**: OWASP Threat Modeling (Four Questions)
**Tool**: ThreatLens

## Executive Summary

This document provides a comprehensive threat model for the {repo_name} repository following the OWASP threat modeling methodology. The analysis systematically addresses the four key questions to ensure comprehensive security coverage.

### Key Findings
- **System Components**: {len(system.components)} components analyzed
- **Threats Identified**: {len(threats)} total threats across STRIDE categories
- **Mitigations Planned**: {len(mitigations)} security controls and mitigations
- **Risk Level**: {'HIGH' if any(t.risk_score >= 7.0 for t in threats) else 'MEDIUM' if any(t.risk_score >= 4.0 for t in threats) else 'LOW'}

---

## 1. What are we working on?

### System Architecture Overview

{system.description}

#### Components ({len(system.components)} total)
"""
        
        # Group components by type for better organization
        component_types = {}
        for component in system.components:
            comp_type = component.type.value
            if comp_type not in component_types:
                component_types[comp_type] = []
            component_types[comp_type].append(component)
        
        for comp_type, components in component_types.items():
            report += f"""
**{comp_type.replace('_', ' ').title()}** ({len(components)} components):
"""
            for component in components:
                report += f"- **{component.name}** - {component.description}\n"
                report += f"  - Trust Level: {component.trust_level.value}\n"
                report += f"  - Interfaces: {len(component.interfaces)} endpoints\n"
        
        # Data stores section
        if system.data_stores:
            report += f"""
#### Data Stores ({len(system.data_stores)} total)
"""
            for data_store in system.data_stores:
                encryption_status = "🔒 Encrypted" if data_store.encryption_at_rest else "🔓 Not Encrypted"
                report += f"- **{data_store.name}** ({data_store.type}) - {encryption_status}\n"
                report += f"  - Data Classification: {data_store.data_classification.value}\n"
                report += f"  - Access Controls: {', '.join(data_store.access_controls) if data_store.access_controls else 'Not specified'}\n"
        
        # Trust boundaries
        if system.trust_boundaries:
            report += f"""
#### Trust Boundaries ({len(system.trust_boundaries)} total)
"""
            for boundary in system.trust_boundaries:
                report += f"- **{boundary.name}** ({boundary.type.value})\n"
                report += f"  - Protected Components: {', '.join(boundary.components)}\n"
                report += f"  - Security Controls: {', '.join(boundary.security_controls)}\n"
        
        # Cloud context
        if system.cloud_context:
            report += f"""
#### Cloud Infrastructure
- **Provider**: {system.cloud_context.provider.value}
- **Deployment Model**: {system.cloud_context.deployment_model.value}
- **Key Services**: {', '.join(system.cloud_context.services_used[:10])}
- **Compliance Requirements**: {', '.join(system.cloud_context.compliance_requirements)}
- **Data Residency**: {system.cloud_context.data_residency}
"""
        
        # Data flows summary
        if system.data_flows:
            report += f"""
#### Data Flow Summary
- **Total Data Flows**: {len(system.data_flows)}
- **Authenticated Flows**: {len([df for df in system.data_flows if df.authentication_required])}
- **High Sensitivity Flows**: {len([df for df in system.data_flows if df.data_classification.value in ['Confidential', 'Restricted']])}
"""
        
        report += """
---

## 2. What can go wrong?

### STRIDE Threat Analysis
"""
        
        if threats:
            # Group threats by STRIDE category
            stride_groups = {}
            for threat in threats:
                category = threat.stride_category.value
                if category not in stride_groups:
                    stride_groups[category] = []
                stride_groups[category].append(threat)
            
            # Risk summary
            high_risk_threats = [t for t in threats if t.risk_score >= 7.0]
            medium_risk_threats = [t for t in threats if 4.0 <= t.risk_score < 7.0]
            low_risk_threats = [t for t in threats if t.risk_score < 4.0]
            
            report += f"""
#### Risk Distribution
- 🔴 **High Risk** (≥7.0): {len(high_risk_threats)} threats requiring immediate attention
- 🟡 **Medium Risk** (4.0-6.9): {len(medium_risk_threats)} threats requiring mitigation
- 🟢 **Low Risk** (<4.0): {len(low_risk_threats)} threats for monitoring

"""
            
            # STRIDE category analysis
            stride_order = ['spoofing', 'tampering', 'repudiation', 'information_disclosure', 'denial_of_service', 'elevation_of_privilege']
            stride_display_names = {
                'spoofing': 'Spoofing',
                'tampering': 'Tampering', 
                'repudiation': 'Repudiation',
                'information_disclosure': 'Information Disclosure',
                'denial_of_service': 'Denial of Service',
                'elevation_of_privilege': 'Elevation of Privilege'
            }
            
            for category in stride_order:
                if category in stride_groups:
                    category_threats = stride_groups[category]
                    display_name = stride_display_names[category]
                    if category_threats:
                        report += f"""
#### {display_name} Threats ({len(category_threats)} identified)
"""
                        # Show top 3 threats per category
                        sorted_threats = sorted(category_threats, key=lambda t: t.risk_score, reverse=True)
                        for threat in sorted_threats[:3]:
                            risk_emoji = "🔴" if threat.risk_score >= 7.0 else "🟡" if threat.risk_score >= 4.0 else "🟢"
                            report += f"""
**{threat.title}** {risk_emoji}
- **Risk Score**: {threat.risk_score:.1f} (Likelihood: {threat.likelihood.value}, Impact: {threat.impact.value})
- **Description**: {threat.description}
- **Affected Components**: {', '.join(threat.affected_assets)}
- **Attack Vectors**: {', '.join([ap.attack_vector.value for ap in threat.attack_paths[:3]])}{'...' if len(threat.attack_paths) > 3 else ''}
"""
                        
                        if len(category_threats) > 3:
                            report += f"\n*... and {len(category_threats) - 3} additional {category.lower()} threats*\n"
        else:
            report += "No significant threats identified through STRIDE analysis.\n"
        
        report += """
---

## 3. What are we going to do about it?

### Mitigation Strategy
"""
        
        if mitigations:
            # Group mitigations by priority
            priority_groups = {}
            for mitigation in mitigations:
                priority = mitigation.priority.value
                if priority not in priority_groups:
                    priority_groups[priority] = []
                priority_groups[priority].append(mitigation)
            
            priority_order = ['Critical', 'High', 'Medium', 'Low']
            
            for priority in priority_order:
                if priority in priority_groups:
                    priority_mitigations = priority_groups[priority]
                    report += f"""
#### {priority} Priority Mitigations ({len(priority_mitigations)} controls)
"""
                    
                    for mitigation in priority_mitigations:
                        report += f"""
**{mitigation.title}**
- **Category**: {mitigation.category.value}
- **Implementation Effort**: {mitigation.effort_estimate.value}
- **Description**: {mitigation.description}
"""
                        if mitigation.owasp_cheatsheet_ids:
                            report += f"- **OWASP References**: {', '.join(mitigation.owasp_cheatsheet_ids)}\n"
                        
                        if mitigation.implementation_guidance:
                            report += f"- **Implementation**: {mitigation.implementation_guidance[:200]}{'...' if len(mitigation.implementation_guidance) > 200 else ''}\n"
                        
                        report += "\n"
        else:
            report += "No specific mitigations required based on current threat analysis.\n"
        
        report += """
---

## 4. Did we do a good enough job?

### Quality Assessment
"""
        
        # Calculate coverage metrics
        total_components = len(system.components)
        components_with_threats = len(set(asset for threat in threats for asset in threat.affected_assets))
        coverage_percentage = (components_with_threats / total_components * 100) if total_components > 0 else 0
        
        stride_categories_covered = len(set(threat.stride_category for threat in threats))
        
        report += f"""
#### Coverage Metrics
- **Component Coverage**: {components_with_threats}/{total_components} components analyzed ({coverage_percentage:.1f}%)
- **STRIDE Coverage**: {stride_categories_covered}/6 categories addressed
- **Threat-to-Mitigation Ratio**: {len(mitigations)}/{len(threats)} mitigations per threat

#### Quality Checklist
- [{'x' if stride_categories_covered >= 5 else ' '}] Comprehensive STRIDE analysis (≥5 categories)
- [{'x' if len([t for t in threats if t.risk_score >= 7.0]) == 0 or len([m for m in mitigations if m.priority.value in ['Critical', 'High']]) > 0 else ' '}] High-risk threats have mitigation strategies
- [{'x' if coverage_percentage >= 80 else ' '}] Adequate component coverage (≥80%)
- [{'x' if len([m for m in mitigations if m.owasp_cheatsheet_ids]) > 0 else ' '}] OWASP-aligned mitigations defined
- [{'x' if system.trust_boundaries else ' '}] Trust boundaries clearly defined
- [{'x' if system.cloud_context else ' '}] Cloud security context documented

#### Recommendations
"""
        
        # Generate specific recommendations
        recommendations = []
        
        if len([t for t in threats if t.risk_score >= 7.0]) > 0:
            high_risk_count = len([t for t in threats if t.risk_score >= 7.0])
            recommendations.append(f"🔴 **Immediate Action Required**: Address {high_risk_count} high-risk threats before production deployment")
        
        if coverage_percentage < 80:
            recommendations.append(f"📊 **Expand Analysis**: Increase component coverage from {coverage_percentage:.1f}% to at least 80%")
        
        if stride_categories_covered < 6:
            missing_categories = 6 - stride_categories_covered
            recommendations.append(f"🎯 **Complete STRIDE**: Address {missing_categories} missing STRIDE categories for comprehensive coverage")
        
        if not system.trust_boundaries:
            recommendations.append("🛡️ **Define Trust Boundaries**: Establish clear trust boundaries to improve security architecture")
        
        if len(mitigations) < len(threats) * 0.5:
            recommendations.append("⚡ **Enhance Mitigations**: Develop more comprehensive mitigation strategies for identified threats")
        
        if not recommendations:
            recommendations.append("✅ **Quality Standards Met**: Threat model meets quality standards for production use")
        
        for i, rec in enumerate(recommendations, 1):
            report += f"{i}. {rec}\n"
        
        report += """
### Next Steps
1. **Review and Approval**: Stakeholder review of threat model and mitigation strategies
2. **Implementation Planning**: Prioritize and schedule mitigation implementation
3. **Monitoring Setup**: Implement security monitoring for identified threats
4. **Regular Updates**: Schedule quarterly reviews and updates to the threat model

---

## Appendices

### A. Component Documentation
Detailed component-level threat models are available in:
"""
        
        for component in system.components:
            component_filename = component.name.lower().replace(' ', '-').replace('_', '-')
            report += f"- [docs/security/components/{component_filename}.md](components/{component_filename}.md)\n"
        
        report += """
### B. Security Checklists
Security review checklists are available in:
- [docs/security/checklists/pr-review.md](checklists/pr-review.md)

### C. OWASP References
This threat model follows OWASP threat modeling methodology and references:
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [OWASP STRIDE Methodology](https://owasp.org/www-community/Threat_Modeling_Process)
"""
        
        if mitigations:
            owasp_refs = set()
            for mitigation in mitigations:
                owasp_refs.update(mitigation.owasp_cheatsheet_ids)
            
            if owasp_refs:
                report += "\n**Additional OWASP Cheat Sheets Referenced:**\n"
                for ref in sorted(owasp_refs):
                    clean_ref = ref.replace('-', '_').title()
                    report += f"- [{ref}](https://cheatsheetseries.owasp.org/cheatsheets/{clean_ref}_Cheat_Sheet.html)\n"
        
        report += f"""
---
*This threat model was generated by ThreatLens on {datetime.now().strftime('%Y-%m-%d')} following OWASP threat modeling best practices.*
*For questions or updates, please contact the security team.*
"""
        
        return report
    
    def generate_component_documentation(
        self,
        component: Component,
        threats: List[Threat],
        mitigations: List[Mitigation],
        system_context: System
    ) -> str:
        """
        Generate component-level threat analysis and mitigation documentation.
        
        Args:
            component: The component to document
            threats: Threats affecting this component
            mitigations: Mitigations for the component
            system_context: Overall system context
            
        Returns:
            Markdown-formatted component documentation with OWASP references
        """
        component_threats = [t for t in threats if component.name in t.affected_assets]
        component_mitigations = [m for m in mitigations if any(t.id in getattr(m, 'threat_ids', []) for t in component_threats)]
        
        report = f"""# Component Security Analysis: {component.name}

**Component Type**: {component.type.value}
**Trust Level**: {component.trust_level.value}
**Last Updated**: {datetime.now().strftime('%Y-%m-%d')}
**Analysis Tool**: ThreatLens

## Component Overview

### Description
{component.description}

### Security Context
- **Trust Level**: {component.trust_level.value}
- **Component Type**: {component.type.value}
- **System**: {system_context.name}

### Interfaces and Endpoints
"""
        
        if component.interfaces:
            for interface in component.interfaces:
                auth_status = "🔒 Required" if interface.authentication_required else "🔓 Not Required"
                report += f"""
#### {interface.name}
- **Protocol**: {interface.protocol}
- **Port**: {interface.port if interface.port else 'N/A'}
- **Authentication**: {auth_status}
- **Public Facing**: {'Yes' if interface.public_facing else 'No'}
- **Description**: {interface.description or 'No description provided'}
"""
        else:
            report += "\nNo external interfaces defined for this component.\n"
        
        # System relationships
        related_flows = [df for df in system_context.data_flows 
                        if component.name in df.source or component.name in df.destination]
        
        if related_flows:
            report += f"""
### System Relationships

This component interacts with {len(set([df.source if component.name == df.destination else df.destination for df in related_flows]))} other components:

"""
            
            # Group by direction
            incoming_flows = [df for df in related_flows if component.name == df.destination]
            outgoing_flows = [df for df in related_flows if component.name == df.source]
            
            if incoming_flows:
                report += "**Incoming Data Flows:**\n"
                for flow in incoming_flows:
                    auth_indicator = "🔒" if flow.authentication_required else "🔓"
                    report += f"- {auth_indicator} **{flow.source}** → {component.name} via {flow.protocol}\n"
                    report += f"  - Data: {flow.data_classification.value}\n"
            
            if outgoing_flows:
                report += "\n**Outgoing Data Flows:**\n"
                for flow in outgoing_flows:
                    auth_indicator = "🔒" if flow.authentication_required else "🔓"
                    report += f"- {auth_indicator} {component.name} → **{flow.destination}** via {flow.protocol}\n"
                    report += f"  - Data: {flow.data_classification.value}\n"
        
        report += """
## Threat Analysis

"""
        
        if component_threats:
            # Risk summary for this component
            high_risk = [t for t in component_threats if t.risk_score >= 7.0]
            medium_risk = [t for t in component_threats if 4.0 <= t.risk_score < 7.0]
            low_risk = [t for t in component_threats if t.risk_score < 4.0]
            
            report += f"""### Risk Summary
- 🔴 **High Risk**: {len(high_risk)} threats requiring immediate attention
- 🟡 **Medium Risk**: {len(medium_risk)} threats requiring mitigation
- 🟢 **Low Risk**: {len(low_risk)} threats for monitoring

"""
            
            # Group by STRIDE category
            stride_groups = {}
            for threat in component_threats:
                category = threat.stride_category.value
                if category not in stride_groups:
                    stride_groups[category] = []
                stride_groups[category].append(threat)
            
            for category, category_threats in stride_groups.items():
                report += f"""### {category} Threats ({len(category_threats)} identified)

"""
                for threat in sorted(category_threats, key=lambda t: t.risk_score, reverse=True):
                    risk_level = "🔴 HIGH" if threat.risk_score >= 7.0 else "🟡 MEDIUM" if threat.risk_score >= 4.0 else "🟢 LOW"
                    report += f"""#### {threat.title}
**Risk Level**: {risk_level} (Score: {threat.risk_score:.1f})  
**Likelihood**: {threat.likelihood.value} | **Impact**: {threat.impact.value}

**Description**: {threat.description}

**Attack Vectors**:
"""
                    for attack_path in threat.attack_paths:
                        report += f"- {attack_path.name}: {attack_path.description}\n"
                    
                    if threat.prerequisites:
                        report += f"""
**Prerequisites**:
"""
                        for prereq in threat.prerequisites:
                            report += f"- {prereq}\n"
                    
                    report += "\n"
        else:
            report += "No specific threats identified for this component through STRIDE analysis.\n"
        
        report += """
## Security Controls and Mitigations

"""
        
        if component_mitigations:
            # Group by category
            mitigation_groups = {}
            for mitigation in component_mitigations:
                category = mitigation.category.value
                if category not in mitigation_groups:
                    mitigation_groups[category] = []
                mitigation_groups[category].append(mitigation)
            
            for category, category_mitigations in mitigation_groups.items():
                report += f"""### {category.title()} Controls ({len(category_mitigations)} controls)

"""
                for mitigation in category_mitigations:
                    priority_emoji = "🔴" if mitigation.priority.value in ['Critical', 'High'] else "🟡" if mitigation.priority.value == 'Medium' else "🟢"
                    report += f"""#### {mitigation.title} {priority_emoji}
**Priority**: {mitigation.priority.value} | **Implementation Effort**: {mitigation.effort_estimate.value}

**Description**: {mitigation.description}

"""
                    
                    if mitigation.implementation_guidance:
                        report += f"""**Implementation Guidance**:
{mitigation.implementation_guidance}

"""
                    
                    if mitigation.code_examples:
                        report += "**Code Examples**:\n"
                        for example in mitigation.code_examples:
                            report += f"""
```{example.language}
{example.code}
```
*{example.description}*

"""
                    
                    if mitigation.verification_criteria:
                        report += "**Verification Criteria**:\n"
                        for criteria in mitigation.verification_criteria:
                            report += f"- [ ] {criteria}\n"
                        report += "\n"
                    
                    if mitigation.owasp_cheatsheet_ids:
                        report += f"**OWASP References**: "
                        owasp_links = []
                        for ref in mitigation.owasp_cheatsheet_ids:
                            clean_ref = ref.replace('-', '_').title()
                            owasp_links.append(f"[{ref}](https://cheatsheetseries.owasp.org/cheatsheets/{clean_ref}_Cheat_Sheet.html)")
                        report += ", ".join(owasp_links) + "\n\n"
        else:
            report += "No specific mitigations required for this component based on current threat analysis.\n"
        
        # Add technology-specific security guidance
        report += """
## Technology-Specific Security Guidance

"""
        
        # Generate guidance based on component type
        component_type_lower = component.type.value.lower()
        
        if 'web' in component_type_lower or 'api' in component_type_lower:
            report += """### Web Application Security
- **Input Validation**: Implement comprehensive input validation for all user inputs
- **Output Encoding**: Properly encode all outputs to prevent XSS attacks
- **Authentication**: Use strong authentication mechanisms (multi-factor where possible)
- **Session Management**: Implement secure session handling with proper timeouts
- **HTTPS**: Enforce HTTPS for all communications
- **CORS**: Configure Cross-Origin Resource Sharing policies appropriately

**OWASP References**:
- [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

"""
        
        if 'database' in component_type_lower or 'data' in component_type_lower:
            report += """### Database Security
- **Access Control**: Implement principle of least privilege for database access
- **Encryption**: Encrypt sensitive data at rest and in transit
- **SQL Injection Prevention**: Use parameterized queries and stored procedures
- **Backup Security**: Secure database backups with encryption and access controls
- **Audit Logging**: Enable comprehensive database audit logging

**OWASP References**:
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)

"""
        
        if 'frontend' in component_type_lower or 'client' in component_type_lower:
            report += """### Frontend Security
- **Content Security Policy**: Implement and maintain strict CSP headers
- **Secure Storage**: Avoid storing sensitive data in client-side storage
- **DOM Security**: Prevent DOM-based XSS vulnerabilities
- **Dependency Management**: Keep frontend dependencies updated and secure
- **Secure Communication**: Use secure protocols for all API communications

**OWASP References**:
- [HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
- [Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

"""
        
        report += """
## Security Testing Recommendations

### Automated Testing
"""
        
        # Generate testing recommendations based on component type
        if 'web' in component_type_lower or 'api' in component_type_lower:
            report += """- **SAST (Static Application Security Testing)**: Integrate static code analysis into CI/CD pipeline
- **DAST (Dynamic Application Security Testing)**: Perform regular dynamic security scans
- **Dependency Scanning**: Monitor and scan for vulnerable dependencies
- **API Security Testing**: Test API endpoints for common vulnerabilities
- **Authentication Testing**: Verify authentication and authorization mechanisms

"""
        
        if 'database' in component_type_lower:
            report += """- **Database Vulnerability Scanning**: Regular scans for database vulnerabilities
- **Access Control Testing**: Verify database access controls and permissions
- **Injection Testing**: Test for SQL injection and other injection attacks
- **Encryption Verification**: Validate data encryption implementation

"""
        
        report += """### Manual Testing
- **Penetration Testing**: Regular penetration testing by security professionals
- **Code Review**: Security-focused code reviews for all changes
- **Architecture Review**: Periodic security architecture assessments
- **Threat Model Updates**: Regular updates to threat model based on changes

### Monitoring and Detection
- **Security Logging**: Implement comprehensive security event logging
- **Anomaly Detection**: Monitor for unusual access patterns or behaviors
- **Intrusion Detection**: Deploy appropriate intrusion detection systems
- **Incident Response**: Maintain incident response procedures for security events

## Maintenance and Updates

### Regular Activities
- **Quarterly Reviews**: Review and update component threat model quarterly
- **Dependency Updates**: Keep all dependencies updated with security patches
- **Configuration Reviews**: Regularly review and validate security configurations
- **Access Reviews**: Periodic review of access permissions and privileges

### Change Management
- **Security Impact Assessment**: Evaluate security impact of all changes
- **Threat Model Updates**: Update threat model when component functionality changes
- **Security Testing**: Perform security testing for all significant changes
- **Documentation Updates**: Keep security documentation current with changes

---

## References

### OWASP Resources
"""
        
        # Collect all OWASP references
        all_owasp_refs = set()
        for mitigation in component_mitigations:
            all_owasp_refs.update(mitigation.owasp_cheatsheet_ids)
        
        # Add standard references based on component type
        standard_refs = [
            "threat-modeling",
            "secure-coding-practices-quick-reference-guide"
        ]
        
        if 'web' in component_type_lower or 'api' in component_type_lower:
            standard_refs.extend([
                "input-validation",
                "cross-site-scripting-prevention",
                "authentication"
            ])
        
        if 'database' in component_type_lower:
            standard_refs.extend([
                "sql-injection-prevention",
                "database-security"
            ])
        
        all_owasp_refs.update(standard_refs)
        
        for ref in sorted(all_owasp_refs):
            clean_ref = ref.replace('-', '_').title()
            report += f"- [{ref}](https://cheatsheetseries.owasp.org/cheatsheets/{clean_ref}_Cheat_Sheet.html)\n"
        
        report += f"""
### Related Documentation
- [System Threat Model](../threat-model.md)
- [Security Review Checklist](../checklists/pr-review.md)

---
*This component security analysis was generated by ThreatLens on {datetime.now().strftime('%Y-%m-%d')}.*
*For questions or updates, please contact the security team.*
"""
        
        return report
    
    def generate_pr_review_checklist(
        self,
        system: System,
        threats: List[Threat],
        mitigations: List[Mitigation],
        technology_stack: List[str] = None,
        repository_context: Dict[str, Any] = None
    ) -> str:
        """
        Generate PR review checklist from OWASP guidance and area-specific sheets.
        
        Args:
            system: System model for context
            threats: Identified threats
            mitigations: Planned mitigations
            technology_stack: Detected technologies
            repository_context: Additional repository context
            
        Returns:
            Markdown-formatted PR review checklist with OWASP guidance
        """
        repo_name = system.name or repository_context.get('name', 'Repository') if repository_context else 'Repository'
        
        checklist = f"""# Security Review Checklist: {repo_name}

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Methodology**: OWASP Review & Validation Guidance
**Tool**: ThreatLens

## Overview

This security review checklist is customized for the {repo_name} repository based on OWASP best practices, detected technologies, and identified security threats. Use this checklist for pull request reviews, security assessments, and compliance validation.

### System Context
- **Components**: {len(system.components)} analyzed
- **Technologies**: {', '.join(technology_stack[:5]) if technology_stack else 'Not specified'}{'...' if technology_stack and len(technology_stack) > 5 else ''}
- **Threat Level**: {'HIGH' if any(t.risk_score >= 7.0 for t in threats) else 'MEDIUM' if any(t.risk_score >= 4.0 for t in threats) else 'LOW'}
- **Security Controls**: {len(mitigations)} mitigations planned

---

## Core Security Review Items

### 🔴 Critical Security Requirements

#### Authentication & Session Management
- [ ] **Multi-factor authentication** is implemented for privileged accounts
  - Verify MFA is required for admin and service accounts
  - Test authentication flows and bypass attempts
  - **OWASP Reference**: [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

- [ ] **Session management** follows secure practices
  - Session tokens use cryptographically secure generation
  - Proper session timeout and invalidation implemented
  - Session fixation and hijacking protections in place
  - **OWASP Reference**: [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

- [ ] **Password security** meets requirements
  - Strong password policies enforced
  - Secure password storage (hashing with salt)
  - Account lockout prevents brute force attacks
  - **OWASP Reference**: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

#### Authorization & Access Control
- [ ] **Principle of least privilege** enforced
  - Users have minimum necessary permissions
  - Role-based access control properly implemented
  - Regular access reviews conducted
  - **OWASP Reference**: [Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

- [ ] **Authorization checks** performed server-side
  - All authorization decisions made on server
  - Client-side controls cannot be bypassed
  - Direct object references protected
  - **OWASP Reference**: [Insecure Direct Object References Prevention](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control)

#### Input Validation & Injection Prevention
- [ ] **Input validation** uses positive validation (allow-lists)
  - All user input validated at entry points
  - Validation performed on server-side
  - Reject known bad input patterns
  - **OWASP Reference**: [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

- [ ] **SQL injection prevention** implemented
  - Parameterized queries or prepared statements used
  - Dynamic SQL construction avoided
  - Database permissions follow least privilege
  - **OWASP Reference**: [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

- [ ] **Cross-Site Scripting (XSS) prevention** implemented
  - Output encoding for all dynamic content
  - Content Security Policy (CSP) configured
  - DOM-based XSS protections in place
  - **OWASP Reference**: [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

### 🟡 High Priority Security Requirements

#### Data Protection & Cryptography
- [ ] **Sensitive data encryption** at rest and in transit
  - Strong encryption algorithms used (AES-256, RSA-2048+)
  - Proper key management implemented
  - TLS 1.2+ for data in transit
  - **OWASP Reference**: [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

- [ ] **Data classification** and handling procedures
  - Sensitive data properly identified and classified
  - Data retention and disposal policies followed
  - Personal data protection (GDPR/privacy compliance)
  - **OWASP Reference**: [Data Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Data_Protection_Cheat_Sheet.html)

#### Error Handling & Logging
- [ ] **Error handling** does not leak sensitive information
  - Generic error messages for users
  - Detailed errors logged securely
  - Stack traces not exposed to users
  - **OWASP Reference**: [Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

- [ ] **Security logging** captures relevant events
  - Authentication and authorization events logged
  - Security-relevant actions tracked
  - Log integrity protection implemented
  - **OWASP Reference**: [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

#### Communication Security
- [ ] **HTTPS/TLS configuration** is secure
  - Strong cipher suites configured
  - Certificate validation implemented
  - HTTP Strict Transport Security (HSTS) enabled
  - **OWASP Reference**: [Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

---

## Technology-Specific Review Items
"""
        
        # Add technology-specific items based on detected stack
        if technology_stack:
            tech_sections = self._generate_technology_sections(technology_stack)
            checklist += tech_sections
        else:
            checklist += "\n*No specific technologies detected. Review general security requirements above.*\n"
        
        # Add threat-specific review items
        if threats:
            high_risk_threats = [t for t in threats if t.risk_score >= 7.0]
            medium_risk_threats = [t for t in threats if 4.0 <= t.risk_score < 7.0]
            
            if high_risk_threats or medium_risk_threats:
                checklist += """
---

## Threat-Specific Review Items

Based on the threat analysis, pay special attention to these areas:

"""
                
                if high_risk_threats:
                    checklist += """### 🔴 High-Risk Threat Areas

"""
                    for threat in high_risk_threats:
                        checklist += f"""#### {threat.title} (Risk: {threat.risk_score:.1f})
- [ ] **Threat Mitigation Verified**
  - Description: {threat.description}
  - Affected Components: {', '.join(threat.affected_assets)}
  - Verify existing controls remain effective
  - Ensure changes don't introduce new attack vectors

"""
                
                if medium_risk_threats:
                    checklist += """### 🟡 Medium-Risk Areas for Review

"""
                    for threat in medium_risk_threats[:5]:  # Limit to top 5
                        checklist += f"""- [ ] **{threat.title}** - {threat.description[:100]}{'...' if len(threat.description) > 100 else ''}\n"""
        
        # Add component-specific items
        if system.components:
            checklist += """
---

## Component-Specific Review Items

"""
            
            # Group components by type
            component_types = {}
            for component in system.components:
                comp_type = component.type.value
                if comp_type not in component_types:
                    component_types[comp_type] = []
                component_types[comp_type].append(component)
            
            for comp_type, components in component_types.items():
                checklist += f"""### {comp_type.replace('_', ' ').title()} Components ({len(components)})

"""
                
                # Add type-specific checks
                if 'web' in comp_type.lower() or 'api' in comp_type.lower():
                    checklist += """- [ ] **Web Application Security**
  - CORS policies properly configured
  - Rate limiting implemented for APIs
  - Request size limits enforced
  - **OWASP Reference**: [REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)

"""
                
                if 'database' in comp_type.lower():
                    checklist += """- [ ] **Database Security**
  - Database access controls configured
  - Sensitive data encrypted in database
  - Database connection security verified
  - **OWASP Reference**: [Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)

"""
                
                if 'frontend' in comp_type.lower() or 'client' in comp_type.lower():
                    checklist += """- [ ] **Frontend Security**
  - Client-side data validation supplemented with server-side
  - Sensitive data not stored in client storage
  - Third-party scripts properly vetted
  - **OWASP Reference**: [HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)

"""
        
        # Add final validation section
        checklist += """
---

## Final Security Validation

### Code Review Completion
- [ ] **Static Analysis** - SAST tools run and issues addressed
- [ ] **Dependency Check** - No known vulnerable dependencies
- [ ] **Secret Scanning** - No hardcoded secrets or credentials
- [ ] **Code Quality** - Security-focused code review completed

### Testing Validation
- [ ] **Security Tests** - Security test cases pass
- [ ] **Penetration Testing** - Security testing completed (if applicable)
- [ ] **Vulnerability Assessment** - No new vulnerabilities introduced

### Documentation & Compliance
- [ ] **Security Documentation** - Updated as needed
- [ ] **Compliance Requirements** - Regulatory requirements met
- [ ] **Incident Response** - Security incident procedures updated if needed

### Approval Criteria
- [ ] **All Critical Items** - All critical security requirements verified
- [ ] **Risk Assessment** - Security risk is acceptable for deployment
- [ ] **Stakeholder Approval** - Security team approval obtained (if required)

---

## Additional Resources

### OWASP References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)

### Security Testing Tools
- Static Analysis Security Testing (SAST)
- Dynamic Analysis Security Testing (DAST)
- Interactive Application Security Testing (IAST)
- Software Composition Analysis (SCA)

### Compliance Frameworks
"""
        
        # Add compliance frameworks based on system context
        if system.cloud_context and system.cloud_context.compliance_requirements:
            for requirement in system.cloud_context.compliance_requirements:
                checklist += f"- {requirement}\n"
        else:
            checklist += """- SOC 2 Type II
- ISO 27001
- NIST Cybersecurity Framework
- PCI DSS (if applicable)
- GDPR/Privacy regulations (if applicable)
"""
        
        checklist += f"""
---

**Review Completed By**: _[Reviewer Name]_  
**Date**: _[Review Date]_  
**Approval Status**: _[Approved/Needs Work/Rejected]_  

*This checklist was generated by ThreatLens based on OWASP security review guidance and customized for your specific system architecture and threat landscape.*
"""
        
        return checklist
    
    def _generate_technology_sections(self, technology_stack: List[str]) -> str:
        """Generate technology-specific review sections."""
        sections = ""
        
        # Web frameworks and languages
        web_techs = [tech for tech in technology_stack if any(web in tech.lower() for web in ['react', 'vue', 'angular', 'javascript', 'typescript', 'html', 'css'])]
        if web_techs:
            sections += """
### Frontend/Web Technologies
- [ ] **Client-Side Security**
  - Content Security Policy (CSP) properly configured
  - Subresource Integrity (SRI) for external resources
  - Secure cookie configuration (HttpOnly, Secure, SameSite)
  - **OWASP Reference**: [HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)

"""
            
            if any('react' in tech.lower() for tech in web_techs):
                sections += """- [ ] **React Security**
  - Avoid dangerouslySetInnerHTML or sanitize content
  - Validate props and state for XSS prevention
  - Secure handling of user-generated content
  - **OWASP Reference**: [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

"""
        
        # Backend technologies
        backend_techs = [tech for tech in technology_stack if any(backend in tech.lower() for backend in ['node', 'python', 'java', 'go', 'rust', 'php', 'ruby'])]
        if backend_techs:
            sections += """### Backend Technologies
"""
            
            if any('node' in tech.lower() for tech in backend_techs):
                sections += """- [ ] **Node.js Security**
  - Dependencies updated and vulnerability-free (npm audit)
  - Prototype pollution prevention implemented
  - Secure deserialization practices
  - **OWASP Reference**: [Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)

"""
            
            if any('python' in tech.lower() for tech in backend_techs):
                sections += """- [ ] **Python Security**
  - Avoid pickle deserialization with untrusted data
  - Template injection prevention (Jinja2/Django)
  - Secure configuration management
  - **OWASP Reference**: [Python Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)

"""
        
        # Database technologies
        db_techs = [tech for tech in technology_stack if any(db in tech.lower() for db in ['mysql', 'postgresql', 'mongodb', 'redis', 'sqlite', 'oracle', 'sql'])]
        if db_techs:
            sections += """### Database Technologies
- [ ] **Database Security**
  - Parameterized queries prevent SQL injection
  - Database access controls and least privilege
  - Sensitive data encryption at rest
  - **OWASP Reference**: [Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)

"""
        
        # Container and orchestration
        container_techs = [tech for tech in technology_stack if any(container in tech.lower() for container in ['docker', 'kubernetes', 'container'])]
        if container_techs:
            sections += """### Container & Orchestration
- [ ] **Container Security**
  - Minimal base images used
  - Containers run as non-root users
  - Image vulnerability scanning performed
  - **OWASP Reference**: [Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

"""
            
            if any('kubernetes' in tech.lower() for tech in container_techs):
                sections += """- [ ] **Kubernetes Security**
  - RBAC properly configured
  - Pod Security Standards enforced
  - Network policies implemented
  - **OWASP Reference**: [Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)

"""
        
        # Cloud platforms
        cloud_techs = [tech for tech in technology_stack if any(cloud in tech.lower() for cloud in ['aws', 'azure', 'gcp', 'cloud'])]
        if cloud_techs:
            sections += """### Cloud Platform Security
- [ ] **Cloud Security**
  - IAM policies follow least privilege
  - Resource access controls properly configured
  - Cloud security monitoring enabled
  - **OWASP Reference**: [Cloud Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cloud_Security_Cheat_Sheet.html)

"""
        
        return sections
    
    def save_report_to_file(self, content: str, filename: str, output_dir: str = None) -> str:
        """
        Save a generated report to a file.
        
        Args:
            content: The report content to save
            filename: Name of the file (without path)
            output_dir: Output directory (defaults to config.output_directory)
            
        Returns:
            Full path to the saved file
        """
        output_directory = output_dir or self.config.output_directory
        
        # Create directory if it doesn't exist
        Path(output_directory).mkdir(parents=True, exist_ok=True)
        
        file_path = os.path.join(output_directory, filename)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return file_path
    
    def generate_all_documentation(
        self,
        system: System,
        threats: List[Threat],
        mitigations: List[Mitigation],
        pr_info: Dict[str, Any] = None
    ) -> Dict[str, str]:
        """
        Generate all types of documentation for a complete threat modeling analysis.
        
        Args:
            system: Complete system model
            threats: All identified threats
            mitigations: All planned mitigations
            pr_info: Optional PR information for PR summary
            
        Returns:
            Dictionary mapping document types to file paths
        """
        generated_files = {}
        
        # Generate system threat model
        system_report = self.generate_system_threat_model(system, threats, mitigations)
        system_file = self.save_report_to_file(system_report, "threat-model.md")
        generated_files["system_threat_model"] = system_file
        
        # Generate component threat models
        components_dir = os.path.join(self.config.output_directory, "components")
        Path(components_dir).mkdir(parents=True, exist_ok=True)
        
        for component in system.components:
            component_report = self.generate_component_threat_model(
                component, threats, mitigations, system
            )
            component_filename = f"{component.name.lower().replace(' ', '-')}.md"
            component_file = self.save_report_to_file(
                component_report, component_filename, components_dir
            )
            generated_files[f"component_{component.name}"] = component_file
        
        # Generate PR summary if PR info provided
        if pr_info:
            pr_report = self.generate_pr_security_summary(pr_info, system, threats, mitigations)
            pr_file = self.save_report_to_file(pr_report, f"pr-{pr_info.get('number', 'summary')}-security-analysis.md")
            generated_files["pr_summary"] = pr_file
        
        return generated_files
    
    def generate_repository_documentation(
        self,
        system: System,
        threats: List[Threat],
        mitigations: List[Mitigation],
        repository_path: str = None,
        technology_stack: List[str] = None,
        output_base_dir: str = None
    ) -> Dict[str, str]:
        """
        Generate complete repository security documentation including threat model,
        component documentation, and PR review checklists.
        
        Args:
            system: Complete system model
            threats: All identified threats
            mitigations: All planned mitigations
            repository_path: Path to the repository
            technology_stack: Detected technologies
            output_base_dir: Base directory for output (defaults to docs/security)
            
        Returns:
            Dictionary mapping document types to file paths
        """
        base_dir = output_base_dir or "docs/security"
        generated_files = {}
        
        # 1. Generate high-level repository threat model (subtask 8.1)
        repo_threat_model = self.generate_repository_threat_model(
            system, threats, mitigations, repository_path
        )
        threat_model_file = self.save_report_to_file(
            repo_threat_model, 
            "threat-model.md", 
            base_dir
        )
        generated_files["repository_threat_model"] = threat_model_file
        
        # 2. Generate component-level documentation (subtask 8.2)
        components_dir = os.path.join(base_dir, "components")
        Path(components_dir).mkdir(parents=True, exist_ok=True)
        
        component_files = []
        for component in system.components:
            component_doc = self.generate_component_documentation(
                component, threats, mitigations, system
            )
            component_filename = f"{component.name.lower().replace(' ', '-').replace('_', '-')}.md"
            component_file = self.save_report_to_file(
                component_doc,
                component_filename,
                components_dir
            )
            component_files.append(component_file)
        
        generated_files["component_documentation"] = component_files
        
        # 3. Generate PR review checklist (subtask 8.3)
        checklists_dir = os.path.join(base_dir, "checklists")
        Path(checklists_dir).mkdir(parents=True, exist_ok=True)
        
        pr_checklist = self.generate_pr_review_checklist(
            system, threats, mitigations, technology_stack,
            {"name": system.name, "path": repository_path}
        )
        checklist_file = self.save_report_to_file(
            pr_checklist,
            "pr-review.md",
            checklists_dir
        )
        generated_files["pr_review_checklist"] = checklist_file
        
        # 4. Generate index/README for the security documentation
        security_readme = self._generate_security_documentation_index(
            system, threats, mitigations, generated_files
        )
        readme_file = self.save_report_to_file(
            security_readme,
            "README.md",
            base_dir
        )
        generated_files["security_readme"] = readme_file
        
        return generated_files
    
    def _generate_security_documentation_index(
        self,
        system: System,
        threats: List[Threat],
        mitigations: List[Mitigation],
        generated_files: Dict[str, Any]
    ) -> str:
        """Generate an index/README for the security documentation."""
        
        readme = f"""# Security Documentation: {system.name}

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Tool**: ThreatLens
**Methodology**: OWASP Threat Modeling

## Overview

This directory contains comprehensive security documentation for the {system.name} system, generated following OWASP threat modeling methodology and best practices.

### Documentation Structure

```
docs/security/
├── README.md                    # This file - documentation overview
├── threat-model.md             # High-level system threat model
├── components/                 # Component-level security analysis
│   ├── [component-name].md    # Individual component threat models
│   └── ...
└── checklists/                # Security review checklists
    └── pr-review.md           # Pull request security review checklist
```

## Security Summary

### System Overview
- **Components Analyzed**: {len(system.components)}
- **Data Stores**: {len(system.data_stores)}
- **Trust Boundaries**: {len(system.trust_boundaries)}
- **External Entities**: {len(system.external_entities)}

### Threat Landscape
- **Total Threats**: {len(threats)}
- **High Risk** (≥7.0): {len([t for t in threats if t.risk_score >= 7.0])} threats
- **Medium Risk** (4.0-6.9): {len([t for t in threats if 4.0 <= t.risk_score < 7.0])} threats
- **Low Risk** (<4.0): {len([t for t in threats if t.risk_score < 4.0])} threats

### Security Controls
- **Planned Mitigations**: {len(mitigations)}
- **Critical Priority**: {len([m for m in mitigations if m.priority.value == 'Critical'])}
- **High Priority**: {len([m for m in mitigations if m.priority.value == 'High'])}

## Documentation Guide

### 1. System Threat Model
**File**: [threat-model.md](threat-model.md)

The main threat model document following the OWASP four questions methodology:
- What are we working on? (System architecture)
- What can go wrong? (STRIDE threat analysis)
- What are we going to do about it? (Mitigation strategies)
- Did we do a good enough job? (Quality assessment)

### 2. Component Documentation
**Directory**: [components/](components/)

Detailed security analysis for each system component:
"""
        
        # List component documentation
        for component in system.components:
            component_filename = component.name.lower().replace(' ', '-').replace('_', '-')
            readme += f"- [{component.name}](components/{component_filename}.md) - {component.type.value}\n"
        
        readme += """
### 3. Security Review Checklists
**Directory**: [checklists/](checklists/)

Security review and validation checklists:
- [PR Review Checklist](checklists/pr-review.md) - Security checklist for pull request reviews

## Usage Guidelines

### For Developers
1. **Before Development**: Review the system threat model to understand security context
2. **During Development**: Follow secure coding practices outlined in component documentation
3. **Before Committing**: Use the PR review checklist to validate security requirements

### For Security Reviews
1. **System Assessment**: Start with the main threat model document
2. **Component Analysis**: Review individual component documentation for detailed threats
3. **Code Review**: Use the PR review checklist for systematic security validation

### For Compliance
This documentation supports compliance with:
- OWASP Application Security Verification Standard (ASVS)
- NIST Cybersecurity Framework
- ISO 27001 security controls
- SOC 2 Type II requirements

## Maintenance

### Update Schedule
- **Quarterly**: Review and update threat models
- **After Major Changes**: Update affected component documentation
- **Continuous**: Keep PR review checklist current with new threats

### Update Process
1. Re-run ThreatLens analysis after significant system changes
2. Review and validate updated threat assessments
3. Update mitigation strategies as needed
4. Regenerate documentation with new analysis results

## Key Security Contacts

- **Security Team**: [Contact Information]
- **System Owner**: [Contact Information]
- **Compliance Officer**: [Contact Information]

## Related Resources

### OWASP References
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)

### Internal Resources
- Security Policies and Procedures
- Incident Response Plan
- Security Training Materials

---
*This documentation was automatically generated by ThreatLens. For questions or updates, contact the security team.*
"""
        
        return readme