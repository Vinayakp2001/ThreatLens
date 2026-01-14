"""
Wiki Generation Error Handler - Comprehensive error handling and graceful degradation
for security wiki generation process
"""
import logging
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime

from .models import (
    SecurityModel, WikiSection, WikiSectionContent, SecurityFinding, 
    CodeReference, SecurityWiki
)

logger = logging.getLogger(__name__)


class WikiGenerationError(Exception):
    """Base exception for wiki generation errors"""
    def __init__(self, message: str, section_type: Optional[str] = None, original_error: Optional[Exception] = None):
        self.message = message
        self.section_type = section_type
        self.original_error = original_error
        super().__init__(message)


class SectionGenerationError(WikiGenerationError):
    """Exception for section-specific generation failures"""
    pass


class OWASPIntegrationError(WikiGenerationError):
    """Exception for OWASP guidance integration failures"""
    pass


class ContentGenerationError(WikiGenerationError):
    """Exception for content generation failures"""
    pass


class WikiGenerationErrorHandler:
    """
    Comprehensive error handler for wiki generation failures with graceful degradation
    """
    
    def __init__(self, settings: Dict[str, Any]):
        self.settings = settings
        self.error_counts = {}
        self.fallback_templates = self._initialize_fallback_templates()
        
    def handle_section_generation_error(
        self, 
        section_type: str, 
        error: Exception,
        security_model: SecurityModel,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """
        Handle section generation errors with graceful degradation
        
        Args:
            section_type: Type of section that failed to generate
            error: The original exception that occurred
            security_model: Security model containing analysis data
            context: Additional context for error handling
            
        Returns:
            WikiSection: Fallback section with available data
        """
        logger.error(f"Section generation failed for {section_type}: {error}")
        
        # Track error for monitoring
        self._track_error(section_type, error)
        
        try:
            # Attempt to generate fallback content using existing analysis data
            fallback_section = self._generate_fallback_content(section_type, security_model, error, context)
            
            # Add error information to section metadata
            fallback_section.metadata = {
                "error_occurred": True,
                "error_type": type(error).__name__,
                "error_message": str(error),
                "fallback_generated": True,
                "generation_timestamp": datetime.now().isoformat(),
                "recovery_method": "fallback_content_generation"
            }
            
            logger.info(f"Generated fallback content for {section_type}")
            return fallback_section
            
        except Exception as fallback_error:
            logger.error(f"Fallback generation also failed for {section_type}: {fallback_error}")
            return self._create_minimal_section(section_type, error, fallback_error)
    
    def handle_owasp_integration_error(
        self,
        section: WikiSection,
        error: Exception,
        security_model: SecurityModel
    ) -> WikiSection:
        """
        Handle OWASP guidance integration errors
        
        Args:
            section: The section that failed OWASP integration
            error: The integration error
            security_model: Security model for context
            
        Returns:
            WikiSection: Section with basic OWASP mappings
        """
        logger.warning(f"OWASP integration failed for section {section.title}: {error}")
        
        # Add basic OWASP mappings based on section type
        basic_mappings = self._get_basic_owasp_mappings(section.title.lower())
        section.owasp_mappings = basic_mappings
        
        # Add note about integration failure
        section.content += f"\n\n*Note: Advanced OWASP guidance integration unavailable. Basic mappings applied.*"
        
        # Update metadata to reflect partial integration
        if not hasattr(section, 'metadata'):
            section.metadata = {}
        section.metadata.update({
            "owasp_integration_error": True,
            "owasp_error_message": str(error),
            "basic_mappings_applied": True,
            "integration_timestamp": datetime.now().isoformat()
        })
        
        return section
    
    def handle_content_generation_error(
        self,
        content_type: str,
        error: Exception,
        security_model: SecurityModel,
        component: Optional[Any] = None
    ) -> str:
        """
        Handle content generation errors with template-based fallback
        
        Args:
            content_type: Type of content that failed to generate
            error: The generation error
            security_model: Security model for context
            component: Specific component if applicable
            
        Returns:
            str: Fallback content
        """
        logger.warning(f"Content generation failed for {content_type}: {error}")
        
        try:
            # Use template-based content generation
            template = self.fallback_templates.get(content_type, self.fallback_templates["default"])
            
            # Fill template with available data
            fallback_content = self._fill_template(template, security_model, component, error)
            
            return fallback_content
            
        except Exception as template_error:
            logger.error(f"Template-based fallback also failed for {content_type}: {template_error}")
            return self._create_minimal_content(content_type, error)
    
    def handle_wiki_build_error(
        self,
        sections: Dict[str, WikiSection],
        error: Exception,
        security_model: SecurityModel
    ) -> SecurityWiki:
        """
        Handle wiki building errors by creating partial wiki
        
        Args:
            sections: Successfully generated sections
            error: The wiki building error
            security_model: Security model for context
            
        Returns:
            SecurityWiki: Partial wiki with available sections
        """
        logger.error(f"Wiki building failed: {error}")
        
        # Filter out any None or invalid sections
        valid_sections = {k: v for k, v in sections.items() if v is not None}
        
        # Create simplified cross-references
        cross_references = {}
        for section_name in valid_sections.keys():
            cross_references[section_name] = []
        
        # Create basic search index
        search_index = {}
        for section_name, section in valid_sections.items():
            search_index[section_name] = {
                "title": section.title,
                "content_length": len(section.content) if section.content else 0,
                "has_error": getattr(section, 'metadata', {}).get('error_occurred', False)
            }
        
        return SecurityWiki(
            id=str(uuid.uuid4()),
            repo_id=security_model.repo_id,
            title=f"Security Wiki - {security_model.repo_id} (Partial)",
            sections=valid_sections,
            cross_references=cross_references,
            search_index=search_index,
            metadata={
                "generation_type": "partial_security_wiki",
                "sections_count": len(valid_sections),
                "error_occurred": True,
                "error_type": type(error).__name__,
                "error_message": str(error),
                "generation_timestamp": datetime.now().isoformat(),
                "partial_generation": True,
                "recovery_method": "partial_wiki_generation"
            }
        )
    
    def _generate_fallback_content(
        self, 
        section_type: str, 
        security_model: SecurityModel, 
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """Generate fallback content using existing analysis data"""
        
        section_generators = {
            "executive_summary": self._generate_fallback_executive_summary,
            "system_architecture": self._generate_fallback_system_architecture,
            "authentication_analysis": self._generate_fallback_auth_analysis,
            "data_flow_security": self._generate_fallback_data_flow,
            "vulnerability_analysis": self._generate_fallback_vulnerability_analysis,
            "threat_landscape": self._generate_fallback_threat_landscape,
            "security_controls": self._generate_fallback_security_controls,
            "risk_assessment": self._generate_fallback_risk_assessment,
            "security_checklist": self._generate_fallback_security_checklist,
            "code_findings": self._generate_fallback_code_findings
        }
        
        generator = section_generators.get(section_type, self._generate_generic_fallback)
        return generator(security_model, error, context)
    
    def _generate_fallback_executive_summary(
        self, 
        security_model: SecurityModel, 
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """Generate fallback executive summary using basic model data"""
        
        content = f"""# Executive Summary

## Repository Analysis Overview
- **Repository**: {security_model.repo_id}
- **Components Analyzed**: {len(security_model.components)}
- **Data Flows Analyzed**: {len(security_model.flows)}
- **Data Stores Identified**: {len(security_model.data_stores)}

## Key Security Observations
"""
        
        # Add basic component analysis
        sensitive_components = [c for c in security_model.components if c.handles_sensitive_data]
        if sensitive_components:
            content += f"- {len(sensitive_components)} components handle sensitive data\n"
        
        auth_components = [c for c in security_model.components if c.auth_mechanisms]
        if auth_components:
            content += f"- {len(auth_components)} components implement authentication mechanisms\n"
        
        # Add trust boundary information
        if security_model.trust_boundaries:
            content += f"- {len(security_model.trust_boundaries)} trust boundaries identified\n"
        
        content += f"\n*Note: Detailed analysis unavailable due to generation error: {str(error)}*"
        
        return WikiSection(
            id=str(uuid.uuid4()),
            title="Executive Summary",
            content=content,
            subsections=[],
            cross_references=["system_architecture", "vulnerability_analysis"],
            owasp_mappings=["threat_modeling", "secure_design"],
            code_references=self._extract_basic_code_references(security_model, limit=5),
            security_findings=[],
            recommendations=["Review system architecture for security implications", "Implement comprehensive security controls"]
        )
    
    def _generate_fallback_system_architecture(
        self, 
        security_model: SecurityModel, 
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """Generate fallback system architecture using component data"""
        
        content = f"""# System Architecture & Components

## Component Overview
The system consists of {len(security_model.components)} components:

"""
        
        for component in security_model.components:
            content += f"""### {component.name}
- **Type**: {component.type.value}
- **File Path**: {component.file_path}
- **Handles Sensitive Data**: {component.handles_sensitive_data}
- **Endpoints**: {len(component.endpoints)}
- **Authentication Mechanisms**: {', '.join(component.auth_mechanisms) if component.auth_mechanisms else 'None'}

"""
        
        if security_model.trust_boundaries:
            content += "\n## Trust Boundaries\n"
            for boundary in security_model.trust_boundaries:
                content += f"- **{boundary.name}**: {boundary.description}\n"
        
        content += f"\n*Note: Detailed architectural analysis unavailable due to error: {str(error)}*"
        
        return WikiSection(
            id=str(uuid.uuid4()),
            title="System Architecture & Components",
            content=content,
            subsections=[],
            cross_references=["data_flow_security", "authentication_analysis"],
            owasp_mappings=["secure_design", "threat_modeling"],
            code_references=self._extract_component_code_references(security_model),
            security_findings=[],
            recommendations=["Review component security configurations", "Validate trust boundary implementations"]
        )
    
    def _generate_fallback_auth_analysis(
        self, 
        security_model: SecurityModel, 
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """Generate fallback authentication analysis"""
        
        content = f"""# Authentication & Authorization Analysis

## Authentication Mechanisms Overview
"""
        
        auth_components = [c for c in security_model.components if c.auth_mechanisms]
        if auth_components:
            content += f"Found {len(auth_components)} components with authentication mechanisms:\n\n"
            for component in auth_components:
                content += f"- **{component.name}**: {', '.join(component.auth_mechanisms)}\n"
        else:
            content += "No explicit authentication mechanisms identified in component analysis.\n"
        
        content += "\n## Authorization Analysis\n"
        
        # Check for endpoints requiring auth
        auth_endpoints = []
        for component in security_model.components:
            for endpoint in component.endpoints:
                if endpoint.requires_auth:
                    auth_endpoints.append(endpoint)
        
        if auth_endpoints:
            content += f"Found {len(auth_endpoints)} endpoints requiring authorization.\n"
        else:
            content += "No endpoints explicitly marked as requiring authorization.\n"
        
        content += f"\n*Note: Detailed authentication analysis unavailable due to error: {str(error)}*"
        
        return WikiSection(
            id=str(uuid.uuid4()),
            title="Authentication & Authorization Analysis",
            content=content,
            subsections=[],
            cross_references=["system_architecture", "vulnerability_analysis"],
            owasp_mappings=["authentication", "access_control"],
            code_references=self._extract_auth_code_references(security_model),
            security_findings=[],
            recommendations=["Implement comprehensive authentication", "Review authorization controls"]
        )
    
    def _generate_fallback_data_flow(
        self, 
        security_model: SecurityModel, 
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """Generate fallback data flow analysis"""
        
        content = f"""# Data Flow Security Assessment

## Data Flow Overview
Identified {len(security_model.flows)} data flows in the system:

"""
        
        for flow in security_model.flows:
            content += f"""### {flow.name}
- **Source**: {flow.source}
- **Destination**: {flow.destination}
- **Data Sensitivity**: {flow.data_sensitivity.value}
- **Protocol**: {flow.protocol}
- **Encrypted**: {flow.encrypted}

"""
        
        # Analyze sensitive flows
        sensitive_flows = [f for f in security_model.flows if f.data_sensitivity.value in ["confidential", "restricted"]]
        if sensitive_flows:
            content += f"\n## Sensitive Data Flows\n{len(sensitive_flows)} flows handle sensitive data:\n"
            for flow in sensitive_flows:
                content += f"- {flow.name}: {flow.data_sensitivity.value}\n"
        
        content += f"\n*Note: Detailed flow analysis unavailable due to error: {str(error)}*"
        
        return WikiSection(
            id=str(uuid.uuid4()),
            title="Data Flow Security Assessment",
            content=content,
            subsections=[],
            cross_references=["system_architecture", "vulnerability_analysis"],
            owasp_mappings=["input_validation", "secure_design"],
            code_references=[],
            security_findings=[],
            recommendations=["Encrypt sensitive data flows", "Validate data at trust boundaries"]
        )
    
    def _generate_fallback_vulnerability_analysis(
        self, 
        security_model: SecurityModel, 
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """Generate fallback vulnerability analysis"""
        
        content = f"""# Vulnerability Analysis

## Basic Security Assessment
Based on component analysis, potential security concerns:

"""
        
        # Check for components with sensitive data but no auth
        vulnerable_components = []
        for component in security_model.components:
            if component.handles_sensitive_data and not component.auth_mechanisms:
                vulnerable_components.append(component)
        
        if vulnerable_components:
            content += f"## Components Handling Sensitive Data Without Authentication\n"
            for component in vulnerable_components:
                content += f"- **{component.name}**: Handles sensitive data but no auth mechanisms identified\n"
        
        # Check for unencrypted sensitive flows
        unencrypted_sensitive = [f for f in security_model.flows 
                               if f.data_sensitivity.value in ["confidential", "restricted"] and not f.encrypted]
        
        if unencrypted_sensitive:
            content += f"\n## Unencrypted Sensitive Data Flows\n"
            for flow in unencrypted_sensitive:
                content += f"- **{flow.name}**: {flow.data_sensitivity.value} data not encrypted\n"
        
        content += f"\n*Note: Comprehensive vulnerability analysis unavailable due to error: {str(error)}*"
        
        return WikiSection(
            id=str(uuid.uuid4()),
            title="Vulnerability Analysis",
            content=content,
            subsections=[],
            cross_references=["threat_landscape", "security_controls"],
            owasp_mappings=["input_validation", "authentication", "access_control"],
            code_references=[],
            security_findings=[],
            recommendations=["Implement authentication for sensitive components", "Encrypt sensitive data flows"]
        )
    
    def _generate_fallback_threat_landscape(
        self, 
        security_model: SecurityModel, 
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """Generate fallback threat landscape analysis"""
        
        content = f"""# Threat Landscape

## Basic Threat Assessment
Based on system architecture, potential threat areas:

## Component-Based Threats
"""
        
        for component in security_model.components:
            if component.handles_sensitive_data or component.endpoints:
                content += f"""### {component.name}
- **Threat Surface**: {len(component.endpoints)} endpoints
- **Data Sensitivity**: {'High' if component.handles_sensitive_data else 'Medium'}
- **Authentication**: {'Implemented' if component.auth_mechanisms else 'Not Identified'}

"""
        
        content += f"\n*Note: Detailed STRIDE analysis unavailable due to error: {str(error)}*"
        
        return WikiSection(
            id=str(uuid.uuid4()),
            title="Threat Landscape",
            content=content,
            subsections=[],
            cross_references=["vulnerability_analysis", "security_controls"],
            owasp_mappings=["threat_modeling"],
            code_references=[],
            security_findings=[],
            recommendations=["Conduct detailed threat modeling", "Implement threat-specific controls"]
        )
    
    def _generate_fallback_security_controls(
        self, 
        security_model: SecurityModel, 
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """Generate fallback security controls analysis"""
        
        content = f"""# Security Controls & Mitigations

## Identified Security Patterns
"""
        
        patterns = security_model.security_patterns
        if patterns.authentication_mechanisms:
            content += f"### Authentication Mechanisms\n"
            for mech in patterns.authentication_mechanisms:
                content += f"- {mech}\n"
        
        if patterns.authorization_patterns:
            content += f"\n### Authorization Patterns\n"
            for pattern in patterns.authorization_patterns:
                content += f"- {pattern}\n"
        
        if patterns.input_validation_patterns:
            content += f"\n### Input Validation Patterns\n"
            for pattern in patterns.input_validation_patterns:
                content += f"- {pattern}\n"
        
        content += f"\n*Note: Detailed security controls analysis unavailable due to error: {str(error)}*"
        
        return WikiSection(
            id=str(uuid.uuid4()),
            title="Security Controls & Mitigations",
            content=content,
            subsections=[],
            cross_references=["vulnerability_analysis", "threat_landscape"],
            owasp_mappings=["access_control", "authentication", "secure_design"],
            code_references=[],
            security_findings=[],
            recommendations=["Implement comprehensive security controls", "Regular security control validation"]
        )
    
    def _generate_fallback_risk_assessment(
        self, 
        security_model: SecurityModel, 
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """Generate fallback risk assessment"""
        
        content = f"""# Risk Assessment Matrix

## Basic Risk Analysis
"""
        
        high_risk_components = [c for c in security_model.components if c.handles_sensitive_data]
        medium_risk_components = [c for c in security_model.components if c.endpoints and not c.handles_sensitive_data]
        
        content += f"- **High Risk Components**: {len(high_risk_components)} (handle sensitive data)\n"
        content += f"- **Medium Risk Components**: {len(medium_risk_components)} (have endpoints)\n"
        content += f"- **Total Components**: {len(security_model.components)}\n"
        
        content += f"\n*Note: Detailed risk assessment unavailable due to error: {str(error)}*"
        
        return WikiSection(
            id=str(uuid.uuid4()),
            title="Risk Assessment Matrix",
            content=content,
            subsections=[],
            cross_references=["vulnerability_analysis", "threat_landscape"],
            owasp_mappings=["threat_modeling"],
            code_references=[],
            security_findings=[],
            recommendations=["Conduct detailed risk assessment", "Prioritize high-risk components"]
        )
    
    def _generate_fallback_security_checklist(
        self, 
        security_model: SecurityModel, 
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """Generate fallback security checklist"""
        
        content = f"""# Security Checklist & Recommendations

## Basic Security Checklist

### Authentication & Authorization
- [ ] Implement authentication for all sensitive endpoints
- [ ] Validate authorization for all protected resources
- [ ] Use secure session management

### Data Protection
- [ ] Encrypt sensitive data at rest and in transit
- [ ] Implement proper key management
- [ ] Validate data integrity

### Input Validation
- [ ] Validate all user inputs
- [ ] Sanitize data before processing
- [ ] Use parameterized queries

### Component Security
"""
        
        for component in security_model.components:
            if component.handles_sensitive_data:
                content += f"- [ ] Review security of {component.name}\n"
        
        content += f"\n*Note: Detailed recommendations unavailable due to error: {str(error)}*"
        
        return WikiSection(
            id=str(uuid.uuid4()),
            title="Security Checklist & Recommendations",
            content=content,
            subsections=[],
            cross_references=["security_controls", "vulnerability_analysis"],
            owasp_mappings=["secure_design", "authentication", "input_validation"],
            code_references=[],
            security_findings=[],
            recommendations=["Follow security checklist", "Regular security reviews"]
        )
    
    def _generate_fallback_code_findings(
        self, 
        security_model: SecurityModel, 
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """Generate fallback code findings"""
        
        content = f"""# Code-Level Security Findings

## Component Analysis
"""
        
        for component in security_model.components:
            content += f"""### {component.name}
- **File**: {component.file_path}
- **Type**: {component.type.value}
- **Endpoints**: {len(component.endpoints)}
- **Security Relevance**: {'High' if component.handles_sensitive_data else 'Medium'}

"""
        
        content += f"\n*Note: Detailed code analysis unavailable due to error: {str(error)}*"
        
        return WikiSection(
            id=str(uuid.uuid4()),
            title="Code-Level Security Findings",
            content=content,
            subsections=[],
            cross_references=["system_architecture", "vulnerability_analysis"],
            owasp_mappings=["code_review", "secure_design"],
            code_references=self._extract_basic_code_references(security_model),
            security_findings=[],
            recommendations=["Conduct detailed code review", "Implement secure coding practices"]
        )
    
    def _generate_generic_fallback(
        self, 
        security_model: SecurityModel, 
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> WikiSection:
        """Generate generic fallback section"""
        
        content = f"""# Security Analysis Section

## Basic Information
- **Repository**: {security_model.repo_id}
- **Components**: {len(security_model.components)}
- **Data Flows**: {len(security_model.flows)}

*Note: Detailed analysis unavailable due to error: {str(error)}*
"""
        
        return WikiSection(
            id=str(uuid.uuid4()),
            title="Security Analysis",
            content=content,
            subsections=[],
            cross_references=[],
            owasp_mappings=[],
            code_references=[],
            security_findings=[],
            recommendations=["Review system for security implications"]
        )
    
    def _create_minimal_section(self, section_type: str, original_error: Exception, fallback_error: Exception) -> WikiSection:
        """Create minimal section when all generation attempts fail"""
        
        content = f"""# {section_type.replace('_', ' ').title()}

## Error Information
This section could not be generated due to errors in the analysis process.

- **Original Error**: {str(original_error)}
- **Fallback Error**: {str(fallback_error)}

Please review the system logs for more details and consider manual analysis of this area.
"""
        
        return WikiSection(
            id=str(uuid.uuid4()),
            title=f"{section_type.replace('_', ' ').title()} (Error)",
            content=content,
            subsections=[],
            cross_references=[],
            owasp_mappings=[],
            code_references=[],
            security_findings=[],
            recommendations=["Manual review required due to generation errors"]
        )
    
    def _track_error(self, section_type: str, error: Exception):
        """Track errors for monitoring and analysis"""
        error_key = f"{section_type}_{type(error).__name__}"
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        
        logger.warning(f"Error tracked: {error_key} (count: {self.error_counts[error_key]})")
    
    def _get_basic_owasp_mappings(self, section_title: str) -> List[str]:
        """Get basic OWASP mappings based on section type"""
        
        mapping_dict = {
            "executive": ["threat_modeling", "secure_design"],
            "system": ["secure_design", "threat_modeling"],
            "authentication": ["authentication", "access_control"],
            "data": ["input_validation", "secure_design"],
            "vulnerability": ["input_validation", "authentication", "access_control"],
            "threat": ["threat_modeling"],
            "security": ["access_control", "authentication", "secure_design"],
            "risk": ["threat_modeling"],
            "checklist": ["secure_design", "authentication", "input_validation"],
            "code": ["code_review", "secure_design"]
        }
        
        for key, mappings in mapping_dict.items():
            if key in section_title:
                return mappings
        
        return ["secure_design"]  # Default mapping
    
    def _initialize_fallback_templates(self) -> Dict[str, str]:
        """Initialize fallback content templates"""
        
        return {
            "default": """# {title}

## Analysis Overview
Basic analysis based on available system data.

{content}

*Note: Detailed analysis unavailable due to generation error.*
""",
            "component_analysis": """## Component: {component_name}
- **Type**: {component_type}
- **File**: {file_path}
- **Security Relevance**: {security_level}
""",
            "flow_analysis": """## Data Flow: {flow_name}
- **Source**: {source}
- **Destination**: {destination}
- **Sensitivity**: {sensitivity}
""",
            "error_notice": """*Note: {error_type} occurred during generation. Fallback content provided.*"""
        }
    
    def _fill_template(self, template: str, security_model: SecurityModel, component: Any, error: Exception) -> str:
        """Fill template with available data"""
        
        try:
            if component:
                return template.format(
                    title=getattr(component, 'name', 'Component'),
                    component_name=getattr(component, 'name', 'Unknown'),
                    component_type=getattr(component, 'type', 'Unknown'),
                    file_path=getattr(component, 'file_path', 'Unknown'),
                    security_level='High' if getattr(component, 'handles_sensitive_data', False) else 'Medium',
                    content=f"Basic information for {getattr(component, 'name', 'component')}",
                    error_type=type(error).__name__
                )
            else:
                return template.format(
                    title="Security Analysis",
                    content=f"Repository: {security_model.repo_id}",
                    error_type=type(error).__name__
                )
        except Exception:
            return f"# Security Analysis\n\nBasic analysis for {security_model.repo_id}\n\n*Error in template generation.*"
    
    def _create_minimal_content(self, content_type: str, error: Exception) -> str:
        """Create minimal content when template filling fails"""
        
        return f"""# {content_type.replace('_', ' ').title()}

Basic security analysis content.

*Note: Detailed content generation failed due to {type(error).__name__}.*
"""
    
    def _extract_basic_code_references(self, security_model: SecurityModel, limit: int = 10) -> List[CodeReference]:
        """Extract basic code references from security model"""
        
        references = []
        
        for component in security_model.components[:limit]:
            references.append(
                CodeReference(
                    id=str(uuid.uuid4()),
                    file_path=component.file_path,
                    line_start=1,
                    function_name=component.name,
                    code_snippet=f"Component: {component.name} ({component.type.value})"
                )
            )
        
        return references
    
    def _extract_component_code_references(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract component-specific code references"""
        
        references = []
        
        for component in security_model.components:
            references.append(
                CodeReference(
                    id=str(uuid.uuid4()),
                    file_path=component.file_path,
                    line_start=1,
                    function_name=component.name,
                    code_snippet=f"Component: {component.name} - {component.type.value}"
                )
            )
        
        return references[:15]  # Limit to avoid overwhelming
    
    def _extract_auth_code_references(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract authentication-related code references"""
        
        references = []
        
        for component in security_model.components:
            if component.auth_mechanisms:
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=component.file_path,
                        line_start=1,
                        function_name=component.name,
                        code_snippet=f"Auth: {component.name} - {', '.join(component.auth_mechanisms)}"
                    )
                )
        
        return references
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics for monitoring"""
        
        return {
            "total_errors": sum(self.error_counts.values()),
            "error_breakdown": dict(self.error_counts),
            "most_common_error": max(self.error_counts.items(), key=lambda x: x[1]) if self.error_counts else None,
            "statistics_timestamp": datetime.now().isoformat()
        }
    
    def reset_error_tracking(self):
        """Reset error tracking counters"""
        self.error_counts.clear()
        logger.info("Error tracking counters reset")
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status of wiki generation"""
        
        total_errors = sum(self.error_counts.values())
        
        # Determine health status based on error patterns
        if total_errors == 0:
            health_status = "healthy"
        elif total_errors < 5:
            health_status = "warning"
        else:
            health_status = "critical"
        
        return {
            "status": health_status,
            "total_errors": total_errors,
            "error_rate": self._calculate_error_rate(),
            "most_problematic_section": self._get_most_problematic_section(),
            "recommendations": self._get_health_recommendations(health_status),
            "timestamp": datetime.now().isoformat()
        }
    
    def _calculate_error_rate(self) -> float:
        """Calculate error rate as percentage"""
        total_errors = sum(self.error_counts.values())
        # Assuming we track generation attempts (simplified for now)
        total_attempts = max(total_errors * 2, 1)  # Rough estimate
        return (total_errors / total_attempts) * 100
    
    def _get_most_problematic_section(self) -> Optional[str]:
        """Get the section type with most errors"""
        if not self.error_counts:
            return None
        
        most_common = max(self.error_counts.items(), key=lambda x: x[1])
        return most_common[0].split('_')[0]  # Extract section type from error key
    
    def _get_health_recommendations(self, health_status: str) -> List[str]:
        """Get recommendations based on health status"""
        
        recommendations = []
        
        if health_status == "critical":
            recommendations.extend([
                "Review LLM service availability and configuration",
                "Check system resources and memory usage",
                "Consider implementing circuit breaker pattern",
                "Review error logs for recurring patterns"
            ])
        elif health_status == "warning":
            recommendations.extend([
                "Monitor error patterns for trends",
                "Review fallback content quality",
                "Consider optimizing section generation order"
            ])
        else:
            recommendations.append("System operating normally")
        
        # Add section-specific recommendations
        problematic_section = self._get_most_problematic_section()
        if problematic_section:
            recommendations.append(f"Focus attention on {problematic_section} section generation")
        
        return recommendations