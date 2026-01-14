"""
Security Wiki Generator - DeepWiki-style comprehensive security documentation
Replaces rigid threat document types with flexible content generation
"""
import asyncio
import logging
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime

from .models import (
    SecurityDocument, SecurityModel, Component, Flow, CodeReference,
    SecurityWiki, WikiSection, WikiSectionContent, SecurityFinding, OWASPMapping
)
from .llm_client import LLMManager, LLMError
from .security_content_generators import SecurityContentGenerators
from .wiki_error_handler import WikiGenerationErrorHandler, WikiGenerationError, SectionGenerationError


logger = logging.getLogger(__name__)
DEBUG_ANALYSIS = logging.getLogger('DEBUG_ANALYSIS')


class SecurityWikiGenerator:
    """
    Main class for generating comprehensive security documentation similar to DeepWiki
    Focuses on security analysis rather than rigid threat modeling document types
    """
    
    def __init__(self, settings):
        self.settings = settings
        self.llm_manager = LLMManager()
        self.content_generators = SecurityContentGenerators()
        self.error_handler = WikiGenerationErrorHandler(settings)
    
    async def generate_comprehensive_security_wiki(
        self, 
        security_model: SecurityModel,
        scope: str = "full_repo"
    ) -> SecurityWiki:
        """
        Generate unified security wiki with all OWASP guidance embedded
        """
        logger.info(f"Generating comprehensive security wiki for repo {security_model.repo_id}")
        
        try:
            # Generate all wiki sections using existing analysis components
            wiki_sections = await self._generate_all_wiki_sections(security_model)
            
            # Integrate OWASP guidance throughout sections
            enhanced_sections = await self._integrate_owasp_guidance(wiki_sections, security_model)
            
            # Create interconnected wiki structure
            wiki = self._build_interconnected_wiki(enhanced_sections, security_model)
            
            logger.info(f"Successfully generated comprehensive security wiki: {wiki.id}")
            return wiki
            
        except Exception as e:
            logger.error(f"Failed to generate comprehensive security wiki: {e}")
            # Use error handler to create partial wiki with available data
            return self.error_handler.handle_wiki_build_error({}, e, security_model)
    
    async def _generate_all_wiki_sections(self, security_model: SecurityModel) -> Dict[str, WikiSection]:
        """Generate all wiki sections using existing analysis components"""
        logger.info("Generating all wiki sections")
        sections = {}
        
        # Generate sections concurrently for better performance
        tasks = [
            ("executive_summary", self._generate_executive_summary(security_model)),
            ("system_architecture", self._generate_system_architecture_section(security_model)),
            ("authentication_analysis", self._generate_auth_analysis_section(security_model)),
            ("data_flow_security", self._generate_data_flow_section(security_model)),
            ("vulnerability_analysis", self._generate_vulnerability_section(security_model)),
            ("threat_landscape", self._generate_threat_landscape_section(security_model)),
            ("security_controls", self._generate_security_controls_section(security_model)),
            ("risk_assessment", self._generate_risk_assessment_section(security_model)),
            ("security_checklist", self._generate_security_checklist_section(security_model)),
            ("code_findings", self._generate_code_findings_section(security_model))
        ]
        
        # Execute tasks in batches to avoid overwhelming the LLM API
        batch_size = 3
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            
            batch_results = await asyncio.gather(
                *[task[1] for task in batch], 
                return_exceptions=True
            )
            
            for j, result in enumerate(batch_results):
                section_name = batch[j][0]
                if isinstance(result, Exception):
                    logger.error(f"Failed to generate {section_name}: {result}")
                    # Use error handler for graceful degradation
                    sections[section_name] = self.error_handler.handle_section_generation_error(
                        section_name, result, security_model
                    )
                else:
                    sections[section_name] = result
            
            # Small delay between batches
            if i + batch_size < len(tasks):
                await asyncio.sleep(1)
        
        return sections
    
    async def _generate_executive_summary(self, security_model: SecurityModel) -> WikiSection:
        """Generate executive summary section with key security findings"""
        try:
            content = await self.content_generators.generate_security_overview(security_model)
            
            # Extract key findings for cross-referencing
            security_findings = self._extract_security_findings_from_content(content, "executive")
            
            return WikiSection(
                id=str(uuid.uuid4()),
                title="Executive Summary",
                content=content,
                subsections=[],
                cross_references=["system_architecture", "vulnerability_analysis", "risk_assessment"],
                owasp_mappings=["threat_modeling", "secure_design"],
                code_references=self._extract_key_code_references(security_model),
                security_findings=security_findings,
                recommendations=self._extract_recommendations_from_content(content),
                metadata={"generation_method": "llm_generated", "error_occurred": False}
            )
        except Exception as e:
            logger.error(f"Failed to generate executive summary: {e}")
            raise SectionGenerationError(f"Executive summary generation failed: {e}", "executive_summary", e)
    
    async def _generate_system_architecture_section(self, security_model: SecurityModel) -> WikiSection:
        """Generate system architecture section with security focus"""
        try:
            # Use existing content generator but enhance with security focus
            content = await self.content_generators.generate_security_overview(security_model)
            
            # Add architecture-specific analysis
            architecture_content = f"""# System Architecture & Components

## Architecture Overview
{content}

## Security-Critical Components
"""
            
            # Add component analysis
            for component in security_model.components:
                if component.handles_sensitive_data or component.auth_mechanisms:
                    architecture_content += f"""
### {component.name} ({component.type.value})
- **File Path**: {component.file_path}
- **Handles Sensitive Data**: {component.handles_sensitive_data}
- **Authentication Mechanisms**: {', '.join(component.auth_mechanisms) if component.auth_mechanisms else 'None'}
- **Endpoints**: {len(component.endpoints)} endpoints
"""
            
            security_findings = self._extract_security_findings_from_content(architecture_content, "architecture")
            
            return WikiSection(
                id=str(uuid.uuid4()),
                title="System Architecture & Components",
                content=architecture_content,
                subsections=[],
                cross_references=["data_flow_security", "authentication_analysis", "code_findings"],
                owasp_mappings=["secure_design", "threat_modeling"],
                code_references=self._extract_component_code_references(security_model),
                security_findings=security_findings,
                recommendations=self._extract_recommendations_from_content(architecture_content),
                metadata={"generation_method": "enhanced_llm", "error_occurred": False}
            )
        except Exception as e:
            logger.error(f"Failed to generate system architecture section: {e}")
            raise SectionGenerationError(f"System architecture generation failed: {e}", "system_architecture", e)
    
    async def _generate_auth_analysis_section(self, security_model: SecurityModel) -> WikiSection:
        """Generate authentication & authorization analysis section"""
        try:
            auth_content = await self.content_generators.generate_authentication_analysis(security_model)
            authz_content = await self.content_generators.generate_authorization_analysis(security_model)
            
            combined_content = f"""# Authentication & Authorization Analysis

## Authentication Analysis
{auth_content}

## Authorization Analysis
{authz_content}
"""
            
            security_findings = self._extract_security_findings_from_content(combined_content, "auth")
            
            return WikiSection(
                id=str(uuid.uuid4()),
                title="Authentication & Authorization Analysis",
                content=combined_content,
                subsections=[],
                cross_references=["system_architecture", "vulnerability_analysis", "security_controls"],
                owasp_mappings=["authentication", "access_control"],
                code_references=self._extract_auth_code_references(security_model),
                security_findings=security_findings,
                recommendations=self._extract_recommendations_from_content(combined_content),
                metadata={"generation_method": "dual_llm", "error_occurred": False}
            )
        except Exception as e:
            logger.error(f"Failed to generate auth analysis section: {e}")
            raise SectionGenerationError(f"Authentication analysis generation failed: {e}", "authentication_analysis", e)
    
    async def _generate_data_flow_section(self, security_model: SecurityModel) -> WikiSection:
        """Generate data flow security assessment section"""
        try:
            content = await self.content_generators.generate_data_flow_analysis(security_model)
            
            # Enhance with trust boundary analysis
            enhanced_content = f"""# Data Flow Security Assessment

{content}

## Trust Boundary Analysis
"""
            
            for boundary in security_model.trust_boundaries:
                enhanced_content += f"""
### {boundary.name}
- **Description**: {boundary.description}
- **Components Inside**: {', '.join(boundary.components_inside)}
- **Components Outside**: {', '.join(boundary.components_outside)}
"""
            
            security_findings = self._extract_security_findings_from_content(enhanced_content, "dataflow")
            
            return WikiSection(
                id=str(uuid.uuid4()),
                title="Data Flow Security Assessment",
                content=enhanced_content,
                subsections=[],
                cross_references=["system_architecture", "vulnerability_analysis", "threat_landscape"],
                owasp_mappings=["input_validation", "secure_design"],
                code_references=self._extract_flow_code_references(security_model),
                security_findings=security_findings,
                recommendations=self._extract_recommendations_from_content(enhanced_content),
                metadata={"generation_method": "enhanced_llm", "error_occurred": False}
            )
        except Exception as e:
            logger.error(f"Failed to generate data flow section: {e}")
            raise SectionGenerationError(f"Data flow analysis generation failed: {e}", "data_flow_security", e)
    
    async def _generate_vulnerability_section(self, security_model: SecurityModel) -> WikiSection:
        """Generate vulnerability analysis section using OWASP Top 10"""
        try:
            content = await self.content_generators.generate_vulnerability_assessment(security_model)
            
            security_findings = self._extract_security_findings_from_content(content, "vulnerability")
            
            return WikiSection(
                id=str(uuid.uuid4()),
                title="Vulnerability Analysis",
                content=content,
                subsections=[],
                cross_references=["threat_landscape", "security_controls", "code_findings"],
                owasp_mappings=["input_validation", "authentication", "access_control"],
                code_references=self._extract_vulnerability_code_references(security_model),
                security_findings=security_findings,
                recommendations=self._extract_recommendations_from_content(content),
                metadata={"generation_method": "llm_generated", "error_occurred": False}
            )
        except Exception as e:
            logger.error(f"Failed to generate vulnerability section: {e}")
            raise SectionGenerationError(f"Vulnerability analysis generation failed: {e}", "vulnerability_analysis", e)
    
    async def _generate_threat_landscape_section(self, security_model: SecurityModel) -> WikiSection:
        """Generate threat landscape section using STRIDE methodology"""
        try:
            # Generate STRIDE-based threat analysis content
            content = f"""# Threat Landscape

## STRIDE Analysis

This section analyzes potential threats using the STRIDE methodology across all system components.

## Component Threat Analysis
"""
            
            for component in security_model.components:
                if component.handles_sensitive_data or component.endpoints:
                    content += f"""
### {component.name} Threats
- **Component Type**: {component.type.value}
- **Sensitive Data Handling**: {component.handles_sensitive_data}
- **Potential Threats**: Analysis of STRIDE categories for this component
"""
            
            security_findings = self._extract_security_findings_from_content(content, "threat")
            
            return WikiSection(
                id=str(uuid.uuid4()),
                title="Threat Landscape",
                content=content,
                subsections=[],
                cross_references=["vulnerability_analysis", "security_controls", "risk_assessment"],
                owasp_mappings=["threat_modeling"],
                code_references=self._extract_threat_code_references(security_model),
                security_findings=security_findings,
                recommendations=self._extract_recommendations_from_content(content),
                metadata={"generation_method": "template_based", "error_occurred": False}
            )
        except Exception as e:
            logger.error(f"Failed to generate threat landscape section: {e}")
            raise SectionGenerationError(f"Threat landscape generation failed: {e}", "threat_landscape", e)
    
    async def _generate_security_controls_section(self, security_model: SecurityModel) -> WikiSection:
        """Generate security controls & mitigations section"""
        try:
            content = await self.content_generators.generate_security_recommendations(security_model)
            
            # Enhance with specific controls analysis
            enhanced_content = f"""# Security Controls & Mitigations

{content}

## Implemented Security Patterns
"""
            
            patterns = security_model.security_patterns
            if patterns.authentication_mechanisms:
                enhanced_content += f"\n### Authentication Mechanisms\n- {chr(10).join(f'- {mech}' for mech in patterns.authentication_mechanisms)}"
            
            if patterns.authorization_patterns:
                enhanced_content += f"\n### Authorization Patterns\n- {chr(10).join(f'- {pattern}' for pattern in patterns.authorization_patterns)}"
            
            security_findings = self._extract_security_findings_from_content(enhanced_content, "controls")
            
            return WikiSection(
                id=str(uuid.uuid4()),
                title="Security Controls & Mitigations",
                content=enhanced_content,
                subsections=[],
                cross_references=["vulnerability_analysis", "threat_landscape", "security_checklist"],
                owasp_mappings=["access_control", "authentication", "secure_design"],
                code_references=self._extract_controls_code_references(security_model),
                security_findings=security_findings,
                recommendations=self._extract_recommendations_from_content(enhanced_content),
                metadata={"generation_method": "enhanced_llm", "error_occurred": False}
            )
        except Exception as e:
            logger.error(f"Failed to generate security controls section: {e}")
            raise SectionGenerationError(f"Security controls generation failed: {e}", "security_controls", e)
    
    async def _generate_risk_assessment_section(self, security_model: SecurityModel) -> WikiSection:
        """Generate risk assessment matrix section"""
        try:
            content = f"""# Risk Assessment Matrix

## Overall Risk Assessment

This section provides a comprehensive risk assessment based on the identified vulnerabilities, threats, and existing security controls.

## Component Risk Analysis
"""
            
            for component in security_model.components:
                if component.handles_sensitive_data:
                    content += f"""
### {component.name} Risk Profile
- **Sensitivity Level**: High (handles sensitive data)
- **Exposure**: {len(component.endpoints)} endpoints
- **Authentication Required**: {any(ep.requires_auth for ep in component.endpoints)}
"""
            
            security_findings = self._extract_security_findings_from_content(content, "risk")
            
            return WikiSection(
                id=str(uuid.uuid4()),
                title="Risk Assessment Matrix",
                content=content,
                subsections=[],
                cross_references=["vulnerability_analysis", "threat_landscape", "executive_summary"],
                owasp_mappings=["threat_modeling"],
                code_references=[],
                security_findings=security_findings,
                recommendations=self._extract_recommendations_from_content(content),
                metadata={"generation_method": "template_based", "error_occurred": False}
            )
        except Exception as e:
            logger.error(f"Failed to generate risk assessment section: {e}")
            raise SectionGenerationError(f"Risk assessment generation failed: {e}", "risk_assessment", e)
    
    async def _generate_security_checklist_section(self, security_model: SecurityModel) -> WikiSection:
        """Generate security checklist & recommendations section"""
        try:
            content = await self.content_generators.generate_security_recommendations(security_model)
            
            # Add checklist format
            checklist_content = f"""# Security Checklist & Recommendations

{content}

## Security Implementation Checklist

### Authentication & Authorization
- [ ] Implement proper authentication mechanisms
- [ ] Ensure authorization checks on all sensitive endpoints
- [ ] Use secure session management

### Input Validation
- [ ] Validate all user inputs
- [ ] Implement proper sanitization
- [ ] Use parameterized queries

### Data Protection
- [ ] Encrypt sensitive data at rest
- [ ] Use HTTPS for all communications
- [ ] Implement proper key management
"""
            
            security_findings = self._extract_security_findings_from_content(checklist_content, "checklist")
            
            return WikiSection(
                id=str(uuid.uuid4()),
                title="Security Checklist & Recommendations",
                content=checklist_content,
                subsections=[],
                cross_references=["security_controls", "vulnerability_analysis", "code_findings"],
                owasp_mappings=["secure_design", "authentication", "input_validation"],
                code_references=[],
                security_findings=security_findings,
                recommendations=self._extract_recommendations_from_content(checklist_content),
                metadata={"generation_method": "enhanced_llm", "error_occurred": False}
            )
        except Exception as e:
            logger.error(f"Failed to generate security checklist section: {e}")
            raise SectionGenerationError(f"Security checklist generation failed: {e}", "security_checklist", e)
    
    async def _generate_code_findings_section(self, security_model: SecurityModel) -> WikiSection:
        """Generate code-level security findings section"""
        try:
            content = f"""# Code-Level Security Findings

## Security Pattern Analysis

This section analyzes security patterns and potential issues identified in the codebase.

## Component Analysis
"""
            
            for component in security_model.components:
                content += f"""
### {component.name}
- **File**: {component.file_path}
- **Type**: {component.type.value}
- **Security Relevance**: {'High' if component.handles_sensitive_data else 'Medium'}
- **Endpoints**: {len(component.endpoints)}
"""
            
            security_findings = self._extract_security_findings_from_content(content, "code")
            
            return WikiSection(
                id=str(uuid.uuid4()),
                title="Code-Level Security Findings",
                content=content,
                subsections=[],
                cross_references=["system_architecture", "vulnerability_analysis", "security_checklist"],
                owasp_mappings=["code_review", "secure_design"],
                code_references=self._extract_comprehensive_code_references(security_model),
                security_findings=security_findings,
                recommendations=self._extract_recommendations_from_content(content),
                metadata={"generation_method": "template_based", "error_occurred": False}
            )
        except Exception as e:
            logger.error(f"Failed to generate code findings section: {e}")
            raise SectionGenerationError(f"Code findings generation failed: {e}", "code_findings", e)
    
    def _build_interconnected_wiki(self, sections: Dict[str, WikiSection], security_model: SecurityModel) -> SecurityWiki:
        """Create interconnected wiki structure with cross-references"""
        
        try:
            # Build cross-reference mapping
            cross_references = {}
            for section_name, section in sections.items():
                cross_references[section_name] = section.cross_references
            
            # Create search index (simplified)
            search_index = {}
            for section_name, section in sections.items():
                search_index[section_name] = {
                    "title": section.title,
                    "content_length": len(section.content),
                    "findings_count": len(section.security_findings),
                    "recommendations_count": len(section.recommendations),
                    "owasp_mappings_count": len(section.owasp_mappings)
                }
            
            return SecurityWiki(
                id=str(uuid.uuid4()),
                repo_id=security_model.repo_id,
                title=f"Security Wiki - {security_model.repo_id}",
                sections=sections,
                cross_references=cross_references,
                search_index=search_index,
                metadata={
                    "generation_type": "comprehensive_security_wiki",
                    "sections_count": len(sections),
                    "components_analyzed": len(security_model.components),
                    "flows_analyzed": len(security_model.flows),
                    "data_stores_analyzed": len(security_model.data_stores),
                    "generation_timestamp": datetime.now().isoformat(),
                    "analysis_depth": "comprehensive",
                    "owasp_integrated": True,
                    "error_occurred": False
                }
            )
        except Exception as e:
            logger.error(f"Failed to build interconnected wiki: {e}")
            # Use error handler for wiki building failure
            return self.error_handler.handle_wiki_build_error(sections, e, security_model)
    
    
    # Helper methods for extracting information from content
    def _extract_security_findings_from_content(self, content: str, section_type: str) -> List[SecurityFinding]:
        """Extract security findings from generated content"""
        # Simplified extraction - in real implementation, this would use NLP or pattern matching
        findings = []
        
        if "vulnerability" in content.lower() or "security issue" in content.lower():
            findings.append(SecurityFinding(
                id=str(uuid.uuid4()),
                type="vulnerability",
                severity="medium",
                description=f"Security issue identified in {section_type} analysis",
                affected_components=[],
                owasp_category="A01:2021-Broken Access Control",
                recommendations=["Review and implement proper security controls"]
            ))
        
        return findings
    
    def _extract_recommendations_from_content(self, content: str) -> List[str]:
        """Extract recommendations from generated content"""
        # Simplified extraction
        recommendations = []
        
        if "recommend" in content.lower():
            recommendations.append("Implement security best practices as outlined in the analysis")
        
        if "should" in content.lower():
            recommendations.append("Address identified security concerns")
        
        return recommendations
    
    # Helper methods for extracting code references
    def _extract_key_code_references(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract key code references for executive summary"""
        references = []
        
        # Add references for most critical components
        for component in security_model.components[:3]:  # Top 3 components
            if component.handles_sensitive_data:
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=component.file_path,
                        line_start=1,
                        function_name=component.name,
                        code_snippet=f"Critical component: {component.name}"
                    )
                )
        
        return references
    
    def _extract_component_code_references(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract code references for system architecture"""
        references = []
        
        for component in security_model.components:
            references.append(
                CodeReference(
                    id=str(uuid.uuid4()),
                    file_path=component.file_path,
                    line_start=1,
                    function_name=component.name,
                    code_snippet=f"Component: {component.name} ({component.type.value})"
                )
            )
        
        return references[:10]  # Limit to avoid overwhelming
    
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
                        code_snippet=f"Auth component: {component.name} - {', '.join(component.auth_mechanisms)}"
                    )
                )
        
        return references
    
    def _extract_flow_code_references(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract data flow related code references"""
        references = []
        
        for flow in security_model.flows:
            if flow.data_sensitivity.value in ["confidential", "restricted"]:
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=f"flow_{flow.name}",
                        line_start=1,
                        function_name=flow.name,
                        code_snippet=f"Sensitive flow: {flow.name} ({flow.data_sensitivity.value})"
                    )
                )
        
        return references
    
    def _extract_vulnerability_code_references(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract vulnerability-related code references"""
        references = []
        
        for component in security_model.components:
            if component.endpoints:
                for endpoint in component.endpoints:
                    if endpoint.sensitive_data and not endpoint.requires_auth:
                        references.append(
                            CodeReference(
                                id=str(uuid.uuid4()),
                                file_path=component.file_path,
                                line_start=1,
                                function_name=endpoint.handler_function or f"{endpoint.method}_{endpoint.path}",
                                code_snippet=f"Potential vulnerability: {endpoint.method} {endpoint.path} - sensitive data without auth"
                            )
                        )
        
        return references
    
    def _extract_threat_code_references(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract threat-related code references"""
        references = []
        
        for component in security_model.components:
            if component.handles_sensitive_data:
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=component.file_path,
                        line_start=1,
                        function_name=component.name,
                        code_snippet=f"Threat target: {component.name} - handles sensitive data"
                    )
                )
        
        return references
    
    def _extract_controls_code_references(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract security controls related code references"""
        references = []
        
        patterns = security_model.security_patterns
        if patterns.authentication_mechanisms:
            references.append(
                CodeReference(
                    id=str(uuid.uuid4()),
                    file_path="security_patterns",
                    line_start=1,
                    function_name="authentication",
                    code_snippet=f"Auth mechanisms: {', '.join(patterns.authentication_mechanisms)}"
                )
            )
        
        return references
    
    # OWASP Integration Methods
    
    async def _integrate_owasp_guidance(self, sections: Dict[str, WikiSection], security_model: SecurityModel) -> Dict[str, WikiSection]:
        """
        Enhance wiki sections with contextual OWASP guidance
        """
        logger.info("Integrating OWASP guidance throughout wiki sections")
        
        enhanced_sections = {}
        
        for section_name, section in sections.items():
            try:
                # Get contextual OWASP guidance for this section
                owasp_guidance = await self._get_contextual_owasp_guidance(section, security_model)
                
                # Integrate guidance into section content
                enhanced_section = await self._embed_owasp_content(section, owasp_guidance)
                
                enhanced_sections[section_name] = enhanced_section
                
            except Exception as e:
                logger.error(f"Failed to integrate OWASP guidance for {section_name}: {e}")
                # Use error handler for OWASP integration failure
                enhanced_sections[section_name] = self.error_handler.handle_owasp_integration_error(
                    section, e, security_model
                )
        
        return enhanced_sections
    
    async def _get_contextual_owasp_guidance(self, section: WikiSection, security_model: SecurityModel) -> Dict[str, Any]:
        """
        Retrieve contextual OWASP guidance for a specific wiki section
        """
        try:
            # Import OWASP retriever (lazy import to avoid circular dependencies)
            from api.owasp_retriever import OWASPRetriever, ContentFilter, SecurityDomain, Phase
            
            retriever = OWASPRetriever()
            
            # Determine relevant security domains based on section type
            security_domains = self._map_section_to_security_domains(section.title)
            
            # Determine relevant phases
            phases = [Phase.DESIGN, Phase.IMPLEMENTATION, Phase.REVIEW]
            
            # Create content filter based on section context
            content_filter = ContentFilter(
                security_domains=security_domains,
                phases=phases,
                component_types=self._extract_component_types_from_model(security_model)
            )
            
            # Get relevant cheat sheets
            retrieval_results = retriever.filter_cheatsheets(content_filter)
            
            # Get actual content for top results
            guidance_content = {}
            for result in retrieval_results[:3]:  # Top 3 most relevant
                content = retriever.get_cheatsheet_content(result.cheat_sheet)
                if content:
                    guidance_content[result.cheat_sheet.id] = {
                        'title': result.cheat_sheet.title,
                        'content': content,
                        'relevance_score': result.relevance_score,
                        'matched_criteria': result.matched_criteria
                    }
            
            return guidance_content
            
        except Exception as e:
            logger.error(f"Failed to get contextual OWASP guidance: {e}")
            return {}
    
    def _map_section_to_security_domains(self, section_title: str) -> List:
        """
        Map wiki section titles to relevant OWASP security domains
        """
        try:
            from api.owasp_retriever import SecurityDomain
            
            section_lower = section_title.lower()
            domain_mapping = {
                'authentication': [SecurityDomain.AUTHENTICATION],
                'authorization': [SecurityDomain.AUTHORIZATION],
                'auth': [SecurityDomain.AUTHENTICATION, SecurityDomain.AUTHORIZATION],
                'data flow': [SecurityDomain.INPUT_VALIDATION, SecurityDomain.CRYPTOGRAPHY],
                'vulnerability': [SecurityDomain.INPUT_VALIDATION, SecurityDomain.WEB_SECURITY],
                'threat': [SecurityDomain.THREAT_MODELING],
                'security controls': [SecurityDomain.AUTHENTICATION, SecurityDomain.AUTHORIZATION, SecurityDomain.CRYPTOGRAPHY],
                'api': [SecurityDomain.API_SECURITY],
                'code': [SecurityDomain.SECURITY_TESTING],
                'logging': [SecurityDomain.LOGGING],
                'cloud': [SecurityDomain.CLOUD_SECURITY],
                'container': [SecurityDomain.CONTAINER_SECURITY]
            }
            
            relevant_domains = []
            for keyword, domains in domain_mapping.items():
                if keyword in section_lower:
                    relevant_domains.extend(domains)
            
            # Default domains if no specific mapping found
            if not relevant_domains:
                relevant_domains = [SecurityDomain.THREAT_MODELING, SecurityDomain.WEB_SECURITY]
            
            return relevant_domains
            
        except ImportError:
            logger.warning("OWASP retriever not available, skipping domain mapping")
            return []
    
    def _extract_component_types_from_model(self, security_model: SecurityModel) -> List:
        """
        Extract component types from security model for OWASP filtering
        """
        try:
            from api.models import ComponentType as OWASPComponentType
            
            # Map ThreatLens component types to OWASP component types
            component_type_mapping = {
                'service': 'web_service',
                'controller': 'web_service', 
                'middleware': 'web_service',
                'worker': 'background_service',
                'model': 'data_layer',
                'utility': 'library'
            }
            
            owasp_component_types = []
            for component in security_model.components:
                mapped_type = component_type_mapping.get(component.type.value, component.type.value)
                try:
                    owasp_type = OWASPComponentType(mapped_type)
                    if owasp_type not in owasp_component_types:
                        owasp_component_types.append(owasp_type)
                except ValueError:
                    # Skip unmappable component types
                    continue
            
            return owasp_component_types
            
        except ImportError:
            logger.warning("OWASP component types not available")
            return []
    
    async def _embed_owasp_content(self, section: WikiSection, owasp_guidance: Dict[str, Any]) -> WikiSection:
        """
        Embed OWASP content seamlessly into wiki section
        """
        if not owasp_guidance:
            return section
        
        enhanced_content = section.content
        owasp_mappings = list(section.owasp_mappings)
        recommendations = list(section.recommendations)
        
        # Add OWASP guidance section
        if owasp_guidance:
            enhanced_content += "\n\n## OWASP Guidance\n\n"
            
            for cheatsheet_id, guidance in owasp_guidance.items():
                enhanced_content += f"### {guidance['title']}\n\n"
                
                # Extract relevant excerpts from the guidance content
                relevant_excerpt = self._extract_relevant_excerpt(
                    guidance['content'], 
                    section.title,
                    max_length=500
                )
                
                if relevant_excerpt:
                    enhanced_content += f"{relevant_excerpt}\n\n"
                    enhanced_content += f"*Relevance Score: {guidance['relevance_score']:.2f}*\n\n"
                
                # Add to OWASP mappings
                owasp_mappings.append(cheatsheet_id)
                
                # Extract recommendations from OWASP content
                owasp_recommendations = self._extract_owasp_recommendations(guidance['content'])
                recommendations.extend(owasp_recommendations)
        
        # Create enhanced section
        enhanced_section = WikiSection(
            id=section.id,
            title=section.title,
            content=enhanced_content,
            subsections=section.subsections,
            cross_references=section.cross_references,
            owasp_mappings=list(set(owasp_mappings)),  # Remove duplicates
            code_references=section.code_references,
            security_findings=section.security_findings,
            recommendations=list(set(recommendations))  # Remove duplicates
        )
        
        return enhanced_section
    
    def _extract_relevant_excerpt(self, content: str, section_title: str, max_length: int = 500) -> str:
        """
        Extract relevant excerpt from OWASP content based on section context
        """
        if not content:
            return ""
        
        # Simple extraction based on section keywords
        section_keywords = section_title.lower().split()
        
        # Split content into paragraphs
        paragraphs = content.split('\n\n')
        
        # Score paragraphs based on keyword relevance
        scored_paragraphs = []
        for paragraph in paragraphs:
            if len(paragraph.strip()) < 50:  # Skip very short paragraphs
                continue
                
            score = 0
            paragraph_lower = paragraph.lower()
            
            for keyword in section_keywords:
                if keyword in paragraph_lower:
                    score += 1
            
            if score > 0:
                scored_paragraphs.append((score, paragraph.strip()))
        
        # Sort by score and take the best paragraph
        if scored_paragraphs:
            scored_paragraphs.sort(key=lambda x: x[0], reverse=True)
            best_paragraph = scored_paragraphs[0][1]
            
            # Truncate if too long
            if len(best_paragraph) > max_length:
                truncated = best_paragraph[:max_length]
                last_sentence = truncated.rfind('.')
                if last_sentence > max_length * 0.7:
                    return truncated[:last_sentence + 1]
                return truncated + "..."
            
            return best_paragraph
        
        # Fallback: return first paragraph if no keyword matches
        if paragraphs:
            first_paragraph = paragraphs[0].strip()
            if len(first_paragraph) > max_length:
                return first_paragraph[:max_length] + "..."
            return first_paragraph
        
        return ""
    
    def _extract_owasp_recommendations(self, content: str) -> List[str]:
        """
        Extract actionable recommendations from OWASP content
        """
        recommendations = []
        
        if not content:
            return recommendations
        
        # Look for common recommendation patterns
        recommendation_patterns = [
            r'(?:should|must|recommend|ensure|implement|use|avoid|never|always)\s+([^.]+\.)',
            r'(?:best practice|guideline|rule):\s*([^.]+\.)',
            r'(?:do|don\'t):\s*([^.]+\.)'
        ]
        
        import re
        
        for pattern in recommendation_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                recommendation = match.strip()
                if len(recommendation) > 20 and len(recommendation) < 200:  # Reasonable length
                    recommendations.append(recommendation)
        
        # Limit to avoid overwhelming the section
        return recommendations[:5]
    
    async def _search_owasp_cheatsheets(self, query: str) -> List[Dict[str, Any]]:
        """
        Search OWASP cheat sheets for relevant content
        """
        try:
            from api.owasp_retriever import OWASPRetriever
            
            retriever = OWASPRetriever()
            results = retriever.search_content(query, max_results=5)
            
            cheatsheet_results = []
            for result in results:
                content = retriever.get_cheatsheet_content(result.cheat_sheet.id)
                cheatsheet_results.append({
                    'id': result.cheat_sheet.id,
                    'title': result.cheat_sheet.title,
                    'content': content,
                    'relevance_score': result.relevance_score,
                    'matched_criteria': result.matched_criteria
                })
            
            return cheatsheet_results
            
        except Exception as e:
            logger.error(f"Failed to search OWASP cheat sheets: {e}")
            return []
    
    async def generate_comprehensive_security_documentation(
        self, 
        security_model: SecurityModel,
        scope: str = "full_repo"
    ) -> SecurityDocument:
        """
        Generate comprehensive security documentation similar to DeepWiki
        Covers all security aspects in a single, searchable document
        LEGACY METHOD - Use generate_comprehensive_security_wiki for new implementations
        """
        logger.info(f"Generating comprehensive security documentation for repo {security_model.repo_id}")
        
        try:
            # Generate comprehensive security analysis content
            content_sections = await self._generate_legacy_security_sections(security_model)
            
            # Combine all sections into comprehensive documentation
            full_content = self._combine_security_sections(content_sections)
            
            # Extract code references from security model
            code_references = self._extract_comprehensive_code_references(security_model)
            
            # Create security document
            security_doc = SecurityDocument(
                id=str(uuid.uuid4()),
                repo_id=security_model.repo_id,
                title=f"Security Analysis - {security_model.repo_id}",
                content=full_content,
                scope=scope,
                metadata={
                    "generation_type": "comprehensive_security_analysis",
                    "sections_generated": list(content_sections.keys()),
                    "components_analyzed": len(security_model.components),
                    "flows_analyzed": len(security_model.flows),
                    "data_stores_analyzed": len(security_model.data_stores),
                    "generation_timestamp": datetime.now().isoformat(),
                    "analysis_depth": "comprehensive"
                },
                code_references=code_references
            )
            
            logger.info(f"Successfully generated comprehensive security documentation: {security_doc.id}")
            return security_doc
            
        except Exception as e:
            logger.error(f"Failed to generate comprehensive security documentation: {e}")
            raise
    
    async def generate_pr_security_analysis(
        self,
        security_model: SecurityModel,
        changed_files: List[str],
        repo_context: Optional[Dict[str, Any]] = None
    ) -> SecurityDocument:
        """
        Generate security analysis focused on PR changes with optional repo context
        """
        logger.info(f"Generating PR security analysis for {len(changed_files)} changed files")
        
        try:
            # Generate PR-specific security analysis
            content_sections = await self._generate_pr_security_sections(
                security_model, changed_files, repo_context
            )
            
            # Combine sections into PR-focused documentation
            full_content = self._combine_security_sections(content_sections)
            
            # Extract code references for changed files
            code_references = self._extract_pr_code_references(security_model, changed_files)
            
            # Create PR security document
            security_doc = SecurityDocument(
                id=str(uuid.uuid4()),
                repo_id=security_model.repo_id,
                title=f"PR Security Analysis - {security_model.repo_id}",
                content=full_content,
                scope="pr_only",
                metadata={
                    "generation_type": "pr_security_analysis",
                    "changed_files": changed_files,
                    "has_repo_context": repo_context is not None,
                    "sections_generated": list(content_sections.keys()),
                    "generation_timestamp": datetime.now().isoformat(),
                    "analysis_depth": "pr_focused"
                },
                code_references=code_references
            )
            
            logger.info(f"Successfully generated PR security analysis: {security_doc.id}")
            return security_doc
            
        except Exception as e:
            logger.error(f"Failed to generate PR security analysis: {e}")
            raise
    
    async def _generate_legacy_security_sections(self, security_model: SecurityModel) -> Dict[str, str]:
        """
        Generate security analysis focused on PR changes with optional repo context
        """
        logger.info(f"Generating PR security analysis for {len(changed_files)} changed files")
        
        try:
            # Generate PR-specific security analysis
            content_sections = await self._generate_pr_security_sections(
                security_model, changed_files, repo_context
            )
            
            # Combine sections into PR-focused documentation
            full_content = self._combine_security_sections(content_sections)
            
            # Extract code references for changed files
            code_references = self._extract_pr_code_references(security_model, changed_files)
            
            # Create PR security document
            security_doc = SecurityDocument(
                id=str(uuid.uuid4()),
                repo_id=security_model.repo_id,
                title=f"PR Security Analysis - {security_model.repo_id}",
                content=full_content,
                scope="pr_only",
                metadata={
                    "generation_type": "pr_security_analysis",
                    "changed_files": changed_files,
                    "has_repo_context": repo_context is not None,
                    "sections_generated": list(content_sections.keys()),
                    "generation_timestamp": datetime.now().isoformat(),
                    "analysis_depth": "pr_focused"
                },
                code_references=code_references
            )
            
            logger.info(f"Successfully generated PR security analysis: {security_doc.id}")
            return security_doc
            
        except Exception as e:
            logger.error(f"Failed to generate PR security analysis: {e}")
            raise
    
    async def _generate_legacy_security_sections(self, security_model: SecurityModel) -> Dict[str, str]:
        """Generate all security analysis sections for comprehensive documentation (LEGACY)"""
        sections = {}
        
        # Generate sections concurrently for better performance
        tasks = [
            ("security_overview", self.content_generators.generate_security_overview(security_model)),
            ("authentication_analysis", self.content_generators.generate_authentication_analysis(security_model)),
            ("authorization_analysis", self.content_generators.generate_authorization_analysis(security_model)),
            ("data_flow_analysis", self.content_generators.generate_data_flow_analysis(security_model)),
            ("api_security_analysis", self.content_generators.generate_api_security_analysis(security_model)),
            ("vulnerability_assessment", self.content_generators.generate_vulnerability_assessment(security_model)),
            ("security_recommendations", self.content_generators.generate_security_recommendations(security_model))
        ]
        
        # Execute tasks in batches to avoid overwhelming the LLM API
        batch_size = 3
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            
            batch_results = await asyncio.gather(
                *[task[1] for task in batch], 
                return_exceptions=True
            )
            
            for j, result in enumerate(batch_results):
                section_name = batch[j][0]
                if isinstance(result, Exception):
                    logger.error(f"Failed to generate {section_name}: {result}")
                    sections[section_name] = f"# {section_name.replace('_', ' ').title()}\n\nError generating this section: {str(result)}"
                else:
                    sections[section_name] = result
            
            # Small delay between batches
            if i + batch_size < len(tasks):
                await asyncio.sleep(1)
        
        return sections
    
    async def _generate_pr_security_sections(
        self, 
        security_model: SecurityModel, 
        changed_files: List[str],
        repo_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """Generate security analysis sections focused on PR changes"""
        sections = {}
        
        # Generate PR-specific sections
        tasks = [
            ("pr_security_overview", self.content_generators.generate_pr_security_overview(
                security_model, changed_files, repo_context
            )),
            ("change_impact_analysis", self.content_generators.generate_change_impact_analysis(
                security_model, changed_files, repo_context
            )),
            ("security_risk_assessment", self.content_generators.generate_security_risk_assessment(
                security_model, changed_files, repo_context
            )),
            ("pr_recommendations", self.content_generators.generate_pr_recommendations(
                security_model, changed_files, repo_context
            ))
        ]
        
        # Execute PR analysis tasks
        batch_results = await asyncio.gather(
            *[task[1] for task in tasks], 
            return_exceptions=True
        )
        
        for i, result in enumerate(batch_results):
            section_name = tasks[i][0]
            if isinstance(result, Exception):
                logger.error(f"Failed to generate {section_name}: {result}")
                sections[section_name] = f"# {section_name.replace('_', ' ').title()}\n\nError generating this section: {str(result)}"
            else:
                sections[section_name] = result
        
        return sections
    
    def _combine_security_sections(self, sections: Dict[str, str]) -> str:
        """Combine all security analysis sections into comprehensive documentation"""
        combined_content = "# Security Analysis Documentation\n\n"
        combined_content += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        combined_content += "---\n\n"
        
        # Define section order for logical flow
        section_order = [
            "security_overview",
            "pr_security_overview", 
            "authentication_analysis",
            "authorization_analysis",
            "data_flow_analysis",
            "api_security_analysis",
            "change_impact_analysis",
            "vulnerability_assessment",
            "security_risk_assessment",
            "security_recommendations",
            "pr_recommendations"
        ]
        
        # Add sections in order
        for section_name in section_order:
            if section_name in sections:
                combined_content += sections[section_name] + "\n\n---\n\n"
        
        # Add any remaining sections not in the predefined order
        for section_name, content in sections.items():
            if section_name not in section_order:
                combined_content += content + "\n\n---\n\n"
        
        return combined_content
    
    def _extract_comprehensive_code_references(self, security_model: SecurityModel) -> List[CodeReference]:
        """Extract comprehensive code references for full repo analysis"""
        references = []
        
        # Add references for all security-relevant components
        for component in security_model.components:
            if (component.handles_sensitive_data or 
                component.auth_mechanisms or 
                component.endpoints or
                any(endpoint.requires_auth for endpoint in component.endpoints)):
                
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=component.file_path,
                        line_start=1,
                        function_name=component.name,
                        code_snippet=f"Security-relevant component: {component.name} ({component.type.value})"
                    )
                )
        
        # Add references for data stores with sensitive data
        for data_store in security_model.data_stores:
            if data_store.sensitive_data_types:
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=f"data_store_{data_store.name}",
                        line_start=1,
                        function_name=data_store.name,
                        code_snippet=f"Data store with sensitive data: {data_store.name} ({', '.join(data_store.sensitive_data_types[:3])})"
                    )
                )
        
        # Add references for high-sensitivity flows
        for flow in security_model.flows:
            if flow.data_sensitivity.value in ["confidential", "restricted"]:
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=f"flow_{flow.name}",
                        line_start=1,
                        function_name=flow.name,
                        code_snippet=f"High-sensitivity flow: {flow.name} ({flow.data_sensitivity.value})"
                    )
                )
        
        return references[:50]  # Limit to avoid overwhelming the document
    
    def _extract_pr_code_references(
        self, 
        security_model: SecurityModel, 
        changed_files: List[str]
    ) -> List[CodeReference]:
        """Extract code references specific to PR changes"""
        references = []
        
        # Add references for components in changed files
        for component in security_model.components:
            if component.file_path in changed_files:
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=component.file_path,
                        line_start=1,
                        function_name=component.name,
                        code_snippet=f"Changed component: {component.name} ({component.type.value})"
                    )
                )
        
        # Add references for changed files not covered by components
        for file_path in changed_files:
            if not any(comp.file_path == file_path for comp in security_model.components):
                references.append(
                    CodeReference(
                        id=str(uuid.uuid4()),
                        file_path=file_path,
                        line_start=1,
                        code_snippet=f"Changed file: {file_path}"
                    )
                )
        
        return references
    
    async def close(self):
        """Close the security wiki generator"""
        await self.llm_manager.close()