"""
Security Wiki Generator - DeepWiki-style comprehensive security documentation
Replaces rigid threat document types with flexible content generation
"""
import asyncio
import logging
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime

from .models import SecurityDocument, SecurityModel, Component, Flow, CodeReference
from .llm_client import LLMManager, LLMError
from .security_content_generators import SecurityContentGenerators


logger = logging.getLogger(__name__)


class SecurityWikiGenerator:
    """
    Main class for generating comprehensive security documentation similar to DeepWiki
    Focuses on security analysis rather than rigid threat modeling document types
    """
    
    def __init__(self, settings):
        self.settings = settings
        self.llm_manager = LLMManager()
        self.content_generators = SecurityContentGenerators()
    
    async def generate_comprehensive_security_documentation(
        self, 
        security_model: SecurityModel,
        scope: str = "full_repo"
    ) -> SecurityDocument:
        """
        Generate comprehensive security documentation similar to DeepWiki
        Covers all security aspects in a single, searchable document
        """
        logger.info(f"Generating comprehensive security documentation for repo {security_model.repo_id}")
        
        try:
            # Generate comprehensive security analysis content
            content_sections = await self._generate_all_security_sections(security_model)
            
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
    
    async def _generate_all_security_sections(self, security_model: SecurityModel) -> Dict[str, str]:
        """Generate all security analysis sections for comprehensive documentation"""
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