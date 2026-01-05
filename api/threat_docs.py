"""
Threat document generation system using LLM integration
"""
import asyncio
import logging
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime

from .models import (
    ThreatDoc, SecurityModel, Component, Flow,
    CodeReference
)
from .llm_client import LLMManager, LLMError
from .prompt_templates import PromptTemplates, ResponseParser


logger = logging.getLogger(__name__)


class ThreatDocGenerator:
    """Main class for generating threat modeling documents using LLM"""
    
    def __init__(self, settings):
        self.settings = settings
        self.llm_manager = LLMManager()
        self.prompt_templates = PromptTemplates()
        self.response_parser = ResponseParser()
    
    async def generate_system_overview(self, security_model: SecurityModel) -> ThreatDoc:
        """Generate System Security Overview document"""
        logger.info(f"Generating system overview for repo {security_model.repo_id}")
        
        try:
            prompt = self.prompt_templates.get_prompt_for_doc_type(
                "system_overview",
                security_model
            )
            
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=PromptTemplates.SYSTEM_PROMPT,
                temperature=0.3  # Lower temperature for more consistent output
            )
            
            parsed_response = self.response_parser.parse_threat_document(
                response.content,
                "system_overview"
            )
            
            # Extract code references from security model
            code_references = self._extract_code_references_for_overview(security_model)
            
            threat_doc = ThreatDoc(
                id=str(uuid.uuid4()),
                repo_id=security_model.repo_id,
                title=parsed_response["title"],
                doc_type="system_overview",
                content=parsed_response["content"],
                metadata={
                    **parsed_response["metadata"],
                    "llm_model": response.model,
                    "llm_usage": response.usage,
                    "generation_timestamp": datetime.now().isoformat()
                },
                code_references=code_references
            )
            
            logger.info(f"Successfully generated system overview: {threat_doc.id}")
            return threat_doc
            
        except Exception as e:
            logger.error(f"Failed to generate system overview: {e}")
            raise
    
    async def generate_component_profiles(self, security_model: SecurityModel) -> List[ThreatDoc]:
        """Generate Component Security Profile documents for all components"""
        logger.info(f"Generating component profiles for {len(security_model.components)} components")
        
        threat_docs = []
        
        # Process components in batches to avoid overwhelming the LLM API
        batch_size = 5
        for i in range(0, len(security_model.components), batch_size):
            batch = security_model.components[i:i + batch_size]
            
            # Process batch concurrently
            tasks = [
                self._generate_single_component_profile(component, security_model)
                for component in batch
            ]
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"Failed to generate component profile: {result}")
                    continue
                threat_docs.append(result)
            
            # Small delay between batches to respect rate limits
            if i + batch_size < len(security_model.components):
                await asyncio.sleep(1)
        
        logger.info(f"Successfully generated {len(threat_docs)} component profiles")
        return threat_docs
    
    async def _generate_single_component_profile(
        self, 
        component: Component, 
        security_model: SecurityModel
    ) -> ThreatDoc:
        """Generate a single component profile"""
        try:
            prompt = self.prompt_templates.get_prompt_for_doc_type(
                "component_profile",
                security_model,
                component=component
            )
            
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=PromptTemplates.SYSTEM_PROMPT,
                temperature=0.3
            )
            
            parsed_response = self.response_parser.parse_threat_document(
                response.content,
                "component_profile"
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
            
            threat_doc = ThreatDoc(
                id=str(uuid.uuid4()),
                repo_id=security_model.repo_id,
                title=f"{parsed_response['title']} - {component.name}",
                doc_type="component_profile",
                content=parsed_response["content"],
                metadata={
                    **parsed_response["metadata"],
                    "component_id": component.id,
                    "component_name": component.name,
                    "component_type": component.type.value,
                    "llm_model": response.model,
                    "llm_usage": response.usage,
                    "generation_timestamp": datetime.now().isoformat()
                },
                code_references=code_references
            )
            
            return threat_doc
            
        except Exception as e:
            logger.error(f"Failed to generate component profile for {component.name}: {e}")
            raise
    
    async def generate_flow_threat_models(self, security_model: SecurityModel) -> List[ThreatDoc]:
        """Generate Flow Threat Model documents using STRIDE methodology"""
        logger.info(f"Generating flow threat models for {len(security_model.flows)} flows")
        
        threat_docs = []
        
        # Process flows in batches
        batch_size = 3  # Smaller batch size for flows as they generate longer content
        for i in range(0, len(security_model.flows), batch_size):
            batch = security_model.flows[i:i + batch_size]
            
            tasks = [
                self._generate_single_flow_threat_model(flow, security_model)
                for flow in batch
            ]
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"Failed to generate flow threat model: {result}")
                    continue
                threat_docs.append(result)
            
            # Longer delay between batches for flows
            if i + batch_size < len(security_model.flows):
                await asyncio.sleep(2)
        
        logger.info(f"Successfully generated {len(threat_docs)} flow threat models")
        return threat_docs
    
    async def _generate_single_flow_threat_model(
        self, 
        flow: Flow, 
        security_model: SecurityModel
    ) -> ThreatDoc:
        """Generate a single flow threat model"""
        try:
            prompt = self.prompt_templates.get_prompt_for_doc_type(
                "flow_threat_model",
                security_model,
                flow=flow
            )
            
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=PromptTemplates.SYSTEM_PROMPT,
                temperature=0.4,  # Slightly higher temperature for more creative threat analysis
                max_tokens=6000  # Longer content for detailed STRIDE analysis
            )
            
            parsed_response = self.response_parser.parse_threat_document(
                response.content,
                "flow_threat_model"
            )
            
            # Extract code references from flow components
            code_references = self._extract_code_references_for_flow(flow, security_model)
            
            threat_doc = ThreatDoc(
                id=str(uuid.uuid4()),
                repo_id=security_model.repo_id,
                title=f"{parsed_response['title']} - {flow.name}",
                doc_type="flow_threat_model",
                content=parsed_response["content"],
                metadata={
                    **parsed_response["metadata"],
                    "flow_id": flow.id,
                    "flow_name": flow.name,
                    "flow_type": flow.flow_type.value,
                    "data_sensitivity": flow.data_sensitivity.value,
                    "trust_boundary_crossings": len(flow.trust_boundary_crossings),
                    "llm_model": response.model,
                    "llm_usage": response.usage,
                    "generation_timestamp": datetime.now().isoformat()
                },
                code_references=code_references
            )
            
            return threat_doc
            
        except Exception as e:
            logger.error(f"Failed to generate flow threat model for {flow.name}: {e}")
            raise
    
    async def generate_mitigations(
        self, 
        security_model: SecurityModel, 
        existing_docs: List[ThreatDoc]
    ) -> ThreatDoc:
        """Generate Mitigations & Requirements document"""
        logger.info(f"Generating mitigations document for repo {security_model.repo_id}")
        
        try:
            # Extract identified threats from existing documents
            identified_threats = self._extract_threats_from_documents(existing_docs)
            
            prompt = self.prompt_templates.get_prompt_for_doc_type(
                "mitigation",
                security_model,
                identified_threats=identified_threats
            )
            
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=PromptTemplates.SYSTEM_PROMPT,
                temperature=0.2,  # Lower temperature for consistent recommendations
                max_tokens=8000  # Longer content for comprehensive mitigations
            )
            
            parsed_response = self.response_parser.parse_threat_document(
                response.content,
                "mitigation"
            )
            
            # Aggregate code references from all components and flows
            code_references = self._extract_code_references_for_mitigations(security_model)
            
            threat_doc = ThreatDoc(
                id=str(uuid.uuid4()),
                repo_id=security_model.repo_id,
                title=parsed_response["title"],
                doc_type="mitigation",
                content=parsed_response["content"],
                metadata={
                    **parsed_response["metadata"],
                    "threats_analyzed": len(identified_threats),
                    "components_covered": len(security_model.components),
                    "flows_covered": len(security_model.flows),
                    "llm_model": response.model,
                    "llm_usage": response.usage,
                    "generation_timestamp": datetime.now().isoformat()
                },
                code_references=code_references
            )
            
            logger.info(f"Successfully generated mitigations document: {threat_doc.id}")
            return threat_doc
            
        except Exception as e:
            logger.error(f"Failed to generate mitigations document: {e}")
            raise
    
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
    
    def _extract_code_references_for_flow(
        self, 
        flow: Flow, 
        security_model: SecurityModel
    ) -> List[CodeReference]:
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
    
    def _extract_threats_from_documents(self, docs: List[ThreatDoc]) -> List[str]:
        """Extract identified threats from existing threat documents"""
        threats = []
        
        for doc in docs:
            content_lower = doc.content.lower()
            
            # Look for common threat indicators in the content
            threat_keywords = [
                "spoofing", "tampering", "repudiation", "information disclosure",
                "denial of service", "elevation of privilege", "vulnerability",
                "attack", "threat", "risk", "exploit"
            ]
            
            for keyword in threat_keywords:
                if keyword in content_lower:
                    # Extract sentences containing the keyword
                    sentences = doc.content.split('.')
                    for sentence in sentences:
                        if keyword in sentence.lower() and len(sentence.strip()) > 20:
                            threats.append(sentence.strip())
                            if len(threats) >= 50:  # Limit to avoid token overflow
                                break
                    if len(threats) >= 50:
                        break
        
        return list(set(threats))  # Remove duplicates
    
    async def generate_all_documents(self, security_model: SecurityModel) -> List[ThreatDoc]:
        """Generate all threat modeling documents for a security model"""
        logger.info(f"Starting complete document generation for repo {security_model.repo_id}")
        
        all_docs = []
        
        try:
            # 1. Generate system overview
            system_overview = await self.generate_system_overview(security_model)
            all_docs.append(system_overview)
            
            # 2. Generate component profiles
            component_profiles = await self.generate_component_profiles(security_model)
            all_docs.extend(component_profiles)
            
            # 3. Generate flow threat models
            flow_threat_models = await self.generate_flow_threat_models(security_model)
            all_docs.extend(flow_threat_models)
            
            # 4. Generate mitigations document
            mitigations = await self.generate_mitigations(security_model, all_docs)
            all_docs.append(mitigations)
            
            logger.info(f"Successfully generated {len(all_docs)} threat documents")
            return all_docs
            
        except Exception as e:
            logger.error(f"Failed to generate complete document set: {e}")
            raise
        finally:
            await self.llm_manager.close()
    
    async def close(self):
        """Close the threat document generator"""
        await self.llm_manager.close()