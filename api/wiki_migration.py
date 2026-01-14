"""
Wiki migration utilities for converting existing ThreatDoc collections to wiki format
"""
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from uuid import uuid4

from .models import (
    ThreatDoc, SecurityWiki, WikiSection, SecurityFinding, 
    CodeReference, WikiSectionContent, SecurityDocument
)
from .document_storage import DocumentStorageService
from .wiki_storage import WikiStorage
from .database import DatabaseManager
from .config import settings


logger = logging.getLogger(__name__)


class WikiMigrationUtility:
    """Utility for migrating existing ThreatDoc collections to wiki format"""
    
    def __init__(self, 
                 document_storage: Optional[DocumentStorageService] = None,
                 wiki_storage: Optional[WikiStorage] = None,
                 db_manager: Optional[DatabaseManager] = None):
        self.document_storage = document_storage or DocumentStorageService()
        self.wiki_storage = wiki_storage or WikiStorage()
        self.db_manager = db_manager or DatabaseManager()
    
    def migrate_repository_to_wiki(self, repo_id: str, preserve_originals: bool = True) -> Dict[str, Any]:
        """Convert existing ThreatDoc collection for a repository to wiki format"""
        migration_result = {
            "repo_id": repo_id,
            "started_at": datetime.now().isoformat(),
            "success": True,
            "wiki_id": None,
            "sections_migrated": 0,
            "documents_processed": 0,
            "errors": [],
            "warnings": []
        }
        
        try:
            # Get existing threat documents for repository
            threat_docs = self.document_storage.get_documents_by_repo(repo_id)
            
            if not threat_docs:
                migration_result["warnings"].append("No threat documents found for repository")
                migration_result["completed_at"] = datetime.now().isoformat()
                return migration_result
            
            logger.info(f"Migrating {len(threat_docs)} threat documents to wiki format for repo {repo_id}")
            
            # Create security wiki from threat documents
            wiki = self._create_wiki_from_threat_docs(repo_id, threat_docs)
            
            # Save the wiki
            if self.wiki_storage.save_wiki(wiki):
                migration_result["wiki_id"] = wiki.id
                migration_result["sections_migrated"] = len(wiki.sections)
                migration_result["documents_processed"] = len(threat_docs)
                
                logger.info(f"Successfully migrated repository {repo_id} to wiki {wiki.id}")
                
                # Optionally preserve original documents by marking them as migrated
                if preserve_originals:
                    self._mark_documents_as_migrated(threat_docs, wiki.id)
                
            else:
                migration_result["success"] = False
                migration_result["errors"].append("Failed to save migrated wiki")
            
        except Exception as e:
            migration_result["success"] = False
            migration_result["errors"].append(f"Migration failed: {str(e)}")
            logger.error(f"Migration failed for repo {repo_id}: {e}")
        
        migration_result["completed_at"] = datetime.now().isoformat()
        return migration_result
    
    def migrate_security_documents_to_wiki(self, repo_id: str, preserve_originals: bool = True) -> Dict[str, Any]:
        """Convert existing SecurityDocument collection for a repository to wiki format"""
        migration_result = {
            "repo_id": repo_id,
            "started_at": datetime.now().isoformat(),
            "success": True,
            "wiki_id": None,
            "sections_migrated": 0,
            "documents_processed": 0,
            "errors": [],
            "warnings": []
        }
        
        try:
            # Get existing security documents for repository
            security_docs = self.db_manager.get_security_documents_by_repo(repo_id)
            
            if not security_docs:
                migration_result["warnings"].append("No security documents found for repository")
                migration_result["completed_at"] = datetime.now().isoformat()
                return migration_result
            
            logger.info(f"Migrating {len(security_docs)} security documents to wiki format for repo {repo_id}")
            
            # Create security wiki from security documents
            wiki = self._create_wiki_from_security_docs(repo_id, security_docs)
            
            # Save the wiki
            if self.wiki_storage.save_wiki(wiki):
                migration_result["wiki_id"] = wiki.id
                migration_result["sections_migrated"] = len(wiki.sections)
                migration_result["documents_processed"] = len(security_docs)
                
                logger.info(f"Successfully migrated repository {repo_id} to wiki {wiki.id}")
                
                # Optionally preserve original documents by marking them as migrated
                if preserve_originals:
                    self._mark_security_documents_as_migrated(security_docs, wiki.id)
                
            else:
                migration_result["success"] = False
                migration_result["errors"].append("Failed to save migrated wiki")
            
        except Exception as e:
            migration_result["success"] = False
            migration_result["errors"].append(f"Migration failed: {str(e)}")
            logger.error(f"Migration failed for repo {repo_id}: {e}")
        
        migration_result["completed_at"] = datetime.now().isoformat()
        return migration_result
    
    def batch_migrate_repositories(self, repo_ids: List[str], preserve_originals: bool = True) -> Dict[str, Any]:
        """Migrate multiple repositories to wiki format"""
        batch_result = {
            "started_at": datetime.now().isoformat(),
            "total_repositories": len(repo_ids),
            "successful_migrations": 0,
            "failed_migrations": 0,
            "migration_results": {},
            "overall_success": True
        }
        
        for repo_id in repo_ids:
            try:
                # Try migrating threat documents first
                threat_result = self.migrate_repository_to_wiki(repo_id, preserve_originals)
                
                # If no threat docs, try security documents
                if not threat_result["success"] or threat_result["documents_processed"] == 0:
                    security_result = self.migrate_security_documents_to_wiki(repo_id, preserve_originals)
                    
                    # Use the better result
                    if security_result["success"] and security_result["documents_processed"] > 0:
                        batch_result["migration_results"][repo_id] = security_result
                        batch_result["successful_migrations"] += 1
                    else:
                        batch_result["migration_results"][repo_id] = threat_result
                        if not threat_result["success"]:
                            batch_result["failed_migrations"] += 1
                        else:
                            batch_result["successful_migrations"] += 1
                else:
                    batch_result["migration_results"][repo_id] = threat_result
                    batch_result["successful_migrations"] += 1
                
            except Exception as e:
                batch_result["migration_results"][repo_id] = {
                    "success": False,
                    "error": str(e)
                }
                batch_result["failed_migrations"] += 1
                logger.error(f"Batch migration failed for repo {repo_id}: {e}")
        
        batch_result["overall_success"] = batch_result["failed_migrations"] == 0
        batch_result["completed_at"] = datetime.now().isoformat()
        
        logger.info(f"Batch migration completed: {batch_result['successful_migrations']}/{batch_result['total_repositories']} successful")
        
        return batch_result
    
    def _create_wiki_from_threat_docs(self, repo_id: str, threat_docs: List[ThreatDoc]) -> SecurityWiki:
        """Create SecurityWiki from ThreatDoc collection"""
        wiki_id = str(uuid4())
        
        # Group documents by type for organized sections
        docs_by_type = {}
        for doc in threat_docs:
            doc_type = doc.doc_type if isinstance(doc.doc_type, str) else doc.doc_type.value
            if doc_type not in docs_by_type:
                docs_by_type[doc_type] = []
            docs_by_type[doc_type].append(doc)
        
        # Create wiki sections from document types
        sections = {}
        
        # Map ThreatDoc types to wiki sections
        section_mapping = {
            "system_overview": "executive_summary",
            "component_profile": "system_architecture", 
            "flow_threat_model": "threat_landscape",
            "mitigation": "security_controls",
            "vulnerability_analysis": "vulnerability_analysis",
            "security_checklist": "security_checklist"
        }
        
        for doc_type, docs in docs_by_type.items():
            section_id = section_mapping.get(doc_type, doc_type.replace(" ", "_").lower())
            
            # Combine content from multiple documents of same type
            combined_content = self._combine_document_content(docs)
            
            # Extract security findings from content
            security_findings = self._extract_security_findings_from_docs(docs)
            
            # Collect all code references
            all_code_refs = []
            for doc in docs:
                all_code_refs.extend(doc.code_references)
            
            # Create wiki section
            sections[section_id] = WikiSection(
                id=section_id,
                title=self._get_section_title(section_id),
                content=combined_content,
                subsections=[],
                cross_references=self._generate_cross_references(section_id, docs_by_type.keys()),
                owasp_mappings=[],  # Will be populated by OWASP integration
                code_references=all_code_refs,
                security_findings=security_findings,
                recommendations=self._extract_recommendations_from_docs(docs)
            )
        
        # Create the security wiki
        wiki = SecurityWiki(
            id=wiki_id,
            repo_id=repo_id,
            title=f"Security Analysis Wiki - {repo_id}",
            sections=sections,
            cross_references=self._build_wiki_cross_references(sections),
            search_index={},  # Will be populated by search indexing
            metadata={
                "migrated_from": "threat_documents",
                "original_doc_count": len(threat_docs),
                "migration_timestamp": datetime.now().isoformat(),
                "doc_types_migrated": list(docs_by_type.keys())
            }
        )
        
        return wiki
    
    def _create_wiki_from_security_docs(self, repo_id: str, security_docs: List[SecurityDocument]) -> SecurityWiki:
        """Create SecurityWiki from SecurityDocument collection"""
        wiki_id = str(uuid4())
        
        # For SecurityDocument, we typically have one comprehensive document
        # We'll split it into logical sections based on content analysis
        
        sections = {}
        
        if len(security_docs) == 1:
            # Single comprehensive document - split into sections
            doc = security_docs[0]
            sections = self._split_security_document_into_sections(doc)
        else:
            # Multiple documents - create sections from each
            for i, doc in enumerate(security_docs):
                section_id = f"security_analysis_{i+1}"
                
                # Extract security findings from content
                security_findings = self._extract_security_findings_from_content(doc.content)
                
                sections[section_id] = WikiSection(
                    id=section_id,
                    title=doc.title,
                    content=doc.content,
                    subsections=[],
                    cross_references=[],
                    owasp_mappings=[],
                    code_references=doc.code_references,
                    security_findings=security_findings,
                    recommendations=self._extract_recommendations_from_content(doc.content)
                )
        
        # Create the security wiki
        wiki = SecurityWiki(
            id=wiki_id,
            repo_id=repo_id,
            title=f"Security Analysis Wiki - {repo_id}",
            sections=sections,
            cross_references=self._build_wiki_cross_references(sections),
            search_index={},
            metadata={
                "migrated_from": "security_documents",
                "original_doc_count": len(security_docs),
                "migration_timestamp": datetime.now().isoformat()
            }
        )
        
        return wiki    

    def _combine_document_content(self, docs: List[ThreatDoc]) -> str:
        """Combine content from multiple documents of the same type"""
        if len(docs) == 1:
            return docs[0].content
        
        combined = f"# Combined {docs[0].doc_type} Analysis\n\n"
        
        for i, doc in enumerate(docs, 1):
            combined += f"## {doc.title}\n\n"
            combined += doc.content + "\n\n"
            
            if i < len(docs):
                combined += "---\n\n"
        
        return combined
    
    def _extract_security_findings_from_docs(self, docs: List[ThreatDoc]) -> List[SecurityFinding]:
        """Extract security findings from ThreatDoc content"""
        findings = []
        
        for doc in docs:
            doc_findings = self._extract_security_findings_from_content(doc.content)
            findings.extend(doc_findings)
        
        return findings
    
    def _extract_security_findings_from_content(self, content: str) -> List[SecurityFinding]:
        """Extract security findings from document content using pattern matching"""
        findings = []
        
        # Simple pattern matching for common security finding indicators
        # This can be enhanced with more sophisticated NLP techniques
        
        lines = content.split('\n')
        current_finding = None
        
        for line in lines:
            line = line.strip()
            
            # Look for vulnerability indicators
            if any(keyword in line.lower() for keyword in ['vulnerability', 'threat', 'risk', 'security issue']):
                if current_finding:
                    findings.append(current_finding)
                
                # Determine severity from context
                severity = "medium"  # default
                if any(word in line.lower() for word in ['critical', 'high']):
                    severity = "high"
                elif any(word in line.lower() for word in ['low', 'minor']):
                    severity = "low"
                
                current_finding = SecurityFinding(
                    id=str(uuid4()),
                    type="vulnerability" if "vulnerability" in line.lower() else "threat",
                    severity=severity,
                    description=line,
                    affected_components=[],
                    recommendations=[]
                )
            
            # Look for recommendations
            elif current_finding and any(keyword in line.lower() for keyword in ['recommend', 'mitigation', 'fix']):
                current_finding.recommendations.append(line)
        
        # Add the last finding if exists
        if current_finding:
            findings.append(current_finding)
        
        return findings
    
    def _extract_recommendations_from_docs(self, docs: List[ThreatDoc]) -> List[str]:
        """Extract recommendations from ThreatDoc content"""
        recommendations = []
        
        for doc in docs:
            doc_recommendations = self._extract_recommendations_from_content(doc.content)
            recommendations.extend(doc_recommendations)
        
        return recommendations
    
    def _extract_recommendations_from_content(self, content: str) -> List[str]:
        """Extract recommendations from document content"""
        recommendations = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if any(keyword in line.lower() for keyword in ['recommend', 'should', 'must', 'mitigation']):
                if len(line) > 20:  # Filter out very short lines
                    recommendations.append(line)
        
        return recommendations
    
    def _generate_cross_references(self, section_id: str, all_section_types: List[str]) -> List[str]:
        """Generate cross-references between sections"""
        cross_refs = []
        
        # Define logical relationships between section types
        relationships = {
            "executive_summary": ["system_architecture", "threat_landscape", "vulnerability_analysis"],
            "system_architecture": ["threat_landscape", "security_controls"],
            "threat_landscape": ["vulnerability_analysis", "security_controls"],
            "vulnerability_analysis": ["security_controls", "security_checklist"],
            "security_controls": ["security_checklist"]
        }
        
        if section_id in relationships:
            for related_section in relationships[section_id]:
                if related_section in all_section_types:
                    cross_refs.append(related_section)
        
        return cross_refs
    
    def _get_section_title(self, section_id: str) -> str:
        """Get human-readable title for section"""
        title_mapping = {
            "executive_summary": "Executive Summary",
            "system_architecture": "System Architecture & Components",
            "threat_landscape": "Threat Landscape Analysis",
            "vulnerability_analysis": "Vulnerability Analysis",
            "security_controls": "Security Controls & Mitigations",
            "security_checklist": "Security Checklist & Recommendations"
        }
        
        return title_mapping.get(section_id, section_id.replace("_", " ").title())
    
    def _build_wiki_cross_references(self, sections: Dict[str, WikiSection]) -> Dict[str, List[str]]:
        """Build comprehensive cross-reference mapping for the wiki"""
        cross_refs = {}
        
        for section_id, section in sections.items():
            cross_refs[section_id] = section.cross_references
        
        return cross_refs
    
    def _split_security_document_into_sections(self, doc: SecurityDocument) -> Dict[str, WikiSection]:
        """Split a comprehensive SecurityDocument into logical wiki sections"""
        sections = {}
        
        # Try to identify section boundaries in the content
        content_lines = doc.content.split('\n')
        current_section = None
        current_content = []
        section_counter = 1
        
        for line in content_lines:
            line_lower = line.lower().strip()
            
            # Look for section headers
            if (line.startswith('#') or 
                any(header in line_lower for header in [
                    'executive summary', 'overview', 'architecture', 'components',
                    'threats', 'vulnerabilities', 'risks', 'mitigations', 
                    'recommendations', 'checklist'
                ])):
                
                # Save previous section if exists
                if current_section and current_content:
                    sections[current_section] = self._create_section_from_content(
                        current_section, '\n'.join(current_content), doc.code_references
                    )
                
                # Start new section
                section_id = self._determine_section_id_from_header(line)
                if not section_id:
                    section_id = f"section_{section_counter}"
                    section_counter += 1
                
                current_section = section_id
                current_content = [line]
            
            else:
                if current_section:
                    current_content.append(line)
                else:
                    # No section identified yet, create a default one
                    current_section = "overview"
                    current_content = [line]
        
        # Save the last section
        if current_section and current_content:
            sections[current_section] = self._create_section_from_content(
                current_section, '\n'.join(current_content), doc.code_references
            )
        
        # If no sections were identified, create a single comprehensive section
        if not sections:
            sections["comprehensive_analysis"] = self._create_section_from_content(
                "comprehensive_analysis", doc.content, doc.code_references
            )
        
        return sections
    
    def _determine_section_id_from_header(self, header_line: str) -> Optional[str]:
        """Determine section ID from header text"""
        header_lower = header_line.lower()
        
        if any(word in header_lower for word in ['executive', 'summary', 'overview']):
            return "executive_summary"
        elif any(word in header_lower for word in ['architecture', 'component', 'system']):
            return "system_architecture"
        elif any(word in header_lower for word in ['threat', 'attack']):
            return "threat_landscape"
        elif any(word in header_lower for word in ['vulnerability', 'vuln']):
            return "vulnerability_analysis"
        elif any(word in header_lower for word in ['mitigation', 'control', 'defense']):
            return "security_controls"
        elif any(word in header_lower for word in ['recommendation', 'checklist']):
            return "security_checklist"
        
        return None
    
    def _create_section_from_content(self, section_id: str, content: str, code_refs: List[CodeReference]) -> WikiSection:
        """Create WikiSection from content"""
        return WikiSection(
            id=section_id,
            title=self._get_section_title(section_id),
            content=content,
            subsections=[],
            cross_references=[],
            owasp_mappings=[],
            code_references=code_refs,
            security_findings=self._extract_security_findings_from_content(content),
            recommendations=self._extract_recommendations_from_content(content)
        )
    
    def _mark_documents_as_migrated(self, threat_docs: List[ThreatDoc], wiki_id: str):
        """Mark ThreatDoc documents as migrated to preserve backward compatibility"""
        try:
            for doc in threat_docs:
                # Update document metadata to indicate migration
                doc.metadata["migrated_to_wiki"] = wiki_id
                doc.metadata["migration_timestamp"] = datetime.now().isoformat()
                
                # Save updated document
                self.document_storage.update_document_metadata(doc.id, {
                    "migrated_to_wiki": wiki_id,
                    "migration_timestamp": datetime.now().isoformat()
                })
                
            logger.info(f"Marked {len(threat_docs)} threat documents as migrated to wiki {wiki_id}")
            
        except Exception as e:
            logger.error(f"Failed to mark documents as migrated: {e}")
    
    def _mark_security_documents_as_migrated(self, security_docs: List[SecurityDocument], wiki_id: str):
        """Mark SecurityDocument documents as migrated to preserve backward compatibility"""
        try:
            for doc in security_docs:
                # Update document metadata to indicate migration
                doc.metadata["migrated_to_wiki"] = wiki_id
                doc.metadata["migration_timestamp"] = datetime.now().isoformat()
                doc.updated_at = datetime.now()
                
                # Save updated document
                self.db_manager.save_security_document(doc)
                
            logger.info(f"Marked {len(security_docs)} security documents as migrated to wiki {wiki_id}")
            
        except Exception as e:
            logger.error(f"Failed to mark security documents as migrated: {e}")
    
    def check_migration_compatibility(self, repo_id: str) -> Dict[str, Any]:
        """Check if repository is ready for wiki migration"""
        compatibility_check = {
            "repo_id": repo_id,
            "compatible": True,
            "issues": [],
            "warnings": [],
            "threat_docs_count": 0,
            "security_docs_count": 0,
            "existing_wiki_count": 0
        }
        
        try:
            # Check for existing threat documents
            threat_docs = self.document_storage.get_documents_by_repo(repo_id)
            compatibility_check["threat_docs_count"] = len(threat_docs)
            
            # Check for existing security documents
            security_docs = self.db_manager.get_security_documents_by_repo(repo_id)
            compatibility_check["security_docs_count"] = len(security_docs)
            
            # Check for existing wikis
            existing_wikis = self.wiki_storage.get_wikis_by_repo(repo_id)
            compatibility_check["existing_wiki_count"] = len(existing_wikis)
            
            # Validate compatibility
            if compatibility_check["threat_docs_count"] == 0 and compatibility_check["security_docs_count"] == 0:
                compatibility_check["compatible"] = False
                compatibility_check["issues"].append("No documents found to migrate")
            
            if compatibility_check["existing_wiki_count"] > 0:
                compatibility_check["warnings"].append(f"Repository already has {compatibility_check['existing_wiki_count']} wiki(s)")
            
            # Check for already migrated documents
            migrated_threat_docs = 0
            for doc in threat_docs:
                if doc.metadata.get("migrated_to_wiki"):
                    migrated_threat_docs += 1
            
            if migrated_threat_docs > 0:
                compatibility_check["warnings"].append(f"{migrated_threat_docs} threat documents already migrated")
            
        except Exception as e:
            compatibility_check["compatible"] = False
            compatibility_check["issues"].append(f"Compatibility check failed: {str(e)}")
        
        return compatibility_check
    
    def rollback_migration(self, repo_id: str, wiki_id: str) -> Dict[str, Any]:
        """Rollback wiki migration by removing wiki and unmarking documents"""
        rollback_result = {
            "repo_id": repo_id,
            "wiki_id": wiki_id,
            "started_at": datetime.now().isoformat(),
            "success": True,
            "errors": []
        }
        
        try:
            # Remove the wiki
            wiki = self.wiki_storage.load_wiki(wiki_id)
            if wiki:
                # Clean up wiki storage
                self.wiki_storage._delete_wiki_from_database(wiki_id)
                self.wiki_storage._delete_wiki_from_file(wiki_id)
                self.wiki_storage._remove_from_search_index(wiki_id)
                
                # Unmark migrated documents
                if wiki.metadata.get("migrated_from") == "threat_documents":
                    self._unmark_migrated_threat_documents(repo_id, wiki_id)
                elif wiki.metadata.get("migrated_from") == "security_documents":
                    self._unmark_migrated_security_documents(repo_id, wiki_id)
                
                logger.info(f"Successfully rolled back migration for wiki {wiki_id}")
            else:
                rollback_result["errors"].append(f"Wiki {wiki_id} not found")
                rollback_result["success"] = False
            
        except Exception as e:
            rollback_result["success"] = False
            rollback_result["errors"].append(f"Rollback failed: {str(e)}")
            logger.error(f"Migration rollback failed: {e}")
        
        rollback_result["completed_at"] = datetime.now().isoformat()
        return rollback_result
    
    def _unmark_migrated_threat_documents(self, repo_id: str, wiki_id: str):
        """Remove migration markers from threat documents"""
        try:
            threat_docs = self.document_storage.get_documents_by_repo(repo_id)
            
            for doc in threat_docs:
                if doc.metadata.get("migrated_to_wiki") == wiki_id:
                    # Remove migration metadata
                    if "migrated_to_wiki" in doc.metadata:
                        del doc.metadata["migrated_to_wiki"]
                    if "migration_timestamp" in doc.metadata:
                        del doc.metadata["migration_timestamp"]
                    
                    # Update document
                    self.document_storage.update_document_metadata(doc.id, doc.metadata)
            
        except Exception as e:
            logger.error(f"Failed to unmark threat documents: {e}")
    
    def _unmark_migrated_security_documents(self, repo_id: str, wiki_id: str):
        """Remove migration markers from security documents"""
        try:
            security_docs = self.db_manager.get_security_documents_by_repo(repo_id)
            
            for doc in security_docs:
                if doc.metadata.get("migrated_to_wiki") == wiki_id:
                    # Remove migration metadata
                    if "migrated_to_wiki" in doc.metadata:
                        del doc.metadata["migrated_to_wiki"]
                    if "migration_timestamp" in doc.metadata:
                        del doc.metadata["migration_timestamp"]
                    
                    doc.updated_at = datetime.now()
                    
                    # Update document
                    self.db_manager.save_security_document(doc)
            
        except Exception as e:
            logger.error(f"Failed to unmark security documents: {e}")


# Global wiki migration utility instance
wiki_migration = WikiMigrationUtility()