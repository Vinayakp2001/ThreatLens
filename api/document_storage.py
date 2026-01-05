"""
Document storage and metadata management service
"""
import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from .models import ThreatDoc, SecurityDocument, CodeReference, RepoContext
from .database import DatabaseManager
from .config import settings


logger = logging.getLogger(__name__)


class DocumentStorageService:
    """Service for managing threat document storage and metadata"""
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db_manager = db_manager or DatabaseManager()
        self.docs_storage_path = Path(settings.docs_storage_path)
        self.docs_storage_path.mkdir(parents=True, exist_ok=True)
    
    def save_document(self, document) -> bool:
        """Save document (ThreatDoc or SecurityDocument) with both database and file storage"""
        try:
            # Handle both legacy ThreatDoc and new SecurityDocument
            if hasattr(document, 'doc_type'):
                # Legacy ThreatDoc
                db_success = self.db_manager.save_threat_doc(document)
            else:
                # New SecurityDocument
                db_success = self.db_manager.save_security_document(document)
            
            if not db_success:
                logger.error(f"Failed to save document {document.id} to database")
                return False
            
            # Save to file system for backup and direct access
            file_success = self._save_document_to_file(document)
            if not file_success:
                logger.warning(f"Failed to save document {document.id} to file system")
                # Don't fail the operation if file save fails, database is primary
            
            logger.info(f"Successfully saved document {document.id}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving document {document.id}: {e}")
            return False
    
    def save_documents_batch(self, documents: List) -> Dict[str, bool]:
        """Save multiple documents (ThreatDoc or SecurityDocument) in batch with transaction support"""
        results = {}
        
        for doc in documents:
            results[doc.id] = self.save_document(doc)
        
        successful_saves = sum(1 for success in results.values() if success)
        logger.info(f"Batch save completed: {successful_saves}/{len(documents)} documents saved")
        
        return results
    
    def get_document(self, doc_id: str, version: Optional[int] = None) -> Optional[ThreatDoc]:
        """Get a specific document by ID and optionally by version"""
        return self.db_manager.get_threat_doc_by_id(doc_id, version)
    
    def get_documents_by_repo(
        self, 
        repo_id: str, 
        doc_type: Optional[str] = None,
        include_all_versions: bool = False
    ) -> List[ThreatDoc]:
        """Get documents for a repository, optionally filtered by type"""
        if doc_type:
            return self.db_manager.get_documents_by_type(repo_id, doc_type)
        else:
            return self.db_manager.get_threat_docs_by_repo(repo_id, include_all_versions)
    
    def get_document_versions(self, doc_id: str) -> List[Dict[str, Any]]:
        """Get version history for a document"""
        return self.db_manager.get_document_versions(doc_id)
    
    def update_document_metadata(self, doc_id: str, metadata_updates: Dict[str, Any]) -> bool:
        """Update document metadata"""
        try:
            # Get current document
            current_doc = self.get_document(doc_id)
            if not current_doc:
                logger.error(f"Document {doc_id} not found")
                return False
            
            # Update metadata
            current_doc.metadata.update(metadata_updates)
            current_doc.updated_at = datetime.now()
            
            # Save updated document
            return self.save_document(current_doc)
            
        except Exception as e:
            logger.error(f"Error updating document metadata: {e}")
            return False
    
    def link_code_reference(self, doc_id: str, code_reference: CodeReference) -> bool:
        """Add a code reference to a document"""
        try:
            current_doc = self.get_document(doc_id)
            if not current_doc:
                logger.error(f"Document {doc_id} not found")
                return False
            
            # Add code reference if not already present
            existing_refs = [ref.id for ref in current_doc.code_references]
            if code_reference.id not in existing_refs:
                current_doc.code_references.append(code_reference)
                current_doc.updated_at = datetime.now()
                return self.save_document(current_doc)
            
            return True
            
        except Exception as e:
            logger.error(f"Error linking code reference: {e}")
            return False
    
    def get_documents_by_code_reference(self, file_path: str) -> List[ThreatDoc]:
        """Get all documents that reference a specific file"""
        try:
            all_docs = []
            # This is a simplified implementation - in practice, you'd want a more efficient query
            repos = self._get_all_repo_ids()
            
            for repo_id in repos:
                docs = self.get_documents_by_repo(repo_id)
                for doc in docs:
                    if any(ref.file_path == file_path for ref in doc.code_references):
                        all_docs.append(doc)
            
            return all_docs
            
        except Exception as e:
            logger.error(f"Error getting documents by code reference: {e}")
            return []
    
    def get_repository_statistics(self, repo_id: str) -> Dict[str, Any]:
        """Get comprehensive statistics for a repository"""
        return self.db_manager.get_repo_statistics(repo_id)
    
    def cleanup_repository_documents(self, repo_id: str) -> bool:
        """Clean up old document versions for a repository"""
        try:
            # Clean up database versions
            db_cleanup = self.db_manager.cleanup_old_versions(repo_id)
            
            # Clean up file system
            file_cleanup = self._cleanup_repository_files(repo_id)
            
            logger.info(f"Repository cleanup completed for {repo_id}")
            return db_cleanup and file_cleanup
            
        except Exception as e:
            logger.error(f"Error cleaning up repository documents: {e}")
            return False
    
    def export_documents(self, repo_id: str, export_format: str = "json") -> Optional[str]:
        """Export all documents for a repository"""
        try:
            docs = self.get_documents_by_repo(repo_id)
            
            if export_format.lower() == "json":
                return self._export_as_json(docs, repo_id)
            elif export_format.lower() == "markdown":
                return self._export_as_markdown(docs, repo_id)
            else:
                logger.error(f"Unsupported export format: {export_format}")
                return None
                
        except Exception as e:
            logger.error(f"Error exporting documents: {e}")
            return None
    
    def _save_document_to_file(self, document) -> bool:
        """Save document (ThreatDoc or SecurityDocument) to file system"""
        try:
            repo_dir = self.docs_storage_path / document.repo_id
            repo_dir.mkdir(exist_ok=True)
            
            # Create filename based on document type and ID
            if hasattr(document, 'doc_type'):
                # Legacy ThreatDoc
                filename = f"{document.doc_type}_{document.id}.md"
            else:
                # New SecurityDocument
                filename = f"security_analysis_{document.id}.md"
            
            file_path = repo_dir / filename
            
            # Create document content with metadata header
            content = self._create_file_content(document)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving document to file: {e}")
            return False
    
    def _create_file_content(self, document) -> str:
        """Create file content with metadata header for ThreatDoc or SecurityDocument"""
        # Handle both legacy ThreatDoc and new SecurityDocument
        if hasattr(document, 'doc_type'):
            # Legacy ThreatDoc
            doc_type = document.doc_type if isinstance(document.doc_type, str) else document.doc_type.value
        else:
            # New SecurityDocument
            doc_type = "security_analysis"
        
        metadata_header = f"""---
id: {document.id}
repo_id: {document.repo_id}
doc_type: {doc_type}
title: {document.title}
created_at: {document.created_at.isoformat()}
updated_at: {document.updated_at.isoformat() if document.updated_at else 'null'}
"""
        
        # Add scope for SecurityDocument
        if hasattr(document, 'scope'):
            metadata_header += f"scope: {document.scope}\n"
        
        # Add version for ThreatDoc
        if hasattr(document, 'doc_type'):
            metadata_header += f"version: {document.metadata.get('version', 1)}\n"
        
        metadata_header += "---\n\n"
        
        # Add code references section if present
        if document.code_references:
            code_refs_section = "\n## Code References\n\n"
            for ref in document.code_references:
                code_refs_section += f"- **{ref.file_path}**"
                if ref.function_name:
                    code_refs_section += f" (Function: {ref.function_name})"
                if ref.line_start:
                    code_refs_section += f" (Lines: {ref.line_start}"
                    if ref.line_end and ref.line_end != ref.line_start:
                        code_refs_section += f"-{ref.line_end}"
                    code_refs_section += ")"
                code_refs_section += "\n"
            
            return metadata_header + document.content + code_refs_section
        
        return metadata_header + document.content
    
    def _cleanup_repository_files(self, repo_id: str) -> bool:
        """Clean up old files for a repository"""
        try:
            repo_dir = self.docs_storage_path / repo_id
            if repo_dir.exists():
                # Get current document IDs from database
                current_docs = self.get_documents_by_repo(repo_id)
                current_ids = {doc.id for doc in current_docs}
                
                # Remove files for documents that no longer exist
                for file_path in repo_dir.glob("*.md"):
                    # Extract document ID from filename
                    filename = file_path.stem
                    if "_" in filename:
                        doc_id = filename.split("_", 1)[1]
                        if doc_id not in current_ids:
                            file_path.unlink()
                            logger.info(f"Removed orphaned file: {file_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error cleaning up repository files: {e}")
            return False
    
    def _get_all_repo_ids(self) -> List[str]:
        """Get all repository IDs from database"""
        # This is a simplified implementation
        # In practice, you'd add this method to DatabaseManager
        return []
    
    def _export_as_json(self, docs: List[ThreatDoc], repo_id: str) -> str:
        """Export documents as JSON"""
        export_data = {
            "repo_id": repo_id,
            "export_timestamp": datetime.now().isoformat(),
            "documents": []
        }
        
        for doc in docs:
            doc_data = {
                "id": doc.id,
                "title": doc.title,
                "doc_type": doc.doc_type.value,
                "content": doc.content,
                "metadata": doc.metadata,
                "code_references": [
                    {
                        "id": ref.id,
                        "file_path": ref.file_path,
                        "line_start": ref.line_start,
                        "line_end": ref.line_end,
                        "function_name": ref.function_name,
                        "class_name": ref.class_name,
                        "code_snippet": ref.code_snippet
                    }
                    for ref in doc.code_references
                ],
                "created_at": doc.created_at.isoformat(),
                "updated_at": doc.updated_at.isoformat() if doc.updated_at else None
            }
            export_data["documents"].append(doc_data)
        
        return json.dumps(export_data, indent=2)
    
    def _export_as_markdown(self, docs: List[ThreatDoc], repo_id: str) -> str:
        """Export documents as combined markdown"""
        markdown_content = f"# Threat Modeling Documentation - {repo_id}\n\n"
        markdown_content += f"Generated on: {datetime.now().isoformat()}\n\n"
        markdown_content += "---\n\n"
        
        # Group documents by type
        docs_by_type = {}
        for doc in docs:
            if doc.doc_type not in docs_by_type:
                docs_by_type[doc.doc_type] = []
            docs_by_type[doc.doc_type].append(doc)
        
        # Export in logical order
        type_order = [
            "system_overview",
            "component_profile", 
            "flow_threat_model",
            "mitigation"
        ]
        
        for doc_type in type_order:
            if doc_type in docs_by_type:
                markdown_content += f"## {doc_type.replace('_', ' ').title()}\n\n"
                
                for doc in docs_by_type[doc_type]:
                    markdown_content += f"### {doc.title}\n\n"
                    markdown_content += doc.content + "\n\n"
                    
                    if doc.code_references:
                        markdown_content += "#### Code References\n\n"
                        for ref in doc.code_references:
                            markdown_content += f"- {ref.file_path}"
                            if ref.function_name:
                                markdown_content += f" ({ref.function_name})"
                            markdown_content += "\n"
                        markdown_content += "\n"
                    
                    markdown_content += "---\n\n"
        
        return markdown_content


# Global document storage service instance
document_storage = DocumentStorageService()