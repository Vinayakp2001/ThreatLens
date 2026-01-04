"""
Repository Knowledge Base Manager for Security Wiki Generator

This module manages repository knowledge bases for context-aware analysis.
It provides functions to check if repo analysis exists, store and retrieve
security knowledge, and manage the knowledge base lifecycle.
"""
import os
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from api.config import settings
from api.models import SecurityDocument, RepoContext
from api.database import DatabaseManager
from api.rag import FAISSIndexManager, EmbeddingGenerator

logger = logging.getLogger(__name__)


class RepositoryKnowledgeBase:
    """Manages repository knowledge base for context-aware analysis"""
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.faiss_manager = FAISSIndexManager()
        self.embedding_generator = EmbeddingGenerator()
        
        # Create knowledge base storage directory
        self.kb_storage_path = Path(settings.storage_base_path) / "knowledge_bases"
        self.kb_storage_path.mkdir(parents=True, exist_ok=True)
    
    def check_repo_analysis_exists(self, repo_id: str) -> Dict[str, Any]:
        """
        Check if repository analysis exists and return status information
        
        Args:
            repo_id: Repository identifier
            
        Returns:
            Dictionary with analysis status information
        """
        try:
            # Check if repo context exists in database
            repo_context = self.db_manager.get_repo_context(repo_id)
            
            if not repo_context:
                return {
                    "exists": False,
                    "repo_id": repo_id,
                    "status": "not_analyzed",
                    "message": "Repository has not been analyzed"
                }
            
            # Check if security documents exist
            security_docs = self._get_security_documents(repo_id)
            
            # Check if FAISS index exists
            has_faiss_index = self._check_faiss_index_exists(repo_id)
            
            # Determine overall status
            if security_docs and has_faiss_index:
                status = "complete"
                message = "Full repository analysis available"
            elif security_docs:
                status = "partial"
                message = "Security documents exist but search index missing"
            else:
                status = "incomplete"
                message = "Repository context exists but no security analysis"
            
            return {
                "exists": len(security_docs) > 0,
                "repo_id": repo_id,
                "status": status,
                "message": message,
                "analysis_date": repo_context.created_at.isoformat() if repo_context else None,
                "document_count": len(security_docs),
                "has_search_index": has_faiss_index,
                "repo_context": {
                    "primary_languages": repo_context.primary_languages if repo_context else [],
                    "analysis_status": repo_context.analysis_status if repo_context else "unknown"
                }
            }
            
        except Exception as e:
            logger.error(f"Error checking repo analysis for {repo_id}: {e}")
            return {
                "exists": False,
                "repo_id": repo_id,
                "status": "error",
                "message": f"Error checking analysis status: {str(e)}"
            }
    
    def get_repo_security_context(self, repo_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve comprehensive security context for a repository
        
        Args:
            repo_id: Repository identifier
            
        Returns:
            Dictionary with security context or None if not available
        """
        try:
            # Check if analysis exists
            analysis_status = self.check_repo_analysis_exists(repo_id)
            
            if not analysis_status["exists"]:
                return None
            
            # Get security documents
            security_docs = self._get_security_documents(repo_id)
            
            # Get repo context
            repo_context = self.db_manager.get_repo_context(repo_id)
            
            # Compile security context
            security_context = {
                "repo_id": repo_id,
                "analysis_date": analysis_status["analysis_date"],
                "status": analysis_status["status"],
                "repo_info": {
                    "primary_languages": repo_context.primary_languages if repo_context else [],
                    "structure_summary": repo_context.structure_summary if repo_context else {}
                },
                "security_documents": [],
                "security_summary": self._generate_security_summary(security_docs),
                "searchable": analysis_status["has_search_index"]
            }
            
            # Add document summaries (not full content to keep context manageable)
            for doc in security_docs:
                doc_summary = {
                    "id": doc.id,
                    "title": doc.title,
                    "scope": doc.scope,
                    "created_at": doc.created_at.isoformat(),
                    "content_preview": doc.content[:500] + "..." if len(doc.content) > 500 else doc.content,
                    "metadata": doc.metadata
                }
                security_context["security_documents"].append(doc_summary)
            
            return security_context
            
        except Exception as e:
            logger.error(f"Error retrieving security context for {repo_id}: {e}")
            return None
    
    def store_security_knowledge(self, repo_id: str, security_docs: List[SecurityDocument]) -> bool:
        """
        Store security knowledge in the knowledge base
        
        Args:
            repo_id: Repository identifier
            security_docs: List of security documents to store
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Store documents in database
            for doc in security_docs:
                success = self.db_manager.save_security_document(doc)
                if not success:
                    logger.error(f"Failed to save security document {doc.id}")
                    return False
            
            # Create embeddings and store in FAISS index
            self._create_and_store_embeddings(repo_id, security_docs)
            
            # Save knowledge base metadata
            self._save_kb_metadata(repo_id, security_docs)
            
            logger.info(f"Successfully stored security knowledge for repo {repo_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing security knowledge for {repo_id}: {e}")
            return False
    
    def search_security_knowledge(self, repo_id: str, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Search repository security knowledge base
        
        Args:
            repo_id: Repository identifier
            query: Search query
            top_k: Number of results to return
            
        Returns:
            List of search results
        """
        try:
            # Check if knowledge base exists
            if not self.check_repo_analysis_exists(repo_id)["exists"]:
                return []
            
            # Load FAISS index if not already loaded
            if not self.faiss_manager.load_index(repo_id):
                logger.warning(f"Could not load FAISS index for repo {repo_id}")
                return []
            
            # Generate query embedding
            query_embeddings = self.embedding_generator.generate_embeddings([query])
            if not query_embeddings:
                return []
            
            query_vector = query_embeddings[0]
            
            # Search FAISS index
            search_results = self.faiss_manager.search(repo_id, query_vector, top_k)
            
            # Enhance results with document content
            enhanced_results = []
            for result in search_results:
                # Get full document content if needed
                doc_id = result.get('content_id')
                if doc_id:
                    security_doc = self.db_manager.get_security_document(doc_id)
                    if security_doc:
                        enhanced_result = {
                            "relevance_score": result["relevance_score"],
                            "document_id": doc_id,
                            "title": security_doc.title,
                            "content_snippet": self._extract_relevant_snippet(security_doc.content, query),
                            "scope": security_doc.scope,
                            "metadata": security_doc.metadata
                        }
                        enhanced_results.append(enhanced_result)
            
            return enhanced_results
            
        except Exception as e:
            logger.error(f"Error searching security knowledge for {repo_id}: {e}")
            return []
    
    def delete_repo_knowledge_base(self, repo_id: str) -> bool:
        """
        Delete repository knowledge base
        
        Args:
            repo_id: Repository identifier
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Delete security documents from database
            self.db_manager.delete_security_documents_by_repo(repo_id)
            
            # Delete FAISS index
            self.faiss_manager.delete_index(repo_id)
            
            # Delete knowledge base metadata
            kb_metadata_path = self.kb_storage_path / f"{repo_id}_metadata.json"
            if kb_metadata_path.exists():
                kb_metadata_path.unlink()
            
            logger.info(f"Successfully deleted knowledge base for repo {repo_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting knowledge base for {repo_id}: {e}")
            return False
    
    def get_knowledge_base_stats(self, repo_id: str) -> Dict[str, Any]:
        """
        Get statistics about repository knowledge base
        
        Args:
            repo_id: Repository identifier
            
        Returns:
            Dictionary with knowledge base statistics
        """
        try:
            analysis_status = self.check_repo_analysis_exists(repo_id)
            
            if not analysis_status["exists"]:
                return {"exists": False, "repo_id": repo_id}
            
            # Get FAISS index stats
            faiss_stats = self.faiss_manager.get_index_stats(repo_id)
            
            # Get document count and sizes
            security_docs = self._get_security_documents(repo_id)
            total_content_size = sum(len(doc.content) for doc in security_docs)
            
            return {
                "exists": True,
                "repo_id": repo_id,
                "status": analysis_status["status"],
                "document_count": len(security_docs),
                "total_content_size": total_content_size,
                "average_doc_size": total_content_size // len(security_docs) if security_docs else 0,
                "faiss_stats": faiss_stats,
                "last_updated": analysis_status["analysis_date"]
            }
            
        except Exception as e:
            logger.error(f"Error getting knowledge base stats for {repo_id}: {e}")
            return {"exists": False, "repo_id": repo_id, "error": str(e)}
    
    def _get_security_documents(self, repo_id: str) -> List[SecurityDocument]:
        """Get all security documents for a repository"""
        try:
            return self.db_manager.get_security_documents_by_repo(repo_id)
        except Exception as e:
            logger.error(f"Error getting security documents for {repo_id}: {e}")
            return []
    
    def _check_faiss_index_exists(self, repo_id: str) -> bool:
        """Check if FAISS index exists for repository"""
        index_path = Path(settings.embeddings_storage_path) / f"{repo_id}.index"
        metadata_path = Path(settings.embeddings_storage_path) / f"{repo_id}.metadata"
        return index_path.exists() and metadata_path.exists()
    
    def _generate_security_summary(self, security_docs: List[SecurityDocument]) -> Dict[str, Any]:
        """Generate a summary of security findings from documents"""
        if not security_docs:
            return {}
        
        summary = {
            "total_documents": len(security_docs),
            "document_types": {},
            "key_topics": [],
            "risk_indicators": []
        }
        
        # Analyze document scopes and metadata
        for doc in security_docs:
            scope = doc.scope
            if scope in summary["document_types"]:
                summary["document_types"][scope] += 1
            else:
                summary["document_types"][scope] = 1
            
            # Extract key topics from titles and metadata
            if "topics" in doc.metadata:
                summary["key_topics"].extend(doc.metadata["topics"])
            
            if "risk_level" in doc.metadata:
                summary["risk_indicators"].append(doc.metadata["risk_level"])
        
        # Remove duplicates and limit
        summary["key_topics"] = list(set(summary["key_topics"]))[:10]
        
        return summary
    
    def _create_and_store_embeddings(self, repo_id: str, security_docs: List[SecurityDocument]):
        """Create embeddings for security documents and store in FAISS"""
        from api.models import Embedding
        
        # Prepare texts for embedding
        texts = []
        embedding_metadata = []
        
        for doc in security_docs:
            # Split document into chunks if it's large
            if len(doc.content) > 1000:
                chunks = self._chunk_document_content(doc.content)
                for i, chunk in enumerate(chunks):
                    texts.append(chunk)
                    embedding_metadata.append({
                        "doc_id": doc.id,
                        "chunk_index": i,
                        "doc_title": doc.title,
                        "doc_scope": doc.scope
                    })
            else:
                texts.append(doc.content)
                embedding_metadata.append({
                    "doc_id": doc.id,
                    "chunk_index": 0,
                    "doc_title": doc.title,
                    "doc_scope": doc.scope
                })
        
        # Generate embeddings
        embedding_vectors = self.embedding_generator.generate_embeddings(texts)
        
        # Create Embedding objects
        embeddings = []
        for i, (vector, metadata) in enumerate(zip(embedding_vectors, embedding_metadata)):
            embedding = Embedding(
                id=f"{repo_id}_{metadata['doc_id']}_chunk_{metadata['chunk_index']}",
                repo_id=repo_id,
                content_type="security_document",
                content_id=metadata["doc_id"],
                embedding_vector=vector,
                metadata=metadata
            )
            embeddings.append(embedding)
        
        # Store in FAISS index
        self.faiss_manager.add_embeddings(repo_id, embeddings)
        self.faiss_manager.save_index(repo_id)
    
    def _chunk_document_content(self, content: str, chunk_size: int = 1000, overlap: int = 100) -> List[str]:
        """Split document content into overlapping chunks"""
        if len(content) <= chunk_size:
            return [content]
        
        chunks = []
        start = 0
        
        while start < len(content):
            end = start + chunk_size
            
            # Try to break at sentence boundary
            if end < len(content):
                sentence_end = content.rfind('.', start, end)
                if sentence_end > start + chunk_size // 2:
                    end = sentence_end + 1
            
            chunk = content[start:end].strip()
            if chunk:
                chunks.append(chunk)
            
            start = end - overlap
            if start >= len(content):
                break
        
        return chunks
    
    def _extract_relevant_snippet(self, content: str, query: str, snippet_length: int = 300) -> str:
        """Extract relevant snippet from content based on query"""
        query_words = query.lower().split()
        content_lower = content.lower()
        
        # Find the best position to extract snippet
        best_pos = 0
        best_score = 0
        
        for i in range(0, len(content) - snippet_length, 50):
            snippet = content_lower[i:i + snippet_length]
            score = sum(1 for word in query_words if word in snippet)
            
            if score > best_score:
                best_score = score
                best_pos = i
        
        # Extract snippet and clean it up
        snippet = content[best_pos:best_pos + snippet_length]
        
        # Try to start and end at word boundaries
        if best_pos > 0:
            space_pos = snippet.find(' ')
            if space_pos > 0:
                snippet = snippet[space_pos + 1:]
        
        if len(snippet) == snippet_length:
            last_space = snippet.rfind(' ')
            if last_space > snippet_length // 2:
                snippet = snippet[:last_space] + "..."
        
        return snippet
    
    def _save_kb_metadata(self, repo_id: str, security_docs: List[SecurityDocument]):
        """Save knowledge base metadata to disk"""
        metadata = {
            "repo_id": repo_id,
            "created_at": datetime.now().isoformat(),
            "document_count": len(security_docs),
            "documents": [
                {
                    "id": doc.id,
                    "title": doc.title,
                    "scope": doc.scope,
                    "content_length": len(doc.content),
                    "created_at": doc.created_at.isoformat()
                }
                for doc in security_docs
            ]
        }
        
        metadata_path = self.kb_storage_path / f"{repo_id}_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)