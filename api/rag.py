"""
RAG (Retrieval Augmented Generation) system for enhanced context retrieval
Enhanced with intelligent CPU/GPU resource management.
"""
import os
import re
import json
import pickle
import hashlib
import logging
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
import openai

from .config import settings
from .models import (
    ThreatDoc, CodeReference, SearchResult, Embedding,
    RepoContext
)
from .resource_manager import get_resource_manager, ResourceManager

logger = logging.getLogger(__name__)


class DocumentChunker:
    """Handles document chunking for optimal embedding size"""
    
    def __init__(self, chunk_size: int = 512, chunk_overlap: int = 50):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
    
    def chunk_document(self, doc: ThreatDoc) -> List[Dict[str, Any]]:
        """
        Chunk a threat document into smaller pieces for embedding
        
        Args:
            doc: ThreatDoc to chunk
            
        Returns:
            List of chunks with metadata
        """
        chunks = []
        content = doc.content
        
        # Split by sections first (markdown headers)
        sections = self._split_by_headers(content)
        
        for section_idx, section in enumerate(sections):
            section_chunks = self._chunk_text(section['content'])
            
            for chunk_idx, chunk_text in enumerate(section_chunks):
                if len(chunk_text.strip()) < 50:  # Skip very small chunks
                    continue
                    
                chunk_id = f"{doc.id}_section_{section_idx}_chunk_{chunk_idx}"
                chunks.append({
                    'id': chunk_id,
                    'content': chunk_text,
                    'doc_id': doc.id,
                    'doc_type': doc.doc_type.value,
                    'doc_title': doc.title,
                    'section_title': section.get('title', ''),
                    'chunk_index': chunk_idx,
                    'section_index': section_idx,
                    'metadata': {
                        'repo_id': doc.repo_id,
                        'created_at': doc.created_at.isoformat(),
                        'doc_metadata': doc.metadata
                    }
                })
        
        return chunks
    
    def _split_by_headers(self, content: str) -> List[Dict[str, Any]]:
        """Split content by markdown headers"""
        sections = []
        lines = content.split('\n')
        current_section = {'title': '', 'content': ''}
        
        for line in lines:
            if line.startswith('#'):
                # Save previous section if it has content
                if current_section['content'].strip():
                    sections.append(current_section)
                
                # Start new section
                current_section = {
                    'title': line.strip('#').strip(),
                    'content': line + '\n'
                }
            else:
                current_section['content'] += line + '\n'
        
        # Add the last section
        if current_section['content'].strip():
            sections.append(current_section)
        
        return sections
    
    def _chunk_text(self, text: str) -> List[str]:
        """Chunk text into smaller pieces with overlap"""
        if len(text) <= self.chunk_size:
            return [text]
        
        chunks = []
        start = 0
        
        while start < len(text):
            end = start + self.chunk_size
            
            # Try to break at sentence boundary
            if end < len(text):
                # Look for sentence endings within the last 100 characters
                sentence_end = text.rfind('.', start, end)
                if sentence_end > start + self.chunk_size // 2:
                    end = sentence_end + 1
                else:
                    # Look for paragraph breaks
                    para_break = text.rfind('\n\n', start, end)
                    if para_break > start + self.chunk_size // 2:
                        end = para_break + 2
            
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            
            # Move start position with overlap
            start = end - self.chunk_overlap
            if start >= len(text):
                break
        
        return chunks


class CodeSnippetExtractor:
    """Extracts and processes code snippets for embedding"""
    
    def __init__(self):
        self.function_patterns = {
            'python': [
                r'def\s+(\w+)\s*\([^)]*\):',
                r'class\s+(\w+)(?:\([^)]*\))?:',
                r'async\s+def\s+(\w+)\s*\([^)]*\):'
            ],
            'javascript': [
                r'function\s+(\w+)\s*\([^)]*\)\s*{',
                r'const\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*{',
                r'class\s+(\w+)(?:\s+extends\s+\w+)?\s*{'
            ],
            'java': [
                r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\([^)]*\)\s*{',
                r'(?:public|private|protected)?\s*class\s+(\w+)(?:\s+extends\s+\w+)?(?:\s+implements\s+[\w,\s]+)?\s*{'
            ]
        }
    
    def extract_from_repo(self, repo_context: RepoContext) -> List[Dict[str, Any]]:
        """
        Extract code snippets from repository
        
        Args:
            repo_context: Repository context
            
        Returns:
            List of code snippets with metadata
        """
        snippets = []
        repo_path = Path(repo_context.local_path)
        
        # Get relevant file extensions based on detected languages
        extensions = self._get_file_extensions(repo_context.primary_languages)
        
        for ext in extensions:
            for file_path in repo_path.rglob(f"*.{ext}"):
                if self._should_skip_file(file_path):
                    continue
                
                try:
                    file_snippets = self._extract_from_file(file_path, repo_context.repo_id)
                    snippets.extend(file_snippets)
                except Exception as e:
                    logger.warning(f"Failed to extract from {file_path}: {e}")
        
        return snippets
    
    def _get_file_extensions(self, languages: List[str]) -> List[str]:
        """Get file extensions for given languages"""
        extension_map = {
            'python': ['py'],
            'javascript': ['js', 'ts', 'jsx', 'tsx'],
            'java': ['java'],
            'go': ['go'],
            'rust': ['rs'],
            'cpp': ['cpp', 'cc', 'cxx', 'h', 'hpp'],
            'c': ['c', 'h'],
            'php': ['php'],
            'ruby': ['rb'],
            'swift': ['swift'],
            'kotlin': ['kt']
        }
        
        extensions = set()
        for lang in languages:
            lang_lower = lang.lower()
            if lang_lower in extension_map:
                extensions.update(extension_map[lang_lower])
        
        # Default to common extensions if no languages detected
        if not extensions:
            extensions = {'py', 'js', 'java', 'go', 'rs'}
        
        return list(extensions)
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped"""
        skip_patterns = [
            'test', 'spec', '__pycache__', 'node_modules',
            '.git', 'vendor', 'build', 'dist', 'target'
        ]
        
        path_str = str(file_path).lower()
        return any(pattern in path_str for pattern in skip_patterns)
    
    def _extract_from_file(self, file_path: Path, repo_id: str) -> List[Dict[str, Any]]:
        """Extract code snippets from a single file"""
        snippets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Could not read file {file_path}: {e}")
            return snippets
        
        # Detect language from file extension
        language = self._detect_language(file_path)
        if not language:
            return snippets
        
        # Extract functions and classes
        patterns = self.function_patterns.get(language, [])
        lines = content.split('\n')
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                function_name = match.group(1)
                start_line = content[:match.start()].count('\n') + 1
                
                # Extract the full function/class body
                snippet_lines, end_line = self._extract_function_body(
                    lines, start_line - 1, language
                )
                
                if snippet_lines:
                    snippet_content = '\n'.join(snippet_lines)
                    relative_path = str(file_path.relative_to(file_path.parents[len(file_path.parents) - 1]))
                    
                    snippet_id = hashlib.md5(
                        f"{repo_id}_{relative_path}_{function_name}_{start_line}".encode()
                    ).hexdigest()
                    
                    snippets.append({
                        'id': snippet_id,
                        'content': snippet_content,
                        'function_name': function_name,
                        'file_path': relative_path,
                        'line_start': start_line,
                        'line_end': end_line,
                        'language': language,
                        'metadata': {
                            'repo_id': repo_id,
                            'content_type': 'code',
                            'file_size': len(content)
                        }
                    })
        
        return snippets
    
    def _detect_language(self, file_path: Path) -> Optional[str]:
        """Detect programming language from file extension"""
        extension = file_path.suffix.lower().lstrip('.')
        
        language_map = {
            'py': 'python',
            'js': 'javascript',
            'ts': 'javascript',
            'jsx': 'javascript',
            'tsx': 'javascript',
            'java': 'java',
            'go': 'go',
            'rs': 'rust',
            'cpp': 'cpp',
            'cc': 'cpp',
            'cxx': 'cpp',
            'c': 'c',
            'php': 'php',
            'rb': 'ruby',
            'swift': 'swift',
            'kt': 'kotlin'
        }
        
        return language_map.get(extension)
    
    def _extract_function_body(self, lines: List[str], start_idx: int, language: str) -> Tuple[List[str], int]:
        """Extract the full body of a function or class"""
        if start_idx >= len(lines):
            return [], start_idx
        
        if language == 'python':
            return self._extract_python_body(lines, start_idx)
        elif language in ['javascript', 'java', 'cpp', 'c']:
            return self._extract_brace_body(lines, start_idx)
        else:
            # Default: extract next 20 lines or until empty line
            end_idx = min(start_idx + 20, len(lines))
            for i in range(start_idx + 1, len(lines)):
                if not lines[i].strip():
                    end_idx = i
                    break
            return lines[start_idx:end_idx], end_idx
    
    def _extract_python_body(self, lines: List[str], start_idx: int) -> Tuple[List[str], int]:
        """Extract Python function/class body based on indentation"""
        if start_idx >= len(lines):
            return [], start_idx
        
        # Find the base indentation level
        base_indent = len(lines[start_idx]) - len(lines[start_idx].lstrip())
        
        end_idx = start_idx + 1
        for i in range(start_idx + 1, len(lines)):
            line = lines[i]
            if not line.strip():  # Empty line
                continue
            
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= base_indent and line.strip():
                break
            
            end_idx = i + 1
        
        return lines[start_idx:end_idx], end_idx
    
    def _extract_brace_body(self, lines: List[str], start_idx: int) -> Tuple[List[str], int]:
        """Extract function/class body for brace-based languages"""
        if start_idx >= len(lines):
            return [], start_idx
        
        brace_count = 0
        end_idx = start_idx
        found_opening = False
        
        for i in range(start_idx, len(lines)):
            line = lines[i]
            for char in line:
                if char == '{':
                    brace_count += 1
                    found_opening = True
                elif char == '}':
                    brace_count -= 1
                    
                if found_opening and brace_count == 0:
                    end_idx = i + 1
                    return lines[start_idx:end_idx], end_idx
        
        # If no closing brace found, return next 30 lines
        end_idx = min(start_idx + 30, len(lines))
        return lines[start_idx:end_idx], end_idx


class EmbeddingGenerator:
    """Generates embeddings for documents and code snippets with intelligent resource management"""
    
    def __init__(self):
        self.provider = settings.embedding_provider
        self.model_name = settings.embedding_model
        self.sentence_transformer = None
        self.openai_client = None
        self.resource_manager = get_resource_manager()
        
        self._initialize_embedding_model()
    
    def _initialize_embedding_model(self):
        """Initialize the embedding model based on provider and resource capabilities"""
        if self.provider == "sentence-transformers":
            try:
                # Get optimal device configuration from resource manager
                embedding_config = self.resource_manager.get_embedding_config()
                device = embedding_config['device']
                
                self.sentence_transformer = SentenceTransformer(
                    settings.sentence_transformer_model,
                    device=device
                )
                logger.info(f"Initialized SentenceTransformer: {settings.sentence_transformer_model} on {device}")
                logger.info(f"Optimal batch size: {embedding_config['batch_size']}")
            except Exception as e:
                logger.error(f"Failed to initialize SentenceTransformer: {e}")
                # Fallback to CPU if GPU initialization fails
                try:
                    self.sentence_transformer = SentenceTransformer(
                        settings.sentence_transformer_model,
                        device='cpu'
                    )
                    logger.info("Fallback to CPU for SentenceTransformer")
                except Exception as fallback_error:
                    logger.error(f"CPU fallback also failed: {fallback_error}")
                    raise
        
        elif self.provider == "openai":
            if not settings.openai_api_key:
                raise ValueError("OpenAI API key not configured")
            
            self.openai_client = openai.OpenAI(
                api_key=settings.openai_api_key,
                base_url=settings.openai_base_url
            )
            logger.info(f"Initialized OpenAI client with model: {self.model_name}")
        
        else:
            raise ValueError(f"Unsupported embedding provider: {self.provider}")
    
    def generate_embeddings(self, texts: List[str]) -> List[List[float]]:
        """
        Generate embeddings for a list of texts with optimal resource utilization
        
        Args:
            texts: List of text strings to embed
            
        Returns:
            List of embedding vectors
        """
        if not texts:
            return []
        
        if self.provider == "sentence-transformers":
            return self._generate_sentence_transformer_embeddings(texts)
        elif self.provider == "openai":
            return self._generate_openai_embeddings(texts)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _generate_sentence_transformer_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using SentenceTransformer with optimal resource utilization"""
        try:
            # Get optimal batch size from resource manager
            optimal_batch_size = self.resource_manager.get_optimal_batch_size('embedding', len(texts))
            
            # Check if we should use GPU for this operation
            use_gpu = self.resource_manager.should_use_gpu_for_operation('embedding', len(texts))
            
            # Log resource allocation decision
            logger.debug(f"Processing {len(texts)} texts with batch_size={optimal_batch_size}, use_gpu={use_gpu}")
            
            # Process in optimal batches if we have many texts
            if len(texts) > optimal_batch_size:
                all_embeddings = []
                for i in range(0, len(texts), optimal_batch_size):
                    batch = texts[i:i + optimal_batch_size]
                    batch_embeddings = self.sentence_transformer.encode(
                        batch,
                        convert_to_numpy=True,
                        show_progress_bar=False,  # Disable for batches
                        batch_size=optimal_batch_size
                    )
                    all_embeddings.extend(batch_embeddings.tolist())
                    
                    # Log progress for large operations
                    if len(texts) > 100:
                        progress = min(100, ((i + len(batch)) / len(texts)) * 100)
                        logger.info(f"Embedding progress: {progress:.1f}%")
                
                return all_embeddings
            else:
                # Process all at once for smaller batches
                embeddings = self.sentence_transformer.encode(
                    texts,
                    convert_to_numpy=True,
                    show_progress_bar=len(texts) > 10,
                    batch_size=optimal_batch_size
                )
                return embeddings.tolist()
                
        except Exception as e:
            logger.error(f"Failed to generate SentenceTransformer embeddings: {e}")
            # Monitor resource usage on failure
            usage = self.resource_manager.monitor_resource_usage()
            logger.error(f"Resource usage at failure: {usage}")
            raise
    
    def _generate_openai_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using OpenAI API"""
        embeddings = []
        
        # Process in batches to avoid rate limits
        batch_size = 100
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            
            try:
                response = self.openai_client.embeddings.create(
                    model=self.model_name,
                    input=batch
                )
                
                batch_embeddings = [item.embedding for item in response.data]
                embeddings.extend(batch_embeddings)
                
            except Exception as e:
                logger.error(f"Failed to generate OpenAI embeddings for batch {i//batch_size}: {e}")
                # Return zero vectors for failed batch
                zero_vector = [0.0] * settings.embedding_dimension
                embeddings.extend([zero_vector] * len(batch))
        
        return embeddings
    
    def get_embedding_dimension(self) -> int:
        """Get the dimension of embeddings"""
        if self.provider == "sentence-transformers":
            return self.sentence_transformer.get_sentence_embedding_dimension()
        elif self.provider == "openai":
            return settings.embedding_dimension
        else:
            return 768  # Default dimension


class FAISSIndexManager:
    """Manages FAISS indices for vector storage and retrieval with intelligent resource management"""
    
    def __init__(self):
        self.embedding_generator = EmbeddingGenerator()
        self.embedding_dim = self.embedding_generator.get_embedding_dimension()
        self.resource_manager = get_resource_manager()
        self.indices = {}  # repo_id -> faiss.Index
        self.metadata_store = {}  # repo_id -> List[Dict]
        
        # Create embeddings storage directory
        os.makedirs(settings.embeddings_storage_path, exist_ok=True)
        
        # Log FAISS configuration
        faiss_config = self.resource_manager.get_faiss_config()
        logger.info(f"FAISS configuration: {faiss_config}")
    
    def create_index_for_repo(self, repo_id: str) -> faiss.Index:
        """
        Create a new FAISS index for a repository with optimal configuration
        
        Args:
            repo_id: Repository identifier
            
        Returns:
            FAISS index
        """
        # Get FAISS configuration from resource manager
        faiss_config = self.resource_manager.get_faiss_config()
        
        if settings.faiss_index_type == "IndexFlatIP":
            # Inner product (cosine similarity with normalized vectors)
            index = faiss.IndexFlatIP(self.embedding_dim)
        elif settings.faiss_index_type == "IndexFlatL2":
            # L2 distance
            index = faiss.IndexFlatL2(self.embedding_dim)
        elif settings.faiss_index_type == "IndexIVFFlat":
            # IVF (Inverted File) index for larger datasets
            quantizer = faiss.IndexFlatL2(self.embedding_dim)
            nlist = 100  # Number of clusters
            index = faiss.IndexIVFFlat(quantizer, self.embedding_dim, nlist)
        else:
            # Default to flat IP
            index = faiss.IndexFlatIP(self.embedding_dim)
        
        # Use GPU if resource manager recommends it and it's available
        if faiss_config['use_gpu'] and faiss_config['gpu_device'] is not None:
            try:
                # Check current GPU usage before allocating
                usage = self.resource_manager.monitor_resource_usage()
                if usage['gpu_memory_percent'] < 80:  # Only use GPU if memory is available
                    res = faiss.StandardGpuResources()
                    index = faiss.index_cpu_to_gpu(res, faiss_config['gpu_device'], index)
                    logger.info(f"Using GPU device {faiss_config['gpu_device']} for FAISS index: {repo_id}")
                else:
                    logger.info(f"GPU memory usage too high ({usage['gpu_memory_percent']:.1f}%), using CPU for FAISS")
            except Exception as e:
                logger.warning(f"Failed to use GPU for FAISS, falling back to CPU: {e}")
        else:
            logger.info(f"Using CPU for FAISS index: {repo_id} (resource manager recommendation)")
        
        self.indices[repo_id] = index
        self.metadata_store[repo_id] = []
        
        logger.info(f"Created FAISS index for repo {repo_id}: {type(index).__name__}")
        return index
    
    def add_embeddings(self, repo_id: str, embeddings: List[Embedding]):
        """
        Add embeddings to the repository index
        
        Args:
            repo_id: Repository identifier
            embeddings: List of Embedding objects
        """
        if not embeddings:
            return
        
        if repo_id not in self.indices:
            self.create_index_for_repo(repo_id)
        
        index = self.indices[repo_id]
        
        # Convert embeddings to numpy array
        vectors = np.array([emb.embedding_vector for emb in embeddings], dtype=np.float32)
        
        # Normalize vectors for cosine similarity (if using IndexFlatIP)
        if isinstance(index, faiss.IndexFlatIP) or settings.faiss_index_type == "IndexFlatIP":
            faiss.normalize_L2(vectors)
        
        # Add vectors to index
        index.add(vectors)
        
        # Store metadata
        metadata_list = []
        for emb in embeddings:
            metadata_list.append({
                'id': emb.id,
                'content_type': emb.content_type,
                'content_id': emb.content_id,
                'metadata': emb.metadata
            })
        
        self.metadata_store[repo_id].extend(metadata_list)
        
        logger.info(f"Added {len(embeddings)} embeddings to index for repo {repo_id}")
    
    def search(self, repo_id: str, query_vector: np.ndarray, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Search for similar vectors in the repository index
        
        Args:
            repo_id: Repository identifier
            query_vector: Query embedding vector
            top_k: Number of results to return
            
        Returns:
            List of search results with metadata
        """
        if repo_id not in self.indices:
            return []
        
        index = self.indices[repo_id]
        metadata = self.metadata_store[repo_id]
        
        if index.ntotal == 0:
            return []
        
        # Normalize query vector if using cosine similarity
        if isinstance(index, faiss.IndexFlatIP) or settings.faiss_index_type == "IndexFlatIP":
            query_vector = query_vector.copy()
            faiss.normalize_L2(query_vector.reshape(1, -1))
        
        # Search
        scores, indices = index.search(query_vector.reshape(1, -1), min(top_k, index.ntotal))
        
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx >= 0 and idx < len(metadata):
                result = metadata[idx].copy()
                result['relevance_score'] = float(score)
                results.append(result)
        
        return results
    
    def save_index(self, repo_id: str):
        """Save FAISS index and metadata to disk"""
        if repo_id not in self.indices:
            return
        
        index_path = os.path.join(settings.embeddings_storage_path, f"{repo_id}.index")
        metadata_path = os.path.join(settings.embeddings_storage_path, f"{repo_id}.metadata")
        
        # Save FAISS index
        faiss.write_index(self.indices[repo_id], index_path)
        
        # Save metadata
        with open(metadata_path, 'wb') as f:
            pickle.dump(self.metadata_store[repo_id], f)
        
        logger.info(f"Saved FAISS index and metadata for repo {repo_id}")
    
    def load_index(self, repo_id: str) -> bool:
        """Load FAISS index and metadata from disk"""
        index_path = os.path.join(settings.embeddings_storage_path, f"{repo_id}.index")
        metadata_path = os.path.join(settings.embeddings_storage_path, f"{repo_id}.metadata")
        
        if not (os.path.exists(index_path) and os.path.exists(metadata_path)):
            return False
        
        try:
            # Load FAISS index
            index = faiss.read_index(index_path)
            
            # Try to move to GPU if configured
            if settings.use_gpu_for_faiss and settings.check_gpu_availability():
                try:
                    res = faiss.StandardGpuResources()
                    index = faiss.index_cpu_to_gpu(res, settings.faiss_gpu_device, index)
                except Exception as e:
                    logger.warning(f"Failed to move loaded index to GPU: {e}")
            
            self.indices[repo_id] = index
            
            # Load metadata
            with open(metadata_path, 'rb') as f:
                self.metadata_store[repo_id] = pickle.load(f)
            
            logger.info(f"Loaded FAISS index and metadata for repo {repo_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load FAISS index for repo {repo_id}: {e}")
            return False
    
    def delete_index(self, repo_id: str):
        """Delete FAISS index and metadata for a repository"""
        # Remove from memory
        if repo_id in self.indices:
            del self.indices[repo_id]
        if repo_id in self.metadata_store:
            del self.metadata_store[repo_id]
        
        # Remove from disk
        index_path = os.path.join(settings.embeddings_storage_path, f"{repo_id}.index")
        metadata_path = os.path.join(settings.embeddings_storage_path, f"{repo_id}.metadata")
        
        for path in [index_path, metadata_path]:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception as e:
                    logger.warning(f"Failed to remove {path}: {e}")
        
        logger.info(f"Deleted FAISS index for repo {repo_id}")
    
    def get_index_stats(self, repo_id: str) -> Dict[str, Any]:
        """Get statistics about the repository index"""
        if repo_id not in self.indices:
            return {'exists': False}
        
        index = self.indices[repo_id]
        metadata = self.metadata_store.get(repo_id, [])
        
        # Count by content type
        content_type_counts = {}
        for item in metadata:
            content_type = item.get('content_type', 'unknown')
            content_type_counts[content_type] = content_type_counts.get(content_type, 0) + 1
        
        return {
            'exists': True,
            'total_vectors': index.ntotal,
            'dimension': index.d,
            'index_type': type(index).__name__,
            'content_type_counts': content_type_counts,
            'is_trained': getattr(index, 'is_trained', True)
        }


class RAGSystem:
    """Main RAG system that orchestrates document chunking, embedding, and retrieval"""
    
    def __init__(self, settings):
        self.settings = settings
        self.chunker = DocumentChunker()
        self.code_extractor = CodeSnippetExtractor()
        self.embedding_generator = EmbeddingGenerator()
        self.index_manager = FAISSIndexManager()
    
    def embed_documents(self, docs: List[ThreatDoc]) -> None:
        """
        Embed threat documents and store in FAISS index
        
        Args:
            docs: List of ThreatDoc objects to embed
        """
        if not docs:
            return
        
        # Group documents by repository
        repo_docs = {}
        for doc in docs:
            if doc.repo_id not in repo_docs:
                repo_docs[doc.repo_id] = []
            repo_docs[doc.repo_id].append(doc)
        
        # Process each repository
        for repo_id, repo_doc_list in repo_docs.items():
            logger.info(f"Embedding {len(repo_doc_list)} documents for repo {repo_id}")
            
            # Chunk all documents
            all_chunks = []
            for doc in repo_doc_list:
                chunks = self.chunker.chunk_document(doc)
                all_chunks.extend(chunks)
            
            if not all_chunks:
                continue
            
            # Generate embeddings
            texts = [chunk['content'] for chunk in all_chunks]
            embeddings_vectors = self.embedding_generator.generate_embeddings(texts)
            
            # Create Embedding objects
            embeddings = []
            for chunk, embedding_vector in zip(all_chunks, embeddings_vectors):
                embedding = Embedding(
                    id=chunk['id'],
                    repo_id=repo_id,
                    content_type='document',
                    content_id=chunk['doc_id'],
                    embedding_vector=embedding_vector,
                    metadata=chunk
                )
                embeddings.append(embedding)
            
            # Add to FAISS index
            self.index_manager.add_embeddings(repo_id, embeddings)
            
            # Save index to disk
            self.index_manager.save_index(repo_id)
            
            logger.info(f"Successfully embedded {len(embeddings)} document chunks for repo {repo_id}")
    
    def embed_code_snippets(self, repo_context: RepoContext) -> None:
        """
        Extract and embed code snippets from repository
        
        Args:
            repo_context: Repository context
        """
        logger.info(f"Extracting code snippets for repo {repo_context.repo_id}")
        
        # Extract code snippets
        snippets = self.code_extractor.extract_from_repo(repo_context)
        
        if not snippets:
            logger.info(f"No code snippets found for repo {repo_context.repo_id}")
            return
        
        # Generate embeddings
        texts = [snippet['content'] for snippet in snippets]
        embeddings_vectors = self.embedding_generator.generate_embeddings(texts)
        
        # Create Embedding objects
        embeddings = []
        for snippet, embedding_vector in zip(snippets, embeddings_vectors):
            embedding = Embedding(
                id=snippet['id'],
                repo_id=repo_context.repo_id,
                content_type='code',
                content_id=snippet['id'],
                embedding_vector=embedding_vector,
                metadata=snippet
            )
            embeddings.append(embedding)
        
        # Add to FAISS index
        self.index_manager.add_embeddings(repo_context.repo_id, embeddings)
        
        # Save index to disk
        self.index_manager.save_index(repo_context.repo_id)
        
        logger.info(f"Successfully embedded {len(embeddings)} code snippets for repo {repo_context.repo_id}")
    
    def search_similar_content(self, query: str, repo_id: str, top_k: int = 5, 
                             content_types: Optional[List[str]] = None) -> List[SearchResult]:
        """
        Search for similar content using vector similarity
        
        Args:
            query: Search query text
            repo_id: Repository identifier
            top_k: Number of results to return
            content_types: Filter by content types ('document', 'code')
            
        Returns:
            List of SearchResult objects
        """
        # Load index if not in memory
        if repo_id not in self.index_manager.indices:
            if not self.index_manager.load_index(repo_id):
                logger.warning(f"No index found for repo {repo_id}")
                return []
        
        # Generate query embedding
        query_embeddings = self.embedding_generator.generate_embeddings([query])
        if not query_embeddings:
            return []
        
        query_vector = np.array(query_embeddings[0], dtype=np.float32)
        
        # Search in FAISS index
        search_results = self.index_manager.search(repo_id, query_vector, top_k * 2)  # Get more to filter
        
        # Convert to SearchResult objects and filter
        results = []
        for result in search_results:
            # Filter by content type if specified
            if content_types and result.get('content_type') not in content_types:
                continue
            
            # Create SearchResult
            if result['content_type'] == 'document':
                search_result = SearchResult(
                    doc_id=result['content_id'],
                    title=result['metadata'].get('doc_title', 'Unknown Document'),
                    content_snippet=self._truncate_content(result['metadata'].get('content', ''), 200),
                    relevance_score=result['relevance_score'],
                    doc_type=result['metadata'].get('doc_type', 'system_overview'),
                    code_references=[]
                )
            else:  # code
                # Create a code reference
                code_ref = CodeReference(
                    id=result['id'],
                    file_path=result['metadata'].get('file_path', ''),
                    line_start=result['metadata'].get('line_start', 0),
                    line_end=result['metadata'].get('line_end'),
                    function_name=result['metadata'].get('function_name'),
                    code_snippet=self._truncate_content(result['metadata'].get('content', ''), 300)
                )
                
                search_result = SearchResult(
                    doc_id=result['id'],
                    title=f"Code: {result['metadata'].get('function_name', 'Unknown Function')}",
                    content_snippet=self._truncate_content(result['metadata'].get('content', ''), 200),
                    relevance_score=result['relevance_score'],
                    doc_type="component_profile",  # Default for code
                    code_references=[code_ref]
                )
            
            results.append(search_result)
            
            if len(results) >= top_k:
                break
        
        return results
    
    def get_context_for_generation(self, context_type: str, repo_id: str, 
                                 query: Optional[str] = None, max_context_length: int = 2000) -> str:
        """
        Get relevant context for LLM generation
        
        Args:
            context_type: Type of context needed ('component', 'flow', 'threat', 'general')
            repo_id: Repository identifier
            query: Optional specific query for context retrieval
            max_context_length: Maximum length of returned context
            
        Returns:
            Assembled context string
        """
        if not query:
            # Use default queries based on context type
            query_map = {
                'component': 'component security profile endpoint authentication',
                'flow': 'data flow security threat boundary',
                'threat': 'threat vulnerability risk mitigation',
                'general': 'security architecture overview system'
            }
            query = query_map.get(context_type, 'security')
        
        # Search for relevant content
        search_results = self.search_similar_content(
            query=query,
            repo_id=repo_id,
            top_k=10,
            content_types=['document', 'code']
        )
        
        # Assemble context
        context_parts = []
        current_length = 0
        
        for result in search_results:
            # Add document context
            doc_context = f"## {result.title}\n{result.content_snippet}\n"
            
            # Add code context if available
            for code_ref in result.code_references:
                if code_ref.code_snippet:
                    code_context = f"### Code: {code_ref.function_name or 'Unknown'} ({code_ref.file_path})\n```\n{code_ref.code_snippet}\n```\n"
                    doc_context += code_context
            
            # Check if adding this context would exceed the limit
            if current_length + len(doc_context) > max_context_length:
                if current_length == 0:  # If first item is too long, truncate it
                    doc_context = doc_context[:max_context_length - 100] + "...\n"
                    context_parts.append(doc_context)
                break
            
            context_parts.append(doc_context)
            current_length += len(doc_context)
        
        return "\n".join(context_parts)
    
    def _truncate_content(self, content: str, max_length: int) -> str:
        """Truncate content to maximum length"""
        if len(content) <= max_length:
            return content
        
        # Try to break at sentence boundary
        truncated = content[:max_length]
        last_sentence = truncated.rfind('.')
        if last_sentence > max_length * 0.7:  # If we can keep most of the content
            return truncated[:last_sentence + 1]
        
        return truncated + "..."
    
    def get_repo_embedding_stats(self, repo_id: str) -> Dict[str, Any]:
        """Get embedding statistics for a repository"""
        return self.index_manager.get_index_stats(repo_id)
    
    def delete_repo_embeddings(self, repo_id: str):
        """Delete all embeddings for a repository"""
        self.index_manager.delete_index(repo_id)
        logger.info(f"Deleted embeddings for repo {repo_id}")
    
    def rebuild_embeddings(self, repo_id: str, docs: List[ThreatDoc], repo_context: RepoContext):
        """Rebuild embeddings for a repository"""
        # Delete existing embeddings
        self.delete_repo_embeddings(repo_id)
        
        # Rebuild document embeddings
        self.embed_documents(docs)
        
        # Rebuild code embeddings
        self.embed_code_snippets(repo_context)
        
        logger.info(f"Rebuilt embeddings for repo {repo_id}")


class QueryExpander:
    """Handles query expansion and semantic search enhancement"""
    
    def __init__(self):
        self.security_synonyms = {
            'auth': ['authentication', 'authorization', 'login', 'access control'],
            'vuln': ['vulnerability', 'weakness', 'security flaw', 'exploit'],
            'threat': ['risk', 'attack', 'security threat', 'danger'],
            'data': ['information', 'sensitive data', 'personal data', 'confidential'],
            'api': ['endpoint', 'service', 'interface', 'web service'],
            'user': ['actor', 'principal', 'subject', 'identity'],
            'system': ['application', 'service', 'component', 'module'],
            'access': ['permission', 'privilege', 'authorization', 'rights'],
            'input': ['parameter', 'data input', 'user input', 'request data'],
            'output': ['response', 'result', 'data output', 'return value']
        }
        
        self.stride_keywords = {
            'spoofing': ['identity', 'impersonation', 'fake', 'masquerade'],
            'tampering': ['modification', 'alteration', 'corruption', 'integrity'],
            'repudiation': ['denial', 'non-repudiation', 'audit', 'logging'],
            'information_disclosure': ['data leak', 'exposure', 'confidentiality', 'privacy'],
            'denial_of_service': ['availability', 'dos', 'resource exhaustion', 'flooding'],
            'elevation_of_privilege': ['privilege escalation', 'unauthorized access', 'admin rights']
        }
    
    def expand_query(self, query: str) -> List[str]:
        """
        Expand query with synonyms and related terms
        
        Args:
            query: Original query string
            
        Returns:
            List of expanded query variations
        """
        expanded_queries = [query]  # Always include original
        query_lower = query.lower()
        
        # Add synonym expansions
        for term, synonyms in self.security_synonyms.items():
            if term in query_lower:
                for synonym in synonyms:
                    expanded_query = query_lower.replace(term, synonym)
                    if expanded_query != query_lower:
                        expanded_queries.append(expanded_query)
        
        # Add STRIDE-related expansions
        for stride_term, related_terms in self.stride_keywords.items():
            if any(related in query_lower for related in related_terms):
                stride_query = f"{query} {stride_term}"
                expanded_queries.append(stride_query)
        
        # Add security context variations
        security_contexts = [
            f"security {query}",
            f"{query} vulnerability",
            f"{query} threat model",
            f"{query} risk assessment"
        ]
        
        # Only add if query doesn't already contain these terms
        for context_query in security_contexts:
            if not any(word in query_lower for word in context_query.split() if word != query.lower()):
                expanded_queries.append(context_query)
        
        return list(set(expanded_queries))  # Remove duplicates


class AdvancedSearchEngine:
    """Advanced search engine with ranking, filtering, and semantic capabilities"""
    
    def __init__(self, rag_system: 'RAGSystem'):
        self.rag_system = rag_system
        self.query_expander = QueryExpander()
    
    def semantic_search(self, query: str, repo_id: str, 
                       filters: Optional[Dict[str, Any]] = None,
                       top_k: int = 10) -> List[SearchResult]:
        """
        Perform semantic search with query expansion and advanced filtering
        
        Args:
            query: Search query
            repo_id: Repository identifier
            filters: Search filters (doc_type, content_type, date_range, etc.)
            top_k: Number of results to return
            
        Returns:
            Ranked and filtered search results
        """
        # Expand query for better semantic matching
        expanded_queries = self.query_expander.expand_query(query)
        
        # Collect results from all query variations
        all_results = []
        seen_ids = set()
        
        for i, expanded_query in enumerate(expanded_queries):
            # Weight original query higher
            query_weight = 1.0 if i == 0 else 0.7
            
            # Search with expanded query
            results = self.rag_system.search_similar_content(
                query=expanded_query,
                repo_id=repo_id,
                top_k=top_k * 2,  # Get more results for better ranking
                content_types=filters.get('content_types') if filters else None
            )
            
            # Add query weight to relevance scores
            for result in results:
                if result.doc_id not in seen_ids:
                    result.relevance_score *= query_weight
                    all_results.append(result)
                    seen_ids.add(result.doc_id)
        
        # Apply additional filters
        if filters:
            all_results = self._apply_filters(all_results, filters)
        
        # Re-rank results
        ranked_results = self._rank_results(all_results, query)
        
        return ranked_results[:top_k]
    
    def _apply_filters(self, results: List[SearchResult], filters: Dict[str, Any]) -> List[SearchResult]:
        """Apply additional filters to search results"""
        filtered_results = results
        
        # Filter by document type
        if 'doc_types' in filters and filters['doc_types']:
            doc_types = set(filters['doc_types'])
            filtered_results = [r for r in filtered_results if r.doc_type.value in doc_types]
        
        # Filter by minimum relevance score
        if 'min_score' in filters:
            min_score = filters['min_score']
            filtered_results = [r for r in filtered_results if r.relevance_score >= min_score]
        
        # Filter by content length
        if 'min_content_length' in filters:
            min_length = filters['min_content_length']
            filtered_results = [r for r in filtered_results if len(r.content_snippet) >= min_length]
        
        return filtered_results
    
    def _rank_results(self, results: List[SearchResult], original_query: str) -> List[SearchResult]:
        """
        Re-rank results using multiple signals
        
        Args:
            results: List of search results
            original_query: Original search query
            
        Returns:
            Re-ranked results
        """
        query_terms = set(original_query.lower().split())
        
        for result in results:
            # Base score from vector similarity
            base_score = result.relevance_score
            
            # Boost for exact term matches in title
            title_boost = 0.0
            title_terms = set(result.title.lower().split())
            common_terms = query_terms.intersection(title_terms)
            if common_terms:
                title_boost = len(common_terms) / len(query_terms) * 0.2
            
            # Boost for document type relevance
            doc_type_boost = self._get_doc_type_boost(result.doc_type, original_query)
            
            # Boost for code references (if query seems code-related)
            code_boost = 0.0
            if result.code_references and any(term in original_query.lower() 
                                            for term in ['function', 'class', 'method', 'code', 'implementation']):
                code_boost = 0.1
            
            # Content quality boost (longer, more structured content)
            content_boost = min(len(result.content_snippet) / 1000, 0.1)
            
            # Calculate final score
            result.relevance_score = base_score + title_boost + doc_type_boost + code_boost + content_boost
        
        # Sort by final score
        return sorted(results, key=lambda x: x.relevance_score, reverse=True)
    
    def _get_doc_type_boost(self, doc_type: str, query: str) -> float:
        """Get relevance boost based on document type and query"""
        query_lower = query.lower()
        
        # Map query terms to preferred document types
        type_preferences = {
            'system': 'system_overview',
            'overview': 'system_overview',
            'architecture': 'system_overview',
            'component': 'component_profile',
            'service': 'component_profile',
            'endpoint': 'component_profile',
            'flow': 'flow_threat_model',
            'process': 'flow_threat_model',
            'workflow': 'flow_threat_model',
            'mitigation': 'mitigation',
            'recommendation': 'mitigation',
            'solution': 'mitigation'
        }
        
        for term, preferred_type in type_preferences.items():
            if term in query_lower and doc_type == preferred_type:
                return 0.15
        
        return 0.0
    
    def search_with_context_assembly(self, query: str, repo_id: str,
                                   context_type: str = 'general',
                                   max_results: int = 5) -> Dict[str, Any]:
        """
        Search and assemble context for LLM generation
        
        Args:
            query: Search query
            repo_id: Repository identifier
            context_type: Type of context needed
            max_results: Maximum number of results
            
        Returns:
            Dictionary with search results and assembled context
        """
        # Perform semantic search
        search_results = self.semantic_search(
            query=query,
            repo_id=repo_id,
            top_k=max_results
        )
        
        # Get additional context using RAG system
        context = self.rag_system.get_context_for_generation(
            context_type=context_type,
            repo_id=repo_id,
            query=query
        )
        
        # Assemble final response
        return {
            'query': query,
            'results': search_results,
            'context': context,
            'total_results': len(search_results),
            'context_type': context_type
        }
    
    def get_related_content(self, doc_id: str, repo_id: str, top_k: int = 5) -> List[SearchResult]:
        """
        Find content related to a specific document
        
        Args:
            doc_id: Document ID to find related content for
            repo_id: Repository identifier
            top_k: Number of related items to return
            
        Returns:
            List of related search results
        """
        # Load the document content to use as query
        # This would typically involve loading the document from storage
        # For now, we'll use a generic approach
        
        # Search for similar content using document type as context
        related_queries = [
            "security threat vulnerability",
            "component authentication authorization",
            "data flow boundary trust"
        ]
        
        all_related = []
        seen_ids = {doc_id}  # Exclude the original document
        
        for query in related_queries:
            results = self.semantic_search(
                query=query,
                repo_id=repo_id,
                top_k=top_k
            )
            
            for result in results:
                if result.doc_id not in seen_ids:
                    all_related.append(result)
                    seen_ids.add(result.doc_id)
        
        # Sort by relevance and return top results
        return sorted(all_related, key=lambda x: x.relevance_score, reverse=True)[:top_k]


# Enhanced RAG System with advanced search capabilities
class EnhancedRAGSystem(RAGSystem):
    """Enhanced RAG system with advanced search and retrieval capabilities"""
    
    def __init__(self):
        super().__init__()
        self.search_engine = AdvancedSearchEngine(self)
    
    def advanced_search(self, query: str, repo_id: str, 
                       filters: Optional[Dict[str, Any]] = None,
                       top_k: int = 10) -> List[SearchResult]:
        """
        Perform advanced semantic search
        
        Args:
            query: Search query
            repo_id: Repository identifier  
            filters: Search filters
            top_k: Number of results to return
            
        Returns:
            Advanced search results
        """
        return self.search_engine.semantic_search(query, repo_id, filters, top_k)
    
    def search_with_context(self, query: str, repo_id: str,
                          context_type: str = 'general') -> Dict[str, Any]:
        """
        Search with assembled context for LLM generation
        
        Args:
            query: Search query
            repo_id: Repository identifier
            context_type: Type of context needed
            
        Returns:
            Search results with context
        """
        return self.search_engine.search_with_context_assembly(query, repo_id, context_type)
    
    def find_related_content(self, doc_id: str, repo_id: str, top_k: int = 5) -> List[SearchResult]:
        """Find content related to a specific document"""
        return self.search_engine.get_related_content(doc_id, repo_id, top_k)