"""
Test script for the RAG system implementation
"""
import os
import sys
from datetime import datetime
from pathlib import Path

# Add the api directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'api'))

from api.rag import RAGSystem, EnhancedRAGSystem, DocumentChunker, CodeSnippetExtractor
from api.models import ThreatDoc, ThreatDocType, RepoContext


def test_document_chunker():
    """Test document chunking functionality"""
    print("Testing DocumentChunker...")
    
    chunker = DocumentChunker(chunk_size=200, chunk_overlap=20)
    
    # Create a sample document
    sample_doc = ThreatDoc(
        id="test_doc_1",
        repo_id="test_repo",
        title="Test Security Document",
        doc_type=ThreatDocType.SYSTEM_OVERVIEW,
        content="""# System Security Overview

This is a comprehensive security overview of the system.

## Authentication
The system uses JWT tokens for authentication. Users must provide valid credentials.

## Authorization  
Role-based access control is implemented using middleware.

## Data Protection
All sensitive data is encrypted at rest and in transit.
""",
        metadata={"test": True}
    )
    
    chunks = chunker.chunk_document(sample_doc)
    print(f"Generated {len(chunks)} chunks from document")
    
    for i, chunk in enumerate(chunks):
        print(f"Chunk {i}: {chunk['id']}")
        print(f"Content preview: {chunk['content'][:100]}...")
        print()
    
    return len(chunks) > 0


def test_code_extractor():
    """Test code snippet extraction"""
    print("Testing CodeSnippetExtractor...")
    
    extractor = CodeSnippetExtractor()
    
    # Create a sample repository context
    repo_context = RepoContext(
        repo_id="test_repo",
        local_path="./api",  # Use the api directory as test
        primary_languages=["python"]
    )
    
    snippets = extractor.extract_from_repo(repo_context)
    print(f"Extracted {len(snippets)} code snippets")
    
    for i, snippet in enumerate(snippets[:3]):  # Show first 3
        print(f"Snippet {i}: {snippet['function_name']} in {snippet['file_path']}")
        print(f"Lines {snippet['line_start']}-{snippet.get('line_end', 'end')}")
        print()
    
    return len(snippets) > 0


def test_basic_rag_system():
    """Test basic RAG system functionality"""
    print("Testing basic RAG system...")
    
    try:
        # Temporarily override settings to use sentence-transformers
        import api.config
        original_provider = api.config.settings.embedding_provider
        api.config.settings.embedding_provider = "sentence-transformers"
        
        try:
            # This will test initialization without requiring API keys
            rag_system = RAGSystem()
            print("RAG system initialized successfully")
            
            # Test chunker and extractor components
            chunker_works = test_document_chunker()
            extractor_works = test_code_extractor()
            
            print(f"Document chunker: {'✓' if chunker_works else '✗'}")
            print(f"Code extractor: {'✓' if extractor_works else '✗'}")
            
            return chunker_works and extractor_works
            
        finally:
            # Restore original provider
            api.config.settings.embedding_provider = original_provider
        
    except Exception as e:
        print(f"Error testing RAG system: {e}")
        return False


def test_enhanced_rag_system():
    """Test enhanced RAG system with advanced search"""
    print("Testing EnhancedRAGSystem...")
    
    try:
        # Temporarily override settings to use sentence-transformers
        import api.config
        original_provider = api.config.settings.embedding_provider
        api.config.settings.embedding_provider = "sentence-transformers"
        
        try:
            enhanced_rag = EnhancedRAGSystem()
            print("Enhanced RAG system initialized successfully")
            
            # Test query expansion
            query_expander = enhanced_rag.search_engine.query_expander
            expanded = query_expander.expand_query("authentication vulnerability")
            print(f"Query expansion test: {len(expanded)} variations generated")
            print(f"Expanded queries: {expanded[:3]}...")  # Show first 3
            
            return True
            
        finally:
            # Restore original provider
            api.config.settings.embedding_provider = original_provider
        
    except Exception as e:
        print(f"Error testing enhanced RAG system: {e}")
        return False


def main():
    """Run all RAG system tests"""
    print("=" * 50)
    print("RAG System Test Suite")
    print("=" * 50)
    
    tests = [
        ("Basic RAG System", test_basic_rag_system),
        ("Enhanced RAG System", test_enhanced_rag_system)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            result = test_func()
            results.append((test_name, result))
            print(f"Result: {'PASS' if result else 'FAIL'}")
        except Exception as e:
            print(f"ERROR: {e}")
            results.append((test_name, False))
    
    print("\n" + "=" * 50)
    print("Test Summary:")
    print("=" * 50)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{test_name}: {status}")
    
    all_passed = all(result for _, result in results)
    print(f"\nOverall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    
    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)