"""
User utilities for Phase 1 MVP - Simple browser-based user identification
"""
import hashlib
import uuid
from typing import Optional


def generate_user_id(request_headers: dict = None, fallback_id: str = None) -> str:
    """
    Generate simple user ID for Phase 1 MVP
    Uses browser fingerprinting approach with fallback to random UUID
    
    Args:
        request_headers: HTTP request headers for fingerprinting
        fallback_id: Fallback ID if provided (e.g., from localStorage)
    
    Returns:
        Unique user identifier string
    """
    if fallback_id:
        return fallback_id
    
    # Simple browser fingerprinting using available headers
    fingerprint_data = []
    
    if request_headers:
        # Use common headers for fingerprinting
        headers_to_use = [
            'user-agent',
            'accept-language', 
            'accept-encoding',
            'x-forwarded-for',
            'x-real-ip'
        ]
        
        for header in headers_to_use:
            value = request_headers.get(header, '')
            if value:
                fingerprint_data.append(f"{header}:{value}")
    
    if fingerprint_data:
        # Create hash from fingerprint data
        fingerprint_string = '|'.join(fingerprint_data)
        user_hash = hashlib.md5(fingerprint_string.encode()).hexdigest()
        return f"user_{user_hash[:12]}"
    
    # Fallback to random UUID if no fingerprinting data available
    return f"user_{str(uuid.uuid4())[:12]}"


def extract_repository_name(repo_url: str) -> str:
    """
    Extract repository name from URL for display purposes
    
    Args:
        repo_url: Repository URL
        
    Returns:
        Repository name for display
    """
    if not repo_url:
        return "Unknown Repository"
    
    # Handle different URL formats
    repo_url = repo_url.strip()
    
    # Remove .git suffix if present
    if repo_url.endswith('.git'):
        repo_url = repo_url[:-4]
    
    # Extract name from URL
    if '/' in repo_url:
        parts = repo_url.split('/')
        # Get the last non-empty part
        for part in reversed(parts):
            if part.strip():
                return part.strip()
    
    return repo_url or "Unknown Repository"