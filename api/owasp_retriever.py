"""
OWASP Content Retrieval System

This module provides utilities to pull relevant OWASP passages by STRIDE category,
implement filtering by phase, tech area, and component type, and add caching
and performance optimization for content retrieval.

Migrated from backend/owasp/retriever.py to api/ folder.
"""

import os
import yaml
import json
import hashlib
from typing import List, Dict, Optional, Set, Any
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import logging
from functools import lru_cache
import time

# Import ThreatLens models - updated to use api models
from api.models import StrideCategory, ComponentType

logger = logging.getLogger(__name__)


class Phase(Enum):
    """Development phases for filtering OWASP content"""
    DESIGN = "design"
    IMPLEMENTATION = "implementation"
    TESTING = "testing"
    DEPLOYMENT = "deployment"
    OPERATIONS = "operations"
    REVIEW = "review"


class SecurityDomain(Enum):
    """Security domains for categorizing OWASP content"""
    THREAT_MODELING = "threat-modeling"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input-validation"
    CRYPTOGRAPHY = "cryptography"
    SESSION_MANAGEMENT = "session-management"
    API_SECURITY = "api-security"
    CLOUD_SECURITY = "cloud-security"
    CONTAINER_SECURITY = "container-security"
    WEB_SECURITY = "web-security"
    DATABASE_SECURITY = "database-security"
    LOGGING = "logging"
    SECURITY_TESTING = "security-testing"


@dataclass
class OWASPCheatSheet:
    """Represents an OWASP cheat sheet with metadata"""
    id: str
    title: str
    url: str
    local_path: str
    tags: List[str]
    categories: List[str]
    security_domains: List[str]
    stride_categories: List[str]
    phases: List[str]
    component_types: List[str]
    priority: str
    description: str


@dataclass
class ContentFilter:
    """Filter criteria for OWASP content retrieval"""
    stride_categories: Optional[List[StrideCategory]] = None
    phases: Optional[List[Phase]] = None
    security_domains: Optional[List[SecurityDomain]] = None
    component_types: Optional[List[ComponentType]] = None
    tags: Optional[List[str]] = None
    priority_levels: Optional[List[str]] = None


@dataclass
class RetrievalResult:
    """Result of OWASP content retrieval"""
    cheat_sheet: OWASPCheatSheet
    relevance_score: float
    matched_criteria: List[str]
    content_excerpt: Optional[str] = None


class OWASPContentCache:
    """Simple in-memory cache for OWASP content with TTL"""
    
    def __init__(self, ttl_seconds: int = 3600):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.ttl_seconds = ttl_seconds
    
    def _generate_key(self, *args) -> str:
        """Generate cache key from arguments"""
        key_data = str(args)
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, *args) -> Optional[Any]:
        """Get cached value if not expired"""
        key = self._generate_key(*args)
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry['timestamp'] < self.ttl_seconds:
                return entry['value']
            else:
                del self.cache[key]
        return None
    
    def set(self, value: Any, *args) -> None:
        """Set cached value with timestamp"""
        key = self._generate_key(*args)
        self.cache[key] = {
            'value': value,
            'timestamp': time.time()
        }
    
    def clear(self) -> None:
        """Clear all cached entries"""
        self.cache.clear()


class OWASPRetriever:
    """
    Main class for retrieving and filtering OWASP content based on various criteria.
    Provides context-aware content retrieval with caching and performance optimization.
    """
    
    def __init__(self, 
                 cheatsheets_index_path: str = "data/owasp_cheatsheets/cheatsheets_index.yaml",
                 content_base_path: str = "data/owasp_cheatsheets/",
                 cache_ttl: int = 3600):
        """
        Initialize the OWASP retriever
        
        Args:
            cheatsheets_index_path: Path to the cheat sheets index YAML file
            content_base_path: Base path for local OWASP content files
            cache_ttl: Cache time-to-live in seconds
        """
        self.cheatsheets_index_path = cheatsheets_index_path
        self.content_base_path = Path(content_base_path)
        self.cache = OWASPContentCache(cache_ttl)
        self._cheatsheets: Optional[Dict[str, OWASPCheatSheet]] = None
        self._stride_mappings: Optional[Dict[str, List[str]]] = None
        self._component_mappings: Optional[Dict[str, List[str]]] = None
        
    def _load_cheatsheets_index(self) -> None:
        """Load and parse the cheat sheets index file"""
        if self._cheatsheets is not None:
            return
            
        try:
            with open(self.cheatsheets_index_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            self._cheatsheets = {}
            for sheet_data in data.get('cheatsheets', []):
                sheet = OWASPCheatSheet(
                    id=sheet_data['id'],
                    title=sheet_data['title'],
                    url=sheet_data['url'],
                    local_path=sheet_data.get('local_path', ''),
                    tags=sheet_data.get('tags', []),
                    categories=sheet_data.get('categories', []),
                    security_domains=sheet_data.get('security_domains', []),
                    stride_categories=sheet_data.get('stride_categories', []),
                    phases=sheet_data.get('phases', []),
                    component_types=sheet_data.get('component_types', []),
                    priority=sheet_data.get('priority', 'medium'),
                    description=sheet_data.get('description', '')
                )
                self._cheatsheets[sheet.id] = sheet
            
            # Load mappings
            self._stride_mappings = data.get('stride_mappings', {})
            self._component_mappings = data.get('component_mappings', {})
            
            logger.info(f"Loaded {len(self._cheatsheets)} OWASP cheat sheets")
            
        except Exception as e:
            logger.error(f"Failed to load cheat sheets index: {e}")
            self._cheatsheets = {}
            self._stride_mappings = {}
            self._component_mappings = {}
    
    @lru_cache(maxsize=128)
    def get_cheatsheets_by_stride_category(self, stride_category: StrideCategory) -> List[OWASPCheatSheet]:
        """
        Get relevant OWASP cheat sheets for a specific STRIDE category
        
        Args:
            stride_category: The STRIDE category to filter by
            
        Returns:
            List of relevant cheat sheets sorted by priority
        """
        self._load_cheatsheets_index()
        
        # Check cache first
        cached_result = self.cache.get('stride', stride_category.value)
        if cached_result is not None:
            return cached_result
        
        relevant_sheets = []
        stride_key = stride_category.value.lower().replace('_', '-')
        
        # Get cheat sheet IDs from stride mappings
        mapped_sheet_ids = self._stride_mappings.get(stride_key, [])
        
        for sheet_id in mapped_sheet_ids:
            if sheet_id in self._cheatsheets:
                sheet = self._cheatsheets[sheet_id]
                # Double-check that the sheet actually supports this STRIDE category
                if stride_key in [cat.replace('_', '-') for cat in sheet.stride_categories]:
                    relevant_sheets.append(sheet)
        
        # Sort by priority (critical > high > medium > low)
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        relevant_sheets.sort(key=lambda x: priority_order.get(x.priority, 3))
        
        # Cache the result
        self.cache.set(relevant_sheets, 'stride', stride_category.value)
        
        return relevant_sheets
    
    @lru_cache(maxsize=128)
    def get_cheatsheets_by_component_type(self, component_type: ComponentType) -> List[OWASPCheatSheet]:
        """
        Get relevant OWASP cheat sheets for a specific component type
        
        Args:
            component_type: The component type to filter by
            
        Returns:
            List of relevant cheat sheets sorted by priority
        """
        self._load_cheatsheets_index()
        
        # Check cache first
        cached_result = self.cache.get('component', component_type.value)
        if cached_result is not None:
            return cached_result
        
        relevant_sheets = []
        component_key = component_type.value.lower().replace('_', '-')
        
        # Get cheat sheet IDs from component mappings
        mapped_sheet_ids = self._component_mappings.get(component_key, [])
        
        for sheet_id in mapped_sheet_ids:
            if sheet_id in self._cheatsheets:
                sheet = self._cheatsheets[sheet_id]
                # Double-check that the sheet actually supports this component type
                if component_key in [ct.replace('_', '-') for ct in sheet.component_types]:
                    relevant_sheets.append(sheet)
        
        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        relevant_sheets.sort(key=lambda x: priority_order.get(x.priority, 3))
        
        # Cache the result
        self.cache.set(relevant_sheets, 'component', component_type.value)
        
        return relevant_sheets
    
    def search_content(self, query: str, max_results: int = 10) -> List[RetrievalResult]:
        """
        Search OWASP content by text query
        
        Args:
            query: Search query string
            max_results: Maximum number of results to return
            
        Returns:
            List of matching cheat sheets
        """
        self._load_cheatsheets_index()
        
        query_lower = query.lower()
        results = []
        
        for sheet in self._cheatsheets.values():
            relevance_score = 0.0
            matched_criteria = []
            
            # Check title match
            if query_lower in sheet.title.lower():
                relevance_score += 0.4
                matched_criteria.append("Title match")
            
            # Check description match
            if query_lower in sheet.description.lower():
                relevance_score += 0.3
                matched_criteria.append("Description match")
            
            # Check tags match
            for tag in sheet.tags:
                if query_lower in tag.lower():
                    relevance_score += 0.2
                    matched_criteria.append("Tag match")
                    break
            
            # Check categories match
            for category in sheet.categories:
                if query_lower in category.lower():
                    relevance_score += 0.1
                    matched_criteria.append("Category match")
                    break
            
            if relevance_score > 0.0:
                results.append(RetrievalResult(
                    cheat_sheet=sheet,
                    relevance_score=relevance_score,
                    matched_criteria=matched_criteria
                ))
        
        # Sort by relevance and limit results
        results.sort(key=lambda x: x.relevance_score, reverse=True)
        return results[:max_results]
    
    def filter_cheatsheets(self, content_filter: ContentFilter) -> List[RetrievalResult]:
        """
        Filter OWASP cheat sheets based on multiple criteria
        
        Args:
            content_filter: Filter criteria for content retrieval
            
        Returns:
            List of filtered cheat sheets with relevance scores
        """
        self._load_cheatsheets_index()
        
        results = []
        
        for sheet in self._cheatsheets.values():
            relevance_score = 0.0
            matched_criteria = []
            
            # Check STRIDE categories
            if content_filter.stride_categories:
                stride_matches = any(
                    stride_cat.value.lower().replace('_', '-') in 
                    [cat.replace('_', '-') for cat in sheet.stride_categories]
                    for stride_cat in content_filter.stride_categories
                )
                if stride_matches:
                    relevance_score += 0.3
                    matched_criteria.append("STRIDE category match")
            
            # Check phases
            if content_filter.phases:
                phase_matches = any(
                    phase.value in sheet.phases
                    for phase in content_filter.phases
                )
                if phase_matches:
                    relevance_score += 0.2
                    matched_criteria.append("Phase match")
            
            # Check security domains
            if content_filter.security_domains:
                domain_matches = any(
                    domain.value in sheet.security_domains
                    for domain in content_filter.security_domains
                )
                if domain_matches:
                    relevance_score += 0.25
                    matched_criteria.append("Security domain match")
            
            # Check component types
            if content_filter.component_types:
                component_matches = any(
                    comp_type.value.lower().replace('_', '-') in 
                    [ct.replace('_', '-') for ct in sheet.component_types]
                    for comp_type in content_filter.component_types
                )
                if component_matches:
                    relevance_score += 0.2
                    matched_criteria.append("Component type match")
            
            # Check tags
            if content_filter.tags:
                tag_matches = any(
                    tag.lower() in [t.lower() for t in sheet.tags]
                    for tag in content_filter.tags
                )
                if tag_matches:
                    relevance_score += 0.15
                    matched_criteria.append("Tag match")
            
            # Check priority levels
            if content_filter.priority_levels:
                if sheet.priority in content_filter.priority_levels:
                    relevance_score += 0.1
                    matched_criteria.append("Priority match")
            
            # Only include if there's at least one match
            if relevance_score > 0.0:
                results.append(RetrievalResult(
                    cheat_sheet=sheet,
                    relevance_score=relevance_score,
                    matched_criteria=matched_criteria
                ))
        
        # Sort by relevance score
        results.sort(key=lambda x: x.relevance_score, reverse=True)
        return results
    
    def get_cheatsheet_content(self, cheat_sheet: OWASPCheatSheet) -> Optional[str]:
        """
        Get the actual content of a cheat sheet from local file
        
        Args:
            cheat_sheet: The cheat sheet to get content for
            
        Returns:
            Content of the cheat sheet or None if not found
        """
        if not cheat_sheet.local_path:
            logger.warning(f"No local path for cheat sheet: {cheat_sheet.id}")
            return None
        
        try:
            content_path = self.content_base_path / cheat_sheet.local_path
            if content_path.exists():
                with open(content_path, 'r', encoding='utf-8') as f:
                    return f.read()
            else:
                logger.warning(f"Cheat sheet file not found: {content_path}")
                return None
        except Exception as e:
            logger.error(f"Failed to read cheat sheet content: {e}")
            return None


# Convenience functions for common use cases

def get_stride_guidance(stride_category: StrideCategory) -> List[OWASPCheatSheet]:
    """
    Convenience function to get OWASP guidance for a STRIDE category
    
    Args:
        stride_category: The STRIDE category
        
    Returns:
        List of relevant cheat sheets
    """
    retriever = OWASPRetriever()
    return retriever.get_cheatsheets_by_stride_category(stride_category)


def get_component_guidance(component_type: ComponentType) -> List[OWASPCheatSheet]:
    """
    Convenience function to get OWASP guidance for a component type
    
    Args:
        component_type: The component type
        
    Returns:
        List of relevant cheat sheets
    """
    retriever = OWASPRetriever()
    return retriever.get_cheatsheets_by_component_type(component_type)


def search_owasp_guidance(query: str) -> List[RetrievalResult]:
    """
    Convenience function to search OWASP guidance
    
    Args:
        query: Search query
        
    Returns:
        List of matching results
    """
    retriever = OWASPRetriever()
    return retriever.search_content(query)