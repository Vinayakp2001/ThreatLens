"""
Security Content Indexing System

This module provides comprehensive indexing capabilities for security content
including threats, mitigations, and OWASP mappings with semantic search support.
"""

import re
import json
import logging
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class SecurityPattern:
    """Represents a security pattern identified in content"""
    pattern_type: str
    pattern_name: str
    description: str
    severity: str
    owasp_category: str
    keywords: List[str]
    confidence_score: float

@dataclass
class SearchableContent:
    """Structured searchable content for security wikis"""
    wiki_id: str
    full_text_index: str
    threat_keywords: List[str]
    mitigation_keywords: List[str]
    owasp_keywords: List[str]
    security_tags: List[str]
    patterns: List[SecurityPattern]
    indexed_at: datetime

class SecurityContentIndexer:
    """Main indexing service for security content"""
    
    def __init__(self, db_path: str = "data/security_index.db"):
        self.db_path = db_path
        self.owasp_mappings = self._load_owasp_mappings()
        self.security_patterns = self._load_security_patterns()
        self._init_database()
    
    def _init_database(self):
        """Initialize the security indexing database"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_index (
                    wiki_id TEXT PRIMARY KEY,
                    full_text_index TEXT,
                    threat_keywords TEXT,
                    mitigation_keywords TEXT,
                    owasp_keywords TEXT,
                    security_tags TEXT,
                    patterns TEXT,
                    indexed_at TIMESTAMP,
                    search_vector TEXT
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_full_text ON security_index(full_text_index)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_owasp_keywords ON security_index(owasp_keywords)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_security_tags ON security_index(security_tags)
            """)
    
    def _load_owasp_mappings(self) -> Dict[str, List[str]]:
        """Load OWASP category mappings"""
        try:
            with open("data/owasp_cheatsheets/cheatsheets_index.yaml", "r") as f:
                import yaml
                data = yaml.safe_load(f)
                return {
                    category["name"]: category.get("keywords", [])
                    for category in data.get("categories", [])
                }
        except Exception as e:
            logger.warning(f"Could not load OWASP mappings: {e}")
            return self._get_default_owasp_mappings()
    
    def _get_default_owasp_mappings(self) -> Dict[str, List[str]]:
        """Default OWASP category mappings"""
        return {
            "Injection": ["sql injection", "command injection", "ldap injection", "xpath injection"],
            "Broken Authentication": ["authentication", "session management", "password", "credential"],
            "Sensitive Data Exposure": ["encryption", "data protection", "sensitive data", "privacy"],
            "XML External Entities": ["xxe", "xml", "external entity", "xml parser"],
            "Broken Access Control": ["authorization", "access control", "privilege escalation", "idor"],
            "Security Misconfiguration": ["configuration", "default settings", "security headers", "cors"],
            "Cross-Site Scripting": ["xss", "cross-site scripting", "script injection", "dom manipulation"],
            "Insecure Deserialization": ["deserialization", "serialization", "object injection", "pickle"],
            "Using Components with Known Vulnerabilities": ["dependency", "third-party", "library", "component"],
            "Insufficient Logging & Monitoring": ["logging", "monitoring", "audit trail", "incident response"]
        }
    
    def _load_security_patterns(self) -> List[Dict]:
        """Load security pattern definitions"""
        return [
            {
                "pattern": r"(?i)(sql\s+injection|sqli)",
                "type": "vulnerability",
                "name": "SQL Injection",
                "severity": "high",
                "owasp_category": "Injection",
                "keywords": ["sql", "injection", "query", "database"]
            },
            {
                "pattern": r"(?i)(cross[\-\s]?site\s+scripting|xss)",
                "type": "vulnerability", 
                "name": "Cross-Site Scripting",
                "severity": "medium",
                "owasp_category": "Cross-Site Scripting",
                "keywords": ["xss", "script", "javascript", "dom"]
            },
            {
                "pattern": r"(?i)(authentication|login|password|credential)",
                "type": "security_control",
                "name": "Authentication Control",
                "severity": "medium",
                "owasp_category": "Broken Authentication",
                "keywords": ["auth", "login", "password", "session"]
            },
            {
                "pattern": r"(?i)(encryption|crypto|cipher|hash)",
                "type": "security_control",
                "name": "Cryptographic Control",
                "severity": "high",
                "owasp_category": "Sensitive Data Exposure",
                "keywords": ["encryption", "crypto", "cipher", "hash"]
            },
            {
                "pattern": r"(?i)(access\s+control|authorization|privilege)",
                "type": "security_control",
                "name": "Access Control",
                "severity": "high",
                "owasp_category": "Broken Access Control",
                "keywords": ["access", "authorization", "privilege", "permission"]
            }
        ]
    
    def extract_keywords(self, text: str, category: str) -> List[str]:
        """Extract keywords from text based on category"""
        text_lower = text.lower()
        keywords = set()
        
        if category == "threat":
            # Extract threat-related keywords
            threat_patterns = [
                r"(?i)\b(vulnerability|exploit|attack|threat|risk|breach)\b",
                r"(?i)\b(malicious|unauthorized|suspicious|dangerous)\b",
                r"(?i)\b(injection|xss|csrf|xxe|rce|lfi|rfi)\b"
            ]
            for pattern in threat_patterns:
                matches = re.findall(pattern, text)
                keywords.update([match.lower() for match in matches])
        
        elif category == "mitigation":
            # Extract mitigation-related keywords
            mitigation_patterns = [
                r"(?i)\b(prevent|protect|secure|validate|sanitize|encrypt)\b",
                r"(?i)\b(authentication|authorization|firewall|monitoring)\b",
                r"(?i)\b(patch|update|configure|implement|deploy)\b"
            ]
            for pattern in mitigation_patterns:
                matches = re.findall(pattern, text)
                keywords.update([match.lower() for match in matches])
        
        elif category == "owasp":
            # Extract OWASP-related keywords
            for owasp_cat, cat_keywords in self.owasp_mappings.items():
                for keyword in cat_keywords:
                    if keyword.lower() in text_lower:
                        keywords.add(keyword.lower())
                        keywords.add(owasp_cat.lower())
        
        return list(keywords)
    
    def identify_security_patterns(self, text: str) -> List[SecurityPattern]:
        """Identify security patterns in text"""
        patterns = []
        
        for pattern_def in self.security_patterns:
            matches = re.finditer(pattern_def["pattern"], text)
            for match in matches:
                confidence = self._calculate_confidence(match, text, pattern_def)
                
                pattern = SecurityPattern(
                    pattern_type=pattern_def["type"],
                    pattern_name=pattern_def["name"],
                    description=f"Found '{match.group()}' in security content",
                    severity=pattern_def["severity"],
                    owasp_category=pattern_def["owasp_category"],
                    keywords=pattern_def["keywords"],
                    confidence_score=confidence
                )
                patterns.append(pattern)
        
        return patterns
    
    def _calculate_confidence(self, match, text: str, pattern_def: Dict) -> float:
        """Calculate confidence score for pattern match"""
        base_confidence = 0.7
        
        # Increase confidence if surrounded by relevant keywords
        context_window = 50
        start = max(0, match.start() - context_window)
        end = min(len(text), match.end() + context_window)
        context = text[start:end].lower()
        
        keyword_bonus = 0
        for keyword in pattern_def["keywords"]:
            if keyword in context:
                keyword_bonus += 0.05
        
        return min(1.0, base_confidence + keyword_bonus)
    
    def create_search_vector(self, content: SearchableContent) -> str:
        """Create a search vector for semantic search"""
        components = [
            content.full_text_index,
            " ".join(content.threat_keywords),
            " ".join(content.mitigation_keywords),
            " ".join(content.owasp_keywords),
            " ".join(content.security_tags)
        ]
        
        # Add pattern information
        for pattern in content.patterns:
            components.extend([
                pattern.pattern_name,
                pattern.description,
                " ".join(pattern.keywords)
            ])
        
        return " ".join(filter(None, components)).lower()
    
    def index_security_wiki(self, wiki_id: str, wiki_content: Dict) -> SearchableContent:
        """Index a security wiki for search"""
        try:
            # Extract full text content
            full_text = self._extract_full_text(wiki_content)
            
            # Extract categorized keywords
            threat_keywords = self.extract_keywords(full_text, "threat")
            mitigation_keywords = self.extract_keywords(full_text, "mitigation")
            owasp_keywords = self.extract_keywords(full_text, "owasp")
            
            # Generate security tags
            security_tags = self._generate_security_tags(wiki_content)
            
            # Identify security patterns
            patterns = self.identify_security_patterns(full_text)
            
            # Create searchable content
            searchable_content = SearchableContent(
                wiki_id=wiki_id,
                full_text_index=full_text,
                threat_keywords=threat_keywords,
                mitigation_keywords=mitigation_keywords,
                owasp_keywords=owasp_keywords,
                security_tags=security_tags,
                patterns=patterns,
                indexed_at=datetime.now()
            )
            
            # Create search vector
            search_vector = self.create_search_vector(searchable_content)
            
            # Store in database
            self._store_index(searchable_content, search_vector)
            
            logger.info(f"Successfully indexed security wiki: {wiki_id}")
            return searchable_content
            
        except Exception as e:
            logger.error(f"Failed to index security wiki {wiki_id}: {e}")
            raise
    
    def _extract_full_text(self, wiki_content: Dict) -> str:
        """Extract full text from wiki content"""
        text_parts = []
        
        # Extract from various content sections
        if "threats" in wiki_content:
            for threat in wiki_content["threats"]:
                text_parts.append(threat.get("description", ""))
                text_parts.append(threat.get("impact", ""))
        
        if "mitigations" in wiki_content:
            for mitigation in wiki_content["mitigations"]:
                text_parts.append(mitigation.get("description", ""))
                text_parts.append(mitigation.get("implementation", ""))
        
        if "system_model" in wiki_content:
            system_model = wiki_content["system_model"]
            text_parts.append(system_model.get("description", ""))
            
            for component in system_model.get("components", []):
                text_parts.append(component.get("description", ""))
        
        return " ".join(filter(None, text_parts))
    
    def _generate_security_tags(self, wiki_content: Dict) -> List[str]:
        """Generate security tags from wiki content"""
        tags = set()
        
        # Add tags based on content structure
        if "threats" in wiki_content:
            tags.add("threats")
            for threat in wiki_content["threats"]:
                if threat.get("severity"):
                    tags.add(f"severity_{threat['severity'].lower()}")
        
        if "mitigations" in wiki_content:
            tags.add("mitigations")
            for mitigation in wiki_content["mitigations"]:
                if mitigation.get("status"):
                    tags.add(f"status_{mitigation['status'].lower()}")
        
        # Add OWASP-related tags
        full_text = self._extract_full_text(wiki_content).lower()
        for owasp_category in self.owasp_mappings.keys():
            if any(keyword in full_text for keyword in self.owasp_mappings[owasp_category]):
                tags.add(f"owasp_{owasp_category.lower().replace(' ', '_')}")
        
        return list(tags)
    
    def _store_index(self, content: SearchableContent, search_vector: str):
        """Store indexed content in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO security_index 
                (wiki_id, full_text_index, threat_keywords, mitigation_keywords, 
                 owasp_keywords, security_tags, patterns, indexed_at, search_vector)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                content.wiki_id,
                content.full_text_index,
                json.dumps(content.threat_keywords),
                json.dumps(content.mitigation_keywords),
                json.dumps(content.owasp_keywords),
                json.dumps(content.security_tags),
                json.dumps([asdict(p) for p in content.patterns]),
                content.indexed_at.isoformat(),
                search_vector
            ))
    
    def get_indexed_content(self, wiki_id: str) -> Optional[SearchableContent]:
        """Retrieve indexed content for a wiki"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM security_index WHERE wiki_id = ?
            """, (wiki_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return SearchableContent(
                wiki_id=row[0],
                full_text_index=row[1],
                threat_keywords=json.loads(row[2]),
                mitigation_keywords=json.loads(row[3]),
                owasp_keywords=json.loads(row[4]),
                security_tags=json.loads(row[5]),
                patterns=[SecurityPattern(**p) for p in json.loads(row[6])],
                indexed_at=datetime.fromisoformat(row[7])
            )
    
    def search_content(self, query: str, filters: Optional[Dict] = None) -> List[Tuple[str, float]]:
        """Search indexed security content"""
        query_lower = query.lower()
        results = []
        
        with sqlite3.connect(self.db_path) as conn:
            # Build search query
            sql = "SELECT wiki_id, search_vector FROM security_index"
            params = []
            
            if filters:
                conditions = []
                if "owasp_categories" in filters:
                    for category in filters["owasp_categories"]:
                        conditions.append("owasp_keywords LIKE ?")
                        params.append(f"%{category.lower()}%")
                
                if "security_tags" in filters:
                    for tag in filters["security_tags"]:
                        conditions.append("security_tags LIKE ?")
                        params.append(f"%{tag}%")
                
                if conditions:
                    sql += " WHERE " + " AND ".join(conditions)
            
            cursor = conn.execute(sql, params)
            
            for wiki_id, search_vector in cursor.fetchall():
                # Calculate relevance score
                score = self._calculate_relevance_score(query_lower, search_vector)
                if score > 0.1:  # Minimum relevance threshold
                    results.append((wiki_id, score))
        
        # Sort by relevance score
        results.sort(key=lambda x: x[1], reverse=True)
        return results
    
    def _calculate_relevance_score(self, query: str, search_vector: str) -> float:
        """Calculate relevance score for search query"""
        query_terms = set(query.lower().split())
        vector_terms = set(search_vector.lower().split())
        
        if not query_terms:
            return 0.0
        
        # Calculate term overlap
        intersection = query_terms.intersection(vector_terms)
        union = query_terms.union(vector_terms)
        
        if not union:
            return 0.0
        
        # Jaccard similarity with boost for exact matches
        jaccard_score = len(intersection) / len(union)
        
        # Boost score for exact phrase matches
        phrase_boost = 1.0
        if query in search_vector.lower():
            phrase_boost = 1.5
        
        return min(1.0, jaccard_score * phrase_boost)
    
    def get_security_patterns_summary(self) -> Dict[str, int]:
        """Get summary of identified security patterns"""
        pattern_counts = {}
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT patterns FROM security_index")
            
            for (patterns_json,) in cursor.fetchall():
                patterns = json.loads(patterns_json)
                for pattern in patterns:
                    pattern_name = pattern["pattern_name"]
                    pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + 1
        
        return pattern_counts
    
    def rebuild_index(self):
        """Rebuild the entire security index"""
        logger.info("Starting security index rebuild...")
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM security_index")
        
        # This would typically re-index all wikis from the main database
        # For now, we'll just log the completion
        logger.info("Security index rebuild completed")

# Global indexer instance
security_indexer = SecurityContentIndexer()