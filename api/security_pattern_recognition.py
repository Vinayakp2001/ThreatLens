"""
Security Pattern Recognition System

Implements advanced algorithms to identify recurring security patterns across repositories,
create pattern matching for common vulnerability types and attack vectors, and implement
trend analysis for emerging security threats.
"""

import re
import json
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import sqlite3
from pathlib import Path

from security_indexing import SecurityPattern, security_indexer

logger = logging.getLogger(__name__)

@dataclass
class PatternTrend:
    """Represents a trend in security pattern occurrence"""
    pattern_name: str
    time_period: str
    occurrence_count: int
    growth_rate: float
    severity_distribution: Dict[str, int]
    affected_repositories: List[str]
    first_seen: datetime
    last_seen: datetime

@dataclass
class VulnerabilityPattern:
    """Represents a specific vulnerability pattern"""
    pattern_id: str
    vulnerability_type: str
    attack_vector: str
    description: str
    indicators: List[str]
    mitigation_patterns: List[str]
    cve_references: List[str]
    owasp_mapping: str
    confidence_threshold: float

@dataclass
class RecurringPattern:
    """Represents a recurring security pattern across repositories"""
    pattern_signature: str
    occurrence_count: int
    affected_wikis: List[str]
    pattern_variations: List[str]
    common_context: str
    risk_score: float
    trend_direction: str  # "increasing", "decreasing", "stable"

class SecurityPatternRecognizer:
    """Main service for security pattern recognition and analysis"""
    
    def __init__(self, db_path: str = "data/security_patterns.db"):
        self.db_path = db_path
        self.indexer = security_indexer
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.pattern_cache = {}
        self._init_database()
    
    def _init_database(self):
        """Initialize the pattern recognition database"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            # Pattern occurrences table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pattern_occurrences (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    wiki_id TEXT,
                    pattern_name TEXT,
                    pattern_type TEXT,
                    occurrence_date TIMESTAMP,
                    context TEXT,
                    confidence_score REAL,
                    severity TEXT,
                    owasp_category TEXT
                )
            """)
            
            # Pattern trends table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pattern_trends (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_name TEXT,
                    time_period TEXT,
                    occurrence_count INTEGER,
                    growth_rate REAL,
                    severity_distribution TEXT,
                    affected_repositories TEXT,
                    calculated_at TIMESTAMP
                )
            """)
            
            # Vulnerability patterns table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    vulnerability_type TEXT,
                    attack_vector TEXT,
                    description TEXT,
                    indicators TEXT,
                    mitigation_patterns TEXT,
                    cve_references TEXT,
                    owasp_mapping TEXT,
                    confidence_threshold REAL,
                    created_at TIMESTAMP
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pattern_name ON pattern_occurrences(pattern_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_occurrence_date ON pattern_occurrences(occurrence_date)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_wiki_id ON pattern_occurrences(wiki_id)")
    
    def _load_vulnerability_patterns(self) -> List[VulnerabilityPattern]:
        """Load predefined vulnerability patterns"""
        return [
            VulnerabilityPattern(
                pattern_id="sql_injection_basic",
                vulnerability_type="SQL Injection",
                attack_vector="Input Manipulation",
                description="Basic SQL injection patterns in user input handling",
                indicators=[
                    r"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table)",
                    r"(?i)(exec\s*\(|execute\s*\(|sp_executesql)",
                    r"(?i)(\'\s*;\s*--|\/\*.*\*\/)"
                ],
                mitigation_patterns=[
                    "parameterized queries", "input validation", "prepared statements"
                ],
                cve_references=["CVE-2021-44228", "CVE-2020-1472"],
                owasp_mapping="Injection",
                confidence_threshold=0.8
            ),
            VulnerabilityPattern(
                pattern_id="xss_reflected",
                vulnerability_type="Cross-Site Scripting",
                attack_vector="Reflected XSS",
                description="Reflected XSS patterns in web applications",
                indicators=[
                    r"(?i)(<script[^>]*>.*</script>|javascript:|on\w+\s*=)",
                    r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()",
                    r"(?i)(document\.cookie|window\.location|eval\s*\()"
                ],
                mitigation_patterns=[
                    "output encoding", "content security policy", "input sanitization"
                ],
                cve_references=["CVE-2021-26855", "CVE-2020-0688"],
                owasp_mapping="Cross-Site Scripting",
                confidence_threshold=0.75
            ),
            VulnerabilityPattern(
                pattern_id="auth_bypass",
                vulnerability_type="Authentication Bypass",
                attack_vector="Logic Flaw",
                description="Authentication bypass patterns",
                indicators=[
                    r"(?i)(bypass|skip)\s+(auth|login|authentication)",
                    r"(?i)(admin|root|superuser)\s+(access|privilege)",
                    r"(?i)(session\s+fixation|privilege\s+escalation)"
                ],
                mitigation_patterns=[
                    "multi-factor authentication", "session management", "access controls"
                ],
                cve_references=["CVE-2021-34527", "CVE-2020-1350"],
                owasp_mapping="Broken Authentication",
                confidence_threshold=0.85
            ),
            VulnerabilityPattern(
                pattern_id="path_traversal",
                vulnerability_type="Path Traversal",
                attack_vector="File System Access",
                description="Directory traversal and path manipulation patterns",
                indicators=[
                    r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)",
                    r"(?i)(\/etc\/passwd|\/windows\/system32|c:\\windows)",
                    r"(?i)(file\s*:\s*\/\/|\.\.%2f|\.\.%5c)"
                ],
                mitigation_patterns=[
                    "input validation", "path canonicalization", "file access controls"
                ],
                cve_references=["CVE-2021-26084", "CVE-2020-5902"],
                owasp_mapping="Broken Access Control",
                confidence_threshold=0.9
            ),
            VulnerabilityPattern(
                pattern_id="deserialization_vuln",
                vulnerability_type="Insecure Deserialization",
                attack_vector="Object Injection",
                description="Insecure deserialization patterns",
                indicators=[
                    r"(?i)(pickle\.loads|yaml\.load|json\.loads)",
                    r"(?i)(serialize|deserialize|unmarshal)",
                    r"(?i)(object\s+injection|gadget\s+chain)"
                ],
                mitigation_patterns=[
                    "input validation", "safe deserialization", "object whitelisting"
                ],
                cve_references=["CVE-2021-44228", "CVE-2020-36179"],
                owasp_mapping="Insecure Deserialization",
                confidence_threshold=0.8
            )
        ]
    
    def identify_recurring_patterns(self, time_window_days: int = 30) -> List[RecurringPattern]:
        """Identify recurring security patterns across repositories"""
        cutoff_date = datetime.now() - timedelta(days=time_window_days)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT pattern_name, wiki_id, context, confidence_score, severity
                FROM pattern_occurrences 
                WHERE occurrence_date >= ?
                ORDER BY pattern_name, occurrence_date
            """, (cutoff_date.isoformat(),))
            
            # Group patterns by name
            pattern_groups = defaultdict(list)
            for row in cursor.fetchall():
                pattern_name, wiki_id, context, confidence, severity = row
                pattern_groups[pattern_name].append({
                    'wiki_id': wiki_id,
                    'context': context,
                    'confidence': confidence,
                    'severity': severity
                })
        
        recurring_patterns = []
        
        for pattern_name, occurrences in pattern_groups.items():
            if len(occurrences) >= 2:  # Must occur in at least 2 wikis to be "recurring"
                # Calculate pattern signature
                contexts = [occ['context'] for occ in occurrences]
                pattern_signature = self._generate_pattern_signature(contexts)
                
                # Get unique wikis
                affected_wikis = list(set(occ['wiki_id'] for occ in occurrences))
                
                # Find pattern variations
                variations = self._find_pattern_variations(contexts)
                
                # Calculate common context
                common_context = self._extract_common_context(contexts)
                
                # Calculate risk score
                risk_score = self._calculate_risk_score(occurrences)
                
                # Determine trend direction
                trend_direction = self._analyze_trend_direction(pattern_name, time_window_days)
                
                recurring_pattern = RecurringPattern(
                    pattern_signature=pattern_signature,
                    occurrence_count=len(occurrences),
                    affected_wikis=affected_wikis,
                    pattern_variations=variations,
                    common_context=common_context,
                    risk_score=risk_score,
                    trend_direction=trend_direction
                )
                
                recurring_patterns.append(recurring_pattern)
        
        # Sort by risk score and occurrence count
        recurring_patterns.sort(key=lambda p: (p.risk_score, p.occurrence_count), reverse=True)
        
        return recurring_patterns
    
    def match_vulnerability_patterns(self, wiki_content: str, wiki_id: str) -> List[SecurityPattern]:
        """Match content against known vulnerability patterns"""
        matched_patterns = []
        
        for vuln_pattern in self.vulnerability_patterns:
            matches = []
            
            # Check each indicator pattern
            for indicator in vuln_pattern.indicators:
                pattern_matches = list(re.finditer(indicator, wiki_content))
                matches.extend(pattern_matches)
            
            if matches:
                # Calculate confidence based on number and quality of matches
                confidence = self._calculate_pattern_confidence(matches, vuln_pattern, wiki_content)
                
                if confidence >= vuln_pattern.confidence_threshold:
                    # Create security pattern
                    security_pattern = SecurityPattern(
                        pattern_type="vulnerability",
                        pattern_name=vuln_pattern.vulnerability_type,
                        description=f"{vuln_pattern.description} (Attack Vector: {vuln_pattern.attack_vector})",
                        severity=self._determine_severity(vuln_pattern, confidence),
                        owasp_category=vuln_pattern.owasp_mapping,
                        keywords=vuln_pattern.mitigation_patterns,
                        confidence_score=confidence
                    )
                    
                    matched_patterns.append(security_pattern)
                    
                    # Store pattern occurrence
                    self._store_pattern_occurrence(
                        wiki_id, vuln_pattern.vulnerability_type, "vulnerability",
                        wiki_content[matches[0].start():matches[0].end()],
                        confidence, security_pattern.severity, vuln_pattern.owasp_mapping
                    )
        
        return matched_patterns
    
    def analyze_emerging_threats(self, analysis_period_days: int = 90) -> List[PatternTrend]:
        """Analyze trends for emerging security threats"""
        cutoff_date = datetime.now() - timedelta(days=analysis_period_days)
        
        with sqlite3.connect(self.db_path) as conn:
            # Get pattern occurrences over time
            cursor = conn.execute("""
                SELECT 
                    pattern_name,
                    DATE(occurrence_date) as occurrence_day,
                    COUNT(*) as daily_count,
                    severity,
                    wiki_id
                FROM pattern_occurrences 
                WHERE occurrence_date >= ?
                GROUP BY pattern_name, DATE(occurrence_date), severity, wiki_id
                ORDER BY pattern_name, occurrence_day
            """, (cutoff_date.isoformat(),))
            
            # Group by pattern and analyze trends
            pattern_data = defaultdict(list)
            for row in cursor.fetchall():
                pattern_name, day, count, severity, wiki_id = row
                pattern_data[pattern_name].append({
                    'day': day,
                    'count': count,
                    'severity': severity,
                    'wiki_id': wiki_id
                })
        
        trends = []
        
        for pattern_name, daily_data in pattern_data.items():
            # Calculate trend metrics
            total_occurrences = sum(item['count'] for item in daily_data)
            
            if total_occurrences < 3:  # Skip patterns with too few occurrences
                continue
            
            # Calculate growth rate
            growth_rate = self._calculate_growth_rate(daily_data)
            
            # Get severity distribution
            severity_counts = Counter(item['severity'] for item in daily_data)
            severity_distribution = dict(severity_counts)
            
            # Get affected repositories
            affected_repos = list(set(item['wiki_id'] for item in daily_data))
            
            # Get time range
            dates = [datetime.fromisoformat(item['day']) for item in daily_data]
            first_seen = min(dates)
            last_seen = max(dates)
            
            trend = PatternTrend(
                pattern_name=pattern_name,
                time_period=f"{analysis_period_days} days",
                occurrence_count=total_occurrences,
                growth_rate=growth_rate,
                severity_distribution=severity_distribution,
                affected_repositories=affected_repos,
                first_seen=first_seen,
                last_seen=last_seen
            )
            
            trends.append(trend)
            
            # Store trend data
            self._store_pattern_trend(trend)
        
        # Sort by growth rate and occurrence count
        trends.sort(key=lambda t: (t.growth_rate, t.occurrence_count), reverse=True)
        
        return trends
    
    def _generate_pattern_signature(self, contexts: List[str]) -> str:
        """Generate a unique signature for a pattern based on contexts"""
        # Extract common keywords and create a signature
        all_words = []
        for context in contexts:
            words = re.findall(r'\b\w+\b', context.lower())
            all_words.extend(words)
        
        # Get most common words
        word_counts = Counter(all_words)
        common_words = [word for word, count in word_counts.most_common(5) if count > 1]
        
        return "_".join(sorted(common_words))
    
    def _find_pattern_variations(self, contexts: List[str]) -> List[str]:
        """Find variations of the same pattern"""
        variations = set()
        
        for context in contexts:
            # Extract potential variations (simplified approach)
            # Look for similar structures with different values
            normalized = re.sub(r'\b\d+\b', 'NUM', context)
            normalized = re.sub(r'\b[a-f0-9]{8,}\b', 'HEX', normalized)
            normalized = re.sub(r'\b\w+@\w+\.\w+\b', 'EMAIL', normalized)
            variations.add(normalized)
        
        return list(variations)
    
    def _extract_common_context(self, contexts: List[str]) -> str:
        """Extract common context from multiple pattern occurrences"""
        if not contexts:
            return ""
        
        # Find common substrings
        common_parts = []
        first_context = contexts[0]
        
        for i in range(len(first_context)):
            for j in range(i + 10, len(first_context) + 1):  # Minimum 10 chars
                substring = first_context[i:j]
                if all(substring in context for context in contexts[1:]):
                    common_parts.append(substring)
        
        # Return the longest common substring
        if common_parts:
            return max(common_parts, key=len)
        
        return "No common context found"
    
    def _calculate_risk_score(self, occurrences: List[Dict]) -> float:
        """Calculate risk score based on pattern occurrences"""
        base_score = len(occurrences) * 0.1  # Base score from frequency
        
        # Severity weighting
        severity_weights = {'low': 0.25, 'medium': 0.5, 'high': 0.75, 'critical': 1.0}
        severity_score = sum(
            severity_weights.get(occ.get('severity', 'medium'), 0.5) 
            for occ in occurrences
        ) / len(occurrences)
        
        # Confidence weighting
        confidence_score = sum(occ.get('confidence', 0.5) for occ in occurrences) / len(occurrences)
        
        return min(1.0, base_score + (severity_score * 0.4) + (confidence_score * 0.3))
    
    def _analyze_trend_direction(self, pattern_name: str, time_window_days: int) -> str:
        """Analyze trend direction for a pattern"""
        cutoff_date = datetime.now() - timedelta(days=time_window_days)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT DATE(occurrence_date) as day, COUNT(*) as count
                FROM pattern_occurrences 
                WHERE pattern_name = ? AND occurrence_date >= ?
                GROUP BY DATE(occurrence_date)
                ORDER BY day
            """, (pattern_name, cutoff_date.isoformat()))
            
            daily_counts = [(row[0], row[1]) for row in cursor.fetchall()]
        
        if len(daily_counts) < 2:
            return "stable"
        
        # Simple trend analysis
        first_half = daily_counts[:len(daily_counts)//2]
        second_half = daily_counts[len(daily_counts)//2:]
        
        first_avg = sum(count for _, count in first_half) / len(first_half)
        second_avg = sum(count for _, count in second_half) / len(second_half)
        
        if second_avg > first_avg * 1.2:
            return "increasing"
        elif second_avg < first_avg * 0.8:
            return "decreasing"
        else:
            return "stable"
    
    def _calculate_pattern_confidence(self, matches: List, vuln_pattern: VulnerabilityPattern, content: str) -> float:
        """Calculate confidence score for pattern matches"""
        base_confidence = 0.6
        
        # More matches increase confidence
        match_bonus = min(0.3, len(matches) * 0.1)
        
        # Context analysis
        context_bonus = 0.0
        for match in matches:
            # Get surrounding context
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 50)
            context = content[start:end].lower()
            
            # Check for mitigation keywords (reduces confidence)
            mitigation_found = any(
                mitigation.lower() in context 
                for mitigation in vuln_pattern.mitigation_patterns
            )
            
            if mitigation_found:
                context_bonus -= 0.1
            else:
                context_bonus += 0.05
        
        return min(1.0, base_confidence + match_bonus + context_bonus)
    
    def _determine_severity(self, vuln_pattern: VulnerabilityPattern, confidence: float) -> str:
        """Determine severity based on vulnerability pattern and confidence"""
        # Base severity mapping
        severity_map = {
            "SQL Injection": "high",
            "Cross-Site Scripting": "medium",
            "Authentication Bypass": "critical",
            "Path Traversal": "high",
            "Insecure Deserialization": "high"
        }
        
        base_severity = severity_map.get(vuln_pattern.vulnerability_type, "medium")
        
        # Adjust based on confidence
        if confidence >= 0.9:
            if base_severity == "medium":
                return "high"
            elif base_severity == "high":
                return "critical"
        elif confidence < 0.7:
            if base_severity == "critical":
                return "high"
            elif base_severity == "high":
                return "medium"
        
        return base_severity
    
    def _store_pattern_occurrence(self, wiki_id: str, pattern_name: str, pattern_type: str,
                                context: str, confidence: float, severity: str, owasp_category: str):
        """Store pattern occurrence in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO pattern_occurrences 
                (wiki_id, pattern_name, pattern_type, occurrence_date, context, 
                 confidence_score, severity, owasp_category)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                wiki_id, pattern_name, pattern_type, datetime.now().isoformat(),
                context, confidence, severity, owasp_category
            ))
    
    def _store_pattern_trend(self, trend: PatternTrend):
        """Store pattern trend in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO pattern_trends 
                (pattern_name, time_period, occurrence_count, growth_rate, 
                 severity_distribution, affected_repositories, calculated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                trend.pattern_name, trend.time_period, trend.occurrence_count,
                trend.growth_rate, json.dumps(trend.severity_distribution),
                json.dumps(trend.affected_repositories), datetime.now().isoformat()
            ))
    
    def _calculate_growth_rate(self, daily_data: List[Dict]) -> float:
        """Calculate growth rate for pattern occurrences"""
        if len(daily_data) < 2:
            return 0.0
        
        # Group by week for smoother trend analysis
        weekly_counts = defaultdict(int)
        for item in daily_data:
            # Get week number
            date = datetime.fromisoformat(item['day'])
            week = date.strftime("%Y-W%U")
            weekly_counts[week] += item['count']
        
        weeks = sorted(weekly_counts.keys())
        if len(weeks) < 2:
            return 0.0
        
        # Calculate linear growth rate
        first_week_count = weekly_counts[weeks[0]]
        last_week_count = weekly_counts[weeks[-1]]
        
        if first_week_count == 0:
            return 1.0 if last_week_count > 0 else 0.0
        
        return (last_week_count - first_week_count) / first_week_count
    
    def get_pattern_statistics(self) -> Dict[str, Any]:
        """Get comprehensive pattern recognition statistics"""
        with sqlite3.connect(self.db_path) as conn:
            # Total patterns
            cursor = conn.execute("SELECT COUNT(*) FROM pattern_occurrences")
            total_patterns = cursor.fetchone()[0]
            
            # Patterns by type
            cursor = conn.execute("""
                SELECT pattern_type, COUNT(*) 
                FROM pattern_occurrences 
                GROUP BY pattern_type
            """)
            patterns_by_type = dict(cursor.fetchall())
            
            # Top patterns
            cursor = conn.execute("""
                SELECT pattern_name, COUNT(*) as count
                FROM pattern_occurrences 
                GROUP BY pattern_name 
                ORDER BY count DESC 
                LIMIT 10
            """)
            top_patterns = dict(cursor.fetchall())
            
            # Recent trends
            cursor = conn.execute("""
                SELECT pattern_name, growth_rate
                FROM pattern_trends 
                ORDER BY calculated_at DESC 
                LIMIT 10
            """)
            recent_trends = dict(cursor.fetchall())
        
        return {
            "total_patterns": total_patterns,
            "patterns_by_type": patterns_by_type,
            "top_patterns": top_patterns,
            "recent_trends": recent_trends,
            "vulnerability_patterns_loaded": len(self.vulnerability_patterns)
        }

# Global pattern recognizer instance
security_pattern_recognizer = SecurityPatternRecognizer()