"""
Database Performance Optimization Module

This module provides comprehensive database performance optimization for security data operations
including query optimization, indexing strategies, and connection pooling.
"""

import sqlite3
import logging
import time
import threading
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from contextlib import contextmanager
from dataclasses import dataclass
from queue import Queue, Empty
import json

logger = logging.getLogger(__name__)

@dataclass
class QueryPerformanceMetrics:
    """Performance metrics for database queries"""
    query_hash: str
    query_type: str
    execution_time: float
    rows_affected: int
    timestamp: datetime
    optimization_applied: bool = False

@dataclass
class IndexRecommendation:
    """Index recommendation based on query analysis"""
    table_name: str
    columns: List[str]
    index_type: str  # "btree", "hash", "composite"
    estimated_benefit: float
    query_patterns: List[str]

class ConnectionPool:
    """Thread-safe SQLite connection pool for improved performance"""
    
    def __init__(self, db_path: str, pool_size: int = 10, timeout: float = 30.0):
        self.db_path = db_path
        self.pool_size = pool_size
        self.timeout = timeout
        self._pool = Queue(maxsize=pool_size)
        self._lock = threading.Lock()
        self._created_connections = 0
        
        # Pre-populate pool with connections
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Initialize the connection pool"""
        for _ in range(self.pool_size):
            conn = self._create_connection()
            self._pool.put(conn)
    
    def _create_connection(self) -> sqlite3.Connection:
        """Create a new optimized database connection"""
        conn = sqlite3.connect(
            self.db_path,
            timeout=self.timeout,
            check_same_thread=False
        )
        
        # Apply performance optimizations
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA cache_size = -64000")  # 64MB cache
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA mmap_size = 268435456")  # 256MB mmap
        conn.execute("PRAGMA foreign_keys = ON")
        
        self._created_connections += 1
        return conn
    
    @contextmanager
    def get_connection(self):
        """Get a connection from the pool"""
        conn = None
        try:
            # Try to get connection from pool
            try:
                conn = self._pool.get(timeout=5.0)
            except Empty:
                # Pool exhausted, create new connection
                conn = self._create_connection()
                logger.warning("Connection pool exhausted, creating new connection")
            
            yield conn
            
        finally:
            if conn:
                try:
                    # Return connection to pool if there's space
                    self._pool.put_nowait(conn)
                except:
                    # Pool full, close connection
                    conn.close()
    
    def close_all(self):
        """Close all connections in the pool"""
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except Empty:
                break

class QueryOptimizer:
    """Query optimization and analysis system"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.query_metrics: Dict[str, List[QueryPerformanceMetrics]] = {}
        self.optimization_rules = self._load_optimization_rules()
        self._init_metrics_table()
    
    def _init_metrics_table(self):
        """Initialize query metrics tracking table"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS query_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query_hash TEXT,
                    query_type TEXT,
                    execution_time REAL,
                    rows_affected INTEGER,
                    timestamp TEXT,
                    optimization_applied BOOLEAN DEFAULT FALSE
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_query_metrics_hash 
                ON query_metrics(query_hash)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_query_metrics_timestamp 
                ON query_metrics(timestamp)
            """)
    
    def _load_optimization_rules(self) -> Dict[str, Dict]:
        """Load query optimization rules"""
        return {
            "security_search": {
                "pattern": r"SELECT.*FROM.*security_wikis.*WHERE.*",
                "indexes": ["idx_security_wikis_search", "idx_security_wikis_content"],
                "optimizations": ["use_fts", "limit_results", "optimize_joins"]
            },
            "threat_analysis": {
                "pattern": r"SELECT.*FROM.*threat_documents.*",
                "indexes": ["idx_threat_docs_repo_type", "idx_threat_docs_current_status"],
                "optimizations": ["filter_current_only", "use_covering_index"]
            },
            "security_metrics": {
                "pattern": r"SELECT.*COUNT.*FROM.*security_.*",
                "indexes": ["idx_security_aggregation"],
                "optimizations": ["use_materialized_views", "cache_results"]
            }
        }
    
    def analyze_query(self, query: str) -> Dict[str, Any]:
        """Analyze query for optimization opportunities"""
        query_hash = self._hash_query(query)
        
        with sqlite3.connect(self.db_path) as conn:
            # Get query plan
            cursor = conn.execute(f"EXPLAIN QUERY PLAN {query}")
            query_plan = cursor.fetchall()
            
            # Analyze for optimization opportunities
            analysis = {
                "query_hash": query_hash,
                "query_plan": query_plan,
                "scan_operations": self._count_scan_operations(query_plan),
                "missing_indexes": self._identify_missing_indexes(query, query_plan),
                "optimization_suggestions": self._get_optimization_suggestions(query, query_plan)
            }
        
        return analysis
    
    def _hash_query(self, query: str) -> str:
        """Create hash for query normalization"""
        import hashlib
        # Normalize query by removing literals and whitespace
        normalized = " ".join(query.split()).upper()
        return hashlib.md5(normalized.encode()).hexdigest()[:16]
    
    def _count_scan_operations(self, query_plan: List[Tuple]) -> int:
        """Count table scan operations in query plan"""
        scan_count = 0
        for row in query_plan:
            if "SCAN" in str(row).upper():
                scan_count += 1
        return scan_count
    
    def _identify_missing_indexes(self, query: str, query_plan: List[Tuple]) -> List[IndexRecommendation]:
        """Identify missing indexes that could improve performance"""
        recommendations = []
        
        # Analyze WHERE clauses for potential indexes
        import re
        where_patterns = re.findall(r"WHERE\s+(\w+\.\w+|\w+)\s*[=<>]", query, re.IGNORECASE)
        
        for pattern in where_patterns:
            if "." in pattern:
                table, column = pattern.split(".")
            else:
                # Try to infer table from query
                table_match = re.search(r"FROM\s+(\w+)", query, re.IGNORECASE)
                table = table_match.group(1) if table_match else "unknown"
                column = pattern
            
            # Check if index exists
            if not self._index_exists(table, column):
                recommendations.append(IndexRecommendation(
                    table_name=table,
                    columns=[column],
                    index_type="btree",
                    estimated_benefit=0.7,  # Estimated improvement
                    query_patterns=[query]
                ))
        
        return recommendations
    
    def _index_exists(self, table: str, column: str) -> bool:
        """Check if index exists for table.column"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='index' AND tbl_name=? AND sql LIKE ?
            """, (table, f"%{column}%"))
            return cursor.fetchone() is not None
    
    def _get_optimization_suggestions(self, query: str, query_plan: List[Tuple]) -> List[str]:
        """Get optimization suggestions based on query analysis"""
        suggestions = []
        
        # Check for table scans
        if self._count_scan_operations(query_plan) > 0:
            suggestions.append("Consider adding indexes to eliminate table scans")
        
        # Check for complex joins
        if "JOIN" in query.upper() and len(query_plan) > 5:
            suggestions.append("Consider optimizing join order or adding covering indexes")
        
        # Check for SELECT *
        if "SELECT *" in query.upper():
            suggestions.append("Consider selecting only required columns")
        
        # Check for missing LIMIT
        if "LIMIT" not in query.upper() and "COUNT" not in query.upper():
            suggestions.append("Consider adding LIMIT clause for large result sets")
        
        return suggestions
    
    def track_query_performance(self, query: str, execution_time: float, rows_affected: int):
        """Track query performance metrics"""
        query_hash = self._hash_query(query)
        query_type = self._classify_query(query)
        
        metrics = QueryPerformanceMetrics(
            query_hash=query_hash,
            query_type=query_type,
            execution_time=execution_time,
            rows_affected=rows_affected,
            timestamp=datetime.now()
        )
        
        # Store in memory
        if query_hash not in self.query_metrics:
            self.query_metrics[query_hash] = []
        self.query_metrics[query_hash].append(metrics)
        
        # Store in database
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO query_metrics 
                (query_hash, query_type, execution_time, rows_affected, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                query_hash, query_type, execution_time, 
                rows_affected, metrics.timestamp.isoformat()
            ))
    
    def _classify_query(self, query: str) -> str:
        """Classify query type for performance tracking"""
        query_upper = query.upper().strip()
        
        if query_upper.startswith("SELECT"):
            if "security_wikis" in query_upper:
                return "security_search"
            elif "threat_documents" in query_upper:
                return "threat_analysis"
            elif "COUNT" in query_upper:
                return "aggregation"
            else:
                return "select"
        elif query_upper.startswith("INSERT"):
            return "insert"
        elif query_upper.startswith("UPDATE"):
            return "update"
        elif query_upper.startswith("DELETE"):
            return "delete"
        else:
            return "other"
    
    def get_slow_queries(self, threshold_ms: float = 100.0) -> List[Dict]:
        """Get queries that exceed performance threshold"""
        slow_queries = []
        
        for query_hash, metrics_list in self.query_metrics.items():
            avg_time = sum(m.execution_time for m in metrics_list) / len(metrics_list)
            if avg_time > threshold_ms / 1000.0:  # Convert to seconds
                slow_queries.append({
                    "query_hash": query_hash,
                    "query_type": metrics_list[0].query_type,
                    "avg_execution_time": avg_time,
                    "execution_count": len(metrics_list),
                    "max_execution_time": max(m.execution_time for m in metrics_list)
                })
        
        return sorted(slow_queries, key=lambda x: x["avg_execution_time"], reverse=True)

class SecurityDatabaseOptimizer:
    """Main database optimization service for security operations"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.connection_pool = ConnectionPool(db_path)
        self.query_optimizer = QueryOptimizer(db_path)
        self._init_security_indexes()
    
    def _init_security_indexes(self):
        """Initialize optimized indexes for security data operations"""
        security_indexes = [
            # Security wikis indexes
            "CREATE INDEX IF NOT EXISTS idx_security_wikis_repo_title ON security_wikis(repo_id, title)",
            "CREATE INDEX IF NOT EXISTS idx_security_wikis_updated_desc ON security_wikis(updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_security_wikis_search_content ON security_wikis(title, sections)",
            
            # Security documents indexes
            "CREATE INDEX IF NOT EXISTS idx_security_docs_repo_scope ON security_documents(repo_id, scope)",
            "CREATE INDEX IF NOT EXISTS idx_security_docs_current_updated ON security_documents(is_current, updated_at DESC)",
            
            # Threat documents indexes
            "CREATE INDEX IF NOT EXISTS idx_threat_docs_repo_type_current ON threat_documents(repo_id, doc_type, is_current)",
            "CREATE INDEX IF NOT EXISTS idx_threat_docs_updated_desc ON threat_documents(updated_at DESC)",
            
            # Security index table indexes
            "CREATE INDEX IF NOT EXISTS idx_security_index_owasp_tags ON security_index(owasp_keywords, security_tags)",
            "CREATE INDEX IF NOT EXISTS idx_security_index_patterns ON security_index(patterns)",
            
            # Analysis sessions indexes
            "CREATE INDEX IF NOT EXISTS idx_analysis_sessions_repo_status ON analysis_sessions(repo_id, status)",
            "CREATE INDEX IF NOT EXISTS idx_analysis_sessions_completed_desc ON analysis_sessions(completed_at DESC)",
            
            # System metrics indexes for security analytics
            "CREATE INDEX IF NOT EXISTS idx_system_metrics_security ON system_metrics(metric_name, recorded_at DESC) WHERE metric_name LIKE 'security_%'",
        ]
        
        with self.connection_pool.get_connection() as conn:
            for index_sql in security_indexes:
                try:
                    conn.execute(index_sql)
                    logger.debug(f"Created index: {index_sql}")
                except sqlite3.Error as e:
                    logger.warning(f"Failed to create index: {e}")
            conn.commit()
    
    @contextmanager
    def optimized_query(self, query: str, params: Optional[Tuple] = None):
        """Execute query with performance tracking and optimization"""
        start_time = time.time()
        
        with self.connection_pool.get_connection() as conn:
            try:
                cursor = conn.cursor()
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                yield cursor
                
                # Track performance
                execution_time = time.time() - start_time
                rows_affected = cursor.rowcount if cursor.rowcount >= 0 else 0
                
                self.query_optimizer.track_query_performance(
                    query, execution_time, rows_affected
                )
                
                # Log slow queries
                if execution_time > 0.1:  # 100ms threshold
                    logger.warning(f"Slow query detected: {execution_time:.3f}s - {query[:100]}...")
                
            except Exception as e:
                logger.error(f"Query execution failed: {e}")
                raise
    
    def execute_optimized_search(self, search_params: Dict[str, Any]) -> List[Dict]:
        """Execute optimized security content search"""
        # Build optimized search query
        base_query = """
            SELECT sw.id, sw.title, sw.repo_id, sw.created_at, sw.updated_at,
                   si.threat_keywords, si.owasp_keywords, si.security_tags
            FROM security_wikis sw
            LEFT JOIN security_index si ON sw.id = si.wiki_id
        """
        
        conditions = []
        params = []
        
        # Add search conditions
        if search_params.get("query"):
            conditions.append("(sw.title LIKE ? OR si.full_text_index LIKE ?)")
            query_param = f"%{search_params['query']}%"
            params.extend([query_param, query_param])
        
        if search_params.get("repo_id"):
            conditions.append("sw.repo_id = ?")
            params.append(search_params["repo_id"])
        
        if search_params.get("owasp_categories"):
            owasp_conditions = []
            for category in search_params["owasp_categories"]:
                owasp_conditions.append("si.owasp_keywords LIKE ?")
                params.append(f"%{category}%")
            conditions.append(f"({' OR '.join(owasp_conditions)})")
        
        if search_params.get("security_tags"):
            tag_conditions = []
            for tag in search_params["security_tags"]:
                tag_conditions.append("si.security_tags LIKE ?")
                params.append(f"%{tag}%")
            conditions.append(f"({' OR '.join(tag_conditions)})")
        
        # Build final query
        if conditions:
            query = f"{base_query} WHERE {' AND '.join(conditions)}"
        else:
            query = base_query
        
        # Add ordering and limit
        query += " ORDER BY sw.updated_at DESC"
        
        if search_params.get("limit"):
            query += " LIMIT ?"
            params.append(search_params["limit"])
        
        # Execute optimized query
        results = []
        with self.optimized_query(query, tuple(params)) as cursor:
            columns = [desc[0] for desc in cursor.description]
            for row in cursor.fetchall():
                result = dict(zip(columns, row))
                # Parse JSON fields
                if result.get("threat_keywords"):
                    result["threat_keywords"] = json.loads(result["threat_keywords"])
                if result.get("owasp_keywords"):
                    result["owasp_keywords"] = json.loads(result["owasp_keywords"])
                if result.get("security_tags"):
                    result["security_tags"] = json.loads(result["security_tags"])
                results.append(result)
        
        return results
    
    def get_security_analytics_data(self, time_range: Optional[Tuple[datetime, datetime]] = None) -> Dict[str, Any]:
        """Get optimized security analytics data"""
        if not time_range:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
            time_range = (start_date, end_date)
        
        analytics_data = {}
        
        # Wiki count by repository
        query = """
            SELECT repo_id, COUNT(*) as wiki_count
            FROM security_wikis 
            WHERE created_at BETWEEN ? AND ?
            GROUP BY repo_id
            ORDER BY wiki_count DESC
        """
        
        with self.optimized_query(query, (time_range[0].isoformat(), time_range[1].isoformat())) as cursor:
            analytics_data["wiki_counts"] = [
                {"repo_id": row[0], "count": row[1]} 
                for row in cursor.fetchall()
            ]
        
        # Security pattern distribution
        query = """
            SELECT si.patterns, COUNT(*) as pattern_count
            FROM security_index si
            JOIN security_wikis sw ON si.wiki_id = sw.id
            WHERE sw.created_at BETWEEN ? AND ?
            GROUP BY si.patterns
        """
        
        pattern_distribution = {}
        with self.optimized_query(query, (time_range[0].isoformat(), time_range[1].isoformat())) as cursor:
            for patterns_json, count in cursor.fetchall():
                if patterns_json:
                    patterns = json.loads(patterns_json)
                    for pattern in patterns:
                        pattern_name = pattern.get("pattern_name", "unknown")
                        pattern_distribution[pattern_name] = pattern_distribution.get(pattern_name, 0) + count
        
        analytics_data["pattern_distribution"] = pattern_distribution
        
        # OWASP category coverage
        query = """
            SELECT si.owasp_keywords, COUNT(*) as coverage_count
            FROM security_index si
            JOIN security_wikis sw ON si.wiki_id = sw.id
            WHERE sw.created_at BETWEEN ? AND ?
            AND si.owasp_keywords IS NOT NULL
        """
        
        owasp_coverage = {}
        with self.optimized_query(query, (time_range[0].isoformat(), time_range[1].isoformat())) as cursor:
            for owasp_json, count in cursor.fetchall():
                if owasp_json:
                    keywords = json.loads(owasp_json)
                    for keyword in keywords:
                        owasp_coverage[keyword] = owasp_coverage.get(keyword, 0) + count
        
        analytics_data["owasp_coverage"] = owasp_coverage
        
        return analytics_data
    
    def optimize_database(self) -> Dict[str, Any]:
        """Perform comprehensive database optimization"""
        optimization_results = {
            "started_at": datetime.now().isoformat(),
            "operations": [],
            "performance_improvements": {},
            "recommendations": []
        }
        
        with self.connection_pool.get_connection() as conn:
            # Update table statistics
            conn.execute("ANALYZE")
            optimization_results["operations"].append("Updated table statistics")
            
            # Vacuum database to reclaim space and optimize
            conn.execute("VACUUM")
            optimization_results["operations"].append("Vacuumed database")
            
            # Rebuild indexes for optimal performance
            conn.execute("REINDEX")
            optimization_results["operations"].append("Rebuilt indexes")
        
        # Get performance recommendations
        slow_queries = self.query_optimizer.get_slow_queries()
        if slow_queries:
            optimization_results["recommendations"].extend([
                f"Optimize query type '{q['query_type']}' (avg: {q['avg_execution_time']:.3f}s)"
                for q in slow_queries[:5]  # Top 5 slow queries
            ])
        
        optimization_results["completed_at"] = datetime.now().isoformat()
        return optimization_results
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "connection_pool": {
                "pool_size": self.connection_pool.pool_size,
                "created_connections": self.connection_pool._created_connections
            },
            "query_performance": {},
            "slow_queries": self.query_optimizer.get_slow_queries(),
            "index_recommendations": []
        }
        
        # Aggregate query performance by type
        for query_hash, metrics_list in self.query_optimizer.query_metrics.items():
            query_type = metrics_list[0].query_type
            if query_type not in report["query_performance"]:
                report["query_performance"][query_type] = {
                    "count": 0,
                    "total_time": 0.0,
                    "avg_time": 0.0,
                    "max_time": 0.0
                }
            
            type_metrics = report["query_performance"][query_type]
            type_metrics["count"] += len(metrics_list)
            type_metrics["total_time"] += sum(m.execution_time for m in metrics_list)
            type_metrics["max_time"] = max(type_metrics["max_time"], 
                                         max(m.execution_time for m in metrics_list))
        
        # Calculate averages
        for query_type in report["query_performance"]:
            metrics = report["query_performance"][query_type]
            if metrics["count"] > 0:
                metrics["avg_time"] = metrics["total_time"] / metrics["count"]
        
        return report
    
    def close(self):
        """Close all database connections"""
        self.connection_pool.close_all()

# Global optimizer instance
db_optimizer = SecurityDatabaseOptimizer("data/threatlens.db")