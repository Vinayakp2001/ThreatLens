# Performance Optimization Implementation

This document describes the comprehensive performance optimization system implemented for security data operations in the ThreatLens platform.

## Overview

The performance optimization system consists of four main components:

1. **Database Performance Optimization** (`database_performance.py`)
2. **Intelligent Caching System** (`intelligent_cache.py`)  
3. **Background Processing & Lazy Loading** (`performance_optimization.py`)
4. **Performance API Router** (`performance_router.py`)

## Components

### 1. Database Performance Optimization

**File**: `api/database_performance.py`

**Features**:
- Connection pooling for SQLite with optimized settings
- Query performance tracking and analysis
- Automatic index recommendations
- Optimized indexes for security data operations
- Query execution monitoring with slow query detection

**Key Classes**:
- `ConnectionPool`: Thread-safe SQLite connection pool
- `QueryOptimizer`: Query analysis and optimization recommendations
- `SecurityDatabaseOptimizer`: Main optimization service

**Optimizations Applied**:
- WAL mode for better concurrency
- Optimized cache sizes (64MB)
- Memory-mapped I/O (256MB)
- Specialized indexes for security queries

### 2. Intelligent Caching System

**File**: `api/intelligent_cache.py`

**Features**:
- Multi-layer caching (memory + disk)
- Intelligent cache invalidation strategies
- Tag-based cache management
- LRU eviction policies
- Cache warming capabilities

**Key Classes**:
- `MemoryCache`: High-performance in-memory cache
- `DiskCache`: Persistent disk-based cache
- `SecurityDataCache`: Unified cache interface for security data

**Cache Types**:
- Wiki data caching (1 hour TTL)
- Search results caching (30 minutes TTL)
- Analytics data caching (15 minutes TTL)
- Security patterns caching (2 hours TTL)
- OWASP mappings caching (24 hours TTL)

### 3. Background Processing & Lazy Loading

**File**: `api/performance_optimization.py`

**Features**:
- Background task processing for intensive operations
- Lazy loading for large datasets
- Advanced pagination with cursor support
- Performance metrics collection
- Integrated optimization management

**Key Classes**:
- `BackgroundProcessor`: Asynchronous task processing
- `LazyLoader`: Lazy loading for large datasets
- `PaginationManager`: Advanced pagination support
- `PerformanceOptimizationManager`: Main coordinator

**Background Tasks**:
- Security analysis processing
- Wiki indexing operations
- Pattern recognition analysis
- Analytics computation
- Cache warming operations

### 4. Performance API Router

**File**: `api/performance_router.py`

**Endpoints**:
- `GET /api/performance/metrics` - Get performance metrics
- `POST /api/performance/optimize` - Trigger system optimization
- `GET /api/performance/database/stats` - Database statistics
- `GET /api/performance/cache/stats` - Cache statistics
- `POST /api/performance/cache/clear` - Clear cache
- `GET /api/performance/search/optimized` - Optimized search
- `GET /api/performance/analytics/{type}` - Optimized analytics
- `GET /api/performance/health` - Performance health check

## Performance Improvements

### Database Optimizations

1. **Specialized Indexes**:
   ```sql
   -- Security wikis indexes
   CREATE INDEX idx_security_wikis_repo_title ON security_wikis(repo_id, title);
   CREATE INDEX idx_security_wikis_updated_desc ON security_wikis(updated_at DESC);
   
   -- Security search indexes
   CREATE INDEX idx_security_index_owasp_tags ON security_index(owasp_keywords, security_tags);
   ```

2. **Connection Pool Settings**:
   - WAL mode for better concurrency
   - 64MB cache size
   - 256MB memory-mapped I/O
   - Connection pooling (10 connections default)

### Caching Strategy

1. **Memory Cache**:
   - 100MB default size
   - LRU eviction policy
   - Sub-second access times

2. **Disk Cache**:
   - 1GB default size
   - Persistent across restarts
   - Automatic cleanup

3. **Cache Invalidation**:
   - Tag-based invalidation
   - Time-based expiration
   - Repository-specific invalidation

### Background Processing

1. **Task Types**:
   - Security analysis (priority 1-5)
   - Wiki indexing (priority 5-10)
   - Analytics computation (priority 10-15)

2. **Processing Features**:
   - Retry logic with exponential backoff
   - Task status tracking
   - Concurrent execution (4 workers default)

## Usage Examples

### Optimized Search

```python
from api.performance_optimization import performance_manager

# Perform optimized search with caching
results = performance_manager.optimize_security_search({
    "query": "SQL injection",
    "owasp_categories": ["Injection"],
    "page": 1,
    "page_size": 50
})
```

### Cache Management

```python
from api.intelligent_cache import security_cache

# Cache security wiki
security_cache.set_wiki(wiki_id, wiki_data)

# Get cached wiki
wiki_data = security_cache.get_wiki(wiki_id)

# Invalidate repository cache
security_cache.invalidate_repo_data(repo_id)
```

### Background Processing

```python
from api.performance_optimization import performance_manager

# Submit background task
task = BackgroundTask(
    task_id="analysis_123",
    task_type="security_analysis",
    priority=5,
    payload={"repo_id": "repo_123"},
    created_at=datetime.now()
)

task_id = performance_manager.background_processor.submit_task(task)
```

## Performance Metrics

The system tracks comprehensive performance metrics:

- **Database**: Query execution times, connection pool usage
- **Cache**: Hit ratios, eviction rates, memory usage
- **Background Tasks**: Queue sizes, completion rates, error rates
- **API**: Response times, throughput, error rates

## Configuration

Key configuration parameters:

```python
# Database optimization
CONNECTION_POOL_SIZE = 10
QUERY_TIMEOUT = 30.0
CACHE_SIZE_MB = 64

# Caching
MEMORY_CACHE_MB = 100
DISK_CACHE_MB = 1000
DEFAULT_TTL_SECONDS = 3600

# Background processing
MAX_WORKERS = 4
TASK_RETRY_COUNT = 3
QUEUE_SIZE_LIMIT = 1000
```

## Monitoring

Performance monitoring includes:

1. **Real-time Metrics**: Available via `/api/performance/metrics`
2. **Health Checks**: Available via `/api/performance/health`
3. **Slow Query Detection**: Automatic logging of queries > 100ms
4. **Cache Statistics**: Hit ratios, eviction rates, memory usage
5. **Background Task Status**: Queue sizes, completion rates

## Integration

The performance optimization system is automatically integrated into:

- Security search operations
- Wiki data retrieval
- Analytics computation
- Pattern recognition
- OWASP compliance checking

All existing API endpoints benefit from these optimizations without requiring changes to client code.