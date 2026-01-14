"""
Intelligent Caching System for Security Data Operations

This module provides multi-layer caching with intelligent invalidation strategies
for security data and analysis results to optimize performance.
"""

import json
import time
import threading
import hashlib
import logging
from typing import Dict, Any, Optional, List, Tuple, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import pickle
import os
from pathlib import Path

logger = logging.getLogger(__name__)

class CacheLevel(Enum):
    """Cache level enumeration"""
    MEMORY = "memory"
    DISK = "disk"
    DISTRIBUTED = "distributed"

@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    value: Any
    created_at: datetime
    expires_at: Optional[datetime]
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    size_bytes: int = 0
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.last_accessed is None:
            self.last_accessed = self.created_at

@dataclass
class CacheStats:
    """Cache performance statistics"""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_size_bytes: int = 0
    entry_count: int = 0
    
    @property
    def hit_ratio(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

class CacheInvalidationStrategy:
    """Base class for cache invalidation strategies"""
    
    def should_invalidate(self, entry: CacheEntry, context: Dict[str, Any]) -> bool:
        """Determine if cache entry should be invalidated"""
        raise NotImplementedError

class TimeBasedInvalidation(CacheInvalidationStrategy):
    """Time-based cache invalidation"""
    
    def should_invalidate(self, entry: CacheEntry, context: Dict[str, Any]) -> bool:
        if entry.expires_at and datetime.now() > entry.expires_at:
            return True
        return False

class TagBasedInvalidation(CacheInvalidationStrategy):
    """Tag-based cache invalidation for related data"""
    
    def __init__(self, invalidation_tags: List[str]):
        self.invalidation_tags = invalidation_tags
    
    def should_invalidate(self, entry: CacheEntry, context: Dict[str, Any]) -> bool:
        return any(tag in entry.tags for tag in self.invalidation_tags)

class LRUEvictionPolicy:
    """Least Recently Used eviction policy"""
    
    def select_for_eviction(self, entries: Dict[str, CacheEntry], target_count: int) -> List[str]:
        """Select entries for eviction based on LRU policy"""
        sorted_entries = sorted(
            entries.items(),
            key=lambda x: x[1].last_accessed or x[1].created_at
        )
        return [key for key, _ in sorted_entries[:target_count]]

class MemoryCache:
    """High-performance in-memory cache with intelligent eviction"""
    
    def __init__(self, max_size_mb: int = 100, max_entries: int = 10000):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_entries = max_entries
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        self._stats = CacheStats()
        self._eviction_policy = LRUEvictionPolicy()
        self._invalidation_strategies: List[CacheInvalidationStrategy] = [
            TimeBasedInvalidation()
        ]
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                self._stats.misses += 1
                return None
            
            # Check if entry should be invalidated
            if self._should_invalidate(entry):
                del self._cache[key]
                self._stats.misses += 1
                self._stats.evictions += 1
                return None
            
            # Update access statistics
            entry.access_count += 1
            entry.last_accessed = datetime.now()
            self._stats.hits += 1
            
            return entry.value
    
    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None, tags: Optional[List[str]] = None):
        """Set value in cache"""
        with self._lock:
            # Calculate size
            size_bytes = self._calculate_size(value)
            
            # Create cache entry
            expires_at = None
            if ttl_seconds:
                expires_at = datetime.now() + timedelta(seconds=ttl_seconds)
            
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=datetime.now(),
                expires_at=expires_at,
                size_bytes=size_bytes,
                tags=tags or []
            )
            
            # Check if we need to evict entries
            self._ensure_capacity(size_bytes)
            
            # Store entry
            old_entry = self._cache.get(key)
            self._cache[key] = entry
            
            # Update statistics
            if old_entry:
                self._stats.total_size_bytes -= old_entry.size_bytes
            else:
                self._stats.entry_count += 1
            
            self._stats.total_size_bytes += size_bytes
    
    def delete(self, key: str) -> bool:
        """Delete entry from cache"""
        with self._lock:
            entry = self._cache.pop(key, None)
            if entry:
                self._stats.total_size_bytes -= entry.size_bytes
                self._stats.entry_count -= 1
                return True
            return False
    
    def invalidate_by_tags(self, tags: List[str]):
        """Invalidate all entries with specified tags"""
        with self._lock:
            keys_to_remove = []
            for key, entry in self._cache.items():
                if any(tag in entry.tags for tag in tags):
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                self.delete(key)
    
    def clear(self):
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            self._stats = CacheStats()
    
    def _should_invalidate(self, entry: CacheEntry) -> bool:
        """Check if entry should be invalidated"""
        context = {"current_time": datetime.now()}
        return any(
            strategy.should_invalidate(entry, context)
            for strategy in self._invalidation_strategies
        )
    
    def _calculate_size(self, value: Any) -> int:
        """Calculate approximate size of value in bytes"""
        try:
            return len(pickle.dumps(value))
        except:
            # Fallback estimation
            if isinstance(value, str):
                return len(value.encode('utf-8'))
            elif isinstance(value, (list, dict)):
                return len(str(value).encode('utf-8'))
            else:
                return 1024  # Default estimate
    
    def _ensure_capacity(self, new_entry_size: int):
        """Ensure cache has capacity for new entry"""
        # Check size limit
        if self._stats.total_size_bytes + new_entry_size > self.max_size_bytes:
            self._evict_by_size(new_entry_size)
        
        # Check entry count limit
        if self._stats.entry_count >= self.max_entries:
            self._evict_by_count(1)
    
    def _evict_by_size(self, required_bytes: int):
        """Evict entries to free up required bytes"""
        bytes_to_free = required_bytes + (self.max_size_bytes - self._stats.total_size_bytes)
        if bytes_to_free <= 0:
            return
        
        # Sort by LRU and evict until we have enough space
        sorted_entries = sorted(
            self._cache.items(),
            key=lambda x: x[1].last_accessed or x[1].created_at
        )
        
        freed_bytes = 0
        for key, entry in sorted_entries:
            if freed_bytes >= bytes_to_free:
                break
            
            freed_bytes += entry.size_bytes
            del self._cache[key]
            self._stats.entry_count -= 1
            self._stats.total_size_bytes -= entry.size_bytes
            self._stats.evictions += 1
    
    def _evict_by_count(self, count: int):
        """Evict specified number of entries"""
        keys_to_evict = self._eviction_policy.select_for_eviction(self._cache, count)
        for key in keys_to_evict:
            self.delete(key)
            self._stats.evictions += 1
    
    def get_stats(self) -> CacheStats:
        """Get cache statistics"""
        with self._lock:
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                total_size_bytes=self._stats.total_size_bytes,
                entry_count=self._stats.entry_count
            )

class DiskCache:
    """Persistent disk-based cache for larger data"""
    
    def __init__(self, cache_dir: str = "storage/cache", max_size_mb: int = 1000):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._metadata_file = self.cache_dir / "metadata.json"
        self._metadata: Dict[str, Dict] = self._load_metadata()
        self._lock = threading.RLock()
    
    def _load_metadata(self) -> Dict[str, Dict]:
        """Load cache metadata from disk"""
        if self._metadata_file.exists():
            try:
                with open(self._metadata_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load cache metadata: {e}")
        return {}
    
    def _save_metadata(self):
        """Save cache metadata to disk"""
        try:
            with open(self._metadata_file, 'w') as f:
                json.dump(self._metadata, f, default=str)
        except Exception as e:
            logger.error(f"Failed to save cache metadata: {e}")
    
    def _get_file_path(self, key: str) -> Path:
        """Get file path for cache key"""
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.cache"
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from disk cache"""
        with self._lock:
            if key not in self._metadata:
                return None
            
            metadata = self._metadata[key]
            
            # Check expiration
            if metadata.get('expires_at'):
                expires_at = datetime.fromisoformat(metadata['expires_at'])
                if datetime.now() > expires_at:
                    self.delete(key)
                    return None
            
            # Load from disk
            file_path = self._get_file_path(key)
            if not file_path.exists():
                # Metadata exists but file doesn't - clean up
                del self._metadata[key]
                self._save_metadata()
                return None
            
            try:
                with open(file_path, 'rb') as f:
                    value = pickle.load(f)
                
                # Update access time
                metadata['last_accessed'] = datetime.now().isoformat()
                metadata['access_count'] = metadata.get('access_count', 0) + 1
                self._save_metadata()
                
                return value
                
            except Exception as e:
                logger.error(f"Failed to load cache entry {key}: {e}")
                self.delete(key)
                return None
    
    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None, tags: Optional[List[str]] = None):
        """Set value in disk cache"""
        with self._lock:
            file_path = self._get_file_path(key)
            
            try:
                # Save to disk
                with open(file_path, 'wb') as f:
                    pickle.dump(value, f)
                
                # Update metadata
                expires_at = None
                if ttl_seconds:
                    expires_at = (datetime.now() + timedelta(seconds=ttl_seconds)).isoformat()
                
                self._metadata[key] = {
                    'created_at': datetime.now().isoformat(),
                    'expires_at': expires_at,
                    'last_accessed': datetime.now().isoformat(),
                    'access_count': 0,
                    'size_bytes': file_path.stat().st_size,
                    'tags': tags or []
                }
                
                self._save_metadata()
                self._ensure_capacity()
                
            except Exception as e:
                logger.error(f"Failed to save cache entry {key}: {e}")
                if file_path.exists():
                    file_path.unlink()
    
    def delete(self, key: str) -> bool:
        """Delete entry from disk cache"""
        with self._lock:
            if key not in self._metadata:
                return False
            
            file_path = self._get_file_path(key)
            if file_path.exists():
                file_path.unlink()
            
            del self._metadata[key]
            self._save_metadata()
            return True
    
    def invalidate_by_tags(self, tags: List[str]):
        """Invalidate all entries with specified tags"""
        with self._lock:
            keys_to_remove = []
            for key, metadata in self._metadata.items():
                entry_tags = metadata.get('tags', [])
                if any(tag in entry_tags for tag in tags):
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                self.delete(key)
    
    def _ensure_capacity(self):
        """Ensure disk cache doesn't exceed size limit"""
        total_size = sum(
            metadata.get('size_bytes', 0)
            for metadata in self._metadata.values()
        )
        
        if total_size <= self.max_size_bytes:
            return
        
        # Sort by last accessed time and remove oldest
        sorted_entries = sorted(
            self._metadata.items(),
            key=lambda x: x[1].get('last_accessed', x[1]['created_at'])
        )
        
        for key, metadata in sorted_entries:
            if total_size <= self.max_size_bytes:
                break
            
            total_size -= metadata.get('size_bytes', 0)
            self.delete(key)
    
    def clear(self):
        """Clear all cache entries"""
        with self._lock:
            for key in list(self._metadata.keys()):
                self.delete(key)

class SecurityDataCache:
    """Intelligent multi-layer cache for security data operations"""
    
    def __init__(self, 
                 memory_cache_mb: int = 100,
                 disk_cache_mb: int = 1000,
                 cache_dir: str = "storage/cache"):
        
        self.memory_cache = MemoryCache(max_size_mb=memory_cache_mb)
        self.disk_cache = DiskCache(cache_dir=cache_dir, max_size_mb=disk_cache_mb)
        
        # Cache key prefixes for different data types
        self.key_prefixes = {
            "wiki": "wiki:",
            "search": "search:",
            "analytics": "analytics:",
            "patterns": "patterns:",
            "owasp": "owasp:",
            "metrics": "metrics:"
        }
        
        # Default TTL values for different data types (in seconds)
        self.default_ttls = {
            "wiki": 3600,      # 1 hour
            "search": 1800,    # 30 minutes
            "analytics": 900,  # 15 minutes
            "patterns": 7200,  # 2 hours
            "owasp": 86400,    # 24 hours
            "metrics": 300     # 5 minutes
        }
    
    def _make_key(self, data_type: str, identifier: str) -> str:
        """Create cache key with proper prefix"""
        prefix = self.key_prefixes.get(data_type, "")
        return f"{prefix}{identifier}"
    
    def _hash_params(self, params: Dict[str, Any]) -> str:
        """Create hash from parameters for cache key"""
        param_str = json.dumps(params, sort_keys=True, default=str)
        return hashlib.md5(param_str.encode()).hexdigest()[:16]
    
    def get_wiki(self, wiki_id: str) -> Optional[Dict[str, Any]]:
        """Get cached security wiki"""
        key = self._make_key("wiki", wiki_id)
        
        # Try memory cache first
        value = self.memory_cache.get(key)
        if value is not None:
            return value
        
        # Try disk cache
        value = self.disk_cache.get(key)
        if value is not None:
            # Promote to memory cache
            self.memory_cache.set(key, value, ttl_seconds=self.default_ttls["wiki"], 
                                tags=["wiki", f"repo:{wiki_id}"])
            return value
        
        return None
    
    def set_wiki(self, wiki_id: str, wiki_data: Dict[str, Any]):
        """Cache security wiki data"""
        key = self._make_key("wiki", wiki_id)
        tags = ["wiki", f"repo:{wiki_data.get('repo_id', '')}"]
        
        # Store in both caches
        self.memory_cache.set(key, wiki_data, ttl_seconds=self.default_ttls["wiki"], tags=tags)
        self.disk_cache.set(key, wiki_data, ttl_seconds=self.default_ttls["wiki"] * 24, tags=tags)
    
    def get_search_results(self, search_params: Dict[str, Any]) -> Optional[List[Dict]]:
        """Get cached search results"""
        param_hash = self._hash_params(search_params)
        key = self._make_key("search", param_hash)
        
        return self.memory_cache.get(key)
    
    def set_search_results(self, search_params: Dict[str, Any], results: List[Dict]):
        """Cache search results"""
        param_hash = self._hash_params(search_params)
        key = self._make_key("search", param_hash)
        
        # Extract tags from search parameters
        tags = ["search"]
        if "repo_id" in search_params:
            tags.append(f"repo:{search_params['repo_id']}")
        if "owasp_categories" in search_params:
            tags.extend([f"owasp:{cat}" for cat in search_params["owasp_categories"]])
        
        self.memory_cache.set(key, results, ttl_seconds=self.default_ttls["search"], tags=tags)
    
    def get_analytics_data(self, analytics_type: str, params: Dict[str, Any]) -> Optional[Dict]:
        """Get cached analytics data"""
        param_hash = self._hash_params(params)
        key = self._make_key("analytics", f"{analytics_type}:{param_hash}")
        
        # Try memory first, then disk for analytics data
        value = self.memory_cache.get(key)
        if value is None:
            value = self.disk_cache.get(key)
            if value is not None:
                # Promote to memory
                self.memory_cache.set(key, value, ttl_seconds=self.default_ttls["analytics"])
        
        return value
    
    def set_analytics_data(self, analytics_type: str, params: Dict[str, Any], data: Dict):
        """Cache analytics data"""
        param_hash = self._hash_params(params)
        key = self._make_key("analytics", f"{analytics_type}:{param_hash}")
        
        tags = ["analytics", f"type:{analytics_type}"]
        if "repo_id" in params:
            tags.append(f"repo:{params['repo_id']}")
        
        # Store in both caches with different TTLs
        self.memory_cache.set(key, data, ttl_seconds=self.default_ttls["analytics"], tags=tags)
        self.disk_cache.set(key, data, ttl_seconds=self.default_ttls["analytics"] * 4, tags=tags)
    
    def get_security_patterns(self, pattern_type: str) -> Optional[List[Dict]]:
        """Get cached security patterns"""
        key = self._make_key("patterns", pattern_type)
        return self.memory_cache.get(key)
    
    def set_security_patterns(self, pattern_type: str, patterns: List[Dict]):
        """Cache security patterns"""
        key = self._make_key("patterns", pattern_type)
        tags = ["patterns", f"type:{pattern_type}"]
        
        self.memory_cache.set(key, patterns, ttl_seconds=self.default_ttls["patterns"], tags=tags)
        self.disk_cache.set(key, patterns, ttl_seconds=self.default_ttls["patterns"] * 12, tags=tags)
    
    def invalidate_repo_data(self, repo_id: str):
        """Invalidate all cached data for a repository"""
        tags = [f"repo:{repo_id}"]
        self.memory_cache.invalidate_by_tags(tags)
        self.disk_cache.invalidate_by_tags(tags)
    
    def invalidate_search_cache(self):
        """Invalidate all search results cache"""
        self.memory_cache.invalidate_by_tags(["search"])
    
    def invalidate_analytics_cache(self, analytics_type: Optional[str] = None):
        """Invalidate analytics cache"""
        if analytics_type:
            self.memory_cache.invalidate_by_tags([f"type:{analytics_type}"])
            self.disk_cache.invalidate_by_tags([f"type:{analytics_type}"])
        else:
            self.memory_cache.invalidate_by_tags(["analytics"])
            self.disk_cache.invalidate_by_tags(["analytics"])
    
    def warm_cache(self, data_loader: Callable[[str], Any], keys: List[str], data_type: str):
        """Warm cache with frequently accessed data"""
        for key in keys:
            cache_key = self._make_key(data_type, key)
            
            # Check if already cached
            if self.memory_cache.get(cache_key) is not None:
                continue
            
            try:
                # Load data and cache it
                data = data_loader(key)
                if data is not None:
                    ttl = self.default_ttls.get(data_type, 3600)
                    tags = [data_type]
                    
                    self.memory_cache.set(cache_key, data, ttl_seconds=ttl, tags=tags)
                    logger.info(f"Warmed cache for {data_type}:{key}")
                    
            except Exception as e:
                logger.error(f"Failed to warm cache for {data_type}:{key}: {e}")
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        memory_stats = self.memory_cache.get_stats()
        
        return {
            "memory_cache": {
                "hits": memory_stats.hits,
                "misses": memory_stats.misses,
                "hit_ratio": memory_stats.hit_ratio,
                "evictions": memory_stats.evictions,
                "entry_count": memory_stats.entry_count,
                "size_mb": memory_stats.total_size_bytes / 1024 / 1024
            },
            "disk_cache": {
                "entry_count": len(self.disk_cache._metadata),
                "total_size_mb": sum(
                    meta.get('size_bytes', 0) 
                    for meta in self.disk_cache._metadata.values()
                ) / 1024 / 1024
            }
        }
    
    def clear_all_caches(self):
        """Clear all cache layers"""
        self.memory_cache.clear()
        self.disk_cache.clear()

# Global cache instance
security_cache = SecurityDataCache()