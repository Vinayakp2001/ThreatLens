"""
Performance Optimization Integration Module

This module integrates database optimization, intelligent caching, background processing,
and lazy loading/pagination for comprehensive security data performance optimization.
"""

import asyncio
import threading
import logging
from typing import Dict, List, Optional, Any, Callable, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, Future
from queue import Queue, PriorityQueue
import time
import json

from api.database_performance import SecurityDatabaseOptimizer, db_optimizer
from api.intelligent_cache import SecurityDataCache, security_cache

logger = logging.getLogger(__name__)

@dataclass
class BackgroundTask:
    """Background processing task"""
    task_id: str
    task_type: str
    priority: int  # Lower number = higher priority
    payload: Dict[str, Any]
    created_at: datetime
    retry_count: int = 0
    max_retries: int = 3

@dataclass
class PaginationConfig:
    """Configuration for pagination"""
    page_size: int = 50
    max_page_size: int = 1000
    default_page: int = 1

@dataclass
class LazyLoadConfig:
    """Configuration for lazy loading"""
    batch_size: int = 20
    prefetch_threshold: float = 0.8  # Load next batch when 80% through current
    max_concurrent_loads: int = 3

class BackgroundProcessor:
    """Background task processing system for intensive security operations"""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.task_queue = PriorityQueue()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_tasks: Dict[str, Future] = {}
        self.task_results: Dict[str, Any] = {}
        self.running = False
        self._worker_thread = None
        
        # Task handlers
        self.task_handlers: Dict[str, Callable] = {
            "security_analysis": self._handle_security_analysis,
            "wiki_indexing": self._handle_wiki_indexing,
            "pattern_recognition": self._handle_pattern_recognition,
            "analytics_computation": self._handle_analytics_computation,
            "cache_warming": self._handle_cache_warming
        }
    
    def start(self):
        """Start background processing"""
        if self.running:
            return
        
        self.running = True
        self._worker_thread = threading.Thread(target=self._process_tasks, daemon=True)
        self._worker_thread.start()
        logger.info("Background processor started")
    
    def stop(self):
        """Stop background processing"""
        self.running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5.0)
        self.executor.shutdown(wait=True)
        logger.info("Background processor stopped")
    
    def submit_task(self, task: BackgroundTask) -> str:
        """Submit task for background processing"""
        # Add to queue with priority
        self.task_queue.put((task.priority, task.created_at, task))
        logger.info(f"Submitted background task: {task.task_id} ({task.task_type})")
        return task.task_id
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get status of background task"""
        if task_id in self.active_tasks:
            future = self.active_tasks[task_id]
            return {
                "task_id": task_id,
                "status": "running" if not future.done() else "completed",
                "result": self.task_results.get(task_id)
            }
        elif task_id in self.task_results:
            return {
                "task_id": task_id,
                "status": "completed",
                "result": self.task_results[task_id]
            }
        else:
            return {
                "task_id": task_id,
                "status": "not_found",
                "result": None
            }
    
    def _process_tasks(self):
        """Main task processing loop"""
        while self.running:
            try:
                # Get next task (blocks for up to 1 second)
                try:
                    priority, created_at, task = self.task_queue.get(timeout=1.0)
                except:
                    continue
                
                # Submit to executor
                if task.task_type in self.task_handlers:
                    handler = self.task_handlers[task.task_type]
                    future = self.executor.submit(self._execute_task, task, handler)
                    self.active_tasks[task.task_id] = future
                else:
                    logger.error(f"No handler for task type: {task.task_type}")
                
                # Clean up completed tasks
                self._cleanup_completed_tasks()
                
            except Exception as e:
                logger.error(f"Error in task processing loop: {e}")
    
    def _execute_task(self, task: BackgroundTask, handler: Callable) -> Any:
        """Execute individual task with error handling"""
        try:
            logger.info(f"Executing task: {task.task_id}")
            result = handler(task.payload)
            self.task_results[task.task_id] = {
                "success": True,
                "result": result,
                "completed_at": datetime.now().isoformat()
            }
            return result
            
        except Exception as e:
            logger.error(f"Task {task.task_id} failed: {e}")
            
            # Retry logic
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                # Re-queue with lower priority
                self.task_queue.put((task.priority + 10, datetime.now(), task))
                logger.info(f"Retrying task {task.task_id} (attempt {task.retry_count})")
            else:
                self.task_results[task.task_id] = {
                    "success": False,
                    "error": str(e),
                    "completed_at": datetime.now().isoformat()
                }
    
    def _cleanup_completed_tasks(self):
        """Clean up completed tasks from active list"""
        completed_tasks = [
            task_id for task_id, future in self.active_tasks.items()
            if future.done()
        ]
        
        for task_id in completed_tasks:
            del self.active_tasks[task_id]
    
    # Task handlers
    def _handle_security_analysis(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle security analysis task"""
        repo_id = payload.get("repo_id")
        analysis_type = payload.get("analysis_type", "full")
        
        # Simulate intensive security analysis
        time.sleep(2)  # Placeholder for actual analysis
        
        return {
            "repo_id": repo_id,
            "analysis_type": analysis_type,
            "threats_found": 5,
            "mitigations_suggested": 8,
            "owasp_compliance": 0.85
        }
    
    def _handle_wiki_indexing(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle wiki indexing task"""
        wiki_id = payload.get("wiki_id")
        
        # Simulate indexing process
        time.sleep(1)
        
        return {
            "wiki_id": wiki_id,
            "indexed_sections": 12,
            "keywords_extracted": 45,
            "patterns_identified": 7
        }
    
    def _handle_pattern_recognition(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle security pattern recognition task"""
        content = payload.get("content", "")
        
        # Simulate pattern recognition
        time.sleep(1.5)
        
        return {
            "patterns_found": 3,
            "confidence_scores": [0.85, 0.72, 0.91],
            "owasp_mappings": ["A1", "A3", "A6"]
        }
    
    def _handle_analytics_computation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle analytics computation task"""
        analytics_type = payload.get("type")
        time_range = payload.get("time_range")
        
        # Simulate analytics computation
        time.sleep(3)
        
        return {
            "analytics_type": analytics_type,
            "time_range": time_range,
            "metrics_computed": 15,
            "trends_identified": 4
        }
    
    def _handle_cache_warming(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle cache warming task"""
        cache_type = payload.get("cache_type")
        keys = payload.get("keys", [])
        
        # Warm specified cache entries
        warmed_count = 0
        for key in keys:
            # Simulate cache warming
            time.sleep(0.1)
            warmed_count += 1
        
        return {
            "cache_type": cache_type,
            "keys_warmed": warmed_count
        }

class LazyLoader:
    """Lazy loading system for large security datasets"""
    
    def __init__(self, config: LazyLoadConfig = None):
        self.config = config or LazyLoadConfig()
        self.loaded_batches: Dict[str, List[Any]] = {}
        self.loading_futures: Dict[str, Future] = {}
        self.executor = ThreadPoolExecutor(max_workers=self.config.max_concurrent_loads)
    
    def load_batch(self, 
                   dataset_id: str, 
                   batch_index: int, 
                   loader_func: Callable[[int, int], List[Any]]) -> List[Any]:
        """Load a batch of data lazily"""
        batch_key = f"{dataset_id}:{batch_index}"
        
        # Return if already loaded
        if batch_key in self.loaded_batches:
            return self.loaded_batches[batch_key]
        
        # Check if currently loading
        if batch_key in self.loading_futures:
            future = self.loading_futures[batch_key]
            if future.done():
                result = future.result()
                self.loaded_batches[batch_key] = result
                del self.loading_futures[batch_key]
                return result
            else:
                # Still loading, return empty for now
                return []
        
        # Start loading
        offset = batch_index * self.config.batch_size
        future = self.executor.submit(loader_func, offset, self.config.batch_size)
        self.loading_futures[batch_key] = future
        
        return []
    
    def prefetch_next_batch(self, 
                           dataset_id: str, 
                           current_batch: int, 
                           loader_func: Callable[[int, int], List[Any]]):
        """Prefetch next batch for better performance"""
        next_batch = current_batch + 1
        batch_key = f"{dataset_id}:{next_batch}"
        
        if batch_key not in self.loaded_batches and batch_key not in self.loading_futures:
            offset = next_batch * self.config.batch_size
            future = self.executor.submit(loader_func, offset, self.config.batch_size)
            self.loading_futures[batch_key] = future
    
    def get_loading_status(self, dataset_id: str) -> Dict[str, Any]:
        """Get loading status for dataset"""
        loaded_count = len([k for k in self.loaded_batches.keys() if k.startswith(f"{dataset_id}:")])
        loading_count = len([k for k in self.loading_futures.keys() if k.startswith(f"{dataset_id}:")])
        
        return {
            "dataset_id": dataset_id,
            "loaded_batches": loaded_count,
            "loading_batches": loading_count
        }

class PaginationManager:
    """Advanced pagination system for security data"""
    
    def __init__(self, config: PaginationConfig = None):
        self.config = config or PaginationConfig()
    
    def paginate_query_results(self, 
                              query_func: Callable[[int, int], Tuple[List[Any], int]], 
                              page: int = 1, 
                              page_size: Optional[int] = None) -> Dict[str, Any]:
        """Paginate query results with metadata"""
        # Validate and normalize parameters
        page = max(1, page)
        page_size = min(
            page_size or self.config.page_size,
            self.config.max_page_size
        )
        
        offset = (page - 1) * page_size
        
        # Execute query
        results, total_count = query_func(offset, page_size)
        
        # Calculate pagination metadata
        total_pages = (total_count + page_size - 1) // page_size
        has_next = page < total_pages
        has_prev = page > 1
        
        return {
            "data": results,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_count": total_count,
                "total_pages": total_pages,
                "has_next": has_next,
                "has_prev": has_prev,
                "next_page": page + 1 if has_next else None,
                "prev_page": page - 1 if has_prev else None
            }
        }
    
    def create_cursor_pagination(self, 
                               results: List[Dict], 
                               cursor_field: str = "id",
                               page_size: Optional[int] = None) -> Dict[str, Any]:
        """Create cursor-based pagination for large datasets"""
        page_size = page_size or self.config.page_size
        
        has_more = len(results) > page_size
        if has_more:
            results = results[:page_size]
        
        next_cursor = None
        if has_more and results:
            next_cursor = results[-1].get(cursor_field)
        
        return {
            "data": results,
            "pagination": {
                "page_size": page_size,
                "has_more": has_more,
                "next_cursor": next_cursor
            }
        }

class PerformanceOptimizationManager:
    """Main performance optimization coordinator"""
    
    def __init__(self):
        self.db_optimizer = db_optimizer
        self.cache = security_cache
        self.background_processor = BackgroundProcessor()
        self.lazy_loader = LazyLoader()
        self.pagination_manager = PaginationManager()
        
        # Start background processing
        self.background_processor.start()
    
    def optimize_security_search(self, search_params: Dict[str, Any]) -> Dict[str, Any]:
        """Perform optimized security search with caching and pagination"""
        # Check cache first
        cached_results = self.cache.get_search_results(search_params)
        if cached_results is not None:
            logger.info("Returning cached search results")
            return self._paginate_cached_results(cached_results, search_params)
        
        # Execute optimized database search
        results = self.db_optimizer.execute_optimized_search(search_params)
        
        # Cache results
        self.cache.set_search_results(search_params, results)
        
        # Apply pagination
        return self._paginate_cached_results(results, search_params)
    
    def _paginate_cached_results(self, results: List[Dict], search_params: Dict[str, Any]) -> Dict[str, Any]:
        """Apply pagination to cached results"""
        page = search_params.get("page", 1)
        page_size = search_params.get("page_size", 50)
        
        def query_func(offset: int, limit: int) -> Tuple[List[Any], int]:
            return results[offset:offset + limit], len(results)
        
        return self.pagination_manager.paginate_query_results(query_func, page, page_size)
    
    def get_analytics_data_optimized(self, analytics_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get analytics data with caching and background computation"""
        # Check cache
        cached_data = self.cache.get_analytics_data(analytics_type, params)
        if cached_data is not None:
            return cached_data
        
        # Check if computation is in progress
        task_id = f"analytics_{analytics_type}_{hash(str(params))}"
        task_status = self.background_processor.get_task_status(task_id)
        
        if task_status["status"] == "completed":
            result = task_status["result"]["result"]
            self.cache.set_analytics_data(analytics_type, params, result)
            return result
        elif task_status["status"] == "running":
            return {"status": "computing", "message": "Analytics computation in progress"}
        else:
            # Submit background task
            task = BackgroundTask(
                task_id=task_id,
                task_type="analytics_computation",
                priority=5,
                payload={"type": analytics_type, **params},
                created_at=datetime.now()
            )
            self.background_processor.submit_task(task)
            return {"status": "submitted", "message": "Analytics computation started"}
    
    def warm_cache_for_repo(self, repo_id: str):
        """Warm cache for frequently accessed repository data"""
        task = BackgroundTask(
            task_id=f"cache_warm_{repo_id}_{int(time.time())}",
            task_type="cache_warming",
            priority=10,
            payload={
                "cache_type": "repo_data",
                "keys": [repo_id]
            },
            created_at=datetime.now()
        )
        self.background_processor.submit_task(task)
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics"""
        return {
            "timestamp": datetime.now().isoformat(),
            "database": self.db_optimizer.get_performance_report(),
            "cache": self.cache.get_cache_statistics(),
            "background_processor": {
                "active_tasks": len(self.background_processor.active_tasks),
                "completed_tasks": len(self.background_processor.task_results),
                "queue_size": self.background_processor.task_queue.qsize()
            }
        }
    
    def optimize_system_performance(self) -> Dict[str, Any]:
        """Perform comprehensive system optimization"""
        optimization_results = {
            "started_at": datetime.now().isoformat(),
            "operations": []
        }
        
        # Database optimization
        db_results = self.db_optimizer.optimize_database()
        optimization_results["operations"].extend(db_results["operations"])
        
        # Cache optimization (clear old entries)
        initial_stats = self.cache.get_cache_statistics()
        
        # Submit cache warming tasks for frequently accessed data
        self.warm_cache_for_repo("*")  # Warm all repos
        
        optimization_results["operations"].append("Initiated cache warming")
        optimization_results["completed_at"] = datetime.now().isoformat()
        
        return optimization_results
    
    def shutdown(self):
        """Shutdown performance optimization system"""
        self.background_processor.stop()
        self.lazy_loader.executor.shutdown(wait=True)

# Global performance manager
performance_manager = PerformanceOptimizationManager()