"""
Performance Optimization API Router

This module provides REST API endpoints for performance optimization features
including database optimization, caching, and background processing.
"""

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

from api.performance_optimization import performance_manager
from api.database_performance import db_optimizer
from api.intelligent_cache import security_cache

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/performance", tags=["performance"])

@router.get("/metrics")
async def get_performance_metrics() -> Dict[str, Any]:
    """Get comprehensive performance metrics"""
    try:
        return performance_manager.get_performance_metrics()
    except Exception as e:
        logger.error(f"Failed to get performance metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve performance metrics")

@router.post("/optimize")
async def optimize_system_performance(background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Trigger comprehensive system performance optimization"""
    try:
        # Run optimization in background
        background_tasks.add_task(performance_manager.optimize_system_performance)
        
        return {
            "message": "System optimization started",
            "status": "initiated",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to start system optimization: {e}")
        raise HTTPException(status_code=500, detail="Failed to start system optimization")

@router.get("/database/stats")
async def get_database_statistics() -> Dict[str, Any]:
    """Get database performance statistics"""
    try:
        return db_optimizer.get_performance_report()
    except Exception as e:
        logger.error(f"Failed to get database statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve database statistics")

@router.post("/database/optimize")
async def optimize_database() -> Dict[str, Any]:
    """Optimize database performance"""
    try:
        return db_optimizer.optimize_database()
    except Exception as e:
        logger.error(f"Failed to optimize database: {e}")
        raise HTTPException(status_code=500, detail="Database optimization failed")

@router.get("/cache/stats")
async def get_cache_statistics() -> Dict[str, Any]:
    """Get cache performance statistics"""
    try:
        return security_cache.get_cache_statistics()
    except Exception as e:
        logger.error(f"Failed to get cache statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve cache statistics")

@router.post("/cache/clear")
async def clear_cache(
    cache_type: Optional[str] = Query(None, description="Type of cache to clear (memory/disk/all)")
) -> Dict[str, Any]:
    """Clear cache entries"""
    try:
        if cache_type == "memory":
            security_cache.memory_cache.clear()
            message = "Memory cache cleared"
        elif cache_type == "disk":
            security_cache.disk_cache.clear()
            message = "Disk cache cleared"
        else:
            security_cache.clear_all_caches()
            message = "All caches cleared"
        
        return {
            "message": message,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to clear cache: {e}")
        raise HTTPException(status_code=500, detail="Failed to clear cache")

@router.post("/cache/invalidate/repo/{repo_id}")
async def invalidate_repo_cache(repo_id: str) -> Dict[str, Any]:
    """Invalidate cache for specific repository"""
    try:
        security_cache.invalidate_repo_data(repo_id)
        return {
            "message": f"Cache invalidated for repository: {repo_id}",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to invalidate repo cache: {e}")
        raise HTTPException(status_code=500, detail="Failed to invalidate repository cache")

@router.post("/cache/warm/repo/{repo_id}")
async def warm_repo_cache(repo_id: str, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Warm cache for specific repository"""
    try:
        background_tasks.add_task(performance_manager.warm_cache_for_repo, repo_id)
        return {
            "message": f"Cache warming initiated for repository: {repo_id}",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to warm repo cache: {e}")
        raise HTTPException(status_code=500, detail="Failed to warm repository cache")

@router.get("/search/optimized")
async def optimized_security_search(
    query: Optional[str] = Query(None, description="Search query"),
    repo_id: Optional[str] = Query(None, description="Repository ID filter"),
    owasp_categories: Optional[List[str]] = Query(None, description="OWASP categories filter"),
    security_tags: Optional[List[str]] = Query(None, description="Security tags filter"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=1000, description="Page size")
) -> Dict[str, Any]:
    """Perform optimized security content search"""
    try:
        search_params = {
            "query": query,
            "repo_id": repo_id,
            "owasp_categories": owasp_categories or [],
            "security_tags": security_tags or [],
            "page": page,
            "page_size": page_size
        }
        
        # Remove None values
        search_params = {k: v for k, v in search_params.items() if v is not None}
        
        return performance_manager.optimize_security_search(search_params)
    except Exception as e:
        logger.error(f"Optimized search failed: {e}")
        raise HTTPException(status_code=500, detail="Search optimization failed")

@router.get("/analytics/{analytics_type}")
async def get_optimized_analytics(
    analytics_type: str,
    repo_id: Optional[str] = Query(None, description="Repository ID filter"),
    time_range_days: int = Query(30, ge=1, le=365, description="Time range in days")
) -> Dict[str, Any]:
    """Get analytics data with optimization"""
    try:
        params = {
            "time_range_days": time_range_days
        }
        
        if repo_id:
            params["repo_id"] = repo_id
        
        return performance_manager.get_analytics_data_optimized(analytics_type, params)
    except Exception as e:
        logger.error(f"Optimized analytics failed: {e}")
        raise HTTPException(status_code=500, detail="Analytics optimization failed")

@router.get("/background-tasks")
async def get_background_task_status() -> Dict[str, Any]:
    """Get status of background tasks"""
    try:
        processor = performance_manager.background_processor
        
        return {
            "active_tasks": len(processor.active_tasks),
            "completed_tasks": len(processor.task_results),
            "queue_size": processor.task_queue.qsize(),
            "running": processor.running,
            "max_workers": processor.max_workers
        }
    except Exception as e:
        logger.error(f"Failed to get background task status: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve task status")

@router.get("/background-tasks/{task_id}")
async def get_task_status(task_id: str) -> Dict[str, Any]:
    """Get status of specific background task"""
    try:
        return performance_manager.background_processor.get_task_status(task_id)
    except Exception as e:
        logger.error(f"Failed to get task status: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve task status")

@router.get("/query-analysis")
async def analyze_slow_queries(
    threshold_ms: float = Query(100.0, ge=1.0, description="Threshold in milliseconds")
) -> Dict[str, Any]:
    """Analyze slow database queries"""
    try:
        slow_queries = db_optimizer.query_optimizer.get_slow_queries(threshold_ms)
        
        return {
            "threshold_ms": threshold_ms,
            "slow_queries": slow_queries,
            "total_slow_queries": len(slow_queries),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to analyze slow queries: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze queries")

@router.post("/query-analysis/{query_hash}")
async def analyze_specific_query(query_hash: str) -> Dict[str, Any]:
    """Analyze specific query for optimization opportunities"""
    try:
        # This would require storing the original query text
        # For now, return placeholder analysis
        return {
            "query_hash": query_hash,
            "analysis": "Query analysis not implemented for specific hash",
            "recommendations": [
                "Consider adding appropriate indexes",
                "Review WHERE clause conditions",
                "Check for unnecessary JOINs"
            ],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to analyze query: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze query")

@router.get("/health")
async def performance_health_check() -> Dict[str, Any]:
    """Health check for performance optimization components"""
    try:
        health_status = {
            "timestamp": datetime.now().isoformat(),
            "components": {}
        }
        
        # Check database optimizer
        try:
            db_stats = db_optimizer.get_performance_report()
            health_status["components"]["database"] = {
                "status": "healthy",
                "connection_pool_size": db_stats.get("connection_pool", {}).get("pool_size", 0)
            }
        except Exception as e:
            health_status["components"]["database"] = {
                "status": "unhealthy",
                "error": str(e)
            }
        
        # Check cache
        try:
            cache_stats = security_cache.get_cache_statistics()
            health_status["components"]["cache"] = {
                "status": "healthy",
                "memory_entries": cache_stats["memory_cache"]["entry_count"],
                "disk_entries": cache_stats["disk_cache"]["entry_count"]
            }
        except Exception as e:
            health_status["components"]["cache"] = {
                "status": "unhealthy",
                "error": str(e)
            }
        
        # Check background processor
        try:
            processor = performance_manager.background_processor
            health_status["components"]["background_processor"] = {
                "status": "healthy" if processor.running else "stopped",
                "active_tasks": len(processor.active_tasks),
                "queue_size": processor.task_queue.qsize()
            }
        except Exception as e:
            health_status["components"]["background_processor"] = {
                "status": "unhealthy",
                "error": str(e)
            }
        
        # Overall health
        all_healthy = all(
            comp.get("status") == "healthy" 
            for comp in health_status["components"].values()
        )
        health_status["overall_status"] = "healthy" if all_healthy else "degraded"
        
        return health_status
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail="Health check failed")