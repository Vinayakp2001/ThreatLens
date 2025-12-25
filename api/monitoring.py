"""
Monitoring and metrics collection system
"""
import time
import psutil
import logging
import threading
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from enum import Enum

from .config import settings

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class MetricPoint:
    """Individual metric data point"""
    name: str
    value: float
    metric_type: MetricType
    timestamp: datetime
    labels: Dict[str, str]
    unit: Optional[str] = None


@dataclass
class SystemMetrics:
    """System resource metrics"""
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_usage_percent: float
    disk_free_gb: float
    network_bytes_sent: int
    network_bytes_recv: int
    process_count: int
    thread_count: int
    file_descriptors: int


@dataclass
class ApplicationMetrics:
    """Application-specific metrics"""
    active_analyses: int
    queued_analyses: int
    total_repositories: int
    total_documents: int
    cache_hit_rate: float
    avg_response_time_ms: float
    error_rate: float
    llm_requests_total: int
    llm_requests_failed: int
    storage_usage_mb: float


class MetricsCollector:
    """Collects and stores application metrics"""
    
    def __init__(self, retention_hours: int = 24):
        self.retention_hours = retention_hours
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges: Dict[str, float] = defaultdict(float)
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.timers: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_metrics, daemon=True)
        self.cleanup_thread.start()
    
    def record_metric(self, name: str, value: float, metric_type: MetricType, 
                     labels: Optional[Dict[str, str]] = None, unit: Optional[str] = None):
        """Record a metric data point"""
        with self.lock:
            metric_point = MetricPoint(
                name=name,
                value=value,
                metric_type=metric_type,
                timestamp=datetime.now(),
                labels=labels or {},
                unit=unit
            )
            
            self.metrics[name].append(metric_point)
            
            # Update aggregated values
            if metric_type == MetricType.COUNTER:
                self.counters[name] += value
            elif metric_type == MetricType.GAUGE:
                self.gauges[name] = value
            elif metric_type == MetricType.HISTOGRAM:
                self.histograms[name].append(value)
                # Keep only recent values for histograms
                if len(self.histograms[name]) > 1000:
                    self.histograms[name] = self.histograms[name][-1000:]
            elif metric_type == MetricType.TIMER:
                self.timers[name].append(value)
                # Keep only recent values for timers
                if len(self.timers[name]) > 1000:
                    self.timers[name] = self.timers[name][-1000:]
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Increment a counter metric"""
        self.record_metric(name, value, MetricType.COUNTER, labels)
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None, unit: Optional[str] = None):
        """Set a gauge metric"""
        self.record_metric(name, value, MetricType.GAUGE, labels, unit)
    
    def record_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None, unit: Optional[str] = None):
        """Record a histogram value"""
        self.record_metric(name, value, MetricType.HISTOGRAM, labels, unit)
    
    def record_timer(self, name: str, duration_ms: float, labels: Optional[Dict[str, str]] = None):
        """Record a timer value"""
        self.record_metric(name, duration_ms, MetricType.TIMER, labels, "ms")
    
    def get_counter(self, name: str) -> float:
        """Get current counter value"""
        return self.counters.get(name, 0.0)
    
    def get_gauge(self, name: str) -> float:
        """Get current gauge value"""
        return self.gauges.get(name, 0.0)
    
    def get_histogram_stats(self, name: str) -> Dict[str, float]:
        """Get histogram statistics"""
        values = self.histograms.get(name, [])
        if not values:
            return {"count": 0, "min": 0, "max": 0, "mean": 0, "p50": 0, "p95": 0, "p99": 0}
        
        sorted_values = sorted(values)
        count = len(sorted_values)
        
        return {
            "count": count,
            "min": sorted_values[0],
            "max": sorted_values[-1],
            "mean": sum(sorted_values) / count,
            "p50": sorted_values[int(count * 0.5)],
            "p95": sorted_values[int(count * 0.95)],
            "p99": sorted_values[int(count * 0.99)]
        }
    
    def get_timer_stats(self, name: str) -> Dict[str, float]:
        """Get timer statistics"""
        return self.get_histogram_stats(name)  # Same calculation
    
    def get_recent_metrics(self, name: str, minutes: int = 60) -> List[MetricPoint]:
        """Get recent metrics for a specific name"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        
        with self.lock:
            recent_metrics = []
            for metric in self.metrics.get(name, []):
                if metric.timestamp >= cutoff_time:
                    recent_metrics.append(metric)
            
            return recent_metrics
    
    def get_all_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all metrics"""
        with self.lock:
            summary = {
                "timestamp": datetime.now().isoformat(),
                "counters": dict(self.counters),
                "gauges": dict(self.gauges),
                "histograms": {name: self.get_histogram_stats(name) for name in self.histograms},
                "timers": {name: self.get_timer_stats(name) for name in self.timers},
                "total_metrics": sum(len(deque_obj) for deque_obj in self.metrics.values())
            }
            
            return summary
    
    def _cleanup_old_metrics(self):
        """Clean up old metrics periodically"""
        while True:
            try:
                cutoff_time = datetime.now() - timedelta(hours=self.retention_hours)
                
                with self.lock:
                    for name, metric_deque in self.metrics.items():
                        # Remove old metrics
                        while metric_deque and metric_deque[0].timestamp < cutoff_time:
                            metric_deque.popleft()
                
                # Sleep for 1 hour before next cleanup
                time.sleep(3600)
                
            except Exception as e:
                logger.error(f"Error during metrics cleanup: {e}")
                time.sleep(300)  # Sleep 5 minutes on error


class SystemMonitor:
    """Monitors system resources and performance"""
    
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics_collector = metrics_collector
        self.process = psutil.Process()
        self.monitoring_active = False
        self.monitor_thread = None
    
    def start_monitoring(self, interval_seconds: int = 60):
        """Start system monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop, 
            args=(interval_seconds,), 
            daemon=True
        )
        self.monitor_thread.start()
        logger.info(f"System monitoring started with {interval_seconds}s interval")
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("System monitoring stopped")
    
    def get_current_system_metrics(self) -> SystemMetrics:
        """Get current system metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network metrics
            network = psutil.net_io_counters()
            
            # Process metrics
            process_count = len(psutil.pids())
            
            # Current process metrics
            process_info = self.process.as_dict(['num_threads', 'num_fds'])
            
            return SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_used_mb=memory.used / 1024 / 1024,
                memory_available_mb=memory.available / 1024 / 1024,
                disk_usage_percent=disk.percent,
                disk_free_gb=disk.free / 1024 / 1024 / 1024,
                network_bytes_sent=network.bytes_sent,
                network_bytes_recv=network.bytes_recv,
                process_count=process_count,
                thread_count=process_info.get('num_threads', 0),
                file_descriptors=process_info.get('num_fds', 0)
            )
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return SystemMetrics(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    def _monitor_loop(self, interval_seconds: int):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                metrics = self.get_current_system_metrics()
                
                # Record system metrics
                self.metrics_collector.set_gauge("system.cpu_percent", metrics.cpu_percent, unit="%")
                self.metrics_collector.set_gauge("system.memory_percent", metrics.memory_percent, unit="%")
                self.metrics_collector.set_gauge("system.memory_used_mb", metrics.memory_used_mb, unit="MB")
                self.metrics_collector.set_gauge("system.disk_usage_percent", metrics.disk_usage_percent, unit="%")
                self.metrics_collector.set_gauge("system.disk_free_gb", metrics.disk_free_gb, unit="GB")
                self.metrics_collector.set_gauge("system.process_count", metrics.process_count)
                self.metrics_collector.set_gauge("system.thread_count", metrics.thread_count)
                
                time.sleep(interval_seconds)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Sleep 1 minute on error


class ApplicationMonitor:
    """Monitors application-specific metrics"""
    
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics_collector = metrics_collector
        self.request_times = deque(maxlen=1000)
        self.error_count = 0
        self.request_count = 0
        self.start_time = time.time()
    
    def record_request(self, duration_ms: float, status_code: int, endpoint: str):
        """Record API request metrics"""
        self.request_count += 1
        self.request_times.append(duration_ms)
        
        # Record metrics
        self.metrics_collector.increment_counter("api.requests_total", labels={"endpoint": endpoint})
        self.metrics_collector.record_timer("api.request_duration", duration_ms, labels={"endpoint": endpoint})
        
        if status_code >= 400:
            self.error_count += 1
            self.metrics_collector.increment_counter("api.errors_total", labels={"status_code": str(status_code)})
    
    def record_analysis_started(self, repo_id: str):
        """Record analysis start"""
        self.metrics_collector.increment_counter("analysis.started_total", labels={"repo_id": repo_id})
    
    def record_analysis_completed(self, repo_id: str, duration_seconds: float):
        """Record analysis completion"""
        self.metrics_collector.increment_counter("analysis.completed_total", labels={"repo_id": repo_id})
        self.metrics_collector.record_timer("analysis.duration", duration_seconds * 1000, labels={"repo_id": repo_id})
    
    def record_analysis_failed(self, repo_id: str, error_type: str):
        """Record analysis failure"""
        self.metrics_collector.increment_counter("analysis.failed_total", labels={"repo_id": repo_id, "error_type": error_type})
    
    def record_llm_request(self, provider: str, model: str, duration_ms: float, success: bool):
        """Record LLM request metrics"""
        labels = {"provider": provider, "model": model}
        
        self.metrics_collector.increment_counter("llm.requests_total", labels=labels)
        self.metrics_collector.record_timer("llm.request_duration", duration_ms, labels=labels)
        
        if not success:
            self.metrics_collector.increment_counter("llm.requests_failed", labels=labels)
    
    def record_storage_usage(self, storage_type: str, usage_mb: float):
        """Record storage usage"""
        self.metrics_collector.set_gauge("storage.usage_mb", usage_mb, labels={"type": storage_type}, unit="MB")
    
    def get_current_application_metrics(self) -> ApplicationMetrics:
        """Get current application metrics"""
        try:
            # Calculate averages
            avg_response_time = sum(self.request_times) / len(self.request_times) if self.request_times else 0
            error_rate = (self.error_count / self.request_count) if self.request_count > 0 else 0
            
            # Get values from metrics collector
            active_analyses = self.metrics_collector.get_gauge("analysis.active_count")
            queued_analyses = self.metrics_collector.get_gauge("analysis.queued_count")
            total_repositories = self.metrics_collector.get_gauge("database.repositories_count")
            total_documents = self.metrics_collector.get_gauge("database.documents_count")
            llm_requests_total = self.metrics_collector.get_counter("llm.requests_total")
            llm_requests_failed = self.metrics_collector.get_counter("llm.requests_failed")
            storage_usage = self.metrics_collector.get_gauge("storage.usage_mb")
            
            return ApplicationMetrics(
                active_analyses=int(active_analyses),
                queued_analyses=int(queued_analyses),
                total_repositories=int(total_repositories),
                total_documents=int(total_documents),
                cache_hit_rate=0.0,  # TODO: Implement cache hit rate tracking
                avg_response_time_ms=avg_response_time,
                error_rate=error_rate,
                llm_requests_total=int(llm_requests_total),
                llm_requests_failed=int(llm_requests_failed),
                storage_usage_mb=storage_usage
            )
            
        except Exception as e:
            logger.error(f"Error collecting application metrics: {e}")
            return ApplicationMetrics(0, 0, 0, 0, 0.0, 0.0, 0.0, 0, 0, 0.0)


class HealthChecker:
    """Performs health checks on system components"""
    
    def __init__(self):
        self.health_checks: Dict[str, Callable] = {}
        self.last_check_results: Dict[str, Dict[str, Any]] = {}
    
    def register_health_check(self, name: str, check_function: Callable):
        """Register a health check function"""
        self.health_checks[name] = check_function
    
    def run_health_check(self, name: str) -> Dict[str, Any]:
        """Run a specific health check"""
        if name not in self.health_checks:
            return {"status": "unknown", "error": f"Health check '{name}' not found"}
        
        try:
            start_time = time.time()
            result = self.health_checks[name]()
            duration = (time.time() - start_time) * 1000
            
            if isinstance(result, bool):
                result = {"status": "healthy" if result else "unhealthy"}
            elif not isinstance(result, dict):
                result = {"status": "healthy", "value": result}
            
            result["check_duration_ms"] = duration
            result["timestamp"] = datetime.now().isoformat()
            
            self.last_check_results[name] = result
            return result
            
        except Exception as e:
            error_result = {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
            self.last_check_results[name] = error_result
            return error_result
    
    def run_all_health_checks(self) -> Dict[str, Any]:
        """Run all registered health checks"""
        results = {}
        overall_healthy = True
        
        for name in self.health_checks:
            result = self.run_health_check(name)
            results[name] = result
            
            if result.get("status") != "healthy":
                overall_healthy = False
        
        return {
            "overall_status": "healthy" if overall_healthy else "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "checks": results
        }
    
    def get_last_results(self) -> Dict[str, Any]:
        """Get last health check results"""
        return self.last_check_results.copy()


class AlertManager:
    """Manages alerts based on metrics and health checks"""
    
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics_collector = metrics_collector
        self.alert_rules: List[Dict[str, Any]] = []
        self.active_alerts: Dict[str, Dict[str, Any]] = {}
        self.alert_callbacks: List[Callable] = []
    
    def add_alert_rule(self, name: str, condition: Callable, threshold: float, 
                      severity: str = "warning", description: str = ""):
        """Add an alert rule"""
        rule = {
            "name": name,
            "condition": condition,
            "threshold": threshold,
            "severity": severity,
            "description": description,
            "enabled": True
        }
        self.alert_rules.append(rule)
    
    def add_alert_callback(self, callback: Callable):
        """Add callback to be called when alerts are triggered"""
        self.alert_callbacks.append(callback)
    
    def check_alerts(self):
        """Check all alert rules and trigger alerts if needed"""
        for rule in self.alert_rules:
            if not rule["enabled"]:
                continue
            
            try:
                triggered = rule["condition"](self.metrics_collector, rule["threshold"])
                
                if triggered and rule["name"] not in self.active_alerts:
                    # New alert
                    alert = {
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "triggered_at": datetime.now().isoformat(),
                        "threshold": rule["threshold"]
                    }
                    
                    self.active_alerts[rule["name"]] = alert
                    
                    # Notify callbacks
                    for callback in self.alert_callbacks:
                        try:
                            callback(alert)
                        except Exception as e:
                            logger.error(f"Alert callback failed: {e}")
                
                elif not triggered and rule["name"] in self.active_alerts:
                    # Alert resolved
                    resolved_alert = self.active_alerts.pop(rule["name"])
                    resolved_alert["resolved_at"] = datetime.now().isoformat()
                    
                    # Notify callbacks about resolution
                    for callback in self.alert_callbacks:
                        try:
                            callback(resolved_alert, resolved=True)
                        except Exception as e:
                            logger.error(f"Alert resolution callback failed: {e}")
            
            except Exception as e:
                logger.error(f"Error checking alert rule '{rule['name']}': {e}")
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active alerts"""
        return list(self.active_alerts.values())


# Global monitoring instances
metrics_collector = MetricsCollector(retention_hours=settings.metrics_retention_days * 24)
system_monitor = SystemMonitor(metrics_collector)
application_monitor = ApplicationMonitor(metrics_collector)
health_checker = HealthChecker()
alert_manager = AlertManager(metrics_collector)


def setup_default_health_checks():
    """Set up default health checks"""
    
    def database_health():
        try:
            from .database import DatabaseManager
            db = DatabaseManager()
            return db.health_check()
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    def storage_health():
        try:
            from .storage_manager import storage_manager
            health = storage_manager.get_system_health()
            return {"status": health["status"], "details": health}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    def llm_health():
        try:
            return {"status": "healthy" if settings.validate_llm_config() else "unhealthy"}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    health_checker.register_health_check("database", database_health)
    health_checker.register_health_check("storage", storage_health)
    health_checker.register_health_check("llm_config", llm_health)


def setup_default_alerts():
    """Set up default alert rules"""
    
    # High CPU usage alert
    def high_cpu_condition(collector, threshold):
        return collector.get_gauge("system.cpu_percent") > threshold
    
    alert_manager.add_alert_rule(
        "high_cpu_usage",
        high_cpu_condition,
        threshold=80.0,
        severity="warning",
        description="CPU usage is above 80%"
    )
    
    # High memory usage alert
    def high_memory_condition(collector, threshold):
        return collector.get_gauge("system.memory_percent") > threshold
    
    alert_manager.add_alert_rule(
        "high_memory_usage",
        high_memory_condition,
        threshold=85.0,
        severity="warning",
        description="Memory usage is above 85%"
    )
    
    # High error rate alert
    def high_error_rate_condition(collector, threshold):
        total_requests = collector.get_counter("api.requests_total")
        total_errors = collector.get_counter("api.errors_total")
        if total_requests > 0:
            error_rate = (total_errors / total_requests) * 100
            return error_rate > threshold
        return False
    
    alert_manager.add_alert_rule(
        "high_error_rate",
        high_error_rate_condition,
        threshold=5.0,
        severity="critical",
        description="API error rate is above 5%"
    )


# Initialize default monitoring setup
setup_default_health_checks()
setup_default_alerts()