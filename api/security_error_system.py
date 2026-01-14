"""
Comprehensive Security Error Handling System

This module integrates error classification, data recovery, graceful degradation,
and comprehensive logging/alerting for security operations.
"""

import logging
import asyncio
import json
import smtplib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time
import requests

from security_error_handler import (
    SecurityError, SecurityErrorCategory, SecurityErrorSeverity, 
    SecurityErrorContext, handle_security_error, error_tracker
)
from security_data_recovery import (
    security_recovery_manager, create_rollback_point, ValidationResult
)

# Configure system logger
system_logger = logging.getLogger('security_system')
system_logger.setLevel(logging.INFO)

class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class ServiceStatus(Enum):
    """Service status for graceful degradation."""
    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    OFFLINE = "offline"

@dataclass
class AlertConfig:
    """Configuration for security alerts."""
    email_enabled: bool = True
    webhook_enabled: bool = False
    slack_enabled: bool = False
    email_recipients: List[str] = field(default_factory=list)
    webhook_url: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    alert_thresholds: Dict[str, int] = field(default_factory=lambda: {
        "critical_errors_per_hour": 5,
        "high_errors_per_hour": 20,
        "total_errors_per_hour": 100
    })

@dataclass
class ServiceFallback:
    """Fallback configuration for external services."""
    service_name: str
    primary_url: str
    fallback_urls: List[str]
    timeout_seconds: int = 30
    retry_attempts: int = 3
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: int = 300  # 5 minutes

class SecurityErrorSystem:
    """Comprehensive security error handling system."""
    
    def __init__(self, config_path: str = "config/security_error_config.json"):
        self.config_path = config_path
        self.alert_config = self._load_alert_config()
        self.service_fallbacks = self._initialize_service_fallbacks()
        self.service_status = {}
        self.circuit_breakers = {}
        self.error_counts = {}
        self.alert_history = []
        
        # Initialize service monitoring
        self._initialize_service_monitoring()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _load_alert_config(self) -> AlertConfig:
        """Load alert configuration from file."""
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
                return AlertConfig(**config_data.get('alerts', {}))
        except Exception as e:
            system_logger.warning(f"Could not load alert config: {e}")
        
        return AlertConfig()
    
    def _initialize_service_fallbacks(self) -> Dict[str, ServiceFallback]:
        """Initialize service fallback configurations."""
        return {
            "llm_service": ServiceFallback(
                service_name="LLM Service",
                primary_url="http://localhost:8000/api/llm",
                fallback_urls=["http://backup-llm:8000/api/llm"],
                timeout_seconds=60,
                retry_attempts=2
            ),
            "owasp_service": ServiceFallback(
                service_name="OWASP Service",
                primary_url="https://owasp.org/api",
                fallback_urls=["http://localhost:8001/owasp-cache"],
                timeout_seconds=30,
                retry_attempts=3
            ),
            "security_scanner": ServiceFallback(
                service_name="Security Scanner",
                primary_url="http://localhost:9000/scan",
                fallback_urls=["http://backup-scanner:9000/scan"],
                timeout_seconds=120,
                retry_attempts=1
            )
        }
    
    def _initialize_service_monitoring(self):
        """Initialize service status monitoring."""
        for service_name in self.service_fallbacks.keys():
            self.service_status[service_name] = ServiceStatus.OPERATIONAL
            self.circuit_breakers[service_name] = {
                "failure_count": 0,
                "last_failure": None,
                "is_open": False
            }
    
    def _start_background_tasks(self):
        """Start background monitoring and cleanup tasks."""
        # Error monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_error_rates, daemon=True)
        monitor_thread.start()
        
        # Service health check thread
        health_thread = threading.Thread(target=self._monitor_service_health, daemon=True)
        health_thread.start()
        
        # Cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_old_data, daemon=True)
        cleanup_thread.start()
    
    def handle_security_operation_error(self, operation: str, exception: Exception, 
                                      context: SecurityErrorContext, 
                                      auto_recover: bool = True) -> SecurityError:
        """Main entry point for handling security operation errors."""
        try:
            # Create rollback point for critical operations
            rollback_id = None
            if operation in ["data_migration", "security_update", "config_change"]:
                try:
                    rollback_id = create_rollback_point(operation)
                    context.additional_data["rollback_id"] = rollback_id
                except Exception as e:
                    system_logger.warning(f"Could not create rollback point: {e}")
            
            # Classify and handle the error
            security_error = handle_security_error(exception, context, f"Security operation '{operation}' failed")
            
            # Update error counts for monitoring
            self._update_error_counts(security_error)
            
            # Attempt automatic recovery if enabled
            if auto_recover:
                recovery_attempted = self._attempt_error_recovery(security_error, operation)
                security_error.context.additional_data["recovery_attempted"] = recovery_attempted
            
            # Check if alerting is needed
            self._check_alert_thresholds(security_error)
            
            # Log comprehensive error information
            self._log_security_error(security_error, operation)
            
            return security_error
            
        except Exception as e:
            # Fallback error handling
            system_logger.critical(f"Critical error in security error system: {e}")
            return self._create_fallback_error(operation, exception, context)
    
    def _attempt_error_recovery(self, security_error: SecurityError, operation: str) -> bool:
        """Attempt automatic recovery based on error type."""
        try:
            category = security_error.category
            
            if category == SecurityErrorCategory.DATA_CORRUPTION:
                # Attempt data recovery
                validation_result = security_recovery_manager.perform_integrity_check()
                if not validation_result.is_valid:
                    recovery_op = security_recovery_manager.handle_data_corruption(validation_result)
                    return recovery_op.status.value == "success"
            
            elif category == SecurityErrorCategory.EXTERNAL_SERVICE:
                # Attempt service failover
                service_name = self._identify_service_from_operation(operation)
                if service_name:
                    return self._attempt_service_failover(service_name)
            
            elif category == SecurityErrorCategory.AUTHENTICATION:
                # Attempt session refresh
                if security_error.context.session_id:
                    return self._attempt_session_refresh(security_error.context.session_id)
            
            elif category == SecurityErrorCategory.PERFORMANCE:
                # Attempt performance optimization
                return self._attempt_performance_recovery(operation)
            
            return False
            
        except Exception as e:
            system_logger.error(f"Error recovery attempt failed: {e}")
            return False
    
    def _identify_service_from_operation(self, operation: str) -> Optional[str]:
        """Identify which external service an operation depends on."""
        service_mapping = {
            "llm_analysis": "llm_service",
            "threat_analysis": "llm_service",
            "owasp_lookup": "owasp_service",
            "security_scan": "security_scanner",
            "vulnerability_check": "security_scanner"
        }
        return service_mapping.get(operation)
    
    def _attempt_service_failover(self, service_name: str) -> bool:
        """Attempt to failover to backup service."""
        try:
            if service_name not in self.service_fallbacks:
                return False
            
            fallback_config = self.service_fallbacks[service_name]
            
            # Check circuit breaker
            if self.circuit_breakers[service_name]["is_open"]:
                # Check if circuit breaker timeout has passed
                last_failure = self.circuit_breakers[service_name]["last_failure"]
                if last_failure:
                    time_since_failure = (datetime.now(timezone.utc) - last_failure).total_seconds()
                    if time_since_failure < fallback_config.circuit_breaker_timeout:
                        return False  # Circuit breaker still open
                    else:
                        # Reset circuit breaker
                        self.circuit_breakers[service_name]["is_open"] = False
                        self.circuit_breakers[service_name]["failure_count"] = 0
            
            # Try fallback URLs
            for fallback_url in fallback_config.fallback_urls:
                try:
                    response = requests.get(
                        f"{fallback_url}/health", 
                        timeout=fallback_config.timeout_seconds
                    )
                    if response.status_code == 200:
                        self.service_status[service_name] = ServiceStatus.DEGRADED
                        system_logger.info(f"Successfully failed over {service_name} to {fallback_url}")
                        return True
                except Exception:
                    continue
            
            # All fallbacks failed
            self.service_status[service_name] = ServiceStatus.OFFLINE
            self._open_circuit_breaker(service_name)
            return False
            
        except Exception as e:
            system_logger.error(f"Service failover failed for {service_name}: {e}")
            return False
    
    def _attempt_session_refresh(self, session_id: str) -> bool:
        """Attempt to refresh user session."""
        try:
            # This would integrate with your authentication system
            # For now, just log the attempt
            system_logger.info(f"Attempting session refresh for session: {session_id}")
            return True  # Placeholder
        except Exception as e:
            system_logger.error(f"Session refresh failed: {e}")
            return False
    
    def _attempt_performance_recovery(self, operation: str) -> bool:
        """Attempt performance recovery measures."""
        try:
            # Clear caches
            cache_cleared = self._clear_operation_cache(operation)
            
            # Reduce operation complexity
            complexity_reduced = self._reduce_operation_complexity(operation)
            
            return cache_cleared or complexity_reduced
            
        except Exception as e:
            system_logger.error(f"Performance recovery failed: {e}")
            return False
    
    def _clear_operation_cache(self, operation: str) -> bool:
        """Clear caches related to an operation."""
        try:
            # This would integrate with your caching system
            system_logger.info(f"Clearing cache for operation: {operation}")
            return True  # Placeholder
        except Exception:
            return False
    
    def _reduce_operation_complexity(self, operation: str) -> bool:
        """Reduce operation complexity to improve performance."""
        try:
            # This would implement operation-specific complexity reduction
            system_logger.info(f"Reducing complexity for operation: {operation}")
            return True  # Placeholder
        except Exception:
            return False
    
    def _open_circuit_breaker(self, service_name: str):
        """Open circuit breaker for a service."""
        self.circuit_breakers[service_name]["is_open"] = True
        self.circuit_breakers[service_name]["last_failure"] = datetime.now(timezone.utc)
        self.circuit_breakers[service_name]["failure_count"] += 1
        
        system_logger.warning(f"Circuit breaker opened for service: {service_name}")
    
    def _update_error_counts(self, security_error: SecurityError):
        """Update error counts for monitoring."""
        current_hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        
        if current_hour not in self.error_counts:
            self.error_counts[current_hour] = {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "by_category": {}
            }
        
        counts = self.error_counts[current_hour]
        counts["total"] += 1
        counts[security_error.severity.value] += 1
        
        category = security_error.category.value
        if category not in counts["by_category"]:
            counts["by_category"][category] = 0
        counts["by_category"][category] += 1
    
    def _check_alert_thresholds(self, security_error: SecurityError):
        """Check if error counts exceed alert thresholds."""
        current_hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        
        if current_hour not in self.error_counts:
            return
        
        counts = self.error_counts[current_hour]
        thresholds = self.alert_config.alert_thresholds
        
        # Check thresholds
        alerts_to_send = []
        
        if counts["critical"] >= thresholds.get("critical_errors_per_hour", 5):
            alerts_to_send.append({
                "severity": AlertSeverity.CRITICAL,
                "message": f"Critical error threshold exceeded: {counts['critical']} errors in the last hour",
                "details": counts
            })
        
        if counts["high"] >= thresholds.get("high_errors_per_hour", 20):
            alerts_to_send.append({
                "severity": AlertSeverity.HIGH,
                "message": f"High severity error threshold exceeded: {counts['high']} errors in the last hour",
                "details": counts
            })
        
        if counts["total"] >= thresholds.get("total_errors_per_hour", 100):
            alerts_to_send.append({
                "severity": AlertSeverity.CRITICAL,
                "message": f"Total error threshold exceeded: {counts['total']} errors in the last hour",
                "details": counts
            })
        
        # Send alerts
        for alert in alerts_to_send:
            self._send_alert(alert["severity"], alert["message"], alert["details"])
    
    def _send_alert(self, severity: AlertSeverity, message: str, details: Dict):
        """Send security alert through configured channels."""
        try:
            alert_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": severity.value,
                "message": message,
                "details": details
            }
            
            # Email alerts
            if self.alert_config.email_enabled and self.alert_config.email_recipients:
                self._send_email_alert(alert_data)
            
            # Webhook alerts
            if self.alert_config.webhook_enabled and self.alert_config.webhook_url:
                self._send_webhook_alert(alert_data)
            
            # Slack alerts
            if self.alert_config.slack_enabled and self.alert_config.slack_webhook_url:
                self._send_slack_alert(alert_data)
            
            # Store alert history
            self.alert_history.append(alert_data)
            
            # Keep only last 1000 alerts
            if len(self.alert_history) > 1000:
                self.alert_history = self.alert_history[-1000:]
            
        except Exception as e:
            system_logger.error(f"Failed to send alert: {e}")
    
    def _send_email_alert(self, alert_data: Dict):
        """Send email alert."""
        try:
            # This is a basic implementation - you'd want to configure SMTP properly
            subject = f"Security Alert - {alert_data['severity'].upper()}"
            body = f"""
Security Alert

Severity: {alert_data['severity']}
Time: {alert_data['timestamp']}
Message: {alert_data['message']}

Details:
{json.dumps(alert_data['details'], indent=2)}
"""
            
            # Log the alert (in production, you'd send actual emails)
            system_logger.warning(f"EMAIL ALERT: {subject}\n{body}")
            
        except Exception as e:
            system_logger.error(f"Failed to send email alert: {e}")
    
    def _send_webhook_alert(self, alert_data: Dict):
        """Send webhook alert."""
        try:
            response = requests.post(
                self.alert_config.webhook_url,
                json=alert_data,
                timeout=10
            )
            response.raise_for_status()
            
        except Exception as e:
            system_logger.error(f"Failed to send webhook alert: {e}")
    
    def _send_slack_alert(self, alert_data: Dict):
        """Send Slack alert."""
        try:
            slack_message = {
                "text": f"Security Alert - {alert_data['severity'].upper()}",
                "attachments": [{
                    "color": "danger" if alert_data['severity'] in ['critical', 'high'] else "warning",
                    "fields": [
                        {"title": "Message", "value": alert_data['message'], "short": False},
                        {"title": "Time", "value": alert_data['timestamp'], "short": True},
                        {"title": "Severity", "value": alert_data['severity'], "short": True}
                    ]
                }]
            }
            
            response = requests.post(
                self.alert_config.slack_webhook_url,
                json=slack_message,
                timeout=10
            )
            response.raise_for_status()
            
        except Exception as e:
            system_logger.error(f"Failed to send Slack alert: {e}")
    
    def _log_security_error(self, security_error: SecurityError, operation: str):
        """Log comprehensive security error information."""
        log_data = {
            "error_id": security_error.error_id,
            "operation": operation,
            "category": security_error.category.value,
            "severity": security_error.severity.value,
            "message": security_error.message,
            "context": security_error.context.__dict__,
            "recovery_actions": [action.__dict__ for action in security_error.recovery_actions],
            "timestamp": security_error.timestamp.isoformat()
        }
        
        # Log at appropriate level based on severity
        if security_error.severity == SecurityErrorSeverity.CRITICAL:
            system_logger.critical(f"CRITICAL SECURITY ERROR: {json.dumps(log_data, indent=2)}")
        elif security_error.severity == SecurityErrorSeverity.HIGH:
            system_logger.error(f"HIGH SECURITY ERROR: {json.dumps(log_data, indent=2)}")
        elif security_error.severity == SecurityErrorSeverity.MEDIUM:
            system_logger.warning(f"MEDIUM SECURITY ERROR: {json.dumps(log_data, indent=2)}")
        else:
            system_logger.info(f"SECURITY ERROR: {json.dumps(log_data, indent=2)}")
    
    def _create_fallback_error(self, operation: str, exception: Exception, 
                             context: SecurityErrorContext) -> SecurityError:
        """Create a fallback error when the main error handling fails."""
        from security_error_handler import SecurityError, SecurityErrorCategory, SecurityErrorSeverity, RecoveryAction
        
        return SecurityError(
            error_id=f"FALLBACK_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            category=SecurityErrorCategory.ANALYSIS_FAILURE,
            severity=SecurityErrorSeverity.HIGH,
            message="Security error system failure - using fallback error handling",
            technical_details=f"Operation: {operation}, Exception: {str(exception)}",
            context=context,
            recovery_actions=[
                RecoveryAction(
                    action_type="manual_review",
                    description="Manual review required due to error system failure",
                    automated=False
                )
            ]
        )
    
    def _monitor_error_rates(self):
        """Background task to monitor error rates."""
        while True:
            try:
                # Clean up old error counts (keep last 24 hours)
                cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
                old_hours = [hour for hour in self.error_counts.keys() if hour < cutoff_time]
                for hour in old_hours:
                    del self.error_counts[hour]
                
                time.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                system_logger.error(f"Error rate monitoring failed: {e}")
                time.sleep(60)
    
    def _monitor_service_health(self):
        """Background task to monitor service health."""
        while True:
            try:
                for service_name, fallback_config in self.service_fallbacks.items():
                    try:
                        # Check primary service
                        response = requests.get(
                            f"{fallback_config.primary_url}/health",
                            timeout=10
                        )
                        
                        if response.status_code == 200:
                            if self.service_status[service_name] != ServiceStatus.OPERATIONAL:
                                self.service_status[service_name] = ServiceStatus.OPERATIONAL
                                system_logger.info(f"Service {service_name} restored to operational status")
                        else:
                            self.service_status[service_name] = ServiceStatus.DEGRADED
                            
                    except Exception:
                        if self.service_status[service_name] == ServiceStatus.OPERATIONAL:
                            self.service_status[service_name] = ServiceStatus.DEGRADED
                            system_logger.warning(f"Service {service_name} health check failed")
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                system_logger.error(f"Service health monitoring failed: {e}")
                time.sleep(60)
    
    def _cleanup_old_data(self):
        """Background task to cleanup old data."""
        while True:
            try:
                # Cleanup old backups
                security_recovery_manager.backup_manager.cleanup_old_backups()
                
                # Cleanup old alert history
                if len(self.alert_history) > 1000:
                    self.alert_history = self.alert_history[-1000:]
                
                time.sleep(3600)  # Cleanup every hour
                
            except Exception as e:
                system_logger.error(f"Data cleanup failed: {e}")
                time.sleep(3600)
    
    def get_system_status(self) -> Dict:
        """Get current system status."""
        return {
            "service_status": {name: status.value for name, status in self.service_status.items()},
            "circuit_breakers": self.circuit_breakers,
            "recent_error_counts": dict(list(self.error_counts.items())[-24:]),  # Last 24 hours
            "recent_alerts": self.alert_history[-10:],  # Last 10 alerts
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

# Global instance
security_error_system = SecurityErrorSystem()

def handle_security_operation_error(operation: str, exception: Exception, 
                                  context: SecurityErrorContext, 
                                  auto_recover: bool = True) -> SecurityError:
    """Main function to handle security operation errors with full system integration."""
    return security_error_system.handle_security_operation_error(operation, exception, context, auto_recover)

def get_security_system_status() -> Dict:
    """Get current security system status."""
    return security_error_system.get_system_status()