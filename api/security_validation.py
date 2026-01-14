"""
Comprehensive input validation and sanitization for ThreatLens
Implements SQL injection and XSS prevention measures
"""
import re
import html
import json
import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Union, Callable
from datetime import datetime
from pathlib import Path
from enum import Enum

import bleach
from pydantic import BaseModel, validator, ValidationError
from sqlalchemy.sql import text

logger = logging.getLogger(__name__)


class ValidationSeverity(str, Enum):
    """Validation error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationError(Exception):
    """Custom validation error with severity"""
    
    def __init__(self, message: str, severity: ValidationSeverity = ValidationSeverity.MEDIUM, 
                 field: Optional[str] = None):
        self.message = message
        self.severity = severity
        self.field = field
        super().__init__(message)


class SecurityValidator:
    """Comprehensive security validation and sanitization"""
    
    # Dangerous patterns that should be blocked
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        r"(\b(UNION|OR|AND)\s+\d+\s*=\s*\d+)",
        r"(--|#|/\*|\*/)",
        r"(\b(SCRIPT|JAVASCRIPT|VBSCRIPT|ONLOAD|ONERROR)\b)",
        r"([\'\";])",
        r"(\b(XP_|SP_)\w+)",
        r"(\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)\b)"
    ]
    
    XSS_PATTERNS = [
        r"<\s*script[^>]*>.*?</\s*script\s*>",
        r"<\s*iframe[^>]*>.*?</\s*iframe\s*>",
        r"<\s*object[^>]*>.*?</\s*object\s*>",
        r"<\s*embed[^>]*>.*?</\s*embed\s*>",
        r"<\s*link[^>]*>",
        r"<\s*meta[^>]*>",
        r"javascript\s*:",
        r"vbscript\s*:",
        r"data\s*:",
        r"on\w+\s*="
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r"\.\.%2f",
        r"\.\.%5c"
    ]
    
    # Allowed HTML tags and attributes for content sanitization
    ALLOWED_HTML_TAGS = [
        'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'blockquote', 'code', 'pre', 'a', 'img', 'table', 'thead', 'tbody', 'tr', 'th', 'td'
    ]
    
    ALLOWED_HTML_ATTRIBUTES = {
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'title', 'width', 'height'],
        'table': ['class'],
        'th': ['scope'],
        'td': ['colspan', 'rowspan']
    }
    
    def __init__(self):
        self.validation_stats = {
            "total_validations": 0,
            "blocked_attempts": 0,
            "sanitized_inputs": 0,
            "last_reset": datetime.now().isoformat()
        }
    
    def validate_and_sanitize(self, data: Any, field_name: str = "unknown", 
                            validation_rules: Optional[Dict[str, Any]] = None) -> Any:
        """Main validation and sanitization entry point"""
        self.validation_stats["total_validations"] += 1
        
        try:
            # Apply basic security checks
            if isinstance(data, str):
                data = self._validate_string_input(data, field_name, validation_rules or {})
            elif isinstance(data, dict):
                data = self._validate_dict_input(data, field_name, validation_rules or {})
            elif isinstance(data, list):
                data = self._validate_list_input(data, field_name, validation_rules or {})
            
            return data
        
        except ValidationError:
            self.validation_stats["blocked_attempts"] += 1
            raise
        except Exception as e:
            logger.error(f"Validation error for field {field_name}: {e}")
            raise ValidationError(f"Validation failed: {e}", ValidationSeverity.HIGH, field_name)
    
    def _validate_string_input(self, value: str, field_name: str, rules: Dict[str, Any]) -> str:
        """Validate and sanitize string input"""
        if not isinstance(value, str):
            raise ValidationError(f"Expected string for field {field_name}", ValidationSeverity.MEDIUM, field_name)
        
        original_value = value
        
        # Length validation
        max_length = rules.get("max_length", 10000)
        if len(value) > max_length:
            raise ValidationError(f"Input too long for field {field_name} (max: {max_length})", 
                                ValidationSeverity.MEDIUM, field_name)
        
        # SQL injection detection
        if self._detect_sql_injection(value):
            raise ValidationError(f"SQL injection attempt detected in field {field_name}", 
                                ValidationSeverity.CRITICAL, field_name)
        
        # XSS detection and sanitization
        if self._detect_xss(value):
            if rules.get("allow_html", False):
                value = self._sanitize_html(value)
                if value != original_value:
                    self.validation_stats["sanitized_inputs"] += 1
            else:
                raise ValidationError(f"XSS attempt detected in field {field_name}", 
                                    ValidationSeverity.HIGH, field_name)
        
        # Path traversal detection
        if self._detect_path_traversal(value):
            raise ValidationError(f"Path traversal attempt detected in field {field_name}", 
                                ValidationSeverity.HIGH, field_name)
        
        # Custom pattern validation
        if "pattern" in rules:
            if not re.match(rules["pattern"], value):
                raise ValidationError(f"Invalid format for field {field_name}", 
                                    ValidationSeverity.MEDIUM, field_name)
        
        # URL validation for URL fields
        if rules.get("type") == "url":
            value = self._validate_url(value, field_name)
        
        # Email validation for email fields
        if rules.get("type") == "email":
            value = self._validate_email(value, field_name)
        
        # File path validation
        if rules.get("type") == "filepath":
            value = self._validate_filepath(value, field_name)
        
        return value
    
    def _validate_dict_input(self, value: Dict[str, Any], field_name: str, rules: Dict[str, Any]) -> Dict[str, Any]:
        """Validate dictionary input recursively"""
        if not isinstance(value, dict):
            raise ValidationError(f"Expected dictionary for field {field_name}", ValidationSeverity.MEDIUM, field_name)
        
        max_keys = rules.get("max_keys", 100)
        if len(value) > max_keys:
            raise ValidationError(f"Too many keys in dictionary {field_name} (max: {max_keys})", 
                                ValidationSeverity.MEDIUM, field_name)
        
        validated_dict = {}
        field_rules = rules.get("fields", {})
        
        for key, val in value.items():
            # Validate key
            validated_key = self._validate_string_input(str(key), f"{field_name}.key", {"max_length": 100})
            
            # Validate value
            key_rules = field_rules.get(key, {})
            validated_value = self.validate_and_sanitize(val, f"{field_name}.{key}", key_rules)
            
            validated_dict[validated_key] = validated_value
        
        return validated_dict
    
    def _validate_list_input(self, value: List[Any], field_name: str, rules: Dict[str, Any]) -> List[Any]:
        """Validate list input"""
        if not isinstance(value, list):
            raise ValidationError(f"Expected list for field {field_name}", ValidationSeverity.MEDIUM, field_name)
        
        max_items = rules.get("max_items", 1000)
        if len(value) > max_items:
            raise ValidationError(f"Too many items in list {field_name} (max: {max_items})", 
                                ValidationSeverity.MEDIUM, field_name)
        
        validated_list = []
        item_rules = rules.get("item_rules", {})
        
        for i, item in enumerate(value):
            validated_item = self.validate_and_sanitize(item, f"{field_name}[{i}]", item_rules)
            validated_list.append(validated_item)
        
        return validated_list
    
    def _detect_sql_injection(self, value: str) -> bool:
        """Detect SQL injection patterns"""
        value_lower = value.lower()
        
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                logger.warning(f"SQL injection pattern detected: {pattern}")
                return True
        
        return False
    
    def _detect_xss(self, value: str) -> bool:
        """Detect XSS patterns"""
        value_lower = value.lower()
        
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE | re.DOTALL):
                logger.warning(f"XSS pattern detected: {pattern}")
                return True
        
        return False
    
    def _detect_path_traversal(self, value: str) -> bool:
        """Detect path traversal patterns"""
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"Path traversal pattern detected: {pattern}")
                return True
        
        return False
    
    def _sanitize_html(self, value: str) -> str:
        """Sanitize HTML content using bleach"""
        try:
            sanitized = bleach.clean(
                value,
                tags=self.ALLOWED_HTML_TAGS,
                attributes=self.ALLOWED_HTML_ATTRIBUTES,
                strip=True
            )
            
            # Additional sanitization
            sanitized = html.escape(sanitized, quote=False)
            
            return sanitized
        
        except Exception as e:
            logger.error(f"HTML sanitization failed: {e}")
            return html.escape(value)
    
    def _validate_url(self, value: str, field_name: str) -> str:
        """Validate URL format and security"""
        try:
            parsed = urllib.parse.urlparse(value)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                raise ValidationError(f"Invalid URL scheme for {field_name}", 
                                    ValidationSeverity.MEDIUM, field_name)
            
            # Check for dangerous protocols
            if parsed.scheme in ['javascript', 'data', 'vbscript']:
                raise ValidationError(f"Dangerous URL scheme for {field_name}", 
                                    ValidationSeverity.HIGH, field_name)
            
            # Validate hostname
            if not parsed.netloc:
                raise ValidationError(f"Invalid URL format for {field_name}", 
                                    ValidationSeverity.MEDIUM, field_name)
            
            return value
        
        except Exception as e:
            raise ValidationError(f"URL validation failed for {field_name}: {e}", 
                                ValidationSeverity.MEDIUM, field_name)
    
    def _validate_email(self, value: str, field_name: str) -> str:
        """Validate email format"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, value):
            raise ValidationError(f"Invalid email format for {field_name}", 
                                ValidationSeverity.MEDIUM, field_name)
        
        return value.lower()
    
    def _validate_filepath(self, value: str, field_name: str) -> str:
        """Validate file path security"""
        try:
            path = Path(value)
            
            # Check for absolute paths (may be security risk)
            if path.is_absolute():
                logger.warning(f"Absolute path provided for {field_name}: {value}")
            
            # Resolve path to check for traversal
            try:
                resolved = path.resolve()
                # Additional security checks could be added here
            except Exception:
                raise ValidationError(f"Invalid file path for {field_name}", 
                                    ValidationSeverity.MEDIUM, field_name)
            
            return str(path)
        
        except Exception as e:
            raise ValidationError(f"File path validation failed for {field_name}: {e}", 
                                ValidationSeverity.MEDIUM, field_name)


class SQLSafetyValidator:
    """SQL query safety validator"""
    
    DANGEROUS_SQL_FUNCTIONS = [
        'xp_cmdshell', 'sp_configure', 'openrowset', 'opendatasource',
        'exec', 'execute', 'eval', 'sp_executesql'
    ]
    
    @classmethod
    def validate_sql_query(cls, query: str, allowed_operations: Optional[List[str]] = None) -> bool:
        """Validate SQL query for safety"""
        if not query or not isinstance(query, str):
            return False
        
        query_lower = query.lower().strip()
        
        # Check for dangerous functions
        for func in cls.DANGEROUS_SQL_FUNCTIONS:
            if func in query_lower:
                logger.error(f"Dangerous SQL function detected: {func}")
                return False
        
        # Check allowed operations
        if allowed_operations:
            operation = query_lower.split()[0] if query_lower.split() else ""
            if operation not in [op.lower() for op in allowed_operations]:
                logger.error(f"SQL operation not allowed: {operation}")
                return False
        
        # Check for multiple statements (basic check)
        if ';' in query and not query.strip().endswith(';'):
            logger.error("Multiple SQL statements detected")
            return False
        
        return True
    
    @classmethod
    def sanitize_sql_parameter(cls, param: Any) -> Any:
        """Sanitize SQL parameter"""
        if isinstance(param, str):
            # Escape single quotes
            return param.replace("'", "''")
        
        return param


class SecurityValidationMiddleware:
    """Middleware for automatic validation of request data"""
    
    def __init__(self):
        self.validator = SecurityValidator()
        self.validation_rules = self._load_validation_rules()
    
    def _load_validation_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load validation rules for different endpoints"""
        return {
            "repository_analysis": {
                "repo_url": {
                    "type": "url",
                    "max_length": 500,
                    "pattern": r"^https?://.*"
                },
                "local_path": {
                    "type": "filepath",
                    "max_length": 500
                },
                "analysis_options": {
                    "max_keys": 20,
                    "fields": {
                        "include_tests": {"type": "boolean"},
                        "max_files": {"type": "integer", "max_value": 10000}
                    }
                }
            },
            "security_document": {
                "title": {
                    "max_length": 200,
                    "pattern": r"^[a-zA-Z0-9\s\-_\.]+$"
                },
                "content": {
                    "max_length": 100000,
                    "allow_html": True
                },
                "metadata": {
                    "max_keys": 50
                }
            },
            "user_input": {
                "search_query": {
                    "max_length": 500
                },
                "filter_criteria": {
                    "max_keys": 10
                }
            }
        }
    
    def validate_request_data(self, data: Dict[str, Any], endpoint: str) -> Dict[str, Any]:
        """Validate request data for specific endpoint"""
        rules = self.validation_rules.get(endpoint, {})
        validated_data = {}
        
        for field, value in data.items():
            field_rules = rules.get(field, {})
            try:
                validated_data[field] = self.validator.validate_and_sanitize(
                    value, field, field_rules
                )
            except ValidationError as e:
                logger.error(f"Validation failed for {endpoint}.{field}: {e.message}")
                raise
        
        return validated_data
    
    def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation statistics"""
        return self.validator.validation_stats


# Global validator instance
security_validator = SecurityValidator()
validation_middleware = SecurityValidationMiddleware()
sql_validator = SQLSafetyValidator()