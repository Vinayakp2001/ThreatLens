"""
LLM client for threat document generation with configurable providers and error recovery
"""
import asyncio
import json
import logging
import time
import pickle
import hashlib
from typing import Dict, Any, Optional, List, Union
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from .config import settings
from .models import ThreatDoc, SecurityModel, Component, Flow


logger = logging.getLogger(__name__)


class LLMErrorType(Enum):
    """Types of LLM errors for categorization"""
    RATE_LIMIT = "rate_limit"
    API_ERROR = "api_error"
    NETWORK_ERROR = "network_error"
    TIMEOUT_ERROR = "timeout_error"
    QUOTA_EXCEEDED = "quota_exceeded"
    INVALID_REQUEST = "invalid_request"
    MODEL_OVERLOADED = "model_overloaded"
    CONTENT_FILTER = "content_filter"
    UNKNOWN_ERROR = "unknown_error"


@dataclass
class LLMResponse:
    """Response from LLM API"""
    content: str
    usage: Dict[str, Any]
    model: str
    finish_reason: str
    response_time: float = 0.0
    cached: bool = False


@dataclass
class LLMRequest:
    """LLM request for caching and retry purposes"""
    prompt: str
    system_prompt: Optional[str]
    max_tokens: Optional[int]
    temperature: float
    model: str
    
    def get_cache_key(self) -> str:
        """Generate cache key for this request"""
        content = f"{self.prompt}|{self.system_prompt}|{self.max_tokens}|{self.temperature}|{self.model}"
        return hashlib.md5(content.encode()).hexdigest()


class LLMError(Exception):
    """Base exception for LLM-related errors"""
    def __init__(self, message: str, error_type: LLMErrorType, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.error_type = error_type
        self.details = details or {}


class LLMRateLimitError(LLMError):
    """Rate limit exceeded error"""
    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message, LLMErrorType.RATE_LIMIT, {"retry_after": retry_after})


class LLMAPIError(LLMError):
    """API error from LLM provider"""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message, LLMErrorType.API_ERROR, {"status_code": status_code})


class LLMNetworkError(LLMError):
    """Network-related error"""
    def __init__(self, message: str):
        super().__init__(message, LLMErrorType.NETWORK_ERROR)


class LLMTimeoutError(LLMError):
    """Timeout error"""
    def __init__(self, message: str):
        super().__init__(message, LLMErrorType.TIMEOUT_ERROR)


class LLMCache:
    """Simple file-based cache for LLM responses"""
    
    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = Path(cache_dir or settings.storage_base_path) / "llm_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.enabled = True
    
    def get(self, cache_key: str) -> Optional[LLMResponse]:
        """Get cached response"""
        if not self.enabled:
            return None
        
        cache_file = self.cache_dir / f"{cache_key}.pkl"
        if cache_file.exists():
            try:
                with open(cache_file, 'rb') as f:
                    cached_response = pickle.load(f)
                    cached_response.cached = True
                    return cached_response
            except Exception as e:
                logger.warning(f"Failed to load cache file {cache_file}: {e}")
        
        return None
    
    def set(self, cache_key: str, response: LLMResponse):
        """Cache response"""
        if not self.enabled:
            return
        
        cache_file = self.cache_dir / f"{cache_key}.pkl"
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(response, f)
        except Exception as e:
            logger.warning(f"Failed to cache response: {e}")
    
    def clear(self):
        """Clear all cached responses"""
        try:
            for cache_file in self.cache_dir.glob("*.pkl"):
                cache_file.unlink()
        except Exception as e:
            logger.warning(f"Failed to clear cache: {e}")


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients"""
    
    def __init__(self):
        self.cache = LLMCache()
        self.request_count = 0
        self.error_count = 0
        self.last_request_time = 0.0
    
    @abstractmethod
    async def _generate_completion_impl(
        self,
        request: LLMRequest
    ) -> LLMResponse:
        """Implementation-specific completion generation"""
        pass
    
    @abstractmethod
    def validate_config(self) -> bool:
        """Validate client configuration"""
        pass
    
    async def generate_completion(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: float = 0.7
    ) -> LLMResponse:
        """Generate completion with caching and error recovery"""
        request = LLMRequest(
            prompt=prompt,
            system_prompt=system_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            model=getattr(self, 'model', 'unknown')
        )
        
        # Check cache first
        cache_key = request.get_cache_key()
        cached_response = self.cache.get(cache_key)
        if cached_response:
            logger.debug(f"Using cached LLM response for key: {cache_key[:8]}...")
            return cached_response
        
        # Rate limiting
        await self._enforce_rate_limit()
        
        start_time = time.time()
        
        try:
            response = await self._generate_completion_impl(request)
            response.response_time = time.time() - start_time
            
            # Cache successful response
            self.cache.set(cache_key, response)
            
            self.request_count += 1
            logger.debug(f"LLM request completed in {response.response_time:.2f}s")
            
            return response
            
        except Exception as e:
            self.error_count += 1
            elapsed_time = time.time() - start_time
            logger.error(f"LLM request failed after {elapsed_time:.2f}s: {e}")
            raise
    
    async def _enforce_rate_limit(self):
        """Enforce rate limiting between requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        # Minimum time between requests (based on requests per minute setting)
        min_interval = 60.0 / settings.llm_requests_per_minute
        
        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f}s")
            await asyncio.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics"""
        return {
            "request_count": self.request_count,
            "error_count": self.error_count,
            "error_rate": self.error_count / max(self.request_count, 1),
            "cache_enabled": self.cache.enabled
        }


class OpenAICompatibleClient(BaseLLMClient):
    """OpenAI-compatible API client with enhanced error recovery"""
    
    def __init__(self):
        super().__init__()
        self.api_key = settings.llm_api_key
        self.base_url = settings.llm_base_url or "https://api.openai.com/v1"
        self.model = settings.openai_model
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            },
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5)
        )
    
    def validate_config(self) -> bool:
        """Validate OpenAI configuration"""
        return self.api_key is not None
    
    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=4, max=60),
        retry=retry_if_exception_type((LLMRateLimitError, LLMNetworkError, LLMTimeoutError))
    )
    async def _generate_completion_impl(self, request: LLMRequest) -> LLMResponse:
        """Generate completion with comprehensive error handling"""
        
        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.prompt})
        
        payload = {
            "model": request.model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens or settings.max_tokens_per_request
        }
        
        try:
            response = await self.client.post(
                f"{self.base_url}/chat/completions",
                json=payload
            )
            
            # Handle different error status codes
            if response.status_code == 429:
                retry_after = self._extract_retry_after(response.headers)
                raise LLMRateLimitError("Rate limit exceeded", retry_after)
            elif response.status_code == 400:
                error_data = self._safe_json_parse(response.text)
                error_msg = error_data.get("error", {}).get("message", "Bad request")
                raise LLMError(f"Invalid request: {error_msg}", LLMErrorType.INVALID_REQUEST)
            elif response.status_code == 401:
                raise LLMAPIError("Authentication failed - check API key", response.status_code)
            elif response.status_code == 403:
                raise LLMError("Access forbidden - check permissions", LLMErrorType.API_ERROR)
            elif response.status_code == 404:
                raise LLMError(f"Model not found: {request.model}", LLMErrorType.INVALID_REQUEST)
            elif response.status_code == 500:
                raise LLMError("Server error - try again later", LLMErrorType.MODEL_OVERLOADED)
            elif response.status_code == 503:
                raise LLMError("Service unavailable - model overloaded", LLMErrorType.MODEL_OVERLOADED)
            elif response.status_code != 200:
                raise LLMAPIError(f"API error: {response.status_code} - {response.text}", response.status_code)
            
            data = self._safe_json_parse(response.text)
            if not data:
                raise LLMAPIError("Empty or invalid JSON response")
            
            # Validate response structure
            if "choices" not in data or not data["choices"]:
                raise LLMAPIError("No choices in response")
            
            choice = data["choices"][0]
            if "message" not in choice or "content" not in choice["message"]:
                raise LLMAPIError("Invalid response structure")
            
            content = choice["message"]["content"]
            if not content or not content.strip():
                raise LLMError("Empty response content", LLMErrorType.CONTENT_FILTER)
            
            return LLMResponse(
                content=content,
                usage=data.get("usage", {}),
                model=data.get("model", request.model),
                finish_reason=choice.get("finish_reason", "unknown")
            )
            
        except httpx.TimeoutException:
            raise LLMTimeoutError("Request timed out")
        except httpx.NetworkError as e:
            raise LLMNetworkError(f"Network error: {e}")
        except httpx.RequestError as e:
            raise LLMNetworkError(f"Request failed: {e}")
        except (KeyError, TypeError) as e:
            logger.error(f"Response parsing error: {e}")
            raise LLMAPIError(f"Invalid response format: {e}")
    
    def _extract_retry_after(self, headers) -> Optional[int]:
        """Extract retry-after header value"""
        retry_after = headers.get("retry-after") or headers.get("x-ratelimit-reset-requests")
        if retry_after:
            try:
                return int(retry_after)
            except ValueError:
                pass
        return None
    
    def _safe_json_parse(self, text: str) -> Optional[Dict[str, Any]]:
        """Safely parse JSON response"""
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}, text: {text[:200]}...")
            return None
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens or settings.max_tokens_per_request
        }
        
        try:
            response = await self.client.post(
                f"{self.base_url}/chat/completions",
                json=payload
            )
            
            if response.status_code == 429:
                raise LLMRateLimitError("Rate limit exceeded")
            elif response.status_code != 200:
                raise LLMAPIError(f"API error: {response.status_code} - {response.text}")
            
            data = response.json()
            
            return LLMResponse(
                content=data["choices"][0]["message"]["content"],
                usage=data.get("usage", {}),
                model=data.get("model", self.model),
                finish_reason=data["choices"][0].get("finish_reason", "unknown")
            )
            
        except httpx.RequestError as e:
            logger.error(f"HTTP request error: {e}")
            raise LLMAPIError(f"Request failed: {e}")
        except KeyError as e:
            logger.error(f"Unexpected response format: {e}")
            raise LLMAPIError(f"Invalid response format: {e}")
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()


class AzureOpenAIClient(BaseLLMClient):
    """Azure OpenAI client"""
    
    def __init__(self):
        self.api_key = settings.azure_openai_api_key
        self.endpoint = settings.azure_openai_endpoint
        self.api_version = settings.azure_openai_api_version
        self.deployment_name = settings.azure_openai_deployment_name
        
        self.client = httpx.AsyncClient(
            timeout=60.0,
            headers={
                "api-key": self.api_key,
                "Content-Type": "application/json"
            }
        )
    
    def validate_config(self) -> bool:
        """Validate Azure OpenAI configuration"""
        return all([
            self.api_key,
            self.endpoint,
            self.deployment_name
        ])
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((LLMRateLimitError, httpx.RequestError))
    )
    async def generate_completion(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: float = 0.7
    ) -> LLMResponse:
        """Generate completion using Azure OpenAI"""
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens or settings.max_tokens_per_request
        }
        
        url = f"{self.endpoint}/openai/deployments/{self.deployment_name}/chat/completions?api-version={self.api_version}"
        
        try:
            response = await self.client.post(url, json=payload)
            
            if response.status_code == 429:
                raise LLMRateLimitError("Rate limit exceeded")
            elif response.status_code != 200:
                raise LLMAPIError(f"API error: {response.status_code} - {response.text}")
            
            data = response.json()
            
            return LLMResponse(
                content=data["choices"][0]["message"]["content"],
                usage=data.get("usage", {}),
                model=self.deployment_name,
                finish_reason=data["choices"][0].get("finish_reason", "unknown")
            )
            
        except httpx.RequestError as e:
            logger.error(f"HTTP request error: {e}")
            raise LLMAPIError(f"Request failed: {e}")
        except KeyError as e:
            logger.error(f"Unexpected response format: {e}")
            raise LLMAPIError(f"Invalid response format: {e}")
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()


class LLMClientFactory:
    """Factory for creating LLM clients"""
    
    @staticmethod
    def create_client() -> BaseLLMClient:
        """Create appropriate LLM client based on configuration"""
        if settings.llm_provider == "openai":
            return OpenAICompatibleClient()
        elif settings.llm_provider == "azure":
            return AzureOpenAIClient()
        else:
            raise ValueError(f"Unsupported LLM provider: {settings.llm_provider}")


class LLMManager:
    """Manager for LLM operations with rate limiting and error handling"""
    
    def __init__(self):
        self.client = LLMClientFactory.create_client()
        self.request_times: List[float] = []
    
    def _check_rate_limit(self):
        """Check if we're within rate limits"""
        current_time = time.time()
        # Remove requests older than 1 minute
        self.request_times = [t for t in self.request_times if current_time - t < 60]
        
        if len(self.request_times) >= settings.llm_requests_per_minute:
            raise LLMRateLimitError("Rate limit exceeded")
        
        self.request_times.append(current_time)
    
    async def generate_completion(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: float = 0.7
    ) -> LLMResponse:
        """Generate completion with rate limiting"""
        self._check_rate_limit()
        
        if not self.client.validate_config():
            raise LLMError("LLM client configuration is invalid")
        
        return await self.client.generate_completion(
            prompt=prompt,
            system_prompt=system_prompt,
            max_tokens=max_tokens,
            temperature=temperature
        )
    
    async def close(self):
        """Close the LLM client"""
        await self.client.close()
cl
ass AzureOpenAIClient(BaseLLMClient):
    """Azure OpenAI client with enhanced error handling"""
    
    def __init__(self):
        super().__init__()
        self.api_key = settings.azure_openai_api_key
        self.endpoint = settings.azure_openai_endpoint
        self.api_version = settings.azure_openai_api_version
        self.deployment_name = settings.azure_openai_deployment_name
        self.model = self.deployment_name
        
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0),
            headers={
                "api-key": self.api_key,
                "Content-Type": "application/json"
            },
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5)
        )
    
    def validate_config(self) -> bool:
        """Validate Azure OpenAI configuration"""
        return all([
            self.api_key,
            self.endpoint,
            self.deployment_name
        ])
    
    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=4, max=60),
        retry=retry_if_exception_type((LLMRateLimitError, LLMNetworkError, LLMTimeoutError))
    )
    async def _generate_completion_impl(self, request: LLMRequest) -> LLMResponse:
        """Generate completion using Azure OpenAI"""
        
        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.prompt})
        
        payload = {
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens or settings.max_tokens_per_request
        }
        
        url = f"{self.endpoint}/openai/deployments/{self.deployment_name}/chat/completions?api-version={self.api_version}"
        
        try:
            response = await self.client.post(url, json=payload)
            
            if response.status_code == 429:
                retry_after = self._extract_retry_after(response.headers)
                raise LLMRateLimitError("Rate limit exceeded", retry_after)
            elif response.status_code != 200:
                raise LLMAPIError(f"Azure API error: {response.status_code} - {response.text}", response.status_code)
            
            data = response.json()
            
            return LLMResponse(
                content=data["choices"][0]["message"]["content"],
                usage=data.get("usage", {}),
                model=data.get("model", self.deployment_name),
                finish_reason=data["choices"][0].get("finish_reason", "unknown")
            )
            
        except httpx.TimeoutException:
            raise LLMTimeoutError("Request timed out")
        except httpx.NetworkError as e:
            raise LLMNetworkError(f"Network error: {e}")
        except httpx.RequestError as e:
            raise LLMNetworkError(f"Request failed: {e}")
        except (KeyError, TypeError) as e:
            logger.error(f"Response parsing error: {e}")
            raise LLMAPIError(f"Invalid response format: {e}")
    
    def _extract_retry_after(self, headers) -> Optional[int]:
        """Extract retry-after header value"""
        return headers.get("retry-after")
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()


class FallbackLLMClient(BaseLLMClient):
    """Fallback client that generates basic threat documents when LLM fails"""
    
    def __init__(self):
        super().__init__()
        self.model = "fallback"
    
    def validate_config(self) -> bool:
        """Fallback is always available"""
        return True
    
    async def _generate_completion_impl(self, request: LLMRequest) -> LLMResponse:
        """Generate basic fallback content"""
        
        # Simple template-based generation
        if "system overview" in request.prompt.lower():
            content = self._generate_system_overview_fallback()
        elif "component profile" in request.prompt.lower():
            content = self._generate_component_profile_fallback()
        elif "flow threat model" in request.prompt.lower():
            content = self._generate_flow_threat_model_fallback()
        elif "mitigation" in request.prompt.lower():
            content = self._generate_mitigation_fallback()
        else:
            content = self._generate_generic_fallback()
        
        return LLMResponse(
            content=content,
            usage={"prompt_tokens": len(request.prompt.split()), "completion_tokens": len(content.split())},
            model="fallback",
            finish_reason="stop"
        )
    
    def _generate_system_overview_fallback(self) -> str:
        return """# System Security Overview

## Summary
This document provides a basic security overview generated using fallback templates due to LLM service unavailability.

## Architecture Overview
The system architecture requires manual analysis to identify:
- Key components and their security boundaries
- Data flow patterns and trust boundaries
- External integrations and dependencies

## Security Considerations
- Authentication and authorization mechanisms need review
- Input validation and sanitization should be verified
- Data encryption in transit and at rest requires assessment
- Logging and monitoring capabilities should be evaluated

## Recommendations
1. Conduct manual security review
2. Implement security testing
3. Review access controls
4. Validate input handling
5. Assess data protection measures

*Note: This is a fallback document. For comprehensive analysis, ensure LLM service is available.*
"""
    
    def _generate_component_profile_fallback(self) -> str:
        return """# Component Security Profile

## Component Overview
This component requires manual security analysis due to LLM service unavailability.

## Security Assessment
- **Authentication**: Requires manual review
- **Authorization**: Needs assessment
- **Input Validation**: Should be verified
- **Data Handling**: Requires analysis
- **Error Handling**: Needs review

## Potential Threats
- Input validation vulnerabilities
- Authentication bypass
- Authorization flaws
- Data exposure risks
- Error information leakage

## Recommendations
1. Review component implementation
2. Test input validation
3. Verify access controls
4. Assess error handling
5. Check data protection

*Note: This is a fallback document. For detailed analysis, ensure LLM service is available.*
"""
    
    def _generate_flow_threat_model_fallback(self) -> str:
        return """# Flow Threat Model

## Flow Overview
This data flow requires manual threat modeling due to LLM service unavailability.

## STRIDE Analysis
- **Spoofing**: Potential identity spoofing risks
- **Tampering**: Data integrity concerns
- **Repudiation**: Non-repudiation requirements
- **Information Disclosure**: Data confidentiality risks
- **Denial of Service**: Availability threats
- **Elevation of Privilege**: Access control bypass

## Recommendations
1. Implement strong authentication
2. Use data integrity checks
3. Enable audit logging
4. Protect sensitive data
5. Implement rate limiting
6. Enforce least privilege

*Note: This is a fallback document. For comprehensive STRIDE analysis, ensure LLM service is available.*
"""
    
    def _generate_mitigation_fallback(self) -> str:
        return """# Security Mitigations and Requirements

## Overview
Basic security mitigations generated using fallback templates due to LLM service unavailability.

## General Security Requirements
1. **Authentication**: Implement strong authentication mechanisms
2. **Authorization**: Enforce role-based access control
3. **Input Validation**: Validate and sanitize all inputs
4. **Data Protection**: Encrypt sensitive data
5. **Logging**: Implement comprehensive audit logging
6. **Error Handling**: Secure error handling practices

## Implementation Guidelines
- Follow OWASP security guidelines
- Implement defense in depth
- Regular security testing
- Security code reviews
- Dependency vulnerability scanning

*Note: This is a fallback document. For specific mitigations, ensure LLM service is available.*
"""
    
    def _generate_generic_fallback(self) -> str:
        return """# Security Analysis Document

## Overview
This document was generated using fallback templates due to LLM service unavailability.

## Manual Review Required
The following areas require manual security analysis:
- Component security assessment
- Threat identification
- Risk evaluation
- Mitigation strategies

## Next Steps
1. Restore LLM service connectivity
2. Regenerate documents with full analysis
3. Conduct manual security review
4. Implement identified security measures

*Note: This is a fallback document with limited analysis.*
"""


class LLMManager:
    """Enhanced LLM manager with error recovery and fallback mechanisms"""
    
    def __init__(self):
        self.primary_client: Optional[BaseLLMClient] = None
        self.fallback_client = FallbackLLMClient()
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.circuit_breaker_threshold = 5
        self.circuit_breaker_timeout = 300  # 5 minutes
        
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the appropriate LLM client"""
        try:
            if settings.llm_provider == "openai":
                self.primary_client = OpenAICompatibleClient()
            elif settings.llm_provider == "azure":
                self.primary_client = AzureOpenAIClient()
            else:
                logger.warning(f"Unknown LLM provider: {settings.llm_provider}, using fallback")
                self.primary_client = None
            
            # Validate configuration
            if self.primary_client and not self.primary_client.validate_config():
                logger.error("LLM client configuration invalid, using fallback")
                self.primary_client = None
                
        except Exception as e:
            logger.error(f"Failed to initialize LLM client: {e}, using fallback")
            self.primary_client = None
    
    async def generate_completion(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: float = 0.7
    ) -> LLMResponse:
        """Generate completion with fallback and circuit breaker"""
        
        # Check circuit breaker
        if self._is_circuit_breaker_open():
            logger.warning("Circuit breaker open, using fallback client")
            return await self.fallback_client.generate_completion(
                prompt, system_prompt, max_tokens, temperature
            )
        
        # Try primary client first
        if self.primary_client:
            try:
                response = await self.primary_client.generate_completion(
                    prompt, system_prompt, max_tokens, temperature
                )
                
                # Reset failure count on success
                self.failure_count = 0
                return response
                
            except Exception as e:
                logger.error(f"Primary LLM client failed: {e}")
                self._record_failure()
                
                # For certain error types, don't use fallback
                if isinstance(e, LLMError) and e.error_type in [
                    LLMErrorType.INVALID_REQUEST, 
                    LLMErrorType.CONTENT_FILTER
                ]:
                    raise
        
        # Use fallback client
        logger.info("Using fallback LLM client")
        return await self.fallback_client.generate_completion(
            prompt, system_prompt, max_tokens, temperature
        )
    
    def _is_circuit_breaker_open(self) -> bool:
        """Check if circuit breaker is open"""
        if self.failure_count < self.circuit_breaker_threshold:
            return False
        
        time_since_failure = time.time() - self.last_failure_time
        return time_since_failure < self.circuit_breaker_timeout
    
    def _record_failure(self):
        """Record a failure for circuit breaker"""
        self.failure_count += 1
        self.last_failure_time = time.time()
    
    def get_status(self) -> Dict[str, Any]:
        """Get LLM manager status"""
        return {
            "primary_client_available": self.primary_client is not None,
            "primary_client_type": type(self.primary_client).__name__ if self.primary_client else None,
            "failure_count": self.failure_count,
            "circuit_breaker_open": self._is_circuit_breaker_open(),
            "fallback_available": True,
            "stats": self.primary_client.get_stats() if self.primary_client else {}
        }
    
    async def close(self):
        """Close all clients"""
        if self.primary_client:
            await self.primary_client.close()