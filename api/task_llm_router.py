"""
Task-Based LLM Router for Effectiveness-Optimized Model Selection

Routes different tasks to appropriate models based on effectiveness requirements:
- Local models for simple, repetitive tasks
- Cloud models for complex, high-quality tasks
- Task-specific parameter optimization
"""

import logging
from typing import Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

from .config import settings
from .llm_client import LLMManager

logger = logging.getLogger(__name__)
DEBUG_ANALYSIS = logging.getLogger('DEBUG_ANALYSIS')


class TaskComplexity(Enum):
    """Task complexity levels for model routing"""
    SIMPLE = "simple"           # Basic operations, embeddings
    STANDARD = "standard"       # Regular analysis tasks
    CREATIVE = "creative"       # Threat brainstorming, ideation
    ANALYTICAL = "analytical"   # Precise analysis, mitigations
    CRITICAL = "critical"       # High-stakes, must be accurate


class TaskType(Enum):
    """Specific task types with effectiveness requirements"""
    # Simple tasks - Local models preferred
    EMBEDDING_GENERATION = "embedding_generation"
    BASIC_CLASSIFICATION = "basic_classification"
    SIMPLE_EXTRACTION = "simple_extraction"
    
    # Standard tasks - Balanced approach
    SECURITY_OVERVIEW = "security_overview"
    COMPONENT_ANALYSIS = "component_analysis"
    AUTHENTICATION_ANALYSIS = "authentication_analysis"
    
    # Creative tasks - Cloud models with higher temperature
    THREAT_BRAINSTORMING = "threat_brainstorming"
    FLOW_THREAT_ANALYSIS = "flow_threat_analysis"
    ATTACK_SCENARIO_GENERATION = "attack_scenario_generation"
    
    # Analytical tasks - Cloud models with lower temperature
    MITIGATION_RECOMMENDATIONS = "mitigation_recommendations"
    SECURITY_CONTROLS = "security_controls"
    COMPLIANCE_ANALYSIS = "compliance_analysis"
    
    # Critical tasks - Best available model
    EXECUTIVE_SUMMARY = "executive_summary"
    RISK_ASSESSMENT = "risk_assessment"
    SECURITY_REQUIREMENTS = "security_requirements"


@dataclass
class TaskConfig:
    """Configuration for specific task types"""
    task_type: TaskType
    complexity: TaskComplexity
    preferred_provider: str  # "local", "cloud", "best"
    temperature: float
    max_tokens: int
    requires_accuracy: bool
    requires_creativity: bool
    cost_sensitivity: str  # "low", "medium", "high"


class TaskLLMRouter:
    """
    Routes tasks to appropriate LLM based on effectiveness requirements
    """
    
    def __init__(self):
        self.llm_manager = LLMManager()
        self.task_configs = self._initialize_task_configs()
        self.provider_availability = self._check_provider_availability()
    
    def _initialize_task_configs(self) -> Dict[TaskType, TaskConfig]:
        """Initialize task-specific configurations"""
        return {
            # Simple tasks - Local models preferred for cost efficiency
            TaskType.EMBEDDING_GENERATION: TaskConfig(
                task_type=TaskType.EMBEDDING_GENERATION,
                complexity=TaskComplexity.SIMPLE,
                preferred_provider="local",
                temperature=0.1,
                max_tokens=500,
                requires_accuracy=True,
                requires_creativity=False,
                cost_sensitivity="high"
            ),
            TaskType.BASIC_CLASSIFICATION: TaskConfig(
                task_type=TaskType.BASIC_CLASSIFICATION,
                complexity=TaskComplexity.SIMPLE,
                preferred_provider="local",
                temperature=0.2,
                max_tokens=1000,
                requires_accuracy=True,
                requires_creativity=False,
                cost_sensitivity="high"
            ),
            
            # Standard tasks - Balanced approach
            TaskType.SECURITY_OVERVIEW: TaskConfig(
                task_type=TaskType.SECURITY_OVERVIEW,
                complexity=TaskComplexity.STANDARD,
                preferred_provider="cloud",
                temperature=0.3,
                max_tokens=4000,
                requires_accuracy=True,
                requires_creativity=False,
                cost_sensitivity="medium"
            ),
            TaskType.COMPONENT_ANALYSIS: TaskConfig(
                task_type=TaskType.COMPONENT_ANALYSIS,
                complexity=TaskComplexity.STANDARD,
                preferred_provider="cloud",
                temperature=0.3,
                max_tokens=3000,
                requires_accuracy=True,
                requires_creativity=False,
                cost_sensitivity="medium"
            ),
            TaskType.AUTHENTICATION_ANALYSIS: TaskConfig(
                task_type=TaskType.AUTHENTICATION_ANALYSIS,
                complexity=TaskComplexity.STANDARD,
                preferred_provider="cloud",
                temperature=0.3,
                max_tokens=3000,
                requires_accuracy=True,
                requires_creativity=False,
                cost_sensitivity="medium"
            ),
            
            # Creative tasks - Cloud models with higher temperature
            TaskType.THREAT_BRAINSTORMING: TaskConfig(
                task_type=TaskType.THREAT_BRAINSTORMING,
                complexity=TaskComplexity.CREATIVE,
                preferred_provider="cloud",
                temperature=0.4,
                max_tokens=4000,
                requires_accuracy=False,
                requires_creativity=True,
                cost_sensitivity="low"
            ),
            TaskType.FLOW_THREAT_ANALYSIS: TaskConfig(
                task_type=TaskType.FLOW_THREAT_ANALYSIS,
                complexity=TaskComplexity.CREATIVE,
                preferred_provider="cloud",
                temperature=0.4,
                max_tokens=6000,
                requires_accuracy=False,
                requires_creativity=True,
                cost_sensitivity="low"
            ),
            TaskType.ATTACK_SCENARIO_GENERATION: TaskConfig(
                task_type=TaskType.ATTACK_SCENARIO_GENERATION,
                complexity=TaskComplexity.CREATIVE,
                preferred_provider="cloud",
                temperature=0.5,
                max_tokens=4000,
                requires_accuracy=False,
                requires_creativity=True,
                cost_sensitivity="low"
            ),
            
            # Analytical tasks - Cloud models with lower temperature
            TaskType.MITIGATION_RECOMMENDATIONS: TaskConfig(
                task_type=TaskType.MITIGATION_RECOMMENDATIONS,
                complexity=TaskComplexity.ANALYTICAL,
                preferred_provider="cloud",
                temperature=0.2,
                max_tokens=8000,
                requires_accuracy=True,
                requires_creativity=False,
                cost_sensitivity="low"
            ),
            TaskType.SECURITY_CONTROLS: TaskConfig(
                task_type=TaskType.SECURITY_CONTROLS,
                complexity=TaskComplexity.ANALYTICAL,
                preferred_provider="cloud",
                temperature=0.2,
                max_tokens=5000,
                requires_accuracy=True,
                requires_creativity=False,
                cost_sensitivity="low"
            ),
            TaskType.COMPLIANCE_ANALYSIS: TaskConfig(
                task_type=TaskType.COMPLIANCE_ANALYSIS,
                complexity=TaskComplexity.ANALYTICAL,
                preferred_provider="cloud",
                temperature=0.2,
                max_tokens=4000,
                requires_accuracy=True,
                requires_creativity=False,
                cost_sensitivity="low"
            ),
            
            # Critical tasks - Best available model
            TaskType.EXECUTIVE_SUMMARY: TaskConfig(
                task_type=TaskType.EXECUTIVE_SUMMARY,
                complexity=TaskComplexity.CRITICAL,
                preferred_provider="best",
                temperature=0.3,
                max_tokens=3000,
                requires_accuracy=True,
                requires_creativity=False,
                cost_sensitivity="low"
            ),
            TaskType.RISK_ASSESSMENT: TaskConfig(
                task_type=TaskType.RISK_ASSESSMENT,
                complexity=TaskComplexity.CRITICAL,
                preferred_provider="best",
                temperature=0.2,
                max_tokens=4000,
                requires_accuracy=True,
                requires_creativity=False,
                cost_sensitivity="low"
            ),
            TaskType.SECURITY_REQUIREMENTS: TaskConfig(
                task_type=TaskType.SECURITY_REQUIREMENTS,
                complexity=TaskComplexity.CRITICAL,
                preferred_provider="best",
                temperature=0.2,
                max_tokens=6000,
                requires_accuracy=True,
                requires_creativity=False,
                cost_sensitivity="low"
            )
        }
    
    def _check_provider_availability(self) -> Dict[str, bool]:
        """Check which providers are available"""
        return {
            "local": settings.llm_provider == "huggingface",
            "openai": bool(settings.openai_api_key),
            "anthropic": bool(settings.anthropic_api_key),
            "google": bool(settings.google_api_key)
        }
    
    async def route_task(
        self,
        task_type: TaskType,
        prompt: str,
        system_prompt: Optional[str] = None,
        override_provider: Optional[str] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Route task to appropriate LLM based on effectiveness requirements
        
        Returns:
            Tuple of (response_content, metadata)
        """
        DEBUG_ANALYSIS.info(f"TASK_ROUTER: Routing task {task_type.value}")
        DEBUG_ANALYSIS.info(f"TASK_ROUTER: Routing task {task_type.value}")
        config = self.task_configs.get(task_type)
        if not config:
            raise ValueError(f"Unknown task type: {task_type}")
        
        # Determine provider to use
        DEBUG_ANALYSIS.info(f"TASK_ROUTER: Selecting provider for {task_type.value}")
        DEBUG_ANALYSIS.info(f"TASK_ROUTER: Selecting provider for {task_type.value}")
        provider = self._select_provider(config, override_provider)
        DEBUG_ANALYSIS.info(f"TASK_ROUTER: Selected provider: {provider}")
        DEBUG_ANALYSIS.info(f"TASK_ROUTER: Selected provider: {provider}")
        
        # Configure LLM manager for this provider
        original_provider = self.llm_manager.provider
        try:
            if provider != original_provider:
                self._switch_provider(provider)
            
            # Execute task with optimized parameters
            DEBUG_ANALYSIS.info(f"TASK_ROUTER: Executing task with {provider}")
            response = await self.llm_manager.generate_completion(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=config.temperature,
                max_tokens=config.max_tokens
            )
            
            metadata = {
                "task_type": task_type.value,
                "complexity": config.complexity.value,
                "provider_used": provider,
                "temperature": config.temperature,
                "max_tokens": config.max_tokens,
                "requires_accuracy": config.requires_accuracy,
                "requires_creativity": config.requires_creativity,
                "cost_sensitivity": config.cost_sensitivity,
                "llm_model": response.model,
                "llm_usage": response.usage,
                "response_time": response.response_time
            }
            
            DEBUG_ANALYSIS.info(f"TASK_ROUTER: Task completed - {len(response.content)} chars")
            return response.content, metadata
            
        finally:
            # Restore original provider
            if provider != original_provider:
                self._switch_provider(original_provider)
    
    def _select_provider(self, config: TaskConfig, override: Optional[str] = None) -> str:
        """Select the best provider for this task"""
        if override:
            if override in self.provider_availability and self.provider_availability[override]:
                return override
            else:
                logger.warning(f"Override provider {override} not available, using default routing")
        
        preferred = config.preferred_provider
        
        if preferred == "local":
            if self.provider_availability.get("local"):
                return "huggingface"
            else:
                # Fallback to cloud for better quality
                return self._get_best_cloud_provider()
        
        elif preferred == "cloud":
            return self._get_best_cloud_provider()
        
        elif preferred == "best":
            # Use best available provider regardless of cost
            if self.provider_availability.get("openai"):
                return "openai"
            elif self.provider_availability.get("anthropic"):
                return "anthropic"
            elif self.provider_availability.get("google"):
                return "google"
            elif self.provider_availability.get("local"):
                return "huggingface"
            else:
                raise RuntimeError("No LLM providers available")
        
        else:
            return self._get_best_cloud_provider()
    
    def _get_best_cloud_provider(self) -> str:
        """Get the best available cloud provider"""
        # Priority order: OpenAI > Anthropic > Google > Local
        if self.provider_availability.get("openai"):
            return "openai"
        elif self.provider_availability.get("anthropic"):
            return "anthropic"
        elif self.provider_availability.get("google"):
            return "google"
        elif self.provider_availability.get("local"):
            return "huggingface"
        else:
            raise RuntimeError("No LLM providers available")
    
    def _switch_provider(self, provider: str):
        """Switch LLM manager to different provider"""
        logger.info(f"Switching LLM provider to: {provider}")
        
        # Actually switch the provider in the LLM manager
        if provider == "openai":
            self.llm_manager.provider = "openai"
            self.llm_manager.model = "gpt-3.5-turbo"  # Use cheaper model for testing
        elif provider == "huggingface":
            self.llm_manager.provider = "huggingface"
            self.llm_manager.model = "microsoft/DialoGPT-medium"
        elif provider == "anthropic":
            self.llm_manager.provider = "anthropic"
            self.llm_manager.model = "claude-3-sonnet-20240229"
        elif provider == "google":
            self.llm_manager.provider = "google"
            self.llm_manager.model = "gemini-1.5-pro"
        
        # Reinitialize the client with new provider
        self.llm_manager._initialize_client()
    
    def get_task_config(self, task_type: TaskType) -> TaskConfig:
        """Get configuration for a specific task type"""
        return self.task_configs.get(task_type)
    
    def get_provider_costs(self) -> Dict[str, Dict[str, float]]:
        """Get estimated costs for different providers"""
        return {
            "huggingface": {"input_cost": 0.0, "output_cost": 0.0},  # Local, no cost
            "openai": {"input_cost": 0.0015, "output_cost": 0.002},  # GPT-3.5-turbo per 1K tokens
            "anthropic": {"input_cost": 0.008, "output_cost": 0.024},  # Claude per 1K tokens
            "google": {"input_cost": 0.00025, "output_cost": 0.0005}  # Gemini per 1K tokens
        }
    
    def estimate_task_cost(self, task_type: TaskType, provider: Optional[str] = None) -> float:
        """Estimate cost for a specific task"""
        DEBUG_ANALYSIS.info(f"TASK_ROUTER: Routing task {task_type.value}")
        DEBUG_ANALYSIS.info(f"TASK_ROUTER: Routing task {task_type.value}")
        config = self.task_configs.get(task_type)
        if not config:
            return 0.0
        
        if not provider:
            provider = self._select_provider(config)
        
        costs = self.get_provider_costs()
        provider_costs = costs.get(provider, {"input_cost": 0.0, "output_cost": 0.0})
        
        # Rough estimation based on max_tokens
        estimated_input_tokens = 1000  # Average prompt size
        estimated_output_tokens = config.max_tokens * 0.8  # Assume 80% of max
        
        total_cost = (
            (estimated_input_tokens / 1000) * provider_costs["input_cost"] +
            (estimated_output_tokens / 1000) * provider_costs["output_cost"]
        )
        
        return total_cost


# Global router instance
_task_router: Optional[TaskLLMRouter] = None


def get_task_router() -> TaskLLMRouter:
    """Get the global task router instance"""
    global _task_router
    if _task_router is None:
        _task_router = TaskLLMRouter()
    return _task_router