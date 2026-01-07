"""
ThreatLens Backend

This is the main backend module for ThreatLens, providing:
- Threat modeling and analysis
- Security documentation generation
- OWASP-aligned security guidance
- Repository analysis and PR review

The backend is organized into the following modules:
- analysis: Repository and threat analysis
- config: Configuration management
- database: Data persistence
- generation: Documentation and report generation
- models: Data models and schemas
- owasp: OWASP content and guidance
- services: Core services (LLM, storage, etc.)
- api: FastAPI web interface
"""

from .main import (
    analyze_pr,
    generate_threat_model,
    generate_docs,
    generate_repository_documentation,
    ThreatLensBackend
)

from .config.settings import settings, config_manager
from .database.manager import get_database_manager
from .services.llm_client import get_llm_manager
from .services.storage_manager import get_storage_manager

__version__ = "2.0.0"
__all__ = [
    "analyze_pr",
    "generate_threat_model", 
    "generate_docs",
    "generate_repository_documentation",
    "ThreatLensBackend",
    "settings",
    "config_manager",
    "get_database_manager",
    "get_llm_manager",
    "get_storage_manager"
]