"""
Generation layer for ThreatLens threat modeling reports and documentation.

This module provides comprehensive document generation capabilities including:
- Structured prompts for the four threat modeling questions
- Security reports for pull requests and system analysis
- Component-specific threat model documentation
- Security review checklists based on OWASP guidance
"""

from .prompt_templates import (
    FourQuestionsPrompts,
    PromptContext,
    PromptTemplateManager
)

from .report_generator import (
    ThreatModelReportGenerator,
    ReportConfig
)

from .checklist_generator import (
    SecurityChecklistGenerator,
    ChecklistItem,
    ChecklistCategory,
    ChecklistConfig
)

__all__ = [
    # Prompt templates
    'FourQuestionsPrompts',
    'PromptContext', 
    'PromptTemplateManager',
    
    # Report generation
    'ThreatModelReportGenerator',
    'ReportConfig',
    
    # Checklist generation
    'SecurityChecklistGenerator',
    'ChecklistItem',
    'ChecklistCategory',
    'ChecklistConfig'
]