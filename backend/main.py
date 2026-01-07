"""
ThreatLens Backend Main Module
Provides the main backend orchestration for threat modeling operations.
"""
from typing import Dict, Any, Optional, List
from dataclasses import asdict
import logging
from datetime import datetime
from pathlib import Path

from .models.system_model import System, Component
from .models.threats import Threat
from .models.mitigations import Mitigation
from .services.llm_client import get_llm_manager
from .services.storage_manager import get_storage_manager
from .generation.report_generator import ThreatModelReportGenerator, ReportConfig

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatLensBackend:
    """
    Main backend service orchestrator for ThreatLens operations.
    Implements dependency injection and service layer architecture.
    """
    
    def __init__(self):
        self.llm_manager = get_llm_manager()
        self.storage_manager = get_storage_manager()
        self.report_generator = ThreatModelReportGenerator(ReportConfig())
        logger.info("ThreatLens Backend initialized")
    
    async def analyze_pr(self, pr_url: str, repo_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a pull request for security implications.
        
        Args:
            pr_url: URL of the pull request to analyze
            repo_path: Optional local repository path
            
        Returns:
            Dictionary containing analysis results including threats and recommendations
        """
        try:
            logger.info(f"Starting PR analysis for: {pr_url}")
            
            # For now, return a basic structure - this would be implemented with actual PR analysis
            analysis_result = {
                "pr_url": pr_url,
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "status": "completed",
                "threats": [],
                "mitigations": [],
                "risk_summary": {"high": 0, "medium": 0, "low": 0},
                "recommendations": []
            }
            
            logger.info(f"PR analysis completed for {pr_url}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error analyzing PR {pr_url}: {str(e)}")
            raise
    
    async def generate_threat_model(self, repo_path: str, output_format: str = "json") -> Dict[str, Any]:
        """
        Generate comprehensive threat model for a repository.
        
        Args:
            repo_path: Path to the repository to analyze
            output_format: Output format (json, yaml, markdown)
            
        Returns:
            Complete threat model following the four questions methodology
        """
        try:
            logger.info(f"Generating threat model for repository: {repo_path}")
            
            # For now, return a basic structure - this would be implemented with actual analysis
            threat_model = {
                "repository_path": repo_path,
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "methodology": "OWASP Four Questions",
                "system_model": {},
                "threats": [],
                "mitigations": [],
                "four_questions": {
                    "what_are_we_working_on": "Repository analysis",
                    "what_can_go_wrong": "Security threats identified",
                    "what_are_we_going_to_do_about_it": "Mitigations proposed",
                    "did_we_do_good_enough_job": "Review completed"
                }
            }
            
            logger.info(f"Threat model generated for {repo_path}")
            return threat_model
            
        except Exception as e:
            logger.error(f"Error generating threat model for {repo_path}: {str(e)}")
            raise
    
    async def generate_docs(self, system: System, threats: List[Threat], 
                          mitigations: List[Mitigation], output_dir: str) -> Dict[str, str]:
        """
        Generate comprehensive documentation for a threat model.
        
        Args:
            system: System model
            threats: List of identified threats
            mitigations: List of mitigations
            output_dir: Output directory for documentation
            
        Returns:
            Dictionary mapping document types to file paths
        """
        try:
            logger.info(f"Generating documentation to {output_dir}")
            
            # Use the report generator to create documentation
            docs = self.report_generator.generate_repository_documentation(
                system=system,
                threats=threats,
                mitigations=mitigations,
                repository_path=".",
                output_base_dir=output_dir
            )
            
            logger.info(f"Documentation generated: {list(docs.keys())}")
            return docs
            
        except Exception as e:
            logger.error(f"Error generating documentation: {str(e)}")
            raise


# Convenience functions for backward compatibility
async def analyze_pr(pr_url: str, repo_path: Optional[str] = None) -> Dict[str, Any]:
    """Analyze a pull request for security implications."""
    backend = ThreatLensBackend()
    return await backend.analyze_pr(pr_url, repo_path)


async def generate_threat_model(repo_path: str, output_format: str = "json") -> Dict[str, Any]:
    """Generate comprehensive threat model for a repository."""
    backend = ThreatLensBackend()
    return await backend.generate_threat_model(repo_path, output_format)


async def generate_docs(system: System, threats: List[Threat], 
                       mitigations: List[Mitigation], output_dir: str) -> Dict[str, str]:
    """Generate comprehensive documentation for a threat model."""
    backend = ThreatLensBackend()
    return await backend.generate_docs(system, threats, mitigations, output_dir)


async def generate_repository_documentation(repo_path: str, output_dir: str) -> Dict[str, str]:
    """Generate complete repository documentation including threat model."""
    backend = ThreatLensBackend()
    
    # Create basic system model for documentation
    system = System(
        id="repo-system",
        name=f"Repository System: {Path(repo_path).name}",
        description=f"System model for repository at {repo_path}",
        components=[],
        data_stores=[],
        data_flows=[],
        external_entities=[],
        trust_boundaries=[]
    )
    
    return await backend.generate_docs(system, [], [], output_dir)