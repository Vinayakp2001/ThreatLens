#!/usr/bin/env python3
"""
ThreatLens CLI - Command Line Interface for Threat Modeling Operations

This CLI provides commands for analyzing pull requests, generating comprehensive
threat modeling documentation, and visualizing threat models.
"""

import click
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import asyncio

# Add backend to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from backend.main import ThreatLensApp
from backend.models.system_model import System
from backend.models.threats import Threat
from backend.analysis.repo_parser import RepoParser
from backend.analysis.system_builder import SystemBuilder
from backend.analysis.threat_identification import ThreatIdentifier
from backend.generation.report_generator import ReportGenerator


class CLIError(Exception):
    """Custom exception for CLI errors"""
    pass


def setup_app() -> ThreatLensApp:
    """Initialize the ThreatLens application"""
    try:
        return ThreatLensApp()
    except Exception as e:
        raise CLIError(f"Failed to initialize ThreatLens: {e}")


def format_output(data: Any, format_type: str = "json") -> str:
    """Format output data for display"""
    if format_type == "json":
        return json.dumps(data, indent=2, default=str)
    elif format_type == "table":
        # Simple table formatting for threat data
        if isinstance(data, list) and data and isinstance(data[0], dict):
            headers = list(data[0].keys())
            output = " | ".join(headers) + "\n"
            output += "-" * len(output) + "\n"
            for item in data:
                output += " | ".join(str(item.get(h, "")) for h in headers) + "\n"
            return output
    return str(data)


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--config', '-c', type=click.Path(exists=True), help='Path to config file')
@click.pass_context
def cli(ctx, verbose: bool, config: Optional[str]):
    """ThreatLens CLI for threat modeling operations
    
    This tool helps security engineers and developers perform threat modeling
    analysis on repositories and pull requests using OWASP methodologies.
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['config'] = config
    
    if verbose:
        click.echo("ThreatLens CLI initialized in verbose mode")


@cli.command()
@click.argument('pr_url', type=str)
@click.option('--output', '-o', type=click.Path(), help='Output file for analysis results')
@click.option('--format', '-f', type=click.Choice(['json', 'markdown']), default='json', 
              help='Output format')
@click.option('--include-mitigations', is_flag=True, 
              help='Include mitigation recommendations in output')
@click.pass_context
def analyze_pr(ctx, pr_url: str, output: Optional[str], format: str, include_mitigations: bool):
    """Analyze a pull request for security implications
    
    This command performs comprehensive security analysis of a pull request,
    identifying potential threats using STRIDE methodology and providing
    OWASP-aligned recommendations.
    
    Example:
        threatlens analyze-pr https://github.com/owner/repo/pull/123
    """
    try:
        if ctx.obj['verbose']:
            click.echo(f"Analyzing PR: {pr_url}")
        
        app = setup_app()
        
        # Extract repo info from PR URL
        # Simple URL parsing - in production, would use proper GitHub API
        if 'github.com' not in pr_url:
            raise CLIError("Currently only GitHub PRs are supported")
        
        # Run async analysis
        result = asyncio.run(app.analyze_pr(pr_url))
        
        if not result:
            raise CLIError("Analysis failed - no results returned")
        
        # Format results
        if format == 'markdown':
            formatted_output = _format_pr_analysis_markdown(result, include_mitigations)
        else:
            formatted_output = format_output(result, 'json')
        
        # Output results
        if output:
            Path(output).write_text(formatted_output)
            click.echo(f"Analysis results written to {output}")
        else:
            click.echo(formatted_output)
        
        # Summary
        if ctx.obj['verbose']:
            threats_count = len(result.get('threats', []))
            click.echo(f"\nAnalysis complete: {threats_count} threats identified")
            
    except Exception as e:
        click.echo(f"Error analyzing PR: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('repo_path', type=click.Path(exists=True))
@click.option('--output-dir', '-o', type=click.Path(), 
              help='Output directory for generated documentation')
@click.option('--include-components', is_flag=True, 
              help='Generate component-level threat documentation')
@click.option('--include-checklists', is_flag=True, 
              help='Generate review checklists')
@click.pass_context
def generate_docs(ctx, repo_path: str, output_dir: Optional[str], 
                  include_components: bool, include_checklists: bool):
    """Generate comprehensive repository threat modeling documentation
    
    This command analyzes a repository and generates complete threat modeling
    documentation following the four questions methodology:
    1. What are we working on?
    2. What can go wrong?
    3. What are we going to do about it?
    4. Did we do a good enough job?
    
    Example:
        threatlens generate-docs /path/to/repo --output-dir ./docs/security
    """
    try:
        if ctx.obj['verbose']:
            click.echo(f"Generating documentation for: {repo_path}")
        
        app = setup_app()
        repo_path = Path(repo_path).resolve()
        
        if not output_dir:
            output_dir = repo_path / "docs" / "security"
        else:
            output_dir = Path(output_dir)
        
        # Run documentation generation
        result = asyncio.run(app.generate_threat_model_docs(
            str(repo_path), 
            str(output_dir),
            include_components=include_components,
            include_checklists=include_checklists
        ))
        
        if not result:
            raise CLIError("Documentation generation failed")
        
        click.echo(f"Documentation generated in: {output_dir}")
        
        # List generated files
        if ctx.obj['verbose']:
            click.echo("\nGenerated files:")
            for file_path in output_dir.rglob("*.md"):
                click.echo(f"  - {file_path.relative_to(output_dir)}")
                
    except Exception as e:
        click.echo(f"Error generating documentation: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('repo_id', type=str)
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'summary']), 
              default='summary', help='Display format')
@click.option('--filter-stride', type=click.Choice(['S', 'T', 'R', 'I', 'D', 'E']), 
              help='Filter threats by STRIDE category')
@click.option('--min-risk', type=click.IntRange(1, 10), 
              help='Minimum risk score to display')
@click.pass_context
def show_threat_model(ctx, repo_id: str, format: str, filter_stride: Optional[str], 
                      min_risk: Optional[int]):
    """Display threat model for a repository
    
    This command retrieves and displays the threat model for a previously
    analyzed repository, showing system components, identified threats,
    and mitigation strategies.
    
    Example:
        threatlens show-threat-model my-repo --format summary --min-risk 5
    """
    try:
        if ctx.obj['verbose']:
            click.echo(f"Loading threat model for: {repo_id}")
        
        app = setup_app()
        
        # Load threat model from storage
        threat_model = app.get_threat_model(repo_id)
        
        if not threat_model:
            raise CLIError(f"No threat model found for repository: {repo_id}")
        
        # Apply filters
        threats = threat_model.get('threats', [])
        if filter_stride:
            threats = [t for t in threats if t.get('stride_category') == filter_stride]
        
        if min_risk:
            threats = [t for t in threats if t.get('risk_score', 0) >= min_risk]
        
        # Format and display
        if format == 'summary':
            _display_threat_model_summary(threat_model, threats)
        elif format == 'table':
            click.echo(format_output(threats, 'table'))
        else:
            click.echo(format_output(threat_model, 'json'))
            
    except Exception as e:
        click.echo(f"Error displaying threat model: {e}", err=True)
        sys.exit(1)


def _format_pr_analysis_markdown(result: Dict[str, Any], include_mitigations: bool) -> str:
    """Format PR analysis results as Markdown"""
    output = f"# PR Security Analysis\n\n"
    output += f"**Repository:** {result.get('repository', 'Unknown')}\n"
    output += f"**PR Number:** {result.get('pr_number', 'Unknown')}\n"
    output += f"**Analysis Date:** {result.get('analysis_date', 'Unknown')}\n\n"
    
    # System changes
    if 'system_changes' in result:
        output += "## What are we working on?\n\n"
        changes = result['system_changes']
        output += f"- **Components Modified:** {len(changes.get('components', []))}\n"
        output += f"- **New Dependencies:** {len(changes.get('dependencies', []))}\n"
        output += f"- **Configuration Changes:** {len(changes.get('config_changes', []))}\n\n"
    
    # Threats
    threats = result.get('threats', [])
    if threats:
        output += "## What can go wrong?\n\n"
        for threat in threats:
            output += f"### {threat.get('title', 'Unknown Threat')}\n"
            output += f"- **STRIDE Category:** {threat.get('stride_category', 'Unknown')}\n"
            output += f"- **Risk Score:** {threat.get('risk_score', 'Unknown')}\n"
            output += f"- **Description:** {threat.get('description', 'No description')}\n\n"
    
    # Mitigations
    if include_mitigations and 'mitigations' in result:
        output += "## What are we going to do about it?\n\n"
        for mitigation in result['mitigations']:
            output += f"- **{mitigation.get('title', 'Unknown')}:** {mitigation.get('description', '')}\n"
    
    return output


def _display_threat_model_summary(threat_model: Dict[str, Any], threats: list):
    """Display a formatted summary of the threat model"""
    click.echo(f"Threat Model Summary for: {threat_model.get('system_name', 'Unknown')}")
    click.echo("=" * 60)
    
    # System overview
    system = threat_model.get('system', {})
    click.echo(f"Components: {len(system.get('components', []))}")
    click.echo(f"Data Stores: {len(system.get('data_stores', []))}")
    click.echo(f"External Entities: {len(system.get('external_entities', []))}")
    click.echo()
    
    # Threat summary
    click.echo(f"Total Threats: {len(threats)}")
    if threats:
        # Group by STRIDE category
        stride_counts = {}
        risk_levels = {'High': 0, 'Medium': 0, 'Low': 0}
        
        for threat in threats:
            category = threat.get('stride_category', 'Unknown')
            stride_counts[category] = stride_counts.get(category, 0) + 1
            
            risk_score = threat.get('risk_score', 0)
            if risk_score >= 7:
                risk_levels['High'] += 1
            elif risk_score >= 4:
                risk_levels['Medium'] += 1
            else:
                risk_levels['Low'] += 1
        
        click.echo("\nSTRIDE Distribution:")
        for category, count in stride_counts.items():
            click.echo(f"  {category}: {count}")
        
        click.echo("\nRisk Distribution:")
        for level, count in risk_levels.items():
            click.echo(f"  {level}: {count}")


if __name__ == '__main__':
    cli()