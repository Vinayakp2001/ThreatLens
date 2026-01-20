"""
PDF Generator for ThreatLens Security Wikis
Generates professional PDF reports from security wiki data
"""

import json
import sqlite3
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import markdown
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration
import logging

logger = logging.getLogger(__name__)

class WikiPDFGenerator:
    """Generate professional PDF reports from security wiki data"""
    
    def __init__(self):
        self.font_config = FontConfiguration()
        
    def generate_pdf(self, repo_id: str, db_path: str) -> bytes:
        """Generate PDF from wiki data"""
        try:
            # Get wiki data from database
            wiki_data = self._get_wiki_data(repo_id, db_path)
            if not wiki_data:
                raise ValueError(f"No wiki data found for repo_id: {repo_id}")
            
            # Generate HTML content
            html_content = self._generate_html(wiki_data)
            
            # Generate PDF
            pdf_bytes = self._html_to_pdf(html_content)
            
            return pdf_bytes
            
        except Exception as e:
            logger.error(f"Failed to generate PDF for repo {repo_id}: {str(e)}")
            raise
    
    def _get_wiki_data(self, repo_id: str, db_path: str) -> Optional[Dict[str, Any]]:
        """Retrieve wiki data from database"""
        try:
            with sqlite3.connect(db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT uw.*, sw.content as wiki_content, sw.title as wiki_title
                    FROM user_wikis uw
                    LEFT JOIN security_wikis sw ON uw.repo_id = sw.repository_id
                    WHERE uw.repo_id = ?
                    ORDER BY uw.created_at DESC
                    LIMIT 1
                """, (repo_id,))
                    WHERE uw.repo_id = ?
                    ORDER BY uw.created_at DESC
                    LIMIT 1
                """, (repo_id,))
                
                row = cursor.fetchone()
                if not row or not row['wiki_content']:
                    return None
                
                # Parse sections
                sections = json.loads(row['wiki_content'])
                
                return {
                    'repo_id': repo_id,
                    'repository_name': row['repository_name'],
                    'repository_url': row['repository_url'],
                    'title': row['wiki_title'] or f"{row['repository_name']} Security Wiki",
                    'sections': sections,
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at'] or row['created_at']
                }
                
        except Exception as e:
            logger.error(f"Failed to get wiki data: {str(e)}")
            return None
    
    def _generate_html(self, wiki_data: Dict[str, Any]) -> str:
        """Generate HTML content for PDF"""
        
        # Get current date for report
        report_date = datetime.now().strftime("%B %d, %Y")
        
        # Start building HTML
        html_parts = [
            self._get_html_header(),
            self._get_cover_page(wiki_data, report_date),
            self._get_table_of_contents(wiki_data['sections']),
        ]
        
        # Add each section
        for section_id, section_data in wiki_data['sections'].items():
            html_parts.append(self._generate_section_html(section_id, section_data))
        
        # Add footer
        html_parts.append(self._get_html_footer())
        
        return '\n'.join(html_parts)
    
    def _get_html_header(self) -> str:
        """Generate HTML header with CSS styling"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatLens Security Report</title>
    <style>
        @page {
            size: A4;
            margin: 2cm;
            @top-center {
                content: "ThreatLens Security Report";
                font-family: Arial, sans-serif;
                font-size: 10pt;
                color: #666;
            }
            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-family: Arial, sans-serif;
                font-size: 10pt;
                color: #666;
            }
        }
        
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
        }
        
        .cover-page {
            page-break-after: always;
            text-align: center;
            padding-top: 5cm;
        }
        
        .cover-title {
            font-size: 36pt;
            font-weight: bold;
            color: #2563eb;
            margin-bottom: 1cm;
        }
        
        .cover-subtitle {
            font-size: 18pt;
            color: #666;
            margin-bottom: 2cm;
        }
        
        .cover-info {
            font-size: 12pt;
            color: #888;
        }
        
        .toc {
            page-break-after: always;
        }
        
        .toc-title {
            font-size: 24pt;
            font-weight: bold;
            margin-bottom: 1cm;
            color: #2563eb;
        }
        
        .toc-item {
            margin: 0.5cm 0;
            font-size: 12pt;
        }
        
        .toc-item a {
            text-decoration: none;
            color: #333;
        }
        
        .section {
            page-break-before: always;
            margin-bottom: 2cm;
        }
        
        .section-title {
            font-size: 20pt;
            font-weight: bold;
            color: #2563eb;
            margin-bottom: 1cm;
            border-bottom: 2px solid #2563eb;
            padding-bottom: 0.5cm;
        }
        
        .section-content {
            font-size: 11pt;
            line-height: 1.8;
        }
        
        .section-content h1 {
            font-size: 16pt;
            color: #1e40af;
            margin-top: 1cm;
            margin-bottom: 0.5cm;
        }
        
        .section-content h2 {
            font-size: 14pt;
            color: #1e40af;
            margin-top: 0.8cm;
            margin-bottom: 0.4cm;
        }
        
        .section-content h3 {
            font-size: 12pt;
            color: #1e40af;
            margin-top: 0.6cm;
            margin-bottom: 0.3cm;
        }
        
        .security-finding {
            background-color: #fef2f2;
            border-left: 4px solid #ef4444;
            padding: 1cm;
            margin: 1cm 0;
        }
        
        .security-finding-title {
            font-weight: bold;
            color: #dc2626;
            margin-bottom: 0.5cm;
        }
        
        .severity-high {
            background-color: #fef2f2;
            border-color: #ef4444;
        }
        
        .severity-medium {
            background-color: #fffbeb;
            border-color: #f59e0b;
        }
        
        .severity-low {
            background-color: #f0fdf4;
            border-color: #10b981;
        }
        
        .owasp-mapping {
            background-color: #f0f9ff;
            border: 1px solid #0ea5e9;
            padding: 0.5cm;
            margin: 0.5cm 0;
            border-radius: 4px;
        }
        
        .code-block {
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            padding: 1cm;
            font-family: 'Courier New', monospace;
            font-size: 9pt;
            overflow-x: auto;
            margin: 0.5cm 0;
        }
        
        .recommendations {
            background-color: #f0fdf4;
            border-left: 4px solid #10b981;
            padding: 1cm;
            margin: 1cm 0;
        }
        
        .recommendations-title {
            font-weight: bold;
            color: #059669;
            margin-bottom: 0.5cm;
        }
        
        ul, ol {
            margin: 0.5cm 0;
            padding-left: 1.5cm;
        }
        
        li {
            margin: 0.3cm 0;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1cm 0;
        }
        
        th, td {
            border: 1px solid #e2e8f0;
            padding: 0.5cm;
            text-align: left;
        }
        
        th {
            background-color: #f8fafc;
            font-weight: bold;
        }
    </style>
</head>
<body>
'''
    
    def _get_cover_page(self, wiki_data: Dict[str, Any], report_date: str) -> str:
        """Generate cover page"""
        return f'''
<div class="cover-page">
    <div class="cover-title">Security Analysis Report</div>
    <div class="cover-subtitle">{wiki_data['repository_name']}</div>
    <div class="cover-info">
        <p><strong>Repository:</strong> {wiki_data['repository_url']}</p>
        <p><strong>Generated:</strong> {report_date}</p>
        <p><strong>Powered by:</strong> ThreatLens</p>
    </div>
</div>
'''
    
    def _get_table_of_contents(self, sections: Dict[str, Any]) -> str:
        """Generate table of contents"""
        toc_items = []
        
        section_titles = {
            'executive_summary': 'Executive Summary',
            'system_architecture': 'System Architecture & Components',
            'authentication_analysis': 'Authentication & Authorization Analysis',
            'data_flow_security': 'Data Flow Security Assessment',
            'vulnerability_analysis': 'Vulnerability Analysis',
            'threat_landscape': 'Threat Landscape',
            'security_controls': 'Security Controls & Mitigations',
            'risk_assessment': 'Risk Assessment Matrix',
            'security_checklist': 'Security Checklist & Recommendations',
            'code_findings': 'Code-Level Security Findings'
        }
        
        for section_id, section_data in sections.items():
            title = section_data.get('title', section_titles.get(section_id, section_id.replace('_', ' ').title()))
            toc_items.append(f'<div class="toc-item"><a href="#{section_id}">{title}</a></div>')
        
        return f'''
<div class="toc">
    <div class="toc-title">Table of Contents</div>
    {''.join(toc_items)}
</div>
'''
    
    def _generate_section_html(self, section_id: str, section_data: Dict[str, Any]) -> str:
        """Generate HTML for a single section"""
        title = section_data.get('title', section_id.replace('_', ' ').title())
        content = section_data.get('content', '')
        
        # Convert markdown to HTML
        html_content = markdown.markdown(content, extensions=['tables', 'fenced_code'])
        
        # Add security findings if present
        findings_html = self._generate_findings_html(section_data.get('security_findings', []))
        
        # Add OWASP mappings if present
        owasp_html = self._generate_owasp_html(section_data.get('owasp_mappings', []))
        
        # Add recommendations if present
        recommendations_html = self._generate_recommendations_html(section_data.get('recommendations', []))
        
        return f'''
<div class="section" id="{section_id}">
    <div class="section-title">{title}</div>
    <div class="section-content">
        {html_content}
        {findings_html}
        {owasp_html}
        {recommendations_html}
    </div>
</div>
'''
    
    def _generate_findings_html(self, findings: list) -> str:
        """Generate HTML for security findings"""
        if not findings:
            return ''
        
        findings_html = []
        for finding in findings:
            severity = finding.get('severity', 'medium').lower()
            severity_class = f"severity-{severity}"
            
            finding_html = f'''
<div class="security-finding {severity_class}">
    <div class="security-finding-title">{finding.get('type', 'Security Finding')} - {severity.upper()}</div>
    <p>{finding.get('description', '')}</p>
    {self._generate_recommendations_html(finding.get('recommendations', []))}
</div>
'''
            findings_html.append(finding_html)
        
        return ''.join(findings_html)
    
    def _generate_owasp_html(self, mappings: list) -> str:
        """Generate HTML for OWASP mappings"""
        if not mappings:
            return ''
        
        mappings_list = ', '.join(mappings)
        return f'''
<div class="owasp-mapping">
    <strong>OWASP References:</strong> {mappings_list}
</div>
'''
    
    def _generate_recommendations_html(self, recommendations: list) -> str:
        """Generate HTML for recommendations"""
        if not recommendations:
            return ''
        
        rec_items = ''.join([f'<li>{rec}</li>' for rec in recommendations])
        return f'''
<div class="recommendations">
    <div class="recommendations-title">Recommendations:</div>
    <ul>{rec_items}</ul>
</div>
'''
    
    def _get_html_footer(self) -> str:
        """Generate HTML footer"""
        return '''
</body>
</html>
'''
    
    def _html_to_pdf(self, html_content: str) -> bytes:
        """Convert HTML to PDF"""
        try:
            # Create HTML document
            html_doc = HTML(string=html_content)
            
            # Generate PDF
            pdf_bytes = html_doc.write_pdf(font_config=self.font_config)
            
            return pdf_bytes
            
        except Exception as e:
            logger.error(f"Failed to convert HTML to PDF: {str(e)}")
            raise