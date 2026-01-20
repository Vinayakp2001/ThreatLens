"""
Simple PDF Generator for ThreatLens Security Wikis
Uses ReportLab for reliable cross-platform PDF generation
"""

import json
import sqlite3
from datetime import datetime
from typing import Dict, Any, Optional
import logging
import re
from io import BytesIO

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, red, orange, green
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

logger = logging.getLogger(__name__)

class SimplePDFGenerator:
    """Generate professional PDF reports using ReportLab"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        
        # Cover page title
        self.styles.add(ParagraphStyle(
            name='CoverTitle',
            parent=self.styles['Title'],
            fontSize=28,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=HexColor('#2563eb')
        ))
        
        # Cover page subtitle
        self.styles.add(ParagraphStyle(
            name='CoverSubtitle',
            parent=self.styles['Normal'],
            fontSize=16,
            spaceAfter=20,
            alignment=TA_CENTER,
            textColor=HexColor('#666666')
        ))
        
        # Section titles
        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=20,
            textColor=HexColor('#2563eb'),
            borderWidth=1,
            borderColor=HexColor('#2563eb'),
            borderPadding=10
        ))
        
        # Security finding styles
        self.styles.add(ParagraphStyle(
            name='SecurityFinding',
            parent=self.styles['Normal'],
            fontSize=10,
            leftIndent=20,
            rightIndent=20,
            spaceAfter=10,
            borderWidth=1,
            borderColor=red,
            borderPadding=10,
            backColor=HexColor('#fef2f2')
        ))
        
        # OWASP mapping style
        self.styles.add(ParagraphStyle(
            name='OwaspMapping',
            parent=self.styles['Normal'],
            fontSize=10,
            leftIndent=20,
            rightIndent=20,
            spaceAfter=10,
            borderWidth=1,
            borderColor=HexColor('#0ea5e9'),
            borderPadding=10,
            backColor=HexColor('#f0f9ff')
        ))
        
        # Recommendations style
        self.styles.add(ParagraphStyle(
            name='Recommendations',
            parent=self.styles['Normal'],
            fontSize=10,
            leftIndent=20,
            rightIndent=20,
            spaceAfter=10,
            borderWidth=1,
            borderColor=green,
            borderPadding=10,
            backColor=HexColor('#f0fdf4')
        ))
    
    def generate_pdf(self, repo_id: str, db_path: str) -> bytes:
        """Generate PDF from wiki data"""
        try:
            # Get wiki data from database
            wiki_data = self._get_wiki_data(repo_id, db_path)
            if not wiki_data:
                raise ValueError(f"No wiki data found for repo_id: {repo_id}")
            
            # Create PDF buffer
            buffer = BytesIO()
            
            # Create document
            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build content
            story = []
            
            # Add cover page
            story.extend(self._create_cover_page(wiki_data))
            story.append(PageBreak())
            
            # Add table of contents
            story.extend(self._create_table_of_contents(wiki_data['sections']))
            story.append(PageBreak())
            
            # Add sections
            for section_id, section_data in wiki_data['sections'].items():
                story.extend(self._create_section(section_id, section_data))
                story.append(PageBreak())
            
            # Build PDF
            doc.build(story)
            
            # Get PDF bytes
            pdf_bytes = buffer.getvalue()
            buffer.close()
            
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
    
    def _create_cover_page(self, wiki_data: Dict[str, Any]) -> list:
        """Create cover page elements"""
        story = []
        
        # Add some space from top
        story.append(Spacer(1, 2*inch))
        
        # Title
        story.append(Paragraph("Security Analysis Report", self.styles['CoverTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        # Repository name
        story.append(Paragraph(wiki_data['repository_name'], self.styles['CoverSubtitle']))
        story.append(Spacer(1, 1*inch))
        
        # Repository info
        info_text = f"""
        <b>Repository:</b> {wiki_data['repository_url']}<br/>
        <b>Generated:</b> {datetime.now().strftime('%B %d, %Y')}<br/>
        <b>Powered by:</b> ThreatLens
        """
        story.append(Paragraph(info_text, self.styles['Normal']))
        
        return story
    
    def _create_table_of_contents(self, sections: Dict[str, Any]) -> list:
        """Create table of contents"""
        story = []
        
        # TOC Title
        story.append(Paragraph("Table of Contents", self.styles['Heading1']))
        story.append(Spacer(1, 0.3*inch))
        
        # Section titles mapping
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
        
        # Create TOC entries
        toc_data = []
        for i, (section_id, section_data) in enumerate(sections.items(), 1):
            title = section_data.get('title', section_titles.get(section_id, section_id.replace('_', ' ').title()))
            toc_data.append([f"{i}.", title])
        
        # Create table
        toc_table = Table(toc_data, colWidths=[0.5*inch, 5*inch])
        toc_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        story.append(toc_table)
        
        return story
    
    def _create_section(self, section_id: str, section_data: Dict[str, Any]) -> list:
        """Create section elements"""
        story = []
        
        # Section title
        title = section_data.get('title', section_id.replace('_', ' ').title())
        story.append(Paragraph(title, self.styles['SectionTitle']))
        story.append(Spacer(1, 0.2*inch))
        
        # Section content
        content = section_data.get('content', '')
        if content:
            # Clean and format content
            formatted_content = self._format_content(content)
            story.append(Paragraph(formatted_content, self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        # Security findings
        findings = section_data.get('security_findings', [])
        if findings:
            story.append(Paragraph("<b>Security Findings:</b>", self.styles['Heading2']))
            for finding in findings:
                finding_text = self._format_security_finding(finding)
                story.append(Paragraph(finding_text, self.styles['SecurityFinding']))
                story.append(Spacer(1, 0.1*inch))
        
        # OWASP mappings
        owasp_mappings = section_data.get('owasp_mappings', [])
        if owasp_mappings:
            mappings_text = f"<b>OWASP References:</b> {', '.join(owasp_mappings)}"
            story.append(Paragraph(mappings_text, self.styles['OwaspMapping']))
            story.append(Spacer(1, 0.1*inch))
        
        # Recommendations
        recommendations = section_data.get('recommendations', [])
        if recommendations:
            rec_text = "<b>Recommendations:</b><br/>"
            for i, rec in enumerate(recommendations, 1):
                rec_text += f"{i}. {rec}<br/>"
            story.append(Paragraph(rec_text, self.styles['Recommendations']))
        
        return story
    
    def _format_content(self, content: str) -> str:
        """Format markdown-like content for ReportLab"""
        # Convert markdown headers to bold text
        content = re.sub(r'^### (.*$)', r'<b>\1</b>', content, flags=re.MULTILINE)
        content = re.sub(r'^## (.*$)', r'<b>\1</b>', content, flags=re.MULTILINE)
        content = re.sub(r'^# (.*$)', r'<b>\1</b>', content, flags=re.MULTILINE)
        
        # Convert markdown bold
        content = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', content)
        
        # Convert markdown italic
        content = re.sub(r'\*(.*?)\*', r'<i>\1</i>', content)
        
        # Convert code blocks
        content = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', content)
        
        # Convert line breaks
        content = content.replace('\n\n', '<br/><br/>')
        content = content.replace('\n', '<br/>')
        
        return content
    
    def _format_security_finding(self, finding: Dict[str, Any]) -> str:
        """Format security finding for display"""
        finding_type = finding.get('type', 'Security Finding')
        severity = finding.get('severity', 'medium').upper()
        description = finding.get('description', '')
        recommendations = finding.get('recommendations', [])
        
        # Choose color based on severity
        severity_color = {
            'HIGH': 'red',
            'CRITICAL': 'red',
            'MEDIUM': 'orange',
            'LOW': 'green'
        }.get(severity, 'black')
        
        text = f'<b><font color="{severity_color}">{finding_type} - {severity}</font></b><br/>'
        text += f'{description}<br/>'
        
        if recommendations:
            text += '<b>Recommendations:</b><br/>'
            for i, rec in enumerate(recommendations, 1):
                text += f'{i}. {rec}<br/>'
        
        return text