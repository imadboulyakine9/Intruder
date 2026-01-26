from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.pdfgen import canvas
from app.db import (get_scans_collection, get_subdomains_collection, 
                    get_technologies_collection, get_vulnerabilities_collection,
                    get_assets_collection, get_attackable_urls_collection)
import datetime
import os
from collections import Counter

class ReportGenerator:
    """
    Generates professional security assessment reports.
    """
    
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.scan_data = get_scans_collection().find_one({"scan_id": scan_id, "type": "master"})
        
        if not self.scan_data:
            raise Exception(f"Scan {scan_id} not found")
        
        self.target = self.scan_data.get('target')
        self.output_dir = "reports"
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def generate_pdf(self):
        """Generate PDF report."""
        filename = f"{self.output_dir}/{self.target}_{self.scan_id[:8]}_report.pdf"
        
        doc = SimpleDocTemplate(filename, pagesize=A4,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)
        
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#00ff9d'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#007bff'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Title Page
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("INTRUDER", title_style))
        story.append(Paragraph("Security Assessment Report", styles['Heading2']))
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(f"<b>Target:</b> {self.target}", styles['Normal']))
        story.append(Paragraph(f"<b>Scan ID:</b> {self.scan_id}", styles['Normal']))
        story.append(Paragraph(f"<b>Generated:</b> {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles['Normal']))
        story.append(PageBreak())
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        summary_data = self._get_summary_data()
        story.append(Paragraph(f"This report presents the findings of a comprehensive security assessment conducted on <b>{self.target}</b>.", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        summary_table_data = [
            ['Metric', 'Count'],
            ['Total Subdomains', str(summary_data['subdomains_count'])],
            ['Live Assets', str(summary_data['live_assets_count'])],
            ['Technologies Detected', str(summary_data['tech_count'])],
            ['Open Ports', str(summary_data['ports_count'])],
            ['Total Vulnerabilities', str(summary_data['total_vulns'])],
            ['Critical/High Severity', str(summary_data['critical_high_count'])]
        ]
        
        summary_table = Table(summary_table_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(PageBreak())
        
        # Reconnaissance Findings
        story.append(Paragraph("Reconnaissance Findings", heading_style))
        
        # Subdomains
        story.append(Paragraph("<b>Discovered Subdomains</b>", styles['Heading3']))
        subdomains = self._get_subdomains()
        if subdomains:
            story.append(Paragraph(f"Total: {len(subdomains)}", styles['Normal']))
            for sub in subdomains[:20]:  # Limit to first 20
                story.append(Paragraph(f"• {sub}", styles['Normal']))
            if len(subdomains) > 20:
                story.append(Paragraph(f"... and {len(subdomains) - 20} more", styles['Italic']))
        else:
            story.append(Paragraph("No subdomains discovered.", styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Technologies
        story.append(Paragraph("<b>Technology Stack</b>", styles['Heading3']))
        technologies = self._get_technologies()
        if technologies:
            tech_list = ", ".join(technologies)
            story.append(Paragraph(tech_list, styles['Normal']))
        else:
            story.append(Paragraph("No technologies detected.", styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Open Ports
        story.append(Paragraph("<b>Open Ports & Services</b>", styles['Heading3']))
        ports = self._get_open_ports()
        if ports:
            port_table_data = [['Port', 'Protocol', 'Service']]
            for port in ports[:10]:  # Limit to 10
                port_table_data.append([
                    str(port.get('port', 'N/A')),
                    str(port.get('protocol', 'N/A')),
                    str(port.get('service', 'N/A'))
                ])
            
            port_table = Table(port_table_data, colWidths=[1.5*inch, 1.5*inch, 2*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(port_table)
        else:
            story.append(Paragraph("No open ports detected.", styles['Normal']))
        
        story.append(PageBreak())
        
        # Vulnerability Findings
        story.append(Paragraph("Vulnerability Assessment", heading_style))
        vulnerabilities = self._get_vulnerabilities()
        
        if vulnerabilities:
            # Group by severity
            by_severity = Counter([v.get('severity', 'UNKNOWN').upper() for v in vulnerabilities])
            
            story.append(Paragraph(f"<b>Total Findings:</b> {len(vulnerabilities)}", styles['Normal']))
            story.append(Paragraph(f"Critical: {by_severity.get('CRITICAL', 0)}, High: {by_severity.get('HIGH', 0)}, Medium: {by_severity.get('MEDIUM', 0)}, Low: {by_severity.get('LOW', 0)}, Info: {by_severity.get('INFO', 0)}", styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            
            # Detailed findings
            for idx, vuln in enumerate(vulnerabilities[:30], 1):  # Limit to 30 findings
                severity = vuln.get('severity', 'UNKNOWN').upper()
                name = vuln.get('name', vuln.get('info', {}).get('name', 'Unknown'))
                tool = vuln.get('tool', 'Unknown')
                location = vuln.get('url', vuln.get('host', 'N/A'))
                
                # Color code by severity
                if severity in ['CRITICAL', 'HIGH']:
                    sev_color = '#ff0055'
                elif severity == 'MEDIUM':
                    sev_color = '#ffc107'
                elif severity == 'LOW':
                    sev_color = '#17a2b8'
                else:
                    sev_color = '#6c757d'
                
                story.append(Paragraph(f"<b>{idx}. [{severity}] {name}</b>", styles['Heading4']))
                story.append(Paragraph(f"<b>Tool:</b> {tool}", styles['Normal']))
                story.append(Paragraph(f"<b>Location:</b> {location}", styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
            
            if len(vulnerabilities) > 30:
                story.append(Paragraph(f"... and {len(vulnerabilities) - 30} more findings", styles['Italic']))
        else:
            story.append(Paragraph("No vulnerabilities detected during this assessment.", styles['Normal']))
        
        story.append(PageBreak())
        
        # Recommendations
        story.append(Paragraph("Recommendations", heading_style))
        recommendations = self._generate_recommendations(summary_data)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", styles['Normal']))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Footer
        story.append(Paragraph("This report was automatically generated by INTRUDER (Jarvis OS).", styles['Italic']))
        
        # Build PDF
        doc.build(story)
        
        return filename
    
    def _get_summary_data(self):
        """Aggregate summary statistics."""
        subdomains = self._get_subdomains()
        assets = self._get_live_assets()
        technologies = self._get_technologies()
        ports = self._get_open_ports()
        vulns = self._get_vulnerabilities()
        
        critical_high = sum(1 for v in vulns if v.get('severity', '').upper() in ['CRITICAL', 'HIGH'])
        
        return {
            'subdomains_count': len(subdomains),
            'live_assets_count': len(assets),
            'tech_count': len(technologies),
            'ports_count': len(ports),
            'total_vulns': len(vulns),
            'critical_high_count': critical_high
        }
    
    def _get_subdomains(self):
        """Fetch subdomains."""
        sub_col = get_subdomains_collection()
        doc = sub_col.find_one({"scan_id": self.scan_id})
        return doc.get('subdomains', []) if doc else []
    
    def _get_technologies(self):
        """Fetch technologies."""
        tech_col = get_technologies_collection()
        docs = tech_col.find({"scan_id": self.scan_id})
        return list(set(doc['name'] for doc in docs if 'name' in doc))
    
    def _get_open_ports(self):
        """Fetch open ports."""
        scans_col = get_scans_collection()
        nmap_doc = scans_col.find_one({"scan_id": self.scan_id, "type": "nmap"})
        return nmap_doc.get('results', []) if nmap_doc else []
    
    def _get_live_assets(self):
        """Fetch live assets."""
        assets_col = get_assets_collection()
        return list(assets_col.find({"scan_id": self.scan_id}))
    
    def _get_vulnerabilities(self):
        """Fetch vulnerabilities."""
        vuln_col = get_vulnerabilities_collection()
        return list(vuln_col.find({"scan_id": self.scan_id}))
    
    def _generate_recommendations(self, summary_data):
        """Generate contextual recommendations."""
        recommendations = []
        
        if summary_data['critical_high_count'] > 0:
            recommendations.append("URGENT: Address all Critical and High severity vulnerabilities immediately.")
        
        if summary_data['ports_count'] > 5:
            recommendations.append("Review open ports and close any unnecessary services to reduce attack surface.")
        
        if summary_data['subdomains_count'] > 20:
            recommendations.append("Consider subdomain takeover protection and DNS security measures.")
        
        recommendations.append("Implement a Web Application Firewall (WAF) if not already in place.")
        recommendations.append("Enable security headers (CSP, HSTS, X-Frame-Options, etc.).")
        recommendations.append("Conduct regular security assessments and maintain an up-to-date asset inventory.")
        recommendations.append("Implement vulnerability disclosure program for responsible reporting.")
        
        return recommendations
    
    def generate_html(self):
        """Generate HTML report (alternative format)."""
        filename = f"{self.output_dir}/{self.target}_{self.scan_id[:8]}_report.html"
        
        summary_data = self._get_summary_data()
        vulnerabilities = self._get_vulnerabilities()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Report - {self.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .header {{ background: #000; color: #00ff9d; padding: 20px; text-align: center; }}
                .section {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }}
                h2 {{ color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
                .vuln-critical {{ background: #ffebee; border-left: 5px solid #f44336; padding: 10px; margin: 10px 0; }}
                .vuln-high {{ background: #fff3e0; border-left: 5px solid #ff9800; padding: 10px; margin: 10px 0; }}
                .vuln-medium {{ background: #fffde7; border-left: 5px solid #ffeb3b; padding: 10px; margin: 10px 0; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #007bff; color: white; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>INTRUDER Security Report</h1>
                <p>Target: {self.target}</p>
                <p>Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <table>
                    <tr><th>Metric</th><th>Count</th></tr>
                    <tr><td>Subdomains</td><td>{summary_data['subdomains_count']}</td></tr>
                    <tr><td>Live Assets</td><td>{summary_data['live_assets_count']}</td></tr>
                    <tr><td>Technologies</td><td>{summary_data['tech_count']}</td></tr>
                    <tr><td>Open Ports</td><td>{summary_data['ports_count']}</td></tr>
                    <tr><td>Total Vulnerabilities</td><td>{summary_data['total_vulns']}</td></tr>
                    <tr><td>Critical/High</td><td>{summary_data['critical_high_count']}</td></tr>
                </table>
            </div>
            
            <div class="section">
                <h2>Vulnerabilities</h2>
        """
        
        for vuln in vulnerabilities[:50]:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            name = vuln.get('name', 'Unknown')
            tool = vuln.get('tool', 'Unknown')
            
            vuln_class = 'vuln-critical' if severity in ['CRITICAL', 'HIGH'] else 'vuln-medium'
            
            html_content += f"""
                <div class="{vuln_class}">
                    <h4>[{severity}] {name}</h4>
                    <p><b>Tool:</b> {tool}</p>
                </div>
            """
        
        html_content += """
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return filename
