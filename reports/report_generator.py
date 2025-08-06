# report_generator.py
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from datetime import datetime
import json

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.custom_styles = self._create_custom_styles()
    
    def _create_custom_styles(self):
        """Create custom styles for the report"""
        return {
            'title': ParagraphStyle(
                'CustomTitle',
                parent=self.styles['Title'],
                fontSize=24,
                textColor=colors.HexColor('#1f4e79'),
                spaceAfter=30
            ),
            'heading': ParagraphStyle(
                'CustomHeading',
                parent=self.styles['Heading1'],
                fontSize=16,
                textColor=colors.HexColor('#2e5d8a'),
                spaceBefore=20,
                spaceAfter=12
            ),
            'threat_high': ParagraphStyle(
                'ThreatHigh',
                parent=self.styles['Normal'],
                textColor=colors.red,
                fontName='Helvetica-Bold'
            ),
            'threat_medium': ParagraphStyle(
                'ThreatMedium',
                parent=self.styles['Normal'],
                textColor=colors.orange,
                fontName='Helvetica-Bold'
            ),
            'threat_low': ParagraphStyle(
                'ThreatLow',
                parent=self.styles['Normal'],
                textColor=colors.green,
                fontName='Helvetica-Bold'
            )
        }
    
    def generate_scan_report(self, scan_results, output_path):
        """Generate comprehensive scan report"""
        try:
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            story = []
            
            # Title
            title = Paragraph("Advanced Antivirus Scan Report", self.custom_styles['title'])
            story.append(title)
            story.append(Spacer(1, 20))
            
            # Summary section
            self._add_summary_section(story, scan_results)
            
            # Detailed results
            self._add_detailed_results(story, scan_results)
            
            # Recommendations
            self._add_recommendations(story, scan_results)
            
            # Footer
            self._add_footer(story)
            
            doc.build(story)
            return True, f"Report generated: {output_path}"
            
        except Exception as e:
            return False, f"Report generation failed: {str(e)}"
    
    def _add_summary_section(self, story, scan_results):
        """Add summary section to report"""
        story.append(Paragraph("Scan Summary", self.custom_styles['heading']))
        
        # Calculate summary statistics
        total_files = len(scan_results)
        malicious_count = sum(1 for r in scan_results if r.get('threat_level') == 'malicious')
        suspicious_count = sum(1 for r in scan_results if r.get('threat_level') == 'suspicious')
        safe_count = total_files - malicious_count - suspicious_count
        
        summary_data = [
            ['Metric', 'Count', 'Percentage'],
            ['Total Files Scanned', str(total_files), '100%'],
            ['Safe Files', str(safe_count), f'{(safe_count/total_files)*100:.1f}%' if total_files > 0 else '0%'],
            ['Suspicious Files', str(suspicious_count), f'{(suspicious_count/total_files)*100:.1f}%' if total_files > 0 else '0%'],
            ['Malicious Files', str(malicious_count), f'{(malicious_count/total_files)*100:.1f}%' if total_files > 0 else '0%'],
        ]
        
        table = Table(summary_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Scan information
        scan_info = f"""
        <b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Scan Duration:</b> N/A<br/>
        <b>Scanner Version:</b> Advanced Antivirus v1.0.0
        """
        story.append(Paragraph(scan_info, self.styles['Normal']))
        story.append(Spacer(1, 20))
    
    def _add_detailed_results(self, story, scan_results):
        """Add detailed scan results"""
        story.append(Paragraph("Detailed Scan Results", self.custom_styles['heading']))
        
        for i, result in enumerate(scan_results, 1):
            # File header
            file_name = result.get('file_path', 'Unknown file')
            story.append(Paragraph(f"<b>{i}. {file_name}</b>", self.styles['Heading2']))
            
            # Threat level
            threat_level = result.get('threat_level', 'unknown').upper()
            threat_style = self._get_threat_style(threat_level)
            story.append(Paragraph(f"<b>Threat Level:</b> {threat_level}", threat_style))
            
            # File hash
            file_hash = result.get('file_hash', 'N/A')
            story.append(Paragraph(f"<b>File Hash (SHA256):</b> {file_hash}", self.styles['Normal']))
            
            # VirusTotal results
            vt_result = result.get('vt_result', {})
            if vt_result and not vt_result.get('error'):
                detection_count = vt_result.get('detection_count', 0)
                total_engines = vt_result.get('total_engines', 0)
                story.append(Paragraph(
                    f"<b>VirusTotal:</b> {detection_count}/{total_engines} engines detected threats",
                    self.styles['Normal']
                ))
            
            # Heuristic results
            heuristic_result = result.get('heuristic_result', {})
            if heuristic_result.get('suspicious_indicators'):
                indicators = '<br/>'.join(f"• {indicator}" for indicator in heuristic_result['suspicious_indicators'])
                story.append(Paragraph(f"<b>Heuristic Indicators:</b><br/>{indicators}", self.styles['Normal']))
            
            # YARA matches
            yara_result = result.get('yara_result', {})
            if yara_result.get('matches'):
                matches = '<br/>'.join(f"• {match['rule_name']}: {match['description']}" 
                                     for match in yara_result['matches'])
                story.append(Paragraph(f"<b>YARA Matches:</b><br/>{matches}", self.styles['Normal']))
            
            story.append(Spacer(1, 15))
    
    def _add_recommendations(self, story, scan_results):
        """Add security recommendations"""
        story.append(Paragraph("Security Recommendations", self.custom_styles['heading']))
        
        recommendations = []
        
        # Check for threats
        has_threats = any(r.get('threat_level') in ['malicious', 'suspicious'] for r in scan_results)
        
        if has_threats:
            recommendations.extend([
                "• Immediately quarantine or remove all malicious files",
                "• Run a full system scan with updated antivirus software",
                "• Check system logs for signs of compromise",
                "• Update all software and operating system patches",
                "• Consider changing passwords for sensitive accounts"
            ])
        else:
            recommendations.extend([
                "• Continue regular security scans",
                "• Keep antivirus definitions updated",
                "• Maintain current software patches",
                "• Be cautious when downloading files from the internet",
                "• Enable real-time protection features"
            ])
        
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['Normal']))
        
        story.append(Spacer(1, 20))
    
    def _add_footer(self, story):
        """Add report footer"""
        footer_text = f"""
        <i>This report was generated by Advanced Antivirus Solution on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}.<br/>
        For technical support or questions about this report, please contact your system administrator.</i>
        """
        story.append(Paragraph(footer_text, self.styles['Normal']))
    
    def _get_threat_style(self, threat_level):
        """Get appropriate style for threat level"""
        threat_level = threat_level.lower()
        if threat_level == 'malicious':
            return self.custom_styles['threat_high']
        elif threat_level == 'suspicious':
            return self.custom_styles['threat_medium']
        else:
            return self.custom_styles['threat_low']
    
    def generate_text_report(self, scan_results, output_path):
        """Generate simple text report"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("ADVANCED ANTIVIRUS SCAN REPORT\n")
                f.write("="*80 + "\n\n")
                
                # Summary
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Files Scanned: {len(scan_results)}\n\n")
                
                # Results
                for i, result in enumerate(scan_results, 1):
                    f.write(f"{i}. {result.get('file_path', 'Unknown')}\n")
                    f.write(f"   Threat Level: {result.get('threat_level', 'unknown').upper()}\n")
                    f.write(f"   File Hash: {result.get('file_hash', 'N/A')}\n")
                    
                    vt_result = result.get('vt_result', {})
                    if vt_result and not vt_result.get('error'):
                        f.write(f"   VirusTotal: {vt_result.get('detection_count', 0)}/{vt_result.get('total_engines', 0)} detections\n")
                    
                    f.write("\n")
                
                f.write("="*80 + "\n")
                f.write("Report generated by Advanced Antivirus Solution v1.0.0\n")
            
            return True, f"Text report generated: {output_path}"
            
        except Exception as e:
            return False, f"Text report generation failed: {str(e)}"
