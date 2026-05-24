"""
Report Generator Module
Generates PDF, CSV, and JSON reports.
"""

import os
import json
import csv
from io import BytesIO, StringIO
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from django.conf import settings
from django.utils import timezone

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.units import inch


class ReportGenerator:
    """Generates various reports from honeypot data."""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
    
    def generate_pdf_report(self, days: int = 7) -> bytes:
        """Generate a comprehensive PDF report."""
        import django
        django.setup()
        
        from dashboard.models import Connection, LoginAttempt, Command, Alert, AttackerProfile
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []
        
        now = timezone.now()
        start_date = now - timedelta(days=days)
        
        # Title
        title_style = ParagraphStyle(
            'Title',
            parent=self.styles['Heading1'],
            fontSize=28,
            spaceAfter=30,
            textColor=colors.HexColor('#1a1a2e')
        )
        elements.append(Paragraph("🍯 Honeypot Security Report", title_style))
        elements.append(Paragraph(f"Report Period: {start_date.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}", self.styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Executive Summary
        elements.append(Paragraph("Executive Summary", self.styles['Heading2']))
        elements.append(Spacer(1, 10))
        
        total_connections = Connection.objects.filter(timestamp__gte=start_date).count()
        total_logins = LoginAttempt.objects.filter(timestamp__gte=start_date).count()
        total_commands = Command.objects.filter(timestamp__gte=start_date).count()
        total_alerts = Alert.objects.filter(timestamp__gte=start_date).count()
        unique_ips = Connection.objects.filter(timestamp__gte=start_date).values('ip_address').distinct().count()
        
        summary = f"""
        During the reporting period, the honeypot system recorded:
        • {total_connections:,} total connections from {unique_ips:,} unique IP addresses
        • {total_logins:,} login attempts across all services
        • {total_commands:,} commands executed by attackers
        • {total_alerts:,} security alerts generated
        """
        elements.append(Paragraph(summary, self.styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Statistics Table
        elements.append(Paragraph("Attack Statistics", self.styles['Heading2']))
        stats_data = [
            ['Metric', 'Count'],
            ['Total Connections', str(total_connections)],
            ['Unique IPs', str(unique_ips)],
            ['Login Attempts', str(total_logins)],
            ['Commands Executed', str(total_commands)],
            ['Alerts Generated', str(total_alerts)],
        ]
        
        table = Table(stats_data, colWidths=[3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))
        
        # Top Attackers
        elements.append(Paragraph("Top Attackers", self.styles['Heading2']))
        top_attackers = AttackerProfile.objects.order_by('-threat_score')[:10]
        
        attacker_data = [['IP Address', 'Threat Level', 'Connections', 'Country']]
        for attacker in top_attackers:
            attacker_data.append([
                attacker.ip_address,
                attacker.threat_level,
                str(attacker.total_connections),
                attacker.country or 'Unknown'
            ])
        
        if len(attacker_data) > 1:
            attacker_table = Table(attacker_data, colWidths=[2*inch, 1.5*inch, 1.2*inch, 1.5*inch])
            attacker_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ]))
            elements.append(attacker_table)
        
        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        return buffer.read()
    
    def generate_csv_export(self, data_type: str, start_date: Optional[datetime] = None, 
                           end_date: Optional[datetime] = None) -> str:
        """Generate CSV export of data."""
        import django
        django.setup()
        
        from dashboard.models import Connection, LoginAttempt, Command, Alert
        
        output = StringIO()
        writer = csv.writer(output)
        
        if data_type == 'connections':
            writer.writerow(['IP Address', 'Port', 'Protocol', 'Country', 'City', 'Timestamp'])
            queryset = Connection.objects.all()
            if start_date:
                queryset = queryset.filter(timestamp__gte=start_date)
            if end_date:
                queryset = queryset.filter(timestamp__lte=end_date)
            
            for conn in queryset[:10000]:
                writer.writerow([
                    conn.ip_address, conn.port, conn.protocol,
                    conn.country, conn.city, conn.timestamp.isoformat()
                ])
        
        elif data_type == 'login_attempts':
            writer.writerow(['IP Address', 'Username', 'Password', 'Service', 'Success', 'Timestamp'])
            queryset = LoginAttempt.objects.all()
            if start_date:
                queryset = queryset.filter(timestamp__gte=start_date)
            
            for attempt in queryset[:10000]:
                writer.writerow([
                    attempt.ip_address, attempt.username, attempt.password,
                    attempt.service, attempt.success, attempt.timestamp.isoformat()
                ])
        
        return output.getvalue()
    
    def generate_json_export(self, data_type: str, start_date: Optional[datetime] = None) -> str:
        """Generate JSON export of data."""
        import django
        django.setup()
        
        from dashboard.models import Connection, LoginAttempt, Command
        
        data = []
        
        if data_type == 'connections':
            queryset = Connection.objects.all()
            if start_date:
                queryset = queryset.filter(timestamp__gte=start_date)
            
            data = [{
                'ip_address': c.ip_address,
                'port': c.port,
                'protocol': c.protocol,
                'country': c.country,
                'city': c.city,
                'latitude': c.latitude,
                'longitude': c.longitude,
                'timestamp': c.timestamp.isoformat(),
            } for c in queryset[:10000]]
        
        return json.dumps(data, indent=2)
    
    def generate_siem_export(self) -> List[Dict]:
        """Generate SIEM-compatible export (CEF format)."""
        import django
        django.setup()
        
        from dashboard.models import Alert
        
        events = []
        for alert in Alert.objects.filter(is_acknowledged=False)[:1000]:
            cef = {
                'CEF': '0',
                'Device Vendor': 'HoneyTrap',
                'Device Product': 'Smart Honeypot',
                'Device Version': '1.0',
                'Signature ID': alert.alert_type,
                'Name': alert.title,
                'Severity': {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}.get(alert.severity, 1),
                'Extension': {
                    'src': alert.ip_address,
                    'msg': alert.description,
                    'rt': alert.timestamp.isoformat(),
                }
            }
            events.append(cef)
        
        return events


# Global instance
report_generator = ReportGenerator()
