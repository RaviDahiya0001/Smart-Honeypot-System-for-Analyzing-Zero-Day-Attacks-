"""
Views for the Honeypot Dashboard.
"""

import json
import csv
from datetime import datetime, timedelta
from io import BytesIO, StringIO

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods, require_POST
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.db.models import Count, Q
from django.db.models.functions import TruncHour, TruncDay
from django.core.paginator import Paginator

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch

from .models import (
    Connection, LoginAttempt, Command, FileActivity,
    Alert, AttackerProfile, IPBlacklist, HoneypotService
)

def dashboard(request):
    """Main dashboard view with statistics and live feed."""
    
    # Get time range
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    
    # Calculate statistics
    stats = {
        'total_connections': Connection.objects.count(),
        'connections_24h': Connection.objects.filter(timestamp__gte=last_24h).count(),
        'unique_ips': Connection.objects.values('ip_address').distinct().count(),
        'unique_ips_24h': Connection.objects.filter(timestamp__gte=last_24h).values('ip_address').distinct().count(),
        'total_login_attempts': LoginAttempt.objects.count(),
        'login_attempts_24h': LoginAttempt.objects.filter(timestamp__gte=last_24h).count(),
        'total_commands': Command.objects.count(),
        'commands_24h': Command.objects.filter(timestamp__gte=last_24h).count(),
        'total_files': FileActivity.objects.count(),
        'malware_detected': FileActivity.objects.filter(is_malware=True).count(),
        'active_alerts': Alert.objects.filter(is_acknowledged=False).count(),
        'critical_alerts': Alert.objects.filter(severity='CRITICAL', is_acknowledged=False).count(),
        'blacklisted_ips': IPBlacklist.objects.count(),
    }
    
    # Get recent connections for the map
    recent_connections = Connection.objects.filter(
        latitude__isnull=False,
        longitude__isnull=False
    ).order_by('-timestamp')[:100]
    
    map_data = [
        {
            'lat': conn.latitude,
            'lng': conn.longitude,
            'ip': conn.ip_address,
            'country': conn.country,
            'protocol': conn.protocol,
            'timestamp': conn.timestamp.isoformat(),
        }
        for conn in recent_connections
    ]
    
    # Get protocol distribution
    protocol_stats = Connection.objects.values('protocol').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Get hourly attack trend (last 24 hours)
    hourly_trend = Connection.objects.filter(
        timestamp__gte=last_24h
    ).annotate(
        hour=TruncHour('timestamp')
    ).values('hour').annotate(
        count=Count('id')
    ).order_by('hour')
    
    # Get top attacking countries
    top_countries = Connection.objects.exclude(
        country__isnull=True
    ).exclude(
        country=''
    ).values('country', 'country_code').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Get recent alerts
    recent_alerts = Alert.objects.filter(
        is_acknowledged=False
    ).order_by('-timestamp')[:10]
    
    # Get honeypot service statuses
    services = HoneypotService.objects.all()
    
    context = {
        'stats': stats,
        'map_data': json.dumps(map_data),
        'protocol_stats': list(protocol_stats),
        'hourly_trend': list(hourly_trend),
        'top_countries': list(top_countries),
        'recent_alerts': recent_alerts,
        'services': services,
    }
    
    return render(request, 'dashboard/dashboard.html', context)


def attacks(request):
    """View all attacks with filtering and pagination."""
    
    # Get filter parameters
    protocol = request.GET.get('protocol', '')
    ip_filter = request.GET.get('ip', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    # Base queryset
    connections = Connection.objects.all()
    
    # Apply filters
    if protocol:
        connections = connections.filter(protocol=protocol)
    if ip_filter:
        connections = connections.filter(ip_address__contains=ip_filter)
    if date_from:
        connections = connections.filter(timestamp__gte=date_from)
    if date_to:
        connections = connections.filter(timestamp__lte=date_to)
    
    # Paginate
    paginator = Paginator(connections, 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'connections': page_obj,
        'protocol': protocol,
        'ip_filter': ip_filter,
        'date_from': date_from,
        'date_to': date_to,
        'protocols': Connection.PROTOCOL_CHOICES,
    }
    
    return render(request, 'dashboard/attacks.html', context)


def alerts_view(request):
    """View and manage security alerts."""
    
    # Get filter parameters
    severity = request.GET.get('severity', '')
    alert_type = request.GET.get('type', '')
    acknowledged = request.GET.get('acknowledged', '')
    
    # Base queryset
    alerts = Alert.objects.all()
    
    # Apply filters
    if severity:
        alerts = alerts.filter(severity=severity)
    if alert_type:
        alerts = alerts.filter(alert_type=alert_type)
    if acknowledged == 'yes':
        alerts = alerts.filter(is_acknowledged=True)
    elif acknowledged == 'no':
        alerts = alerts.filter(is_acknowledged=False)
    
    # Paginate
    paginator = Paginator(alerts, 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'alerts': page_obj,
        'severity': severity,
        'alert_type': alert_type,
        'acknowledged': acknowledged,
        'severity_choices': Alert.SEVERITY_LEVELS,
        'type_choices': Alert.ALERT_TYPES,
    }
    
    return render(request, 'dashboard/alerts.html', context)


def attackers(request):
    """View attacker profiles."""
    
    # Get attacker profiles ordered by threat score
    profiles = AttackerProfile.objects.all().order_by('-threat_score')
    
    # Paginate
    paginator = Paginator(profiles, 25)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'profiles': page_obj,
    }
    
    return render(request, 'dashboard/attackers.html', context)


def attacker_detail(request, ip_address):
    """View detailed information about a specific attacker."""
    
    profile = get_object_or_404(AttackerProfile, ip_address=ip_address)
    
    # Get related data
    connections = Connection.objects.filter(ip_address=ip_address).order_by('-timestamp')[:50]
    login_attempts = LoginAttempt.objects.filter(ip_address=ip_address).order_by('-timestamp')[:50]
    commands = Command.objects.filter(ip_address=ip_address).order_by('-timestamp')[:50]
    files = FileActivity.objects.filter(ip_address=ip_address).order_by('-timestamp')[:50]
    alerts = Alert.objects.filter(ip_address=ip_address).order_by('-timestamp')[:20]
    
    context = {
        'profile': profile,
        'connections': connections,
        'login_attempts': login_attempts,
        'commands': commands,
        'files': files,
        'alerts': alerts,
    }
    
    return render(request, 'dashboard/attacker_detail.html', context)


def reports(request):
    """Reports generation page."""
    return render(request, 'dashboard/reports.html')


def settings_view(request):
    """System settings page."""
    
    services = HoneypotService.objects.all()
    blacklist = IPBlacklist.objects.order_by('-created_at')[:20]
    
    context = {
        'services': services,
        'blacklist': blacklist,
    }
    
    return render(request, 'dashboard/settings.html', context)


# Export functionality
def export_csv(request):
    """Export attack data as CSV."""
    
    export_type = request.GET.get('type', 'connections')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="honeypot_{export_type}_{timezone.now().strftime("%Y%m%d")}.csv"'
    
    writer = csv.writer(response)
    
    if export_type == 'connections':
        writer.writerow(['IP Address', 'Port', 'Protocol', 'Country', 'City', 'Timestamp'])
        connections = Connection.objects.all()
        if date_from:
            connections = connections.filter(timestamp__gte=date_from)
        if date_to:
            connections = connections.filter(timestamp__lte=date_to)
        
        for conn in connections[:10000]:
            writer.writerow([
                conn.ip_address, conn.port, conn.protocol,
                conn.country, conn.city, conn.timestamp.isoformat()
            ])
    
    elif export_type == 'login_attempts':
        writer.writerow(['IP Address', 'Username', 'Password', 'Service', 'Success', 'Timestamp'])
        attempts = LoginAttempt.objects.all()
        if date_from:
            attempts = attempts.filter(timestamp__gte=date_from)
        if date_to:
            attempts = attempts.filter(timestamp__lte=date_to)
        
        for attempt in attempts[:10000]:
            writer.writerow([
                attempt.ip_address, attempt.username, attempt.password,
                attempt.service, attempt.success, attempt.timestamp.isoformat()
            ])
    
    elif export_type == 'commands':
        writer.writerow(['IP Address', 'Command', 'Service', 'Risk Level', 'Timestamp'])
        commands = Command.objects.all()
        if date_from:
            commands = commands.filter(timestamp__gte=date_from)
        if date_to:
            commands = commands.filter(timestamp__lte=date_to)
        
        for cmd in commands[:10000]:
            writer.writerow([
                cmd.ip_address, cmd.command, cmd.service,
                cmd.risk_level, cmd.timestamp.isoformat()
            ])
    
    elif export_type == 'alerts':
        writer.writerow(['Type', 'Severity', 'Title', 'Description', 'IP Address', 'Timestamp'])
        alerts = Alert.objects.all()
        if date_from:
            alerts = alerts.filter(timestamp__gte=date_from)
        if date_to:
            alerts = alerts.filter(timestamp__lte=date_to)
        
        for alert in alerts[:10000]:
            writer.writerow([
                alert.alert_type, alert.severity, alert.title,
                alert.description, alert.ip_address, alert.timestamp.isoformat()
            ])
    
    return response


def export_json(request):
    """Export attack data as JSON."""
    
    export_type = request.GET.get('type', 'connections')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    data = []
    
    if export_type == 'connections':
        connections = Connection.objects.all()
        if date_from:
            connections = connections.filter(timestamp__gte=date_from)
        if date_to:
            connections = connections.filter(timestamp__lte=date_to)
        
        data = [
            {
                'ip_address': conn.ip_address,
                'port': conn.port,
                'protocol': conn.protocol,
                'country': conn.country,
                'city': conn.city,
                'latitude': conn.latitude,
                'longitude': conn.longitude,
                'timestamp': conn.timestamp.isoformat(),
            }
            for conn in connections[:10000]
        ]
    
    elif export_type == 'login_attempts':
        attempts = LoginAttempt.objects.all()
        if date_from:
            attempts = attempts.filter(timestamp__gte=date_from)
        if date_to:
            attempts = attempts.filter(timestamp__lte=date_to)
        
        data = [
            {
                'ip_address': attempt.ip_address,
                'username': attempt.username,
                'password': attempt.password,
                'service': attempt.service,
                'success': attempt.success,
                'timestamp': attempt.timestamp.isoformat(),
            }
            for attempt in attempts[:10000]
        ]
    
    response = HttpResponse(
        json.dumps(data, indent=2),
        content_type='application/json'
    )
    response['Content-Disposition'] = f'attachment; filename="honeypot_{export_type}_{timezone.now().strftime("%Y%m%d")}.json"'
    
    return response


def export_pdf(request):
    """Export attack summary as PDF report."""
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.HexColor('#1a1a2e')
    )
    elements.append(Paragraph("🍯 Honeypot Security Report", title_style))
    elements.append(Spacer(1, 12))
    
    # Report date
    elements.append(Paragraph(f"Generated: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['Normal']))
    elements.append(Spacer(1, 20))
    
    # Statistics summary
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    
    stats_data = [
        ['Metric', 'Total', 'Last 24 Hours', 'Last 7 Days'],
        ['Connections', 
         str(Connection.objects.count()),
         str(Connection.objects.filter(timestamp__gte=last_24h).count()),
         str(Connection.objects.filter(timestamp__gte=last_7d).count())],
        ['Unique IPs',
         str(Connection.objects.values('ip_address').distinct().count()),
         str(Connection.objects.filter(timestamp__gte=last_24h).values('ip_address').distinct().count()),
         str(Connection.objects.filter(timestamp__gte=last_7d).values('ip_address').distinct().count())],
        ['Login Attempts',
         str(LoginAttempt.objects.count()),
         str(LoginAttempt.objects.filter(timestamp__gte=last_24h).count()),
         str(LoginAttempt.objects.filter(timestamp__gte=last_7d).count())],
        ['Commands Executed',
         str(Command.objects.count()),
         str(Command.objects.filter(timestamp__gte=last_24h).count()),
         str(Command.objects.filter(timestamp__gte=last_7d).count())],
        ['Malware Detected',
         str(FileActivity.objects.filter(is_malware=True).count()),
         str(FileActivity.objects.filter(is_malware=True, timestamp__gte=last_24h).count()),
         str(FileActivity.objects.filter(is_malware=True, timestamp__gte=last_7d).count())],
        ['Active Alerts',
         str(Alert.objects.filter(is_acknowledged=False).count()),
         '-', '-'],
    ]
    
    table = Table(stats_data, colWidths=[2*inch, 1.2*inch, 1.5*inch, 1.5*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
    ]))
    elements.append(Paragraph("Summary Statistics", styles['Heading2']))
    elements.append(Spacer(1, 12))
    elements.append(table)
    elements.append(Spacer(1, 20))
    
    # Top attacking IPs
    top_ips = Connection.objects.values('ip_address').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    ip_data = [['Rank', 'IP Address', 'Connections']]
    for i, ip in enumerate(top_ips, 1):
        ip_data.append([str(i), ip['ip_address'], str(ip['count'])])
    
    ip_table = Table(ip_data, colWidths=[0.8*inch, 2.5*inch, 1.5*inch])
    ip_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fdf2f2')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#f5c6cb')),
    ]))
    elements.append(Paragraph("Top Attacking IP Addresses", styles['Heading2']))
    elements.append(Spacer(1, 12))
    elements.append(ip_table)
    
    # Build PDF
    doc.build(elements)
    
    buffer.seek(0)
    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="honeypot_report_{timezone.now().strftime("%Y%m%d")}.pdf"'
    
    return response

@require_POST
def resolve_alert(request, alert_id):
    from django.utils import timezone
    try:
        alert = Alert.objects.get(id=alert_id)
        alert.status = request.POST.get('status', 'RESOLVED')
        alert.resolved_by = request.user.username if request.user.is_authenticated else 'admin'
        alert.resolved_at = timezone.now()
        alert.resolution_note = request.POST.get('note', '')
        alert.is_acknowledged = True
        alert.save()

        # Resolution email bhejo
        if alert.status in ('RESOLVED', 'ESCALATED'):
            from dashboard.notifications import send_resolution_email
            send_resolution_email(alert)

        return JsonResponse({'success': True})
    except Alert.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Not found'}, status=404)