"""
REST API views for the dashboard.
"""

import json
from datetime import timedelta
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.db.models import Count
from django.db.models.functions import TruncHour, TruncDay

from .models import (
    Connection, LoginAttempt, Command, FileActivity,
    Alert, AttackerProfile, IPBlacklist, HoneypotService
)


def get_stats(request):
    """Get overall statistics."""
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    
    stats = {
        'total_connections': Connection.objects.count(),
        'connections_24h': Connection.objects.filter(timestamp__gte=last_24h).count(),
        'unique_ips': Connection.objects.values('ip_address').distinct().count(),
        'total_login_attempts': LoginAttempt.objects.count(),
        'total_commands': Command.objects.count(),
        'malware_detected': FileActivity.objects.filter(is_malware=True).count(),
        'active_alerts': Alert.objects.filter(is_acknowledged=False).count(),
        'critical_alerts': Alert.objects.filter(severity='CRITICAL', is_acknowledged=False).count(),
    }
    return JsonResponse(stats)


def get_timeline(request):
    """Get attack timeline data."""
    hours = int(request.GET.get('hours', 24))
    now = timezone.now()
    since = now - timedelta(hours=hours)
    
    data = Connection.objects.filter(timestamp__gte=since).annotate(
        hour=TruncHour('timestamp')
    ).values('hour').annotate(count=Count('id')).order_by('hour')
    
    return JsonResponse({'timeline': list(data)}, safe=False)


def get_connections(request):
    """Get paginated connections."""
    page = int(request.GET.get('page', 1))
    limit = int(request.GET.get('limit', 50))
    offset = (page - 1) * limit
    
    connections = Connection.objects.all()[offset:offset+limit]
    data = [{
        'id': c.id, 'ip': c.ip_address, 'port': c.port,
        'protocol': c.protocol, 'country': c.country,
        'timestamp': c.timestamp.isoformat()
    } for c in connections]
    
    return JsonResponse({'connections': data, 'total': Connection.objects.count()})


def get_recent_connections(request):
    """Get recent connections for live feed."""
    limit = int(request.GET.get('limit', 20))
    connections = Connection.objects.order_by('-timestamp')[:limit]
    
    data = [{
        'id': c.id, 'ip': c.ip_address, 'port': c.port,
        'protocol': c.protocol, 'country': c.country,
        'city': c.city, 'timestamp': c.timestamp.isoformat()
    } for c in connections]
    
    return JsonResponse({'connections': data})


def get_login_attempts(request):
    """Get recent login attempts."""
    limit = int(request.GET.get('limit', 50))
    attempts = LoginAttempt.objects.order_by('-timestamp')[:limit]
    
    data = [{
        'id': a.id, 'ip': a.ip_address, 'username': a.username,
        'service': a.service, 'success': a.success,
        'timestamp': a.timestamp.isoformat()
    } for a in attempts]
    
    return JsonResponse({'attempts': data})


def get_commands(request):
    """Get executed commands."""
    limit = int(request.GET.get('limit', 50))
    commands = Command.objects.order_by('-timestamp')[:limit]
    
    data = [{
        'id': c.id, 'ip': c.ip_address, 'command': c.command[:100],
        'service': c.service, 'risk_level': c.risk_level,
        'timestamp': c.timestamp.isoformat()
    } for c in commands]
    
    return JsonResponse({'commands': data})


def get_alerts(request):
    """Get alerts."""
    unacknowledged_only = request.GET.get('unacknowledged', 'false') == 'true'
    limit = int(request.GET.get('limit', 50))
    
    alerts = Alert.objects.all()
    if unacknowledged_only:
        alerts = alerts.filter(is_acknowledged=False)
    alerts = alerts.order_by('-timestamp')[:limit]
    
    data = [{
        'id': a.id, 'type': a.alert_type, 'severity': a.severity,
        'title': a.title, 'description': a.description[:200],
        'ip': a.ip_address, 'acknowledged': a.is_acknowledged,
        'timestamp': a.timestamp.isoformat()
    } for a in alerts]
    
    return JsonResponse({'alerts': data})


@csrf_exempt
@require_http_methods(["POST"])
def acknowledge_alert(request, alert_id):
    """Acknowledge an alert."""
    try:
        alert = Alert.objects.get(id=alert_id)
        alert.is_acknowledged = True
        alert.acknowledged_at = timezone.now()
        alert.save()
        return JsonResponse({'success': True})
    except Alert.DoesNotExist:
        return JsonResponse({'error': 'Alert not found'}, status=404)


def get_map_data(request):
    """Get geolocation data for map."""
    limit = int(request.GET.get('limit', 200))
    connections = Connection.objects.filter(
        latitude__isnull=False, longitude__isnull=False
    ).order_by('-timestamp')[:limit]
    
    data = [{
        'lat': c.latitude, 'lng': c.longitude,
        'ip': c.ip_address, 'country': c.country,
        'protocol': c.protocol
    } for c in connections]
    
    return JsonResponse({'markers': data})


def get_blacklist(request):
    """Get blacklisted IPs."""
    entries = IPBlacklist.objects.order_by('-created_at')[:100]
    data = [{
        'id': e.id, 'ip': e.ip_address, 'reason': e.reason,
        'permanent': e.is_permanent, 'created': e.created_at.isoformat()
    } for e in entries]
    
    return JsonResponse({'blacklist': data})


@csrf_exempt
@require_http_methods(["POST"])
def add_to_blacklist(request):
    """Add IP to blacklist."""
    try:
        data = json.loads(request.body)
        entry = IPBlacklist.objects.create(
            ip_address=data['ip'],
            reason=data.get('reason', 'MANUAL'),
            description=data.get('description', ''),
            is_permanent=data.get('permanent', False)
        )
        return JsonResponse({'success': True, 'id': entry.id})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


@csrf_exempt
@require_http_methods(["DELETE"])
def remove_from_blacklist(request, entry_id):
    """Remove IP from blacklist."""
    try:
        entry = IPBlacklist.objects.get(id=entry_id)
        entry.delete()
        return JsonResponse({'success': True})
    except IPBlacklist.DoesNotExist:
        return JsonResponse({'error': 'Entry not found'}, status=404)


def get_services(request):
    """Get honeypot service statuses."""
    services = HoneypotService.objects.all()
    data = [{
        'name': s.name, 'port': s.port, 'status': s.status,
        'connections': s.total_connections
    } for s in services]
    
    return JsonResponse({'services': data})


@csrf_exempt
@require_http_methods(["POST"])
def toggle_service(request, service_name):
    """Toggle honeypot service on/off."""
    try:
        service = HoneypotService.objects.get(name=service_name)
        if service.status == 'RUNNING':
            service.status = 'STOPPED'
        else:
            service.status = 'RUNNING'
            service.started_at = timezone.now()
        service.save()
        return JsonResponse({'success': True, 'status': service.status})
    except HoneypotService.DoesNotExist:
        return JsonResponse({'error': 'Service not found'}, status=404)
