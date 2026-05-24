"""
Celery tasks for background processing.
"""

from celery import shared_task
from django.utils import timezone
from datetime import timedelta


@shared_task
def update_attacker_profiles():
    """Update attacker profiles based on recent activity."""
    from .models import Connection, LoginAttempt, Command, FileActivity, AttackerProfile
    from django.db.models import Count, Min, Max
    
    # Get all unique IPs
    ips = Connection.objects.values('ip_address').annotate(
        count=Count('id'),
        first=Min('timestamp'),
        last=Max('timestamp')
    )
    
    for ip_data in ips:
        ip = ip_data['ip_address']
        conn = Connection.objects.filter(ip_address=ip).first()
        
        profile, created = AttackerProfile.objects.update_or_create(
            ip_address=ip,
            defaults={
                'first_seen': ip_data['first'],
                'last_seen': ip_data['last'],
                'total_connections': ip_data['count'],
                'total_login_attempts': LoginAttempt.objects.filter(ip_address=ip).count(),
                'total_commands': Command.objects.filter(ip_address=ip).count(),
                'total_files': FileActivity.objects.filter(ip_address=ip).count(),
                'country': conn.country if conn else None,
                'country_code': conn.country_code if conn else None,
                'city': conn.city if conn else None,
                'isp': conn.isp if conn else None,
            }
        )
        
        # Calculate threat score
        score = calculate_threat_score(profile)
        profile.threat_score = score
        
        if score >= 80:
            profile.threat_level = 'CRITICAL'
        elif score >= 60:
            profile.threat_level = 'HIGH'
        elif score >= 30:
            profile.threat_level = 'MEDIUM'
        else:
            profile.threat_level = 'LOW'
        
        profile.save()


def calculate_threat_score(profile):
    """Calculate threat score for an attacker."""
    score = 0
    
    # Connection frequency
    if profile.total_connections > 100:
        score += 20
    elif profile.total_connections > 50:
        score += 10
    
    # Login attempts
    if profile.total_login_attempts > 50:
        score += 25
    elif profile.total_login_attempts > 20:
        score += 15
    
    # Commands executed
    if profile.total_commands > 20:
        score += 25
    elif profile.total_commands > 5:
        score += 10
    
    # File activity
    if profile.total_files > 10:
        score += 20
    elif profile.total_files > 0:
        score += 10
    
    return min(score, 100)


@shared_task
def cleanup_old_data():
    """Clean up old data based on retention policy."""
    from .models import Connection, LoginAttempt, Command
    
    # Keep data for 90 days
    cutoff = timezone.now() - timedelta(days=90)
    
    Connection.objects.filter(timestamp__lt=cutoff).delete()
    LoginAttempt.objects.filter(timestamp__lt=cutoff).delete()
    Command.objects.filter(timestamp__lt=cutoff).delete()


@shared_task
def check_rate_limits():
    """Check for rate limit violations and auto-blacklist."""
    from .models import Connection, IPBlacklist, Alert
    from django.db.models import Count
    
    now = timezone.now()
    last_hour = now - timedelta(hours=1)
    
    # Find IPs with excessive connections
    excessive_ips = Connection.objects.filter(
        timestamp__gte=last_hour
    ).values('ip_address').annotate(
        count=Count('id')
    ).filter(count__gte=500)
    
    for ip_data in excessive_ips:
        ip = ip_data['ip_address']
        
        # Check if already blacklisted
        if not IPBlacklist.objects.filter(ip_address=ip).exists():
            IPBlacklist.objects.create(
                ip_address=ip,
                reason='ABUSE',
                description=f'Automatic blacklist: {ip_data["count"]} connections in 1 hour',
                is_permanent=False,
                expires_at=now + timedelta(hours=24)
            )
            
            Alert.objects.create(
                alert_type='RATE_LIMIT',
                severity='HIGH',
                title=f'Rate limit exceeded: {ip}',
                description=f'IP {ip} made {ip_data["count"]} connections in the last hour',
                ip_address=ip
            )


@shared_task
def send_daily_report():
    """Generate and send daily report."""
    from django.core.mail import send_mail
    from django.conf import settings
    from .models import Connection, Alert
    
    now = timezone.now()
    yesterday = now - timedelta(days=1)
    
    stats = {
        'connections': Connection.objects.filter(timestamp__gte=yesterday).count(),
        'unique_ips': Connection.objects.filter(timestamp__gte=yesterday).values('ip_address').distinct().count(),
        'alerts': Alert.objects.filter(timestamp__gte=yesterday).count(),
    }
    
    message = f"""
    Honeypot Daily Report - {now.strftime('%Y-%m-%d')}
    
    Connections: {stats['connections']}
    Unique IPs: {stats['unique_ips']}
    Alerts: {stats['alerts']}
    """
    
    # Would send email here in production
    return stats
