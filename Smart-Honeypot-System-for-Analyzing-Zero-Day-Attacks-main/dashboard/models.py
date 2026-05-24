"""
Database models for the Honeypot Dashboard.
Captures all attack data, connections, and alert information.
"""

from django.db import models
from django.utils import timezone
import hashlib


class Connection(models.Model):
    """Logs all connection attempts to honeypot services."""
    
    PROTOCOL_CHOICES = [
        ('SSH', 'SSH'),
        ('FTP', 'FTP'),
        ('HTTP', 'HTTP'),
        ('TELNET', 'Telnet'),
        ('SMB', 'SMB'),
        ('UNKNOWN', 'Unknown'),
    ]
    
    ip_address = models.GenericIPAddressField(db_index=True)
    port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=20, choices=PROTOCOL_CHOICES)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    
    # Geolocation data
    country = models.CharField(max_length=100, blank=True, null=True)
    country_code = models.CharField(max_length=10, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    isp = models.CharField(max_length=200, blank=True, null=True)
    
    # Additional metadata
    user_agent = models.TextField(blank=True, null=True)
    raw_data = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['protocol', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.ip_address}:{self.port} ({self.protocol}) - {self.timestamp}"


class LoginAttempt(models.Model):
    """Captures all login attempts with credentials."""
    
    SERVICE_CHOICES = [
        ('SSH', 'SSH'),
        ('FTP', 'FTP'),
        ('HTTP', 'HTTP'),
        ('TELNET', 'Telnet'),
        ('SMB', 'SMB'),
        ('ADMIN', 'Admin Panel'),
    ]
    
    connection = models.ForeignKey(Connection, on_delete=models.CASCADE, related_name='login_attempts', null=True, blank=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    service = models.CharField(max_length=20, choices=SERVICE_CHOICES)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    success = models.BooleanField(default=False)
    
    # Hash for quick lookup of common credentials
    credential_hash = models.CharField(max_length=64, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['username']),
        ]
    
    def save(self, *args, **kwargs):
        # Create hash of username:password for pattern analysis
        self.credential_hash = hashlib.sha256(
            f"{self.username}:{self.password}".encode()
        ).hexdigest()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.ip_address} - {self.username}:{self.password[:20]}... ({self.service})"


class Command(models.Model):
    """Logs commands executed by attackers."""
    
    RISK_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    SERVICE_CHOICES = [
        ('SSH', 'SSH'),
        ('TELNET', 'Telnet'),
        ('FTP', 'FTP'),
        ('HTTP', 'HTTP'),
    ]
    
    connection = models.ForeignKey(Connection, on_delete=models.CASCADE, related_name='commands', null=True, blank=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    command = models.TextField()
    service = models.CharField(max_length=20, choices=SERVICE_CHOICES)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    risk_level = models.CharField(max_length=20, choices=RISK_LEVELS, default='LOW')
    
    # Analysis results
    attack_type = models.CharField(max_length=100, blank=True, null=True)
    is_malicious = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['risk_level']),
        ]
    
    def __str__(self):
        return f"{self.ip_address}: {self.command[:50]}..."


class FileActivity(models.Model):
    """Tracks file access and upload attempts."""
    
    ACTION_CHOICES = [
        ('ACCESS', 'File Access'),
        ('UPLOAD', 'File Upload'),
        ('DOWNLOAD', 'File Download'),
        ('DELETE', 'Delete Attempt'),
        ('MODIFY', 'Modify Attempt'),
    ]
    
    connection = models.ForeignKey(Connection, on_delete=models.CASCADE, related_name='file_activities', null=True, blank=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    filename = models.CharField(max_length=500)
    filepath = models.CharField(max_length=1000, blank=True, null=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    
    # File analysis
    file_hash = models.CharField(max_length=64, blank=True, null=True)  # SHA256
    file_size = models.BigIntegerField(blank=True, null=True)
    file_type = models.CharField(max_length=100, blank=True, null=True)
    is_malware = models.BooleanField(default=False)
    malware_name = models.CharField(max_length=200, blank=True, null=True)
    virustotal_result = models.JSONField(blank=True, null=True)
    
    # Quarantine status
    is_quarantined = models.BooleanField(default=False)
    quarantine_path = models.CharField(max_length=1000, blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name_plural = 'File Activities'
    
    def __str__(self):
        return f"{self.ip_address} - {self.action}: {self.filename}"


class Alert(models.Model):
    """Security alerts generated by the system."""
    
    ALERT_TYPES = [
        ('BRUTE_FORCE', 'Brute Force Attack'),
        ('SQL_INJECTION', 'SQL Injection'),
        ('XSS', 'Cross-Site Scripting'),
        ('MALWARE', 'Malware Upload'),
        ('PORT_SCAN', 'Port Scanning'),
        ('ZERO_DAY', 'Potential Zero-Day'),
        ('ANOMALY', 'Anomaly Detected'),
        ('RATE_LIMIT', 'Rate Limit Exceeded'),
        ('BLACKLIST', 'Blacklisted IP'),
    ]
    
    SEVERITY_LEVELS = [
        ('INFO', 'Info'),
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    # ── NEW: Resolution status ─────────────────────────
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('INVESTIGATING', 'Investigating'),
        ('RESOLVED', 'Resolved'),
        ('ESCALATED', 'Escalated'),
        ('FALSE_POSITIVE', 'False Positive'),
    ]
    # ──────────────────────────────────────────────────
    
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS)
    title = models.CharField(max_length=200)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    
    # Alert status
    is_acknowledged = models.BooleanField(default=False)
    acknowledged_by = models.CharField(max_length=100, blank=True, null=True)
    acknowledged_at = models.DateTimeField(blank=True, null=True)

    # ── NEW: Resolution fields ─────────────────────────
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')
    resolved_by = models.CharField(max_length=100, blank=True, null=True)
    resolved_at = models.DateTimeField(blank=True, null=True)
    resolution_note = models.TextField(blank=True, null=True)
    # ──────────────────────────────────────────────────
    
    # Related objects
    related_connection = models.ForeignKey(Connection, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Additional data
    metadata = models.JSONField(blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['alert_type', 'timestamp']),
            models.Index(fields=['severity', 'is_acknowledged']),
        ]
    
    def __str__(self):
        return f"[{self.severity}] {self.title} - {self.timestamp}"


class AttackerProfile(models.Model):
    """Aggregated profile of attackers based on their activities."""
    
    THREAT_LEVELS = [
        ('LOW', 'Low Threat'),
        ('MEDIUM', 'Medium Threat'),
        ('HIGH', 'High Threat'),
        ('CRITICAL', 'Critical Threat'),
    ]
    
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    
    # Statistics
    total_connections = models.PositiveIntegerField(default=0)
    total_login_attempts = models.PositiveIntegerField(default=0)
    total_commands = models.PositiveIntegerField(default=0)
    total_files = models.PositiveIntegerField(default=0)
    
    # Threat assessment
    threat_level = models.CharField(max_length=20, choices=THREAT_LEVELS, default='LOW')
    threat_score = models.FloatField(default=0.0)
    
    # Geolocation
    country = models.CharField(max_length=100, blank=True, null=True)
    country_code = models.CharField(max_length=10, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    isp = models.CharField(max_length=200, blank=True, null=True)
    
    # Attack patterns
    attack_types = models.JSONField(default=list, blank=True)
    targeted_services = models.JSONField(default=list, blank=True)
    
    # Reputation
    is_known_attacker = models.BooleanField(default=False)
    reputation_sources = models.JSONField(default=list, blank=True)
    
    class Meta:
        ordering = ['-threat_score']
    
    def __str__(self):
        return f"{self.ip_address} - {self.threat_level}"


class IPBlacklist(models.Model):
    """Blacklisted IP addresses."""
    
    REASON_CHOICES = [
        ('BRUTE_FORCE', 'Brute Force Attack'),
        ('MALWARE', 'Malware Upload'),
        ('ABUSE', 'Excessive Abuse'),
        ('MANUAL', 'Manually Blacklisted'),
        ('REPUTATION', 'Known Bad Reputation'),
    ]
    
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    reason = models.CharField(max_length=50, choices=REASON_CHOICES)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(blank=True, null=True)
    is_permanent = models.BooleanField(default=False)
    created_by = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'IP Blacklist Entry'
        verbose_name_plural = 'IP Blacklist Entries'
    
    def __str__(self):
        return f"{self.ip_address} - {self.reason}"
    
    @property
    def is_active(self):
        if self.is_permanent:
            return True
        if self.expires_at is None:
            return True
        return timezone.now() < self.expires_at


class HoneypotService(models.Model):
    """Tracks the status of honeypot services."""
    
    SERVICE_CHOICES = [
        ('SSH', 'SSH Honeypot'),
        ('FTP', 'FTP Honeypot'),
        ('HTTP', 'HTTP Honeypot'),
        ('TELNET', 'Telnet Honeypot'),
        ('SMB', 'SMB Honeypot'),
    ]
    
    STATUS_CHOICES = [
        ('RUNNING', 'Running'),
        ('STOPPED', 'Stopped'),
        ('ERROR', 'Error'),
    ]
    
    name = models.CharField(max_length=50, choices=SERVICE_CHOICES, unique=True)
    port = models.PositiveIntegerField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='STOPPED')
    started_at = models.DateTimeField(blank=True, null=True)
    last_activity = models.DateTimeField(blank=True, null=True)
    total_connections = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True, null=True)
    
    class Meta:
        verbose_name = 'Honeypot Service'
        verbose_name_plural = 'Honeypot Services'
    
    def __str__(self):
        return f"{self.name} on port {self.port} - {self.status}"

# Email Alert Signal
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=Alert)
def alert_created(sender, instance, created, **kwargs):
    if created and instance.severity in ('CRITICAL', 'HIGH'):
        from dashboard.notifications import notify_on_alert
        notify_on_alert(instance)

# VirusTotal Auto Check
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=Connection)
def check_ip_on_connection(sender, instance, created, **kwargs):
    if created:
        from dashboard.virustotal import check_ip_virustotal
        result = check_ip_virustotal(instance.ip_address)
        if result and result['malicious'] >= 3:
            from dashboard.models import Alert
            Alert.objects.create(
                alert_type='BLACKLIST',
                severity='CRITICAL',
                title=f'Malicious IP Detected: {instance.ip_address}',
                description=f'VirusTotal: {result["malicious"]}/{result["total"]} engines flagged. Country: {result["country"]}. Reputation: {result["reputation"]}',
                ip_address=instance.ip_address,
                related_connection=instance
            )