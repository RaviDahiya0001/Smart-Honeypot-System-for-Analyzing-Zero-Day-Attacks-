"""
Django Admin configuration for Honeypot Dashboard.
"""

from django.contrib import admin
from django.utils.html import format_html
from .models import (
    Connection, LoginAttempt, Command, FileActivity,
    Alert, AttackerProfile, IPBlacklist, HoneypotService
)


@admin.register(Connection)
class ConnectionAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'port', 'protocol', 'country', 'city', 'timestamp']
    list_filter = ['protocol', 'country', 'timestamp']
    search_fields = ['ip_address', 'country', 'city', 'isp']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'username', 'masked_password', 'service', 'success', 'timestamp']
    list_filter = ['service', 'success', 'timestamp']
    search_fields = ['ip_address', 'username']
    readonly_fields = ['credential_hash', 'timestamp']
    date_hierarchy = 'timestamp'
    
    def masked_password(self, obj):
        if len(obj.password) > 4:
            return obj.password[:2] + '*' * (len(obj.password) - 4) + obj.password[-2:]
        return '*' * len(obj.password)
    masked_password.short_description = 'Password'


@admin.register(Command)
class CommandAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'short_command', 'service', 'risk_level_badge', 'is_malicious', 'timestamp']
    list_filter = ['service', 'risk_level', 'is_malicious', 'timestamp']
    search_fields = ['ip_address', 'command', 'attack_type']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    
    def short_command(self, obj):
        return obj.command[:50] + '...' if len(obj.command) > 50 else obj.command
    short_command.short_description = 'Command'
    
    def risk_level_badge(self, obj):
        colors = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107',
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545',
        }
        color = colors.get(obj.risk_level, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 3px;">{}</span>',
            color, obj.risk_level
        )
    risk_level_badge.short_description = 'Risk Level'


@admin.register(FileActivity)
class FileActivityAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'filename', 'action', 'is_malware', 'is_quarantined', 'timestamp']
    list_filter = ['action', 'is_malware', 'is_quarantined', 'timestamp']
    search_fields = ['ip_address', 'filename', 'malware_name']
    readonly_fields = ['timestamp', 'file_hash', 'virustotal_result']
    date_hierarchy = 'timestamp'


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['title', 'alert_type', 'severity_badge', 'ip_address', 'is_acknowledged', 'timestamp']
    list_filter = ['alert_type', 'severity', 'is_acknowledged', 'timestamp']
    search_fields = ['title', 'description', 'ip_address']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    actions = ['acknowledge_alerts']
    
    def severity_badge(self, obj):
        colors = {
            'INFO': '#17a2b8',
            'LOW': '#28a745',
            'MEDIUM': '#ffc107',
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545',
        }
        color = colors.get(obj.severity, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 3px;">{}</span>',
            color, obj.severity
        )
    severity_badge.short_description = 'Severity'
    
    @admin.action(description='Acknowledge selected alerts')
    def acknowledge_alerts(self, request, queryset):
        from django.utils import timezone
        queryset.update(
            is_acknowledged=True,
            acknowledged_by=request.user.username,
            acknowledged_at=timezone.now()
        )


@admin.register(AttackerProfile)
class AttackerProfileAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'threat_level', 'threat_score', 'total_connections', 'country', 'first_seen', 'last_seen']
    list_filter = ['threat_level', 'country', 'is_known_attacker']
    search_fields = ['ip_address', 'country', 'city', 'isp']
    readonly_fields = ['first_seen', 'last_seen', 'total_connections', 'total_login_attempts', 'total_commands', 'total_files']
    ordering = ['-threat_score']


@admin.register(IPBlacklist)
class IPBlacklistAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'reason', 'is_permanent', 'is_active', 'created_at', 'expires_at']
    list_filter = ['reason', 'is_permanent', 'created_at']
    search_fields = ['ip_address', 'description']
    readonly_fields = ['created_at']


@admin.register(HoneypotService)
class HoneypotServiceAdmin(admin.ModelAdmin):
    list_display = ['name', 'port', 'status_badge', 'total_connections', 'started_at', 'last_activity']
    list_filter = ['status']
    readonly_fields = ['started_at', 'last_activity', 'total_connections']
    
    def status_badge(self, obj):
        colors = {
            'RUNNING': '#28a745',
            'STOPPED': '#6c757d',
            'ERROR': '#dc3545',
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 3px;">{}</span>',
            color, obj.status
        )
    status_badge.short_description = 'Status'


# Customize admin site
admin.site.site_header = '🍯 Smart Honeypot Admin'
admin.site.site_title = 'Honeypot Admin'
admin.site.index_title = 'Honeypot Management Dashboard'
