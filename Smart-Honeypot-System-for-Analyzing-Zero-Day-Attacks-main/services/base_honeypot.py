"""
Base honeypot class for all services.
"""

import asyncio
import logging
import socket
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Dict, Any

import django
django.setup()

from django.conf import settings
from django.utils import timezone
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync, sync_to_async

logger = logging.getLogger('honeypot')


class BaseHoneypot(ABC):
    """Abstract base class for honeypot services."""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 0, service_name: str = 'UNKNOWN'):
        self.host = host
        self.port = port
        self.service_name = service_name
        self.is_running = False
        self.server = None
        self.connections = {}
        
    @abstractmethod
    async def start(self):
        """Start the honeypot service."""
        pass
    
    @abstractmethod
    async def stop(self):
        """Stop the honeypot service."""
        pass
    
    @abstractmethod
    async def handle_connection(self, reader, writer):
        """Handle incoming connections."""
        pass
    
    async def log_connection(self, ip_address: str, port: int, **extra):
        """Log a connection to the database."""
        from dashboard.models import Connection
        
        geo_data = await sync_to_async(self.get_geolocation)(ip_address)
        
        @sync_to_async
        def create_conn():
            return Connection.objects.create(
                ip_address=ip_address,
                port=port,
                protocol=self.service_name,
                country=geo_data.get('country'),
                country_code=geo_data.get('countryCode'),
                city=geo_data.get('city'),
                latitude=geo_data.get('lat'),
                longitude=geo_data.get('lon'),
                isp=geo_data.get('isp'),
                **extra
            )
        
        connection = await create_conn()
        
        self.broadcast_event('new_attack', {
            'id': connection.id,
            'ip': ip_address,
            'port': port,
            'protocol': self.service_name,
            'country': geo_data.get('country'),
            'timestamp': connection.timestamp.isoformat(),
        })
        
        logger.info(f"[{self.service_name}] Connection from {ip_address}:{port}")
        return connection
    
    async def log_login_attempt(self, ip_address: str, username: str, password: str,
                                success: bool = False, connection=None):
        """Log a login attempt."""
        from dashboard.models import LoginAttempt
        
        @sync_to_async
        def create_attempt():
            return LoginAttempt.objects.create(
                connection=connection,
                ip_address=ip_address,
                username=username,
                password=password,
                service=self.service_name,
                success=success,
            )
        
        attempt = await create_attempt()
        logger.info(f"[{self.service_name}] Login attempt from {ip_address}: {username}:{password[:10]}...")
        await self.check_brute_force(ip_address)
        return attempt
    
    async def log_command(self, ip_address: str, command: str, connection=None):
        """Log a command execution."""
        from dashboard.models import Command
        
        risk_level = self.assess_command_risk(command)
        attack_type = self.detect_attack_type(command)
        
        @sync_to_async
        def create_cmd():
            return Command.objects.create(
                connection=connection,
                ip_address=ip_address,
                command=command,
                service=self.service_name,
                risk_level=risk_level,
                attack_type=attack_type,
                is_malicious=risk_level in ['HIGH', 'CRITICAL'],
            )
        
        cmd = await create_cmd()
        logger.info(f"[{self.service_name}] Command from {ip_address}: {command[:50]}...")
        
        if risk_level in ['HIGH', 'CRITICAL']:
            await self.create_alert(
                alert_type='ANOMALY',
                severity=risk_level,
                title='Suspicious command detected',
                description=f'Command: {command[:200]}',
                ip_address=ip_address,
            )
        
        return cmd
    
    async def log_file_activity(self, ip_address: str, filename: str, action: str,
                                file_content: bytes = None, connection=None):
        """Log file access or upload."""
        from dashboard.models import FileActivity
        import hashlib
        
        file_hash = None
        file_size = None
        is_malware = False
        
        if file_content:
            file_hash = hashlib.sha256(file_content).hexdigest()
            file_size = len(file_content)
            is_malware = b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' in file_content
        
        @sync_to_async
        def create_activity():
            return FileActivity.objects.create(
                connection=connection,
                ip_address=ip_address,
                filename=filename,
                action=action,
                file_hash=file_hash,
                file_size=file_size,
                is_malware=is_malware,
                malware_name='EICAR Test File' if is_malware else None,
            )
        
        activity = await create_activity()
        
        if is_malware:
            await self.create_alert(
                alert_type='MALWARE',
                severity='CRITICAL',
                title=f'Malware detected: {filename}',
                description=f'SHA256: {file_hash}',
                ip_address=ip_address,
            )
        
        return activity
    
    async def create_alert(self, alert_type: str, severity: str, title: str,
                           description: str, ip_address: str = None):
        """Create a security alert."""
        from dashboard.models import Alert
        
        @sync_to_async
        def create():
            return Alert.objects.create(
                alert_type=alert_type,
                severity=severity,
                title=title,
                description=description,
                ip_address=ip_address,
            )
        
        alert = await create()
        
        self.broadcast_event('new_alert', {
            'id': alert.id,
            'type': alert_type,
            'severity': severity,
            'title': title,
            'ip': ip_address,
            'timestamp': alert.timestamp.isoformat(),
        })
        
        logger.warning(f"[ALERT] {severity}: {title}")
        return alert
    
    def get_geolocation(self, ip_address: str) -> Dict[str, Any]:
        """Get geolocation data for an IP address."""
        import requests
        
        if ip_address.startswith('127.') or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            return {}
        
        try:
            response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"Geolocation failed for {ip_address}: {e}")
        
        return {}
    
    async def check_brute_force(self, ip_address: str):
        """Check for brute force attacks."""
        from dashboard.models import LoginAttempt
        from datetime import timedelta
        
        @sync_to_async
        def count_attempts():
            recent_window = timezone.now() - timedelta(minutes=5)
            return LoginAttempt.objects.filter(
                ip_address=ip_address,
                timestamp__gte=recent_window
            ).count()
        
        recent_attempts = await count_attempts()
        
        if recent_attempts >= 10:
            await self.create_alert(
                alert_type='BRUTE_FORCE',
                severity='HIGH',
                title='Brute force attack detected',
                description=f'{recent_attempts} login attempts in 5 minutes',
                ip_address=ip_address,
            )
        
        if recent_attempts >= 50:
            await self.blacklist_ip(ip_address, 'BRUTE_FORCE')
    
    async def blacklist_ip(self, ip_address: str, reason: str):
        """Add IP to blacklist."""
        from dashboard.models import IPBlacklist
        
        @sync_to_async
        def do_blacklist():
            if not IPBlacklist.objects.filter(ip_address=ip_address).exists():
                IPBlacklist.objects.create(
                    ip_address=ip_address,
                    reason=reason,
                    description=f'Auto-blacklisted by {self.service_name} honeypot',
                )
                logger.warning(f"IP {ip_address} blacklisted: {reason}")
        
        await do_blacklist()
    
    async def is_blacklisted(self, ip_address: str) -> bool:
        """Check if IP is blacklisted."""
        from dashboard.models import IPBlacklist
        
        @sync_to_async
        def check():
            entry = IPBlacklist.objects.filter(ip_address=ip_address).first()
            if entry:
                return entry.is_active
            return False
        
        return await check()
    
    def assess_command_risk(self, command: str) -> str:
        """Assess the risk level of a command."""
        command_lower = command.lower()
        
        critical_patterns = ['rm -rf', 'mkfs', 'dd if=', ':(){', 'chmod 777', 'wget', 'curl', 'nc -e', 'bash -i']
        high_patterns = ['cat /etc/passwd', 'cat /etc/shadow', 'sudo', 'su -', 'id', 'whoami', 'uname -a']
        medium_patterns = ['ls', 'pwd', 'cd', 'ps', 'netstat', 'ifconfig']
        
        for pattern in critical_patterns:
            if pattern in command_lower:
                return 'CRITICAL'
        
        for pattern in high_patterns:
            if pattern in command_lower:
                return 'HIGH'
        
        for pattern in medium_patterns:
            if pattern in command_lower:
                return 'MEDIUM'
        
        return 'LOW'
    
    def detect_attack_type(self, command: str) -> Optional[str]:
        """Detect the type of attack from command."""
        command_lower = command.lower()
        
        if 'select' in command_lower and ('from' in command_lower or 'union' in command_lower):
            return 'SQL_INJECTION'
        if '<script>' in command_lower or 'javascript:' in command_lower:
            return 'XSS'
        if 'wget' in command_lower or 'curl' in command_lower:
            return 'MALWARE_DOWNLOAD'
        if '../' in command or '..\\ ' in command:
            return 'PATH_TRAVERSAL'
        if 'nc -e' in command_lower or 'bash -i' in command_lower:
            return 'REVERSE_SHELL'
        
        return None
    
    def broadcast_event(self, event_type: str, data: dict):
        """Broadcast event to WebSocket clients."""
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'dashboard_updates',
                {
                    'type': event_type.replace('-', '_'),
                    'data': data,
                }
            )
        except Exception as e:
            logger.error(f"Failed to broadcast event: {e}")
