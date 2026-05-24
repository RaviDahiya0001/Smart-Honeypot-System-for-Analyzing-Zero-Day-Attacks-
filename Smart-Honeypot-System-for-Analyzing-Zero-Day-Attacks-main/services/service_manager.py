"""
Service Manager - Controls all honeypot services.
"""

import asyncio
import logging
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeypot.settings')

import django
django.setup()

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger('honeypot')


class ServiceManager:
    """Manages all honeypot services."""
    
    def __init__(self):
        self.services = {}
        self.tasks = {}
        self.loop = None
    
    def initialize_services(self):
        """Initialize service records in database."""
        from dashboard.models import HoneypotService
        
        config = settings.HONEYPOT_CONFIG
        
        service_configs = [
            ('SSH', config.get('SSH_PORT', 2222)),
            ('FTP', config.get('FTP_PORT', 2121)),
            ('HTTP', config.get('HTTP_PORT', 8080)),
            ('TELNET', config.get('TELNET_PORT', 2323)),
        ]
        
        for name, port in service_configs:
            try:
                obj = HoneypotService.objects.filter(name=name).first()
                if obj:
                    obj.port = port
                    obj.status = 'STOPPED'
                    obj.save()
                else:
                    HoneypotService.objects.create(
                        name=name,
                        port=port,
                        status='STOPPED'
                    )
            except Exception as e:
                logger.error(f"Error initializing {name}: {e}")
    
    async def start_service(self, service_name: str):
        """Start a specific honeypot service."""
        try:
            if service_name == 'SSH':
                from services.ssh_honeypot import SSHHoneypot
                honeypot = SSHHoneypot()
            elif service_name == 'FTP':
                from services.ftp_honeypot import FTPHoneypot
                honeypot = FTPHoneypot()
            elif service_name == 'HTTP':
                from services.http_honeypot import HTTPHoneypot
                honeypot = HTTPHoneypot()
            elif service_name == 'TELNET':
                from services.telnet_honeypot import TelnetHoneypot
                honeypot = TelnetHoneypot()
            else:
                logger.error(f"Unknown service: {service_name}")
                return None
            
            self.services[service_name] = honeypot
            
            from asgiref.sync import sync_to_async

            @sync_to_async
            def update_running():
                from dashboard.models import HoneypotService
                HoneypotService.objects.filter(name=service_name).update(
                    status='RUNNING',
                    started_at=timezone.now()
                )

            await update_running()
            
            task = asyncio.create_task(honeypot.start())
            self.tasks[service_name] = task
            
            logger.info(f"Started {service_name} honeypot")
            return honeypot
            
        except Exception as e:
            logger.error(f"Failed to start {service_name}: {e}")
            try:
                from asgiref.sync import sync_to_async

                @sync_to_async
                def update_error():
                    from dashboard.models import HoneypotService
                    HoneypotService.objects.filter(name=service_name).update(
                        status='ERROR'
                    )

                await update_error()
            except Exception:
                pass
            return None
    
    async def stop_service(self, service_name: str):
        """Stop a specific honeypot service."""
        if service_name in self.services:
            try:
                await self.services[service_name].stop()
                del self.services[service_name]
                
                if service_name in self.tasks:
                    self.tasks[service_name].cancel()
                    del self.tasks[service_name]

                from asgiref.sync import sync_to_async

                @sync_to_async
                def update_stopped():
                    from dashboard.models import HoneypotService
                    HoneypotService.objects.filter(name=service_name).update(
                        status='STOPPED'
                    )

                await update_stopped()
                logger.info(f"Stopped {service_name} honeypot")
                
            except Exception as e:
                logger.error(f"Error stopping {service_name}: {e}")
    
    async def start_all(self):
        """Start all honeypot services."""
        from asgiref.sync import sync_to_async
        await sync_to_async(self.initialize_services)()
        
        for service in ['SSH', 'FTP', 'HTTP', 'TELNET']:
            await self.start_service(service)
    
    async def stop_all(self):
        """Stop all honeypot services."""
        for service_name in list(self.services.keys()):
            await self.stop_service(service_name)
    
    def get_status(self):
        """Get status of all services."""
        from dashboard.models import HoneypotService
        return {
            service.name: {
                'status': service.status,
                'port': service.port,
                'connections': service.total_connections,
            }
            for service in HoneypotService.objects.all()
        }


def run_services():
    """Run all honeypot services."""
    manager = ServiceManager()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(manager.start_all())
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(manager.stop_all())
    finally:
        loop.close()


if __name__ == '__main__':
    run_services()
