"""
Management command to run all honeypot services.
"""

import asyncio
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Run all honeypot services'

    def add_arguments(self, parser):
        parser.add_argument(
            '--services',
            nargs='+',
            type=str,
            default=['SSH', 'FTP', 'HTTP', 'TELNET'],
            help='Services to run (SSH, FTP, HTTP, TELNET)'
        )

    def handle(self, *args, **options):
        from services.service_manager import ServiceManager
        
        self.stdout.write(self.style.SUCCESS('Starting Honeypot Services...'))
        
        manager = ServiceManager()
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(manager.start_all())
            self.stdout.write(self.style.SUCCESS('All services started. Press Ctrl+C to stop.'))
            loop.run_forever()
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\nShutting down services...'))
            loop.run_until_complete(manager.stop_all())
        finally:
            loop.close()
            self.stdout.write(self.style.SUCCESS('Honeypot services stopped.'))
