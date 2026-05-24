"""
Threat Intelligence Module
Integrates with external threat intelligence sources.
"""

import logging
import requests
import hashlib
from typing import Dict, Optional, List
from functools import lru_cache

from django.conf import settings

logger = logging.getLogger('honeypot')


class ThreatIntelligence:
    """Threat intelligence integration for IP reputation and malware checking."""
    
    def __init__(self):
        self.virustotal_api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
        self.cache = {}
    
    @lru_cache(maxsize=1000)
    def check_ip_reputation(self, ip_address: str) -> Dict:
        """Check IP reputation using free services."""
        result = {
            'ip': ip_address,
            'is_malicious': False,
            'threat_level': 'UNKNOWN',
            'sources': [],
        }
        
        # Check AbuseIPDB (would need API key in production)
        # For now, use heuristics
        
        # Check if IP is in known bad ranges
        bad_ranges = ['45.33.32', '185.220.101']  # Example Tor exit nodes
        for bad_range in bad_ranges:
            if ip_address.startswith(bad_range):
                result['is_malicious'] = True
                result['threat_level'] = 'HIGH'
                result['sources'].append('Known Tor Exit Node')
                break
        
        # Try ip-api.com for location and ISP info (free, no key needed)
        try:
            resp = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                result['country'] = data.get('country')
                result['isp'] = data.get('isp')
                result['org'] = data.get('org')
                
                # Flag datacenter IPs as potentially suspicious
                suspicious_isps = ['digitalocean', 'amazon', 'linode', 'vultr', 'ovh']
                if data.get('isp', '').lower() in suspicious_isps:
                    result['is_datacenter'] = True
        except Exception as e:
            logger.error(f"IP reputation check failed: {e}")
        
        return result
    
    def check_file_hash(self, file_hash: str) -> Dict:
        """Check file hash against VirusTotal."""
        result = {
            'hash': file_hash,
            'is_malware': False,
            'detections': 0,
            'total_engines': 0,
        }
        
        if not self.virustotal_api_key:
            # EICAR test file detection
            eicar_hashes = [
                '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
                '44d88612fea8a8f36de82e1278abb02f',
            ]
            if file_hash.lower() in [h.lower() for h in eicar_hashes]:
                result['is_malware'] = True
                result['malware_name'] = 'EICAR-Test-File'
                result['detections'] = 70
                result['total_engines'] = 70
            return result
        
        try:
            headers = {'x-apikey': self.virustotal_api_key}
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            resp = requests.get(url, headers=headers, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                result['detections'] = stats.get('malicious', 0)
                result['total_engines'] = sum(stats.values())
                result['is_malware'] = result['detections'] > 0
                
                if result['is_malware']:
                    result['malware_names'] = []
                    results = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
                    for engine, res in results.items():
                        if res.get('result'):
                            result['malware_names'].append(res['result'])
                            if len(result['malware_names']) >= 3:
                                break
                    result['malware_name'] = result['malware_names'][0] if result['malware_names'] else 'Unknown'
                    
        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
        
        return result
    
    def check_url(self, url: str) -> Dict:
        """Check URL reputation."""
        result = {
            'url': url,
            'is_malicious': False,
            'categories': [],
        }
        
        # Basic heuristics
        suspicious_patterns = [
            '.tk', '.ml', '.ga', '.cf',  # Free domains
            'bit.ly', 'goo.gl', 'tinyurl',  # URL shorteners
            'pastebin.com', 'hastebin.com',  # Paste sites
        ]
        
        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if pattern in url_lower:
                result['is_suspicious'] = True
                result['categories'].append(f'Contains {pattern}')
        
        return result
    
    def get_threat_report(self, ip_address: str) -> Dict:
        """Generate comprehensive threat report for an IP."""
        import os
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeypot.settings')
        
        import django
        django.setup()
        
        from dashboard.models import Connection, LoginAttempt, Command, Alert
        
        # Get IP reputation
        reputation = self.check_ip_reputation(ip_address)
        
        # Get attack history
        connections = Connection.objects.filter(ip_address=ip_address).count()
        login_attempts = LoginAttempt.objects.filter(ip_address=ip_address).count()
        commands = Command.objects.filter(ip_address=ip_address).count()
        alerts = Alert.objects.filter(ip_address=ip_address).count()
        
        # Calculate threat score
        threat_score = 0
        if connections > 50:
            threat_score += 20
        if login_attempts > 20:
            threat_score += 30
        if commands > 10:
            threat_score += 25
        if alerts > 0:
            threat_score += 25
        if reputation.get('is_malicious'):
            threat_score += 25
        
        threat_score = min(threat_score, 100)
        
        return {
            'ip_address': ip_address,
            'reputation': reputation,
            'activity': {
                'connections': connections,
                'login_attempts': login_attempts,
                'commands': commands,
                'alerts': alerts,
            },
            'threat_score': threat_score,
            'threat_level': 'CRITICAL' if threat_score >= 80 else ('HIGH' if threat_score >= 50 else ('MEDIUM' if threat_score >= 25 else 'LOW')),
            'recommendation': 'BLOCK' if threat_score >= 50 else 'MONITOR',
        }


# Global instance
threat_intel = ThreatIntelligence()
