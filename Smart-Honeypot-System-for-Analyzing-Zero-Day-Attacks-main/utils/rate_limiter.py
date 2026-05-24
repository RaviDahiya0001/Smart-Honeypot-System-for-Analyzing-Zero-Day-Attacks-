"""
Rate limiter for honeypot protection.
"""

import time
from collections import defaultdict
from typing import Dict, Tuple
from datetime import datetime, timedelta

from django.conf import settings


class RateLimiter:
    """Rate limiter to prevent honeypot abuse."""
    
    def __init__(self):
        self.connections: Dict[str, list] = defaultdict(list)
        self.blacklist: Dict[str, datetime] = {}
        self.config = getattr(settings, 'HONEYPOT_CONFIG', {})
        self.max_connections = self.config.get('MAX_CONNECTIONS_PER_IP', 100)
        self.window = self.config.get('RATE_LIMIT_WINDOW', 60)
        self.blacklist_threshold = self.config.get('BLACKLIST_THRESHOLD', 500)
    
    def is_allowed(self, ip_address: str) -> Tuple[bool, str]:
        """Check if IP is allowed to connect."""
        now = time.time()
        
        # Check blacklist
        if ip_address in self.blacklist:
            if datetime.now() < self.blacklist[ip_address]:
                return False, 'IP is blacklisted'
            else:
                del self.blacklist[ip_address]
        
        # Clean old entries
        self.connections[ip_address] = [
            t for t in self.connections[ip_address] 
            if now - t < self.window
        ]
        
        # Check rate limit
        if len(self.connections[ip_address]) >= self.max_connections:
            return False, 'Rate limit exceeded'
        
        # Record connection
        self.connections[ip_address].append(now)
        
        # Auto-blacklist if threshold exceeded
        if len(self.connections[ip_address]) >= self.blacklist_threshold:
            self.add_to_blacklist(ip_address, hours=24)
            return False, 'Auto-blacklisted for abuse'
        
        return True, 'OK'
    
    def add_to_blacklist(self, ip_address: str, hours: int = 24):
        """Add IP to temporary blacklist."""
        self.blacklist[ip_address] = datetime.now() + timedelta(hours=hours)
    
    def remove_from_blacklist(self, ip_address: str):
        """Remove IP from blacklist."""
        if ip_address in self.blacklist:
            del self.blacklist[ip_address]
    
    def get_stats(self, ip_address: str) -> Dict:
        """Get rate limit stats for an IP."""
        now = time.time()
        recent = [t for t in self.connections.get(ip_address, []) if now - t < self.window]
        return {
            'ip': ip_address,
            'connections_in_window': len(recent),
            'max_allowed': self.max_connections,
            'is_blacklisted': ip_address in self.blacklist,
        }


# Global instance
rate_limiter = RateLimiter()
