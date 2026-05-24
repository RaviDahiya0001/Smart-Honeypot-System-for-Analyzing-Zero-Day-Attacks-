"""
Geolocation utilities using ip-api.com (free).
"""

import requests
import logging
from functools import lru_cache
from typing import Dict, Optional

logger = logging.getLogger('honeypot')

GEOIP_API_URL = 'http://ip-api.com/json/'


@lru_cache(maxsize=10000)
def get_geolocation(ip_address: str) -> Dict:
    """Get geolocation data for an IP address."""
    result = {
        'ip': ip_address,
        'country': None,
        'countryCode': None,
        'city': None,
        'lat': None,
        'lon': None,
        'isp': None,
        'org': None,
    }
    
    # Skip local/private IPs
    if is_private_ip(ip_address):
        result['country'] = 'Local Network'
        return result
    
    try:
        response = requests.get(f'{GEOIP_API_URL}{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                result.update({
                    'country': data.get('country'),
                    'countryCode': data.get('countryCode'),
                    'city': data.get('city'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'region': data.get('regionName'),
                    'timezone': data.get('timezone'),
                    'as': data.get('as'),
                })
    except Exception as e:
        logger.warning(f"Geolocation lookup failed for {ip_address}: {e}")
    
    return result


def is_private_ip(ip_address: str) -> bool:
    """Check if IP is private/local."""
    private_ranges = [
        '10.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
        '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
        '172.30.', '172.31.', '192.168.', '127.', '0.', '::1',
        'fe80:', 'fc00:', 'fd00:'
    ]
    return any(ip_address.startswith(prefix) for prefix in private_ranges)
