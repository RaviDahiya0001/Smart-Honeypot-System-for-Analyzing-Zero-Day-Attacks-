import requests
from django.conf import settings
import logging

logger = logging.getLogger('honeypot')

def check_ip_virustotal(ip_address):
    api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
    if not api_key:
        return None

    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            result = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'total': sum(stats.values()),
                'country': data['data']['attributes'].get('country', 'Unknown'),
                'reputation': data['data']['attributes'].get('reputation', 0),
            }
            logger.info(f"VT check {ip_address}: {result['malicious']}/{result['total']} malicious")
            return result
    except Exception as e:
        logger.error(f"VirusTotal error: {e}")
    return None