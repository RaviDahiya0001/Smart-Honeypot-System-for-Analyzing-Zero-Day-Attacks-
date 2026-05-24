"""
WSGI config for honeypot project.
"""

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeypot.settings')

application = get_wsgi_application()
