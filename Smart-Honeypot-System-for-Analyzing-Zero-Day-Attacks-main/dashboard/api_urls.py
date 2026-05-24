"""
REST API URL configuration for dashboard.
"""

from django.urls import path
from . import api_views

urlpatterns = [
    path('stats/', api_views.get_stats, name='api_stats'),
    path('stats/timeline/', api_views.get_timeline, name='api_timeline'),
    path('connections/', api_views.get_connections, name='api_connections'),
    path('connections/recent/', api_views.get_recent_connections, name='api_recent_connections'),
    path('login-attempts/', api_views.get_login_attempts, name='api_login_attempts'),
    path('commands/', api_views.get_commands, name='api_commands'),
    path('alerts/', api_views.get_alerts, name='api_alerts'),
    path('alerts/<int:alert_id>/acknowledge/', api_views.acknowledge_alert, name='api_acknowledge_alert'),
    path('map-data/', api_views.get_map_data, name='api_map_data'),
    path('blacklist/', api_views.get_blacklist, name='api_blacklist'),
    path('blacklist/add/', api_views.add_to_blacklist, name='api_add_blacklist'),
    path('blacklist/remove/<int:entry_id>/', api_views.remove_from_blacklist, name='api_remove_blacklist'),
    path('services/', api_views.get_services, name='api_services'),
    path('services/<str:service_name>/toggle/', api_views.toggle_service, name='api_toggle_service'),
]
