"""
URL configuration for dashboard app.
"""

from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('attacks/', views.attacks, name='attacks'),
    path('alerts/', views.alerts_view, name='alerts'),
    path('attackers/', views.attackers, name='attackers'),
    path('attackers/<str:ip_address>/', views.attacker_detail, name='attacker_detail'),
    path('reports/', views.reports, name='reports'),
    path('settings/', views.settings_view, name='settings'),
    
    # Export endpoints
    path('export/csv/', views.export_csv, name='export_csv'),
    path('export/json/', views.export_json, name='export_json'),
    path('export/pdf/', views.export_pdf, name='export_pdf'),

    # Alert resolution
    path('alerts/<int:alert_id>/resolve/', views.resolve_alert, name='resolve_alert'),
]