"""
WebSocket consumers for real-time updates.
"""

import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from asgiref.sync import sync_to_async


class DashboardConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for real-time dashboard updates."""
    
    async def connect(self):
        self.room_group_name = 'dashboard_updates'
        
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()
        
        # Send initial data
        await self.send_initial_data()
    
    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
    
    async def receive(self, text_data):
        data = json.loads(text_data)
        message_type = data.get('type', '')
        
        if message_type == 'get_stats':
            await self.send_stats()
        elif message_type == 'get_recent':
            await self.send_recent_attacks()
    
    async def send_initial_data(self):
        await self.send_stats()
        await self.send_recent_attacks()
    
    @database_sync_to_async
    def get_stats_data(self):
        from datetime import timedelta
        from django.utils import timezone
        from django.db.models import Count
        from .models import Connection, LoginAttempt, Command, Alert
        
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        
        return {
            'total_connections': Connection.objects.count(),
            'connections_24h': Connection.objects.filter(timestamp__gte=last_24h).count(),
            'unique_ips': Connection.objects.values('ip_address').distinct().count(),
            'total_login_attempts': LoginAttempt.objects.count(),
            'total_commands': Command.objects.count(),
            'active_alerts': Alert.objects.filter(is_acknowledged=False).count(),
        }
    
    @database_sync_to_async
    def get_recent_data(self):
        from .models import Connection
        
        connections = Connection.objects.order_by('-timestamp')[:20]
        return [{
            'id': c.id,
            'ip': c.ip_address,
            'port': c.port,
            'protocol': c.protocol,
            'country': c.country,
            'timestamp': c.timestamp.isoformat(),
        } for c in connections]
    
    async def send_stats(self):
        stats = await self.get_stats_data()
        await self.send(text_data=json.dumps({
            'type': 'stats_update',
            'data': stats
        }))
    
    async def send_recent_attacks(self):
        recent = await self.get_recent_data()
        await self.send(text_data=json.dumps({
            'type': 'recent_attacks',
            'data': recent
        }))
    
    async def attack_update(self, event):
        """Handle new attack events."""
        await self.send(text_data=json.dumps({
            'type': 'new_attack',
            'data': event['data']
        }))
    
    async def alert_update(self, event):
        """Handle new alert events."""
        await self.send(text_data=json.dumps({
            'type': 'new_alert',
            'data': event['data']
        }))
    
    async def stats_update(self, event):
        """Handle stats update events."""
        await self.send(text_data=json.dumps({
            'type': 'stats_update',
            'data': event['data']
        }))


class AlertConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for real-time alerts."""
    
    async def connect(self):
        self.room_group_name = 'alerts'
        
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()
    
    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
    
    async def new_alert(self, event):
        """Send new alert to client."""
        await self.send(text_data=json.dumps({
            'type': 'new_alert',
            'data': event['data']
        }))
