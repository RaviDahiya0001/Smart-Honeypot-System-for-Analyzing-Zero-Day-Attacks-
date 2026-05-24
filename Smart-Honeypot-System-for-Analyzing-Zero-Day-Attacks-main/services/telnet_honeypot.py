"""
Telnet Honeypot Service
Simulates a Telnet server / IoT device.
"""

import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeypot.settings')

import django
django.setup()

from services.base_honeypot import BaseHoneypot

logger = logging.getLogger('honeypot')


class TelnetHoneypot(BaseHoneypot):
    """Telnet Honeypot simulating IoT devices and routers."""
    
    BANNERS = [
        "BusyBox v1.29.3 () built-in shell (ash)\n",
        "Welcome to Router Admin\n",
        "MikroTik v6.49.6\n",
    ]
    
    FAKE_RESPONSES = {
        'ls': 'bin  dev  etc  lib  proc  sbin  sys  tmp  usr  var',
        'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh',
        'uname -a': 'Linux router 4.14.81 armv7l GNU/Linux',
        'ps': 'PID   USER     COMMAND\n    1 root     init\n  100 root     httpd\n  101 root     telnetd',
        'id': 'uid=0(root) gid=0(root)',
        'whoami': 'root',
        'ifconfig': 'eth0      Link encap:Ethernet  HWaddr AA:BB:CC:DD:EE:FF\n          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0',
    }
    
    def __init__(self, host='0.0.0.0', port=2323):
        super().__init__(host, port, 'TELNET')
    
    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_connection, self.host, self.port
        )
        self.is_running = True
        logger.info(f"Telnet Honeypot started on {self.host}:{self.port}")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.is_running = False
    
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        ip_address = addr[0]
        
        # await added
        if await self.is_blacklisted(ip_address):
            writer.close()
            return
        
        # await added
        connection = await self.log_connection(ip_address, self.port)
        
        try:
            writer.write(b"\r\nlogin: ")
            await writer.drain()
            
            username = await asyncio.wait_for(reader.readline(), timeout=30)
            username = username.decode('utf-8', errors='ignore').strip()
            
            writer.write(b"Password: ")
            await writer.drain()
            
            password = await asyncio.wait_for(reader.readline(), timeout=30)
            password = password.decode('utf-8', errors='ignore').strip()
            
            if username or password:
                # await added
                await self.log_login_attempt(ip_address, username, password, connection=connection)
            
            import random
            banner = random.choice(self.BANNERS)
            writer.write(f"\r\n{banner}\r\n".encode())
            await writer.drain()
            
            prompt = b"# "
            writer.write(prompt)
            await writer.drain()
            
            while True:
                try:
                    cmd = await asyncio.wait_for(reader.readline(), timeout=120)
                    cmd = cmd.decode('utf-8', errors='ignore').strip()
                    
                    if not cmd:
                        continue
                    
                    # await added
                    await self.log_command(ip_address, cmd, connection=connection)
                    
                    if cmd in ['exit', 'quit', 'logout']:
                        break
                    
                    response = self.get_response(cmd)
                    writer.write(f"{response}\r\n".encode())
                    writer.write(prompt)
                    await writer.drain()
                    
                except asyncio.TimeoutError:
                    break
                    
        except Exception as e:
            logger.error(f"Telnet error from {ip_address}: {e}")
        finally:
            writer.close()
    
    def get_response(self, cmd: str) -> str:
        if cmd in self.FAKE_RESPONSES:
            return self.FAKE_RESPONSES[cmd]
        
        cmd_base = cmd.split()[0] if cmd else ''
        for key, val in self.FAKE_RESPONSES.items():
            if cmd_base == key.split()[0]:
                return val
        
        if cmd_base in ['wget', 'curl', 'tftp']:
            return f'{cmd_base}: not found'
        elif cmd_base in ['cd', 'echo']:
            return ''
        
        return f'-sh: {cmd_base}: not found'


async def run_telnet_honeypot():
    honeypot = TelnetHoneypot()
    await honeypot.start()


if __name__ == '__main__':
    asyncio.run(run_telnet_honeypot())
