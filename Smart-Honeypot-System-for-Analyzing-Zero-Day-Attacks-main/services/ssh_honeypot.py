"""
SSH Honeypot Service
Simulates an SSH server to capture login attempts and commands.
"""

import asyncio
import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeypot.settings')

import django
django.setup()

from services.base_honeypot import BaseHoneypot

logger = logging.getLogger('honeypot')


class SSHHoneypot(BaseHoneypot):
    """SSH Honeypot that simulates an SSH server."""
    
    BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    
    FAKE_RESPONSES = {
        'ls': 'bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var',
        'pwd': '/root',
        'whoami': 'root',
        'id': 'uid=0(root) gid=0(root) groups=0(root)',
        'uname -a': 'Linux honeypot 5.4.0-91-generic #102-Ubuntu SMP x86_64 GNU/Linux',
        'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin',
        'ps aux': 'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 169432 12384 ?        Ss   00:00   0:02 /sbin/init',
        'ifconfig': 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255',
        'netstat -an': 'Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State',
        'history': '    1  ls\n    2  cd /var/www\n    3  cat config.php\n    4  mysql -u admin -p',
    }
    
    def __init__(self, host='0.0.0.0', port=2222):
        super().__init__(host, port, 'SSH')
        
    async def start(self):
        """Start the SSH honeypot server."""
        self.server = await asyncio.start_server(
            self.handle_connection,
            self.host,
            self.port
        )
        self.is_running = True
        logger.info(f"SSH Honeypot started on {self.host}:{self.port}")
        async with self.server:
            await self.server.serve_forever()
    
    async def stop(self):
        """Stop the SSH honeypot server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.is_running = False
            logger.info("SSH Honeypot stopped")
    
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming SSH connections."""
        addr = writer.get_extra_info('peername')
        ip_address = addr[0]
        
        # Check blacklist — await added
        if await self.is_blacklisted(ip_address):
            writer.close()
            await writer.wait_closed()
            return
        
        # Log connection — await added
        connection = await self.log_connection(ip_address, self.port)
        
        try:
            writer.write(self.BANNER)
            await writer.drain()
            
            client_banner = await asyncio.wait_for(reader.readline(), timeout=30)
            await asyncio.sleep(0.5)
            
            await self.handle_authentication(reader, writer, ip_address, connection)
            
        except asyncio.TimeoutError:
            logger.debug(f"Connection timeout from {ip_address}")
        except Exception as e:
            logger.error(f"Error handling SSH connection from {ip_address}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def handle_authentication(self, reader, writer, ip_address: str, connection):
        """Handle SSH authentication attempts."""
        max_attempts = 3
        attempts = 0
        
        while attempts < max_attempts:
            try:
                writer.write(b"login: ")
                await writer.drain()
                username = await asyncio.wait_for(reader.readline(), timeout=30)
                username = username.decode('utf-8', errors='ignore').strip()
                
                writer.write(b"Password: ")
                await writer.drain()
                password = await asyncio.wait_for(reader.readline(), timeout=30)
                password = password.decode('utf-8', errors='ignore').strip()
                
                if username and password:
                    # Log login attempt — await added
                    await self.log_login_attempt(ip_address, username, password, connection=connection)
                    
                    if attempts >= 1:
                        writer.write(b"\r\nLast login: Mon Dec 25 10:30:00 2024 from 192.168.1.50\r\n")
                        await writer.drain()
                        await self.handle_shell(reader, writer, ip_address, connection)
                        return
                    else:
                        writer.write(b"\r\nPermission denied, please try again.\r\n")
                        await writer.drain()
                
                attempts += 1
                
            except asyncio.TimeoutError:
                break
            except Exception as e:
                logger.error(f"Auth error from {ip_address}: {e}")
                break
    
    async def handle_shell(self, reader, writer, ip_address: str, connection):
        """Handle shell commands after authentication."""
        prompt = b"\r\nroot@honeypot:~# "
        
        writer.write(prompt)
        await writer.drain()
        
        while True:
            try:
                command = await asyncio.wait_for(reader.readline(), timeout=120)
                command = command.decode('utf-8', errors='ignore').strip()
                
                if not command:
                    continue
                
                # Log command — await added
                await self.log_command(ip_address, command, connection=connection)
                
                if command.lower() in ['exit', 'logout', 'quit']:
                    writer.write(b"\r\nlogout\r\n")
                    await writer.drain()
                    break
                
                response = self.get_command_response(command)
                writer.write(f"\r\n{response}\r\n".encode())
                writer.write(prompt)
                await writer.drain()
                
            except asyncio.TimeoutError:
                writer.write(b"\r\nConnection timed out.\r\n")
                await writer.drain()
                break
            except Exception as e:
                logger.error(f"Shell error from {ip_address}: {e}")
                break
    
    def get_command_response(self, command: str) -> str:
        """Generate fake response for commands."""
        cmd_base = command.split()[0] if command else ''
        
        if command in self.FAKE_RESPONSES:
            return self.FAKE_RESPONSES[command]
        
        for key, response in self.FAKE_RESPONSES.items():
            if cmd_base == key.split()[0]:
                return response
        
        if cmd_base in ['cd', 'echo']:
            return ''
        elif cmd_base in ['cat', 'less', 'more', 'head', 'tail']:
            return 'cat: cannot access: No such file or directory'
        elif cmd_base in ['wget', 'curl']:
            return 'Connecting...\nConnection refused'
        elif cmd_base in ['rm', 'mkdir', 'touch', 'mv', 'cp']:
            return ''
        
        return f'{cmd_base}: command not found'


async def run_ssh_honeypot():
    """Run the SSH honeypot."""
    honeypot = SSHHoneypot()
    await honeypot.start()


if __name__ == '__main__':
    asyncio.run(run_ssh_honeypot())
