"""
FTP Honeypot Service
Simulates an FTP server to capture credentials and file operations.
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


class FTPHoneypot(BaseHoneypot):
    """FTP Honeypot that simulates an FTP server."""
    
    BANNER = "220 Welcome to FTP Server (vsFTPd 3.0.3)\r\n"
    
    FAKE_FILES = {
        '/': ['backup', 'www', 'logs', 'config', 'database.sql.gz'],
        '/backup': ['backup_2024-01-01.tar.gz', 'backup_2024-01-15.tar.gz', 'secrets.zip'],
        '/www': ['index.html', 'config.php', 'wp-config.php', '.htaccess'],
        '/config': ['database.ini', 'settings.json', 'credentials.txt'],
    }
    
    def __init__(self, host='0.0.0.0', port=2121):
        super().__init__(host, port, 'FTP')
        self.current_user = None
        self.authenticated = False
        self.current_dir = '/'
    
    async def start(self):
        """Start the FTP honeypot."""
        self.server = await asyncio.start_server(
            self.handle_connection,
            self.host,
            self.port
        )
        self.is_running = True
        logger.info(f"FTP Honeypot started on {self.host}:{self.port}")
        
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
        self.authenticated = False
        self.current_user = None
        self.current_dir = '/'
        
        try:
            writer.write(self.BANNER.encode())
            await writer.drain()
            
            while True:
                try:
                    data = await asyncio.wait_for(reader.readline(), timeout=60)
                    if not data:
                        break
                    
                    command = data.decode('utf-8', errors='ignore').strip()
                    if not command:
                        continue
                    
                    response = await self.process_command(command, ip_address, connection)
                    writer.write(f"{response}\r\n".encode())
                    await writer.drain()
                    
                    if command.upper().startswith('QUIT'):
                        break
                        
                except asyncio.TimeoutError:
                    writer.write(b"421 Timeout.\r\n")
                    await writer.drain()
                    break
                    
        except Exception as e:
            logger.error(f"FTP error from {ip_address}: {e}")
        finally:
            writer.close()
    
    async def process_command(self, command: str, ip_address: str, connection) -> str:
        """Process FTP commands."""
        parts = command.split(' ', 1)
        cmd = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ''
        
        # await added
        await self.log_command(ip_address, command, connection=connection)
        
        if cmd == 'USER':
            self.current_user = args
            return "331 Please specify the password."
        
        elif cmd == 'PASS':
            if self.current_user:
                # await added
                await self.log_login_attempt(ip_address, self.current_user, args, connection=connection)
                self.authenticated = True
                return "230 Login successful."
            return "503 Login with USER first."
        
        elif cmd == 'SYST':
            return "215 UNIX Type: L8"
        
        elif cmd == 'FEAT':
            return "211-Features:\r\n SIZE\r\n MDTM\r\n211 End"
        
        elif cmd == 'PWD':
            if not self.authenticated:
                return "530 Please login with USER and PASS."
            return f'257 "{self.current_dir}" is the current directory'
        
        elif cmd == 'CWD':
            if not self.authenticated:
                return "530 Please login with USER and PASS."
            if args in self.FAKE_FILES or args == '..':
                self.current_dir = args if args != '..' else '/'
                return "250 Directory successfully changed."
            return "550 Failed to change directory."
        
        elif cmd == 'LIST' or cmd == 'NLST':
            if not self.authenticated:
                return "530 Please login with USER and PASS."
            return self.generate_listing()
        
        elif cmd == 'RETR':
            if not self.authenticated:
                return "530 Please login with USER and PASS."
            # await added
            await self.log_file_activity(ip_address, args, 'DOWNLOAD', connection=connection)
            return "550 File not found."
        
        elif cmd == 'STOR':
            if not self.authenticated:
                return "530 Please login with USER and PASS."
            # await added
            await self.log_file_activity(ip_address, args, 'UPLOAD', connection=connection)
            return "226 Transfer complete."
        
        elif cmd == 'DELE':
            # await added
            await self.log_file_activity(ip_address, args, 'DELETE', connection=connection)
            return "550 Permission denied."
        
        elif cmd == 'QUIT':
            return "221 Goodbye."
        
        elif cmd == 'TYPE':
            return "200 Switching to Binary mode."
        
        elif cmd == 'PASV':
            return "227 Entering Passive Mode (192,168,1,100,39,50)."
        
        return "500 Unknown command."
    
    def generate_listing(self) -> str:
        """Generate fake directory listing."""
        files = self.FAKE_FILES.get(self.current_dir, [])
        listing = "150 Here comes the directory listing.\r\n"
        for f in files:
            if '.' in f:
                listing += f"-rw-r--r-- 1 root root     1024 Dec 25 10:00 {f}\r\n"
            else:
                listing += f"drwxr-xr-x 2 root root     4096 Dec 25 10:00 {f}\r\n"
        listing += "226 Directory send OK."
        return listing


async def run_ftp_honeypot():
    honeypot = FTPHoneypot()
    await honeypot.start()


if __name__ == '__main__':
    asyncio.run(run_ftp_honeypot())
