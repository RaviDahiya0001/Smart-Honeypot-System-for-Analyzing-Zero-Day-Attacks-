"""
HTTP Honeypot Service
Simulates vulnerable web applications with SQLi, XSS, and file upload vulnerabilities.
"""

import asyncio
import logging
import os
import sys
import re
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeypot.settings')

import django
django.setup()

from services.base_honeypot import BaseHoneypot

logger = logging.getLogger('honeypot')


class HTTPHoneypot(BaseHoneypot):
    """HTTP Honeypot simulating vulnerable web applications."""
    
    def __init__(self, host='0.0.0.0', port=8080):
        super().__init__(host, port, 'HTTP')
    
    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_connection, self.host, self.port
        )
        self.is_running = True
        logger.info(f"HTTP Honeypot started on {self.host}:{self.port}")
        
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
            request_data = await asyncio.wait_for(reader.read(8192), timeout=30)
            if not request_data:
                return
            
            request = request_data.decode('utf-8', errors='ignore')
            response = await self.process_request(request, ip_address, connection)
            
            writer.write(response.encode())
            await writer.drain()
            
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.error(f"HTTP error from {ip_address}: {e}")
        finally:
            writer.close()
    
    async def process_request(self, request: str, ip_address: str, connection) -> str:
        """Process HTTP request and return response."""
        lines = request.split('\r\n')
        if not lines:
            return self.error_response(400, "Bad Request")
        
        request_line = lines[0].split(' ')
        if len(request_line) < 2:
            return self.error_response(400, "Bad Request")
        
        method = request_line[0]
        path = request_line[1]
        
        # await added
        await self.log_command(ip_address, f"{method} {path}", connection=connection)
        
        # await added
        await self.detect_web_attacks(path, request, ip_address)
        
        parsed = urlparse(path)
        route = parsed.path
        query = parse_qs(parsed.query)
        
        body = ''
        if '\r\n\r\n' in request:
            body = request.split('\r\n\r\n', 1)[1]
        
        if route in ['/', '/index.html', '/index.php']:
            return self.home_page()
        elif route in ['/admin', '/admin/', '/admin/login', '/wp-admin', '/administrator']:
            return self.admin_login_page()
        elif route == '/login' and method == 'POST':
            return await self.handle_login(body, ip_address, connection)
        elif route in ['/phpmyadmin', '/pma', '/mysql']:
            return self.phpmyadmin_page()
        elif route == '/search':
            return self.search_page(query, ip_address)
        elif route == '/upload':
            return self.upload_page()
        elif route.endswith(('.php', '.asp', '.aspx', '.jsp')):
            return self.fake_php_page(route)
        elif 'robots.txt' in route:
            return self.robots_txt()
        elif '.env' in route or 'config' in route.lower():
            # await added
            await self.log_file_activity(ip_address, route, 'ACCESS', connection=connection)
            return self.fake_config_file(route)
        
        return self.error_response(404, "Not Found")
    
    async def detect_web_attacks(self, path: str, request: str, ip_address: str):
        """Detect common web attacks."""
        combined = path + request
        
        sql_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"union.*select",
            r"select.*from",
            r"insert.*into",
            r"drop.*table",
            r"1(\s*)=(\s*)1",
            r"or(\s+)1(\s*)=(\s*)1",
        ]
        for pattern in sql_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                # await added
                await self.create_alert('SQL_INJECTION', 'HIGH',
                    'SQL Injection attempt detected',
                    f'Pattern: {pattern}\nPath: {path}', ip_address)
                break
        
        xss_patterns = [r"<script", r"javascript:", r"onerror", r"onload", r"onclick"]
        for pattern in xss_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                # await added
                await self.create_alert('XSS', 'MEDIUM',
                    'XSS attempt detected',
                    f'Pattern: {pattern}\nPath: {path}', ip_address)
                break
        
        if '../' in combined or '..\\' in combined:
            # await added
            await self.create_alert('ANOMALY', 'HIGH',
                'Path traversal attempt',
                f'Path: {path}', ip_address)
    
    def home_page(self) -> str:
        html = """<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body>
<h1>Welcome to Our Server</h1>
<form action="/search" method="get">
<input name="q" placeholder="Search...">
<button type="submit">Search</button>
</form>
<a href="/admin">Admin Panel</a>
</body></html>"""
        return self.html_response(html)
    
    def admin_login_page(self) -> str:
        html = """<!DOCTYPE html>
<html><head><title>Admin Login</title></head>
<body style="font-family: Arial; display: flex; justify-content: center; align-items: center; height: 100vh; background: #1a1a2e;">
<div style="background: white; padding: 40px; border-radius: 10px;">
<h2 style="text-align: center; color: #333;">Administrator Login</h2>
<form action="/login" method="post">
<input type="text" name="username" placeholder="Username" style="width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
<input type="password" name="password" placeholder="Password" style="width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
<button type="submit" style="width: 100%; padding: 12px; background: #e74c3c; color: white; border: none; border-radius: 5px;">Login</button>
</form>
</div>
</body></html>"""
        return self.html_response(html)
    
    async def handle_login(self, body: str, ip_address: str, connection) -> str:
        params = parse_qs(body)
        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]
        
        if username or password:
            # await added
            await self.log_login_attempt(ip_address, username, password, connection=connection)
        
        return self.html_response("<h1>Invalid credentials</h1><a href='/admin'>Try again</a>")
    
    def phpmyadmin_page(self) -> str:
        html = """<!DOCTYPE html>
<html><head><title>phpMyAdmin</title></head>
<body style="font-family: Arial; background: #2c3e50; color: white; padding: 40px;">
<h1>phpMyAdmin 5.2.0</h1>
<form method="post">
<input name="pma_username" placeholder="Username"><br><br>
<input type="password" name="pma_password" placeholder="Password"><br><br>
<button type="submit">Log in</button>
</form>
</body></html>"""
        return self.html_response(html)
    
    def search_page(self, query: dict, ip_address: str) -> str:
        q = query.get('q', [''])[0]
        html = f"""<!DOCTYPE html>
<html><head><title>Search Results</title></head>
<body>
<h1>Search Results for: {q}</h1>
<p>No results found.</p>
</body></html>"""
        return self.html_response(html)
    
    def upload_page(self) -> str:
        html = """<!DOCTYPE html>
<html><head><title>File Upload</title></head>
<body>
<h1>Upload File</h1>
<form method="post" enctype="multipart/form-data">
<input type="file" name="file">
<button type="submit">Upload</button>
</form>
</body></html>"""
        return self.html_response(html)
    
    def fake_php_page(self, route: str) -> str:
        return self.html_response(f"<h1>Page not found: {route}</h1>")
    
    def robots_txt(self) -> str:
        content = """User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/
Disallow: /database/
Disallow: /.git/"""
        return f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n{content}"
    
    def fake_config_file(self, route: str) -> str:
        content = """DB_HOST=localhost
DB_USER=admin
DB_PASS=password123
SECRET_KEY=supersecretkey12345"""
        return f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n{content}"
    
    def html_response(self, content: str) -> str:
        return f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(content)}\r\n\r\n{content}"
    
    def error_response(self, code: int, message: str) -> str:
        return f"HTTP/1.1 {code} {message}\r\nContent-Type: text/html\r\n\r\n<h1>{code} {message}</h1>"


async def run_http_honeypot():
    honeypot = HTTPHoneypot()
    await honeypot.start()


if __name__ == '__main__':
    asyncio.run(run_http_honeypot())
