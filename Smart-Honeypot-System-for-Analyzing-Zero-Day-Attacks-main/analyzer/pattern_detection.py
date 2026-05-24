"""
Pattern Detection Module
Detects known attack patterns and signatures.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger('honeypot')


class PatternDetector:
    """Detects attack patterns in commands and inputs."""
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        (r"(\%27)|(\')|(\-\-)|(\%23)|(#)", "SQL comment/quote injection"),
        (r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))", "SQL equals with injection"),
        (r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))", "SQL OR injection"),
        (r"((\%27)|(\'))union", "SQL UNION injection"),
        (r"exec(\s|\+)+(s|x)p\w+", "SQL exec injection"),
        (r"insert\s+into", "SQL INSERT injection"),
        (r"delete\s+from", "SQL DELETE injection"),
        (r"drop\s+table", "SQL DROP injection"),
        (r"select\s+.*\s+from", "SQL SELECT injection"),
        (r"union\s+select", "SQL UNION SELECT injection"),
        (r"1\s*=\s*1", "SQL always true condition"),
        (r"or\s+1\s*=\s*1", "SQL OR true injection"),
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        (r"<\s*script[^>]*>", "Script tag injection"),
        (r"javascript\s*:", "JavaScript protocol"),
        (r"on\w+\s*=", "Event handler injection"),
        (r"<\s*img[^>]+onerror", "IMG onerror injection"),
        (r"<\s*iframe", "Iframe injection"),
        (r"<\s*svg[^>]+onload", "SVG onload injection"),
        (r"expression\s*\(", "CSS expression injection"),
        (r"document\.cookie", "Cookie access attempt"),
        (r"document\.location", "Location manipulation"),
    ]
    
    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        (r";\s*cat\s+/etc/passwd", "Password file access"),
        (r";\s*cat\s+/etc/shadow", "Shadow file access"),
        (r"\|\s*bash", "Bash pipe injection"),
        (r"\|\s*sh", "Shell pipe injection"),
        (r"`[^`]+`", "Backtick command execution"),
        (r"\$\([^)]+\)", "Subshell execution"),
        (r"&&\s*\w+", "Command chaining"),
        (r"\|\|\s*\w+", "Command chaining OR"),
        (r";\s*wget\s+", "wget injection"),
        (r";\s*curl\s+", "curl injection"),
        (r"nc\s+-e", "Netcat reverse shell"),
        (r"bash\s+-i\s+>&", "Bash reverse shell"),
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        (r"\.\./", "Path traversal dot-dot-slash"),
        (r"\.\.\\", "Path traversal dot-dot-backslash"),
        (r"%2e%2e%2f", "URL encoded path traversal"),
        (r"%2e%2e/", "Partial encoded path traversal"),
        (r"\.%2e/", "Mixed encoding path traversal"),
        (r"/etc/passwd", "Direct passwd access"),
        (r"/etc/shadow", "Direct shadow access"),
        (r"c:\\windows", "Windows path access"),
    ]
    
    # Brute force patterns (username patterns)
    COMMON_USERNAMES = [
        'admin', 'root', 'administrator', 'user', 'test',
        'guest', 'oracle', 'mysql', 'postgres', 'ftp',
        'www', 'nobody', 'apache', 'nginx', 'www-data'
    ]
    
    # Malware download patterns
    MALWARE_PATTERNS = [
        (r"wget\s+http[^\s]+\.sh", "Shell script download"),
        (r"curl\s+http[^\s]+\.sh", "Shell script download"),
        (r"wget\s+.*\|.*bash", "Wget pipe to bash"),
        (r"curl\s+.*\|.*bash", "Curl pipe to bash"),
        (r"python\s+-c\s+.*import\s+socket", "Python socket"),
        (r"perl\s+-e\s+.*socket", "Perl socket"),
        (r"tftp\s+-i", "TFTP download"),
    ]
    
    def __init__(self):
        self.compile_patterns()
    
    def compile_patterns(self):
        """Compile all regex patterns for performance."""
        self.compiled_sql = [(re.compile(p, re.IGNORECASE), d) for p, d in self.SQL_INJECTION_PATTERNS]
        self.compiled_xss = [(re.compile(p, re.IGNORECASE), d) for p, d in self.XSS_PATTERNS]
        self.compiled_cmd = [(re.compile(p, re.IGNORECASE), d) for p, d in self.COMMAND_INJECTION_PATTERNS]
        self.compiled_path = [(re.compile(p, re.IGNORECASE), d) for p, d in self.PATH_TRAVERSAL_PATTERNS]
        self.compiled_malware = [(re.compile(p, re.IGNORECASE), d) for p, d in self.MALWARE_PATTERNS]
    
    def detect_sql_injection(self, input_str: str) -> List[Tuple[str, str]]:
        """Detect SQL injection patterns."""
        matches = []
        for pattern, description in self.compiled_sql:
            if pattern.search(input_str):
                matches.append(('SQL_INJECTION', description))
        return matches
    
    def detect_xss(self, input_str: str) -> List[Tuple[str, str]]:
        """Detect XSS patterns."""
        matches = []
        for pattern, description in self.compiled_xss:
            if pattern.search(input_str):
                matches.append(('XSS', description))
        return matches
    
    def detect_command_injection(self, input_str: str) -> List[Tuple[str, str]]:
        """Detect command injection patterns."""
        matches = []
        for pattern, description in self.compiled_cmd:
            if pattern.search(input_str):
                matches.append(('COMMAND_INJECTION', description))
        return matches
    
    def detect_path_traversal(self, input_str: str) -> List[Tuple[str, str]]:
        """Detect path traversal patterns."""
        matches = []
        for pattern, description in self.compiled_path:
            if pattern.search(input_str):
                matches.append(('PATH_TRAVERSAL', description))
        return matches
    
    def detect_malware_download(self, input_str: str) -> List[Tuple[str, str]]:
        """Detect malware download patterns."""
        matches = []
        for pattern, description in self.compiled_malware:
            if pattern.search(input_str):
                matches.append(('MALWARE_DOWNLOAD', description))
        return matches
    
    def analyze(self, input_str: str) -> Dict:
        """Analyze input for all attack patterns."""
        results = {
            'sql_injection': self.detect_sql_injection(input_str),
            'xss': self.detect_xss(input_str),
            'command_injection': self.detect_command_injection(input_str),
            'path_traversal': self.detect_path_traversal(input_str),
            'malware_download': self.detect_malware_download(input_str),
        }
        
        # Determine primary attack type
        all_matches = []
        for category, matches in results.items():
            all_matches.extend(matches)
        
        results['total_matches'] = len(all_matches)
        results['is_attack'] = len(all_matches) > 0
        
        if all_matches:
            results['primary_attack'] = all_matches[0][0]
            results['severity'] = self.calculate_severity(all_matches)
        else:
            results['primary_attack'] = None
            results['severity'] = 'NONE'
        
        return results
    
    def calculate_severity(self, matches: List[Tuple[str, str]]) -> str:
        """Calculate severity based on attack matches."""
        critical_attacks = ['MALWARE_DOWNLOAD', 'COMMAND_INJECTION']
        high_attacks = ['SQL_INJECTION']
        
        attack_types = [m[0] for m in matches]
        
        if any(a in attack_types for a in critical_attacks):
            return 'CRITICAL'
        elif any(a in attack_types for a in high_attacks):
            return 'HIGH'
        elif len(matches) > 3:
            return 'HIGH'
        elif len(matches) > 1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def is_common_credential(self, username: str, password: str) -> bool:
        """Check if credentials are commonly used in attacks."""
        common_passwords = ['password', '123456', 'admin', 'root', 'test', 'guest', 'default']
        
        is_common_user = username.lower() in self.COMMON_USERNAMES
        is_common_pass = password.lower() in common_passwords or len(password) < 4
        
        return is_common_user or is_common_pass


# Global instance
pattern_detector = PatternDetector()
