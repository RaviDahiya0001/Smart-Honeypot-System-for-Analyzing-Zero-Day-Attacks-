"""
Encryption utilities for secure log storage.
"""

import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from django.conf import settings


class EncryptionManager:
    """Manages encryption for sensitive data."""
    
    def __init__(self):
        self.key = self._get_or_create_key()
        self.fernet = Fernet(self.key)
    
    def _get_or_create_key(self) -> bytes:
        """Get or derive encryption key from Django secret."""
        secret = settings.SECRET_KEY.encode()
        salt = b'honeypot_salt_v1'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret))
        return key
    
    def encrypt(self, data: str) -> str:
        """Encrypt a string."""
        return self.fernet.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt an encrypted string."""
        return self.fernet.decrypt(encrypted_data.encode()).decode()
    
    def hash_password(self, password: str) -> str:
        """Create a secure hash of a password."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def hash_file(self, file_content: bytes) -> str:
        """Create SHA256 hash of file content."""
        return hashlib.sha256(file_content).hexdigest()


# Global instance
encryption_manager = EncryptionManager()
