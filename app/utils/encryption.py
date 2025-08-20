"""
Encryption utilities for securing sensitive data at rest.

This module provides AES-256 encryption for PATs, cookies, and other
sensitive data with proper key management and security practices.
"""

import base64
import hashlib
import secrets
from typing import Union, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import bcrypt

from app.exceptions import SecurityError
from app.utils.logging import get_logger

logger = get_logger(__name__)


class EncryptionManager:
    """
    Manages encryption and decryption of sensitive data.
    
    Uses AES-256 encryption via Fernet (symmetric encryption) with
    PBKDF2 key derivation for secure key generation.
    """
    
    def __init__(self, master_key: Optional[str] = None) -> None:
        """
        Initialize encryption manager.
        
        Args:
            master_key: Master key for encryption (uses app secret if not provided)
        """
        if master_key is None:
            # In production, this should come from environment or secure key management
            from app.config import settings
            master_key = settings.secret_key
        
        self._master_key = master_key.encode()
        self._fernet = None
    
    def _get_fernet(self, salt: bytes) -> Fernet:
        """
        Get Fernet instance with derived key.
        
        Args:
            salt: Salt for key derivation
            
        Returns:
            Fernet encryption instance
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # OWASP recommended minimum
        )
        key = base64.urlsafe_b64encode(kdf.derive(self._master_key))
        return Fernet(key)
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext string.
        
        Args:
            plaintext: String to encrypt
            
        Returns:
            Base64 encoded encrypted string with salt
            
        Raises:
            SecurityError: If encryption fails
        """
        try:
            if not isinstance(plaintext, str):
                plaintext = str(plaintext)
            
            # Generate random salt
            salt = secrets.token_bytes(16)
            
            # Get Fernet instance with derived key
            fernet = self._get_fernet(salt)
            
            # Encrypt the plaintext
            encrypted_data = fernet.encrypt(plaintext.encode())
            
            # Combine salt and encrypted data
            combined = salt + encrypted_data
            
            # Return base64 encoded result
            return base64.urlsafe_b64encode(combined).decode()
            
        except Exception as e:
            logger.error("Encryption failed", error=str(e))
            raise SecurityError(
                "Failed to encrypt data",
                error_code="ENCRYPTION_FAILED",
                details={"error": str(e)}
            ) from e
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt encrypted string.
        
        Args:
            encrypted_data: Base64 encoded encrypted string with salt
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            SecurityError: If decryption fails
        """
        try:
            if not isinstance(encrypted_data, str):
                raise SecurityError("Encrypted data must be a string")
            
            # Decode base64
            combined = base64.urlsafe_b64decode(encrypted_data.encode())
            
            # Extract salt and encrypted data
            salt = combined[:16]
            encrypted_bytes = combined[16:]
            
            # Get Fernet instance with derived key
            fernet = self._get_fernet(salt)
            
            # Decrypt the data
            decrypted_bytes = fernet.decrypt(encrypted_bytes)
            
            return decrypted_bytes.decode()
            
        except Exception as e:
            logger.error("Decryption failed", error=str(e))
            raise SecurityError(
                "Failed to decrypt data",
                error_code="DECRYPTION_FAILED",
                details={"error": str(e)}
            ) from e
    
    def is_encrypted(self, data: str) -> bool:
        """
        Check if data appears to be encrypted.
        
        Args:
            data: String to check
            
        Returns:
            True if data appears encrypted, False otherwise
        """
        try:
            # Try to decode as base64
            decoded = base64.urlsafe_b64decode(data.encode())
            # Should have at least 16 bytes for salt + some encrypted data
            return len(decoded) > 16
        except Exception:
            return False


class PasswordManager:
    """
    Manages password hashing and verification using bcrypt.
    
    Provides secure password hashing with salt and configurable rounds
    for protection against rainbow table and brute force attacks.
    """
    
    def __init__(self, rounds: int = 12) -> None:
        """
        Initialize password manager.
        
        Args:
            rounds: Number of bcrypt rounds (higher = more secure but slower)
        """
        self.rounds = rounds
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt with salt.
        
        Args:
            password: Plain text password
            
        Returns:
            Bcrypt hashed password
            
        Raises:
            SecurityError: If hashing fails
        """
        try:
            if not isinstance(password, str):
                password = str(password)
            
            # Generate salt and hash password
            salt = bcrypt.gensalt(rounds=self.rounds)
            hashed = bcrypt.hashpw(password.encode(), salt)
            
            return hashed.decode()
            
        except Exception as e:
            logger.error("Password hashing failed", error=str(e))
            raise SecurityError(
                "Failed to hash password",
                error_code="PASSWORD_HASH_FAILED",
                details={"error": str(e)}
            ) from e
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Plain text password
            hashed_password: Bcrypt hashed password
            
        Returns:
            True if password matches, False otherwise
            
        Raises:
            SecurityError: If verification fails
        """
        try:
            if not isinstance(password, str) or not isinstance(hashed_password, str):
                return False
            
            return bcrypt.checkpw(password.encode(), hashed_password.encode())
            
        except Exception as e:
            logger.error("Password verification failed", error=str(e))
            raise SecurityError(
                "Failed to verify password",
                error_code="PASSWORD_VERIFY_FAILED",
                details={"error": str(e)}
            ) from e
    
    def is_password_hash(self, data: str) -> bool:
        """
        Check if data appears to be a bcrypt hash.
        
        Args:
            data: String to check
            
        Returns:
            True if data appears to be bcrypt hash, False otherwise
        """
        try:
            # Bcrypt hashes start with $2a$, $2b$, or $2y$
            return (
                isinstance(data, str) and
                len(data) == 60 and
                data.startswith(('$2a$', '$2b$', '$2y$'))
            )
        except Exception:
            return False


class TokenManager:
    """
    Manages secure token generation and validation.
    
    Provides utilities for generating secure random tokens
    for sessions, API keys, and other security purposes.
    """
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """
        Generate cryptographically secure random token.
        
        Args:
            length: Token length in bytes
            
        Returns:
            URL-safe base64 encoded token
        """
        token_bytes = secrets.token_bytes(length)
        return base64.urlsafe_b64encode(token_bytes).decode().rstrip('=')
    
    @staticmethod
    def generate_session_id() -> str:
        """
        Generate secure session ID.
        
        Returns:
            Session ID string
        """
        return TokenManager.generate_token(24)
    
    @staticmethod
    def generate_api_key() -> str:
        """
        Generate secure API key.
        
        Returns:
            API key string
        """
        return TokenManager.generate_token(32)
    
    @staticmethod
    def hash_token(token: str) -> str:
        """
        Hash token for secure storage.
        
        Args:
            token: Token to hash
            
        Returns:
            SHA-256 hash of token
        """
        return hashlib.sha256(token.encode()).hexdigest()
    
    @staticmethod
    def verify_token_hash(token: str, token_hash: str) -> bool:
        """
        Verify token against its hash.
        
        Args:
            token: Original token
            token_hash: SHA-256 hash of token
            
        Returns:
            True if token matches hash, False otherwise
        """
        try:
            computed_hash = TokenManager.hash_token(token)
            return secrets.compare_digest(computed_hash, token_hash)
        except Exception:
            return False


# Global instances
encryption_manager = EncryptionManager()
password_manager = PasswordManager()


def encrypt_sensitive_data(data: str) -> str:
    """
    Encrypt sensitive data using the global encryption manager.
    
    Args:
        data: Sensitive data to encrypt
        
    Returns:
        Encrypted data
    """
    return encryption_manager.encrypt(data)


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """
    Decrypt sensitive data using the global encryption manager.
    
    Args:
        encrypted_data: Encrypted data to decrypt
        
    Returns:
        Decrypted data
    """
    return encryption_manager.decrypt(encrypted_data)


def hash_password(password: str) -> str:
    """
    Hash password using the global password manager.
    
    Args:
        password: Password to hash
        
    Returns:
        Hashed password
    """
    return password_manager.hash_password(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify password using the global password manager.
    
    Args:
        password: Plain text password
        hashed_password: Hashed password
        
    Returns:
        True if password is valid, False otherwise
    """
    return password_manager.verify_password(password, hashed_password)


def generate_secure_token(length: int = 32) -> str:
    """
    Generate secure random token.
    
    Args:
        length: Token length in bytes
        
    Returns:
        Secure token
    """
    return TokenManager.generate_token(length)


def hash_token(token: str) -> str:
    """
    Hash token for secure storage.
    
    Args:
        token: Token to hash
        
    Returns:
        Token hash
    """
    return TokenManager.hash_token(token)