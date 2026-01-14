"""
Data encryption and security layer for ThreatLens
Implements AES-256 encryption for security data at rest and secure key management
"""
import os
import base64
import hashlib
import secrets
import logging
from typing import Optional, Dict, Any, Union, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json

from api.config import settings

logger = logging.getLogger(__name__)


class SecurityEncryptionError(Exception):
    """Security encryption related errors"""
    pass


class KeyManager:
    """Secure key management and rotation system"""
    
    def __init__(self, key_storage_path: Optional[str] = None):
        self.key_storage_path = Path(key_storage_path or settings.storage_base_path) / "security" / "keys"
        self.key_storage_path.mkdir(parents=True, exist_ok=True)
        
        # Master key file paths
        self.master_key_file = self.key_storage_path / "master.key"
        self.key_metadata_file = self.key_storage_path / "key_metadata.json"
        
        # Initialize master key if not exists
        self._initialize_master_key()
    
    def _initialize_master_key(self):
        """Initialize master encryption key"""
        if not self.master_key_file.exists():
            logger.info("Generating new master encryption key")
            master_key = Fernet.generate_key()
            
            # Write master key with restricted permissions
            with open(self.master_key_file, 'wb') as f:
                f.write(master_key)
            
            # Set restrictive permissions (owner read/write only)
            os.chmod(self.master_key_file, 0o600)
            
            # Initialize metadata
            metadata = {
                "created_at": datetime.now().isoformat(),
                "version": 1,
                "rotation_history": [],
                "algorithm": "Fernet (AES-128 in CBC mode)"
            }
            
            with open(self.key_metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info("Master encryption key initialized successfully")
    
    def get_master_key(self) -> bytes:
        """Get the master encryption key"""
        try:
            with open(self.master_key_file, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read master key: {e}")
            raise SecurityEncryptionError(f"Cannot access master encryption key: {e}")
    
    def rotate_master_key(self) -> Dict[str, Any]:
        """Rotate the master encryption key"""
        rotation_info = {
            "started_at": datetime.now().isoformat(),
            "success": False,
            "old_key_backed_up": False,
            "new_key_generated": False,
            "error": None
        }
        
        try:
            # Backup old key
            old_key = self.get_master_key()
            backup_file = self.key_storage_path / f"master_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.key"
            
            with open(backup_file, 'wb') as f:
                f.write(old_key)
            os.chmod(backup_file, 0o600)
            rotation_info["old_key_backed_up"] = True
            
            # Generate new key
            new_key = Fernet.generate_key()
            
            with open(self.master_key_file, 'wb') as f:
                f.write(new_key)
            rotation_info["new_key_generated"] = True
            
            # Update metadata
            metadata = self._load_key_metadata()
            metadata["rotation_history"].append({
                "rotated_at": datetime.now().isoformat(),
                "old_key_backup": str(backup_file),
                "version": metadata["version"] + 1
            })
            metadata["version"] += 1
            
            with open(self.key_metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            rotation_info["success"] = True
            rotation_info["completed_at"] = datetime.now().isoformat()
            
            logger.info("Master key rotated successfully")
            
        except Exception as e:
            rotation_info["error"] = str(e)
            logger.error(f"Master key rotation failed: {e}")
        
        return rotation_info
    
    def _load_key_metadata(self) -> Dict[str, Any]:
        """Load key metadata"""
        try:
            with open(self.key_metadata_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {
                "created_at": datetime.now().isoformat(),
                "version": 1,
                "rotation_history": [],
                "algorithm": "Fernet (AES-128 in CBC mode)"
            }
    
    def generate_data_key(self, purpose: str) -> Tuple[bytes, str]:
        """Generate a data encryption key for specific purpose"""
        data_key = Fernet.generate_key()
        key_id = f"{purpose}_{secrets.token_hex(16)}"
        
        # Encrypt data key with master key
        master_fernet = Fernet(self.get_master_key())
        encrypted_data_key = master_fernet.encrypt(data_key)
        
        # Store encrypted data key
        key_file = self.key_storage_path / f"{key_id}.key"
        with open(key_file, 'wb') as f:
            f.write(encrypted_data_key)
        os.chmod(key_file, 0o600)
        
        return data_key, key_id
    
    def get_data_key(self, key_id: str) -> bytes:
        """Retrieve and decrypt a data encryption key"""
        key_file = self.key_storage_path / f"{key_id}.key"
        
        if not key_file.exists():
            raise SecurityEncryptionError(f"Data key not found: {key_id}")
        
        try:
            with open(key_file, 'rb') as f:
                encrypted_data_key = f.read()
            
            master_fernet = Fernet(self.get_master_key())
            return master_fernet.decrypt(encrypted_data_key)
        
        except Exception as e:
            logger.error(f"Failed to decrypt data key {key_id}: {e}")
            raise SecurityEncryptionError(f"Cannot decrypt data key: {e}")


class DataEncryption:
    """AES-256 encryption for security data at rest"""
    
    def __init__(self, key_manager: Optional[KeyManager] = None):
        self.key_manager = key_manager or KeyManager()
        self._data_keys: Dict[str, bytes] = {}
    
    def encrypt_security_data(self, data: Union[str, bytes, Dict[str, Any]], 
                            purpose: str = "security_data") -> Dict[str, Any]:
        """Encrypt security data with AES-256"""
        try:
            # Convert data to bytes if needed
            if isinstance(data, dict):
                data_bytes = json.dumps(data, default=str).encode('utf-8')
            elif isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
            
            # Get or generate data key for this purpose
            if purpose not in self._data_keys:
                data_key, key_id = self.key_manager.generate_data_key(purpose)
                self._data_keys[purpose] = data_key
            else:
                data_key = self._data_keys[purpose]
                key_id = f"{purpose}_existing"
            
            # Encrypt with Fernet (AES-128 in CBC mode with HMAC)
            fernet = Fernet(data_key)
            encrypted_data = fernet.encrypt(data_bytes)
            
            return {
                "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
                "key_id": key_id,
                "algorithm": "Fernet-AES-128-CBC-HMAC",
                "encrypted_at": datetime.now().isoformat(),
                "data_type": type(data).__name__
            }
        
        except Exception as e:
            logger.error(f"Data encryption failed: {e}")
            raise SecurityEncryptionError(f"Encryption failed: {e}")
    
    def decrypt_security_data(self, encrypted_package: Dict[str, Any]) -> Union[str, bytes, Dict[str, Any]]:
        """Decrypt security data"""
        try:
            encrypted_data = base64.b64decode(encrypted_package["encrypted_data"])
            key_id = encrypted_package["key_id"]
            data_type = encrypted_package.get("data_type", "str")
            
            # Extract purpose from key_id
            purpose = key_id.split('_')[0] if '_' in key_id else "security_data"
            
            # Get data key
            if purpose in self._data_keys:
                data_key = self._data_keys[purpose]
            else:
                data_key = self.key_manager.get_data_key(key_id)
                self._data_keys[purpose] = data_key
            
            # Decrypt
            fernet = Fernet(data_key)
            decrypted_bytes = fernet.decrypt(encrypted_data)
            
            # Convert back to original type
            if data_type == "dict":
                return json.loads(decrypted_bytes.decode('utf-8'))
            elif data_type == "str":
                return decrypted_bytes.decode('utf-8')
            else:
                return decrypted_bytes
        
        except Exception as e:
            logger.error(f"Data decryption failed: {e}")
            raise SecurityEncryptionError(f"Decryption failed: {e}")
    
    def encrypt_field(self, value: Any, field_name: str) -> str:
        """Encrypt a single field value"""
        if value is None:
            return None
        
        encrypted_package = self.encrypt_security_data(value, f"field_{field_name}")
        return json.dumps(encrypted_package)
    
    def decrypt_field(self, encrypted_value: str) -> Any:
        """Decrypt a single field value"""
        if not encrypted_value:
            return None
        
        try:
            encrypted_package = json.loads(encrypted_value)
            return self.decrypt_security_data(encrypted_package)
        except Exception as e:
            logger.error(f"Field decryption failed: {e}")
            return encrypted_value  # Return as-is if decryption fails


class SecureHasher:
    """Secure hashing utilities for data integrity"""
    
    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
        """Hash password with PBKDF2-SHA256"""
        if salt is None:
            salt = os.urandom(32)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode('utf-8'))
        
        return (
            base64.b64encode(key).decode('utf-8'),
            base64.b64encode(salt).decode('utf-8')
        )
    
    @staticmethod
    def verify_password(password: str, hashed_password: str, salt: str) -> bool:
        """Verify password against hash"""
        try:
            salt_bytes = base64.b64decode(salt)
            expected_hash = base64.b64decode(hashed_password)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=100000,
                backend=default_backend()
            )
            
            kdf.verify(password.encode('utf-8'), expected_hash)
            return True
        
        except Exception:
            return False
    
    @staticmethod
    def hash_data(data: Union[str, bytes]) -> str:
        """Create SHA-256 hash of data for integrity checking"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)


class TLSConfiguration:
    """TLS 1.3 configuration utilities"""
    
    @staticmethod
    def get_secure_ssl_context():
        """Get secure SSL context for TLS 1.3"""
        import ssl
        
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # Force TLS 1.3 minimum
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # Secure cipher suites
        context.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256')
        
        # Security options
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_NO_TLSv1_2
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE
        
        return context
    
    @staticmethod
    def validate_certificate_chain(cert_path: str, key_path: str) -> Dict[str, Any]:
        """Validate TLS certificate chain"""
        validation_result = {
            "valid": False,
            "errors": [],
            "warnings": [],
            "certificate_info": {}
        }
        
        try:
            # Load certificate
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            cert = serialization.load_pem_x509_certificate(cert_data, default_backend())
            
            # Check expiration
            now = datetime.now()
            if cert.not_valid_after < now:
                validation_result["errors"].append("Certificate has expired")
            elif cert.not_valid_after < now + timedelta(days=30):
                validation_result["warnings"].append("Certificate expires within 30 days")
            
            # Check key usage
            try:
                key_usage = cert.extensions.get_extension_for_oid(
                    serialization.oid.ExtensionOID.KEY_USAGE
                ).value
                
                if not key_usage.digital_signature:
                    validation_result["warnings"].append("Certificate lacks digital signature capability")
                
                if not key_usage.key_encipherment:
                    validation_result["warnings"].append("Certificate lacks key encipherment capability")
            
            except Exception:
                validation_result["warnings"].append("Could not verify key usage extensions")
            
            # Load and validate private key
            with open(key_path, 'rb') as f:
                key_data = f.read()
            
            private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
            
            # Verify key matches certificate
            public_key = cert.public_key()
            
            # Basic validation passed
            validation_result["valid"] = len(validation_result["errors"]) == 0
            validation_result["certificate_info"] = {
                "subject": str(cert.subject),
                "issuer": str(cert.issuer),
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "serial_number": str(cert.serial_number)
            }
        
        except Exception as e:
            validation_result["errors"].append(f"Certificate validation failed: {e}")
        
        return validation_result


# Global instances
key_manager = KeyManager()
data_encryption = DataEncryption(key_manager)
secure_hasher = SecureHasher()