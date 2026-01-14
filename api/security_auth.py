"""
Secure session management with multi-factor authentication and role-based access controls
"""
import os
import jwt
import pyotp
import qrcode
import logging
import secrets
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import json
import hashlib
from io import BytesIO
import base64

from pydantic import BaseModel, Field
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from api.config import settings
from api.security_encryption import secure_hasher, SecurityEncryptionError
from api.security_validation import security_validator, ValidationError

logger = logging.getLogger(__name__)


class UserRole(str, Enum):
    """User roles for RBAC"""
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class Permission(str, Enum):
    """System permissions"""
    # Repository permissions
    REPO_CREATE = "repo:create"
    REPO_READ = "repo:read"
    REPO_UPDATE = "repo:update"
    REPO_DELETE = "repo:delete"
    
    # Security document permissions
    SECURITY_DOC_CREATE = "security_doc:create"
    SECURITY_DOC_READ = "security_doc:read"
    SECURITY_DOC_UPDATE = "security_doc:update"
    SECURITY_DOC_DELETE = "security_doc:delete"
    
    # Analysis permissions
    ANALYSIS_RUN = "analysis:run"
    ANALYSIS_VIEW = "analysis:view"
    ANALYSIS_MANAGE = "analysis:manage"
    
    # System administration
    SYSTEM_ADMIN = "system:admin"
    USER_MANAGE = "user:manage"
    AUDIT_VIEW = "audit:view"
    
    # Security operations
    SECURITY_CONFIG = "security:config"
    ENCRYPTION_MANAGE = "encryption:manage"


class SessionStatus(str, Enum):
    """Session status"""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    LOCKED = "locked"


class User(BaseModel):
    """User model with security features"""
    id: str
    username: str
    email: str
    password_hash: str
    password_salt: str
    role: UserRole
    permissions: List[Permission] = Field(default_factory=list)
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    failed_login_attempts: int = 0
    account_locked_until: Optional[datetime] = None
    last_login: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    is_active: bool = True
    
    class Config:
        use_enum_values = True


class Session(BaseModel):
    """User session model"""
    id: str
    user_id: str
    token: str
    refresh_token: str
    status: SessionStatus
    created_at: datetime = Field(default_factory=datetime.now)
    expires_at: datetime
    last_activity: datetime = Field(default_factory=datetime.now)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    mfa_verified: bool = False
    
    class Config:
        use_enum_values = True


class AuditLog(BaseModel):
    """Security audit log entry"""
    id: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    action: str
    resource: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)


class AuthenticationManager:
    """Secure authentication and session management"""
    
    def __init__(self):
        self.jwt_secret = self._get_jwt_secret()
        self.jwt_algorithm = "HS256"
        self.session_timeout = timedelta(hours=8)
        self.refresh_token_timeout = timedelta(days=30)
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
        
        # In-memory stores (in production, use Redis or database)
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.audit_logs: List[AuditLog] = []
        
        # Load default admin user
        self._create_default_admin()
    
    def _get_jwt_secret(self) -> str:
        """Get or generate JWT secret"""
        secret_file = Path(settings.storage_base_path) / "security" / "jwt_secret.key"
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        
        if secret_file.exists():
            with open(secret_file, 'r') as f:
                return f.read().strip()
        else:
            secret = secrets.token_urlsafe(64)
            with open(secret_file, 'w') as f:
                f.write(secret)
            os.chmod(secret_file, 0o600)
            return secret
    
    def _create_default_admin(self):
        """Create default admin user if none exists"""
        if not any(user.role == UserRole.ADMIN for user in self.users.values()):
            admin_password = os.getenv("ADMIN_PASSWORD", "admin123!")
            password_hash, password_salt = secure_hasher.hash_password(admin_password)
            
            admin_user = User(
                id="admin",
                username="admin",
                email="admin@threatlens.local",
                password_hash=password_hash,
                password_salt=password_salt,
                role=UserRole.ADMIN,
                permissions=list(Permission),  # Admin has all permissions
                is_active=True
            )
            
            self.users["admin"] = admin_user
            logger.info("Default admin user created")
    
    def register_user(self, username: str, email: str, password: str, 
                     role: UserRole = UserRole.VIEWER) -> User:
        """Register a new user"""
        try:
            # Validate input
            username = security_validator.validate_and_sanitize(username, "username", {
                "max_length": 50,
                "pattern": r"^[a-zA-Z0-9_-]+$"
            })
            
            email = security_validator.validate_and_sanitize(email, "email", {
                "type": "email"
            })
            
            # Check if user exists
            if any(u.username == username or u.email == email for u in self.users.values()):
                raise HTTPException(status_code=400, detail="User already exists")
            
            # Hash password
            password_hash, password_salt = secure_hasher.hash_password(password)
            
            # Create user
            user_id = secure_hasher.generate_secure_token(16)
            user = User(
                id=user_id,
                username=username,
                email=email,
                password_hash=password_hash,
                password_salt=password_salt,
                role=role,
                permissions=self._get_role_permissions(role)
            )
            
            self.users[user_id] = user
            
            # Audit log
            self._log_audit_event("user_registered", user_id, True, {
                "username": username,
                "email": email,
                "role": role
            })
            
            logger.info(f"User registered: {username}")
            return user
        
        except ValidationError as e:
            self._log_audit_event("user_registration_failed", None, False, {
                "error": e.message,
                "username": username
            })
            raise HTTPException(status_code=400, detail=e.message)
    
    def authenticate_user(self, username: str, password: str, 
                         request: Request, mfa_token: Optional[str] = None) -> Tuple[User, Session]:
        """Authenticate user with optional MFA"""
        try:
            # Find user
            user = None
            for u in self.users.values():
                if u.username == username or u.email == username:
                    user = u
                    break
            
            if not user:
                self._log_audit_event("login_failed", None, False, {
                    "username": username,
                    "reason": "user_not_found",
                    "ip": request.client.host
                })
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            # Check if account is locked
            if user.account_locked_until and user.account_locked_until > datetime.now():
                self._log_audit_event("login_failed", user.id, False, {
                    "username": username,
                    "reason": "account_locked",
                    "ip": request.client.host
                })
                raise HTTPException(status_code=423, detail="Account locked")
            
            # Verify password
            if not secure_hasher.verify_password(password, user.password_hash, user.password_salt):
                user.failed_login_attempts += 1
                
                # Lock account after max attempts
                if user.failed_login_attempts >= self.max_failed_attempts:
                    user.account_locked_until = datetime.now() + self.lockout_duration
                
                self._log_audit_event("login_failed", user.id, False, {
                    "username": username,
                    "reason": "invalid_password",
                    "attempts": user.failed_login_attempts,
                    "ip": request.client.host
                })
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            # Check MFA if enabled
            if user.mfa_enabled:
                if not mfa_token:
                    raise HTTPException(status_code=202, detail="MFA token required")
                
                if not self._verify_mfa_token(user, mfa_token):
                    self._log_audit_event("mfa_failed", user.id, False, {
                        "username": username,
                        "ip": request.client.host
                    })
                    raise HTTPException(status_code=401, detail="Invalid MFA token")
            
            # Reset failed attempts on successful login
            user.failed_login_attempts = 0
            user.account_locked_until = None
            user.last_login = datetime.now()
            
            # Create session
            session = self._create_session(user, request, user.mfa_enabled)
            
            self._log_audit_event("login_success", user.id, True, {
                "username": username,
                "session_id": session.id,
                "mfa_used": user.mfa_enabled,
                "ip": request.client.host
            })
            
            logger.info(f"User authenticated: {username}")
            return user, session
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise HTTPException(status_code=500, detail="Authentication failed")
    
    def _create_session(self, user: User, request: Request, mfa_verified: bool = False) -> Session:
        """Create a new user session"""
        session_id = secure_hasher.generate_secure_token(32)
        
        # Generate JWT token
        token_payload = {
            "user_id": user.id,
            "session_id": session_id,
            "role": user.role,
            "permissions": [p.value for p in user.permissions],
            "exp": datetime.now() + self.session_timeout,
            "iat": datetime.now()
        }
        
        token = jwt.encode(token_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        refresh_token = secure_hasher.generate_secure_token(64)
        
        session = Session(
            id=session_id,
            user_id=user.id,
            token=token,
            refresh_token=refresh_token,
            status=SessionStatus.ACTIVE,
            expires_at=datetime.now() + self.session_timeout,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent"),
            mfa_verified=mfa_verified
        )
        
        self.sessions[session_id] = session
        return session
    
    def verify_session(self, token: str) -> Tuple[User, Session]:
        """Verify and return user session"""
        try:
            # Decode JWT token
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            session_id = payload.get("session_id")
            user_id = payload.get("user_id")
            
            # Get session
            session = self.sessions.get(session_id)
            if not session or session.status != SessionStatus.ACTIVE:
                raise HTTPException(status_code=401, detail="Invalid session")
            
            # Check expiration
            if session.expires_at < datetime.now():
                session.status = SessionStatus.EXPIRED
                raise HTTPException(status_code=401, detail="Session expired")
            
            # Get user
            user = self.users.get(user_id)
            if not user or not user.is_active:
                raise HTTPException(status_code=401, detail="User not found or inactive")
            
            # Update last activity
            session.last_activity = datetime.now()
            
            return user, session
        
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    def refresh_session(self, refresh_token: str) -> Session:
        """Refresh user session"""
        # Find session by refresh token
        session = None
        for s in self.sessions.values():
            if s.refresh_token == refresh_token and s.status == SessionStatus.ACTIVE:
                session = s
                break
        
        if not session:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        # Get user
        user = self.users.get(session.user_id)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Generate new tokens
        token_payload = {
            "user_id": user.id,
            "session_id": session.id,
            "role": user.role,
            "permissions": [p.value for p in user.permissions],
            "exp": datetime.now() + self.session_timeout,
            "iat": datetime.now()
        }
        
        session.token = jwt.encode(token_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        session.refresh_token = secure_hasher.generate_secure_token(64)
        session.expires_at = datetime.now() + self.session_timeout
        session.last_activity = datetime.now()
        
        return session
    
    def logout_user(self, session_id: str):
        """Logout user and revoke session"""
        session = self.sessions.get(session_id)
        if session:
            session.status = SessionStatus.REVOKED
            
            self._log_audit_event("logout", session.user_id, True, {
                "session_id": session_id
            })
    
    def setup_mfa(self, user_id: str) -> Tuple[str, str]:
        """Setup MFA for user"""
        user = self.users.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Generate MFA secret
        secret = pyotp.random_base32()
        user.mfa_secret = secret
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name="ThreatLens"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        
        return secret, qr_code_data
    
    def enable_mfa(self, user_id: str, mfa_token: str) -> bool:
        """Enable MFA after verification"""
        user = self.users.get(user_id)
        if not user or not user.mfa_secret:
            return False
        
        if self._verify_mfa_token(user, mfa_token):
            user.mfa_enabled = True
            
            self._log_audit_event("mfa_enabled", user_id, True, {
                "username": user.username
            })
            return True
        
        return False
    
    def _verify_mfa_token(self, user: User, token: str) -> bool:
        """Verify MFA token"""
        if not user.mfa_secret:
            return False
        
        totp = pyotp.TOTP(user.mfa_secret)
        return totp.verify(token, valid_window=1)
    
    def _get_role_permissions(self, role: UserRole) -> List[Permission]:
        """Get permissions for role"""
        role_permissions = {
            UserRole.ADMIN: list(Permission),
            UserRole.SECURITY_ANALYST: [
                Permission.REPO_READ, Permission.REPO_CREATE, Permission.REPO_UPDATE,
                Permission.SECURITY_DOC_CREATE, Permission.SECURITY_DOC_READ, 
                Permission.SECURITY_DOC_UPDATE, Permission.SECURITY_DOC_DELETE,
                Permission.ANALYSIS_RUN, Permission.ANALYSIS_VIEW, Permission.ANALYSIS_MANAGE,
                Permission.AUDIT_VIEW
            ],
            UserRole.DEVELOPER: [
                Permission.REPO_READ, Permission.REPO_CREATE,
                Permission.SECURITY_DOC_READ, Permission.ANALYSIS_RUN, Permission.ANALYSIS_VIEW
            ],
            UserRole.VIEWER: [
                Permission.REPO_READ, Permission.SECURITY_DOC_READ, Permission.ANALYSIS_VIEW
            ]
        }
        
        return role_permissions.get(role, [])
    
    def _log_audit_event(self, action: str, user_id: Optional[str], success: bool, 
                        details: Dict[str, Any], session_id: Optional[str] = None):
        """Log security audit event"""
        audit_log = AuditLog(
            id=secure_hasher.generate_secure_token(16),
            user_id=user_id,
            session_id=session_id,
            action=action,
            success=success,
            details=details
        )
        
        self.audit_logs.append(audit_log)
        
        # Keep only last 10000 audit logs in memory
        if len(self.audit_logs) > 10000:
            self.audit_logs = self.audit_logs[-10000:]


class RBACManager:
    """Role-Based Access Control manager"""
    
    def __init__(self, auth_manager: AuthenticationManager):
        self.auth_manager = auth_manager
    
    def check_permission(self, user: User, permission: Permission, 
                        resource: Optional[str] = None) -> bool:
        """Check if user has permission"""
        if not user.is_active:
            return False
        
        # Admin has all permissions
        if user.role == UserRole.ADMIN:
            return True
        
        # Check specific permission
        return permission in user.permissions
    
    def require_permission(self, permission: Permission, resource: Optional[str] = None):
        """Decorator to require specific permission"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                # This would be used with FastAPI dependency injection
                # Implementation depends on how the current user is obtained
                pass
            return wrapper
        return decorator


# FastAPI security scheme
security_scheme = HTTPBearer()

# Global instances
auth_manager = AuthenticationManager()
rbac_manager = RBACManager(auth_manager)


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)) -> User:
    """FastAPI dependency to get current authenticated user"""
    try:
        user, session = auth_manager.verify_session(credentials.credentials)
        return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")


def require_permission(permission: Permission):
    """FastAPI dependency to require specific permission"""
    def permission_checker(user: User = Depends(get_current_user)) -> User:
        if not rbac_manager.check_permission(user, permission):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    
    return permission_checker