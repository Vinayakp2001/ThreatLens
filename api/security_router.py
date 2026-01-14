"""
FastAPI router for security management endpoints
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel

from api.security_auth import (
    auth_manager, rbac_manager, get_current_user, require_permission,
    User, UserRole, Permission, security_scheme
)
from api.security_audit import audit_logger, AuditEventType, AuditSeverity
from api.security_integration import security_health_checker, security_middleware
from api.security_encryption import key_manager

router = APIRouter(prefix="/api/security", tags=["security"])


# Request/Response models
class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_token: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.VIEWER


class MFASetupResponse(BaseModel):
    secret: str
    qr_code: str


class HealthCheckResponse(BaseModel):
    overall_status: str
    components: Dict[str, Any]
    warnings: List[str]
    errors: List[str]
    timestamp: str


class AuditEventResponse(BaseModel):
    id: str
    event_type: str
    severity: str
    user_id: Optional[str]
    action: str
    success: bool
    timestamp: str
    details: Dict[str, Any]


# Authentication endpoints
@router.post("/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest, http_request: Request):
    """Authenticate user and create session"""
    try:
        user, session = auth_manager.authenticate_user(
            username=request.username,
            password=request.password,
            request=http_request,
            mfa_token=request.mfa_token
        )
        
        return LoginResponse(
            access_token=session.token,
            refresh_token=session.refresh_token,
            expires_in=int((session.expires_at - datetime.now()).total_seconds()),
            user={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "permissions": [p.value for p in user.permissions],
                "mfa_enabled": user.mfa_enabled
            }
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {e}")


@router.post("/auth/register", response_model=Dict[str, str])
async def register(request: RegisterRequest, 
                  current_user: User = Depends(require_permission(Permission.USER_MANAGE))):
    """Register a new user (admin only)"""
    try:
        user = auth_manager.register_user(
            username=request.username,
            email=request.email,
            password=request.password,
            role=request.role
        )
        
        return {"message": f"User {user.username} registered successfully", "user_id": user.id}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {e}")


@router.post("/auth/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)):
    """Logout user and revoke session"""
    try:
        user, session = auth_manager.verify_session(credentials.credentials)
        auth_manager.logout_user(session.id)
        
        return {"message": "Logged out successfully"}
    
    except HTTPException:
        raise


@router.post("/auth/refresh", response_model=LoginResponse)
async def refresh_token(refresh_token: str):
    """Refresh access token"""
    try:
        session = auth_manager.refresh_session(refresh_token)
        user = auth_manager.users.get(session.user_id)
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return LoginResponse(
            access_token=session.token,
            refresh_token=session.refresh_token,
            expires_in=int((session.expires_at - datetime.now()).total_seconds()),
            user={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "permissions": [p.value for p in user.permissions],
                "mfa_enabled": user.mfa_enabled
            }
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token refresh failed: {e}")


# MFA endpoints
@router.post("/auth/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(current_user: User = Depends(get_current_user)):
    """Setup MFA for current user"""
    try:
        secret, qr_code = auth_manager.setup_mfa(current_user.id)
        
        return MFASetupResponse(
            secret=secret,
            qr_code=qr_code
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MFA setup failed: {e}")


@router.post("/auth/mfa/enable")
async def enable_mfa(mfa_token: str, current_user: User = Depends(get_current_user)):
    """Enable MFA after verification"""
    try:
        success = auth_manager.enable_mfa(current_user.id, mfa_token)
        
        if success:
            return {"message": "MFA enabled successfully"}
        else:
            raise HTTPException(status_code=400, detail="Invalid MFA token")
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MFA enable failed: {e}")


# Security management endpoints
@router.get("/health", response_model=HealthCheckResponse)
async def security_health_check(current_user: User = Depends(require_permission(Permission.SYSTEM_ADMIN))):
    """Get security system health status"""
    try:
        health_report = security_health_checker.perform_security_health_check()
        
        return HealthCheckResponse(**health_report)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {e}")


@router.get("/audit/events", response_model=List[AuditEventResponse])
async def get_audit_events(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    user_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    current_user: User = Depends(require_permission(Permission.AUDIT_VIEW))
):
    """Get audit events with filtering"""
    try:
        # Convert string event_type to enum if provided
        event_type_enum = None
        if event_type:
            try:
                event_type_enum = AuditEventType(event_type)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid event type: {event_type}")
        
        events = audit_logger.get_audit_events(
            start_date=start_date,
            end_date=end_date,
            user_id=user_id,
            event_type=event_type_enum,
            limit=limit
        )
        
        return [
            AuditEventResponse(
                id=event.id,
                event_type=event.event_type.value,
                severity=event.severity.value,
                user_id=event.user_id,
                action=event.action,
                success=event.success,
                timestamp=event.timestamp.isoformat(),
                details=event.details
            )
            for event in events
        ]
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get audit events: {e}")


@router.get("/audit/statistics")
async def get_audit_statistics(
    days: int = 30,
    current_user: User = Depends(require_permission(Permission.AUDIT_VIEW))
):
    """Get audit statistics"""
    try:
        stats = audit_logger.get_audit_statistics(days=days)
        return stats
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get audit statistics: {e}")


@router.post("/encryption/rotate-key")
async def rotate_encryption_key(current_user: User = Depends(require_permission(Permission.ENCRYPTION_MANAGE))):
    """Rotate master encryption key"""
    try:
        rotation_result = key_manager.rotate_master_key()
        
        # Log security event
        audit_logger.log_event(
            event_type=AuditEventType.ENCRYPTION_KEY_ROTATED,
            action="Master encryption key rotated",
            success=rotation_result["success"],
            user_id=current_user.id,
            severity=AuditSeverity.HIGH,
            details=rotation_result
        )
        
        return rotation_result
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key rotation failed: {e}")


@router.get("/users", response_model=List[Dict[str, Any]])
async def list_users(current_user: User = Depends(require_permission(Permission.USER_MANAGE))):
    """List all users (admin only)"""
    try:
        users = []
        for user in auth_manager.users.values():
            users.append({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role.value,
                "is_active": user.is_active,
                "mfa_enabled": user.mfa_enabled,
                "last_login": user.last_login.isoformat() if user.last_login else None,
                "created_at": user.created_at.isoformat()
            })
        
        return users
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list users: {e}")


@router.put("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    new_role: UserRole,
    current_user: User = Depends(require_permission(Permission.USER_MANAGE))
):
    """Update user role (admin only)"""
    try:
        user = auth_manager.users.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        old_role = user.role
        user.role = new_role
        user.permissions = auth_manager._get_role_permissions(new_role)
        user.updated_at = datetime.now()
        
        # Log audit event
        audit_logger.log_event(
            event_type=AuditEventType.ROLE_CHANGED,
            action=f"User role changed from {old_role.value} to {new_role.value}",
            success=True,
            user_id=current_user.id,
            resource_type="user",
            resource_id=user_id,
            severity=AuditSeverity.HIGH,
            details={
                "target_user": user.username,
                "old_role": old_role.value,
                "new_role": new_role.value
            }
        )
        
        return {"message": f"User role updated to {new_role.value}"}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update user role: {e}")


@router.put("/users/{user_id}/status")
async def update_user_status(
    user_id: str,
    is_active: bool,
    current_user: User = Depends(require_permission(Permission.USER_MANAGE))
):
    """Activate or deactivate user (admin only)"""
    try:
        user = auth_manager.users.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        old_status = user.is_active
        user.is_active = is_active
        user.updated_at = datetime.now()
        
        # Revoke all sessions if deactivating
        if not is_active:
            for session in auth_manager.sessions.values():
                if session.user_id == user_id:
                    auth_manager.logout_user(session.id)
        
        # Log audit event
        audit_logger.log_event(
            event_type=AuditEventType.PERMISSION_CHANGED,
            action=f"User {'activated' if is_active else 'deactivated'}",
            success=True,
            user_id=current_user.id,
            resource_type="user",
            resource_id=user_id,
            severity=AuditSeverity.MEDIUM,
            details={
                "target_user": user.username,
                "old_status": old_status,
                "new_status": is_active
            }
        )
        
        return {"message": f"User {'activated' if is_active else 'deactivated'}"}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update user status: {e}")


@router.get("/permissions")
async def list_permissions(current_user: User = Depends(get_current_user)):
    """List all available permissions"""
    return {
        "permissions": [
            {
                "name": perm.value,
                "description": perm.value.replace(":", " ").replace("_", " ").title()
            }
            for perm in Permission
        ]
    }


@router.get("/roles")
async def list_roles(current_user: User = Depends(get_current_user)):
    """List all available roles with their permissions"""
    return {
        "roles": [
            {
                "name": role.value,
                "permissions": [p.value for p in auth_manager._get_role_permissions(role)]
            }
            for role in UserRole
        ]
    }