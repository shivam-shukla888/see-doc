import uuid
from typing import Optional
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt.exceptions import ExpiredSignatureError, PyJWTError
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.core.context import TenantContext, set_tenant_context, get_tenant_context
from app.db.models import User
from app.db.session import get_db

# Security scheme: Bearer token extracted from HTTP Authorization header
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Extracts Bearer token, validates signature and expiration,
    verifies user and tenant bounds in the database, and binds TenantContext.

    CRITICAL SECURITY RULE:
    Never trust client-supplied X-Tenant-ID headers.
    Tenant boundary is derived strictly from the cryptographically verified token.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id_str = payload.get("sub")
    token_org_id_str = payload.get("org_id")
    token_role = payload.get("role")

    if not user_id_str or not token_org_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing required identity claims",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_uuid = uuid.UUID(user_id_str)
        token_org_uuid = uuid.UUID(token_org_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid UUID format in token claims",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Set tenant context on the session so RLS permits finding the user in this organization
    from sqlalchemy import text
    db.execute(
        text("SELECT set_config('app.current_tenant_id', :org_id, true);"),
        {"org_id": str(token_org_uuid)}
    )

    # Verify user exists in database and belongs to claimed organization
    user = db.query(User).filter(
        User.id == user_uuid,
        User.organization_id == token_org_uuid
    ).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.organization_id != token_org_uuid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token organization claim does not match user organization",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.role != token_role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token role claim is stale or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Establish trusted request-scoped tenant context
    tenant_context = TenantContext(
        user_id=user.id,
        organization_id=user.organization_id,
        role=user.role,
    )
    set_tenant_context(tenant_context)

    return user


def get_current_tenant(
    user: User = Depends(get_current_user),
) -> TenantContext:
    """Dependency providing the verified request-scoped TenantContext."""
    ctx = get_tenant_context()
    if not ctx:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tenant context could not be established",
        )
    return ctx
