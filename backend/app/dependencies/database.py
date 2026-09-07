from typing import Generator
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.core.context import get_tenant_context


def get_db() -> Generator[Session, None, None]:
    """
    Standard database session dependency.
    Used for unauthenticated or pre-tenant operations (e.g., login verification).
    """
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


from fastapi import Depends
from app.db.models import User
from app.dependencies.auth import get_current_user


def get_tenant_db(
    current_user: User = Depends(get_current_user)
) -> Generator[Session, None, None]:
    """
    Tenant-scoped database session dependency.
    Enforces PostgreSQL Row-Level Security (RLS) by executing:
    `SELECT set_config('app.current_tenant_id', :org_id, true);`
    inside the active transaction using the authenticated user's organization.
    """
    session = SessionLocal()
    try:
        session.execute(
            text("SELECT set_config('app.current_tenant_id', :org_id, true);"),
            {"org_id": str(current_user.organization_id)}
        )

        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
