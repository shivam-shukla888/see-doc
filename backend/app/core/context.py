import uuid
from contextvars import ContextVar
from typing import Optional
from pydantic import BaseModel, ConfigDict


class TenantContext(BaseModel):
    """
    Immutable request-scoped identity and tenant boundary context.
    Populated solely from authenticated credentials, never from arbitrary client headers.
    """
    user_id: uuid.UUID
    organization_id: uuid.UUID
    role: str

    model_config = ConfigDict(frozen=True)


# ContextVar ensures thread-local and async task-local isolation across requests
_current_tenant_context: ContextVar[Optional[TenantContext]] = ContextVar(
    "current_tenant_context", default=None
)


def get_tenant_context() -> Optional[TenantContext]:
    """Retrieve the current request's tenant context."""
    return _current_tenant_context.get()


def set_tenant_context(context: TenantContext) -> None:
    """Set the tenant context for the current request execution flow."""
    _current_tenant_context.set(context)


def clear_tenant_context() -> None:
    """Clear tenant context to ensure zero state bleeding."""
    _current_tenant_context.set(None)
