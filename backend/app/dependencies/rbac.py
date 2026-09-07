from typing import Callable
from enum import Enum
from fastapi import Depends, HTTPException, status

from app.db.models import User
from app.dependencies.auth import get_current_user


class Role(str, Enum):
    """Seedoc documented system roles."""
    ADMIN = "ADMIN"
    MEMBER = "MEMBER"


def require_role(required_role: Role | str) -> Callable[[User], User]:
    """
    Dependency factory enforcing Role-Based Access Control (RBAC).
    Guarantees authorization check executes before the endpoint handler runs.
    """
    target_role = required_role.value if isinstance(required_role, Role) else required_role

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role != target_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Action requires '{target_role}' privileges.",
            )
        return current_user

    return role_checker
