from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import User
from app.core.security import verify_password, create_access_token, DUMMY_PASSWORD_HASH
from app.dependencies.database import get_db
from app.dependencies.auth import get_current_user
from app.schemas.auth import LoginRequest, TokenResponse
from app.schemas.user import UserResponse

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    Authenticate user with email and password.
    Returns standard Bearer JWT containing identity and tenant boundary claims.
    Uses SECURITY DEFINER database function for credential lookup without bypassing RLS.
    Equalizes verification timing using pre-computed dummy hash for non-existent users.
    """
    auth_row = db.execute(
        text("SELECT id, organization_id, hashed_password, role FROM public.get_user_auth_by_email(:email);"),
        {"email": login_data.email},
    ).mappings().first()

    if auth_row:
        password_valid = verify_password(login_data.password, auth_row["hashed_password"])
    else:
        # Perform equivalent Argon2 verification work on dummy hash to mitigate user enumeration timing
        verify_password(login_data.password, DUMMY_PASSWORD_HASH)
        password_valid = False

    if not auth_row or not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        user_id=auth_row["id"],
        org_id=auth_row["organization_id"],
        role=auth_row["role"],
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        organization_id=auth_row["organization_id"],
        role=auth_row["role"],
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """
    Return profile information for the authenticated user.
    Hashed passwords or sensitive tenant internal metadata are strictly excluded.
    """
    return UserResponse.model_validate(current_user)
