import uuid
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """Schema for user authentication request."""
    email: EmailStr
    password: str = Field(..., min_length=6)


class TokenResponse(BaseModel):
    """Schema for successful authentication response containing JWT."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    organization_id: uuid.UUID
    role: str


class TokenPayload(BaseModel):
    """Internal validated representation of JWT payload claims."""
    sub: str
    org_id: str
    role: str
    exp: int
    iat: int
