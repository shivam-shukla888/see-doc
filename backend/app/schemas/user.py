import uuid
from datetime import datetime
from pydantic import BaseModel, EmailStr, ConfigDict


class UserResponse(BaseModel):
    """
    Public representation of a User.
    CRITICAL SECURITY RULE: Never include hashed_password or secrets in API responses.
    """
    id: uuid.UUID
    organization_id: uuid.UUID
    email: EmailStr
    name: str
    role: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
