import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class DocumentResponse(BaseModel):
    """Schema for document metadata returned to clients."""
    id: uuid.UUID
    organization_id: uuid.UUID
    uploaded_by: Optional[uuid.UUID]
    filename: str
    storage_path: str
    mime_type: str
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
