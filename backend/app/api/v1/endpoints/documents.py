import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.models import User, Document
from app.dependencies.auth import get_current_user
from app.dependencies.database import get_tenant_db
from app.dependencies.rbac import require_role, Role
from app.schemas.document import DocumentResponse

router = APIRouter()


@router.get("", response_model=List[DocumentResponse])
def list_documents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_tenant_db),
) -> List[DocumentResponse]:
    """
    List all documents for the authenticated tenant.
    Enforces dual-layer security:
    1. Application-level filter: WHERE organization_id = current_user.organization_id
    2. Database-level RLS: SET LOCAL app.current_tenant_id automatically limits rows
    """
    docs = db.query(Document).filter(
        Document.organization_id == current_user.organization_id
    ).all()
    return [DocumentResponse.model_validate(doc) for doc in docs]


@router.get("/{document_id}", response_model=DocumentResponse)
def get_document(
    document_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_tenant_db),
) -> DocumentResponse:
    """
    Retrieve document metadata by ID.
    CRITICAL MULTI-TENANT SECURITY RULE:
    If a document belongs to another tenant, return 404 Not Found.
    Never return 403 or disclose whether another tenant's document exists.
    """
    doc = db.query(Document).filter(
        Document.id == document_id,
        Document.organization_id == current_user.organization_id,
    ).first()

    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    return DocumentResponse.model_validate(doc)


@router.delete("/{document_id}", status_code=status.HTTP_200_OK)
def delete_document(
    document_id: uuid.UUID,
    admin_user: User = Depends(require_role(Role.ADMIN)),
    db: Session = Depends(get_tenant_db),
):
    """
    Administrative document deletion endpoint.
    Guarded by RBAC: Requires 'ADMIN' role.
    Members attempting this operation receive 403 Forbidden.
    """
    doc = db.query(Document).filter(
        Document.id == document_id,
        Document.organization_id == admin_user.organization_id,
    ).first()

    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    db.delete(doc)
    return {"status": "deleted", "document_id": str(document_id)}
