"""
Mission 2B Security & Tenant Isolation Verification Suite.
Validates both application-level tenant scoping and PostgreSQL Row-Level Security (RLS).
"""
import uuid
import sys
import os
import pytest
from sqlalchemy import text, select

# Add backend directory to sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.db.session import SessionLocal
from app.db.models import Organization, User, Document, DocumentChunk

# Seed Data UUIDs
ORG_A_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
USER_A_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
DOC_A_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")

ORG_B_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")
USER_B_ID = uuid.UUID("55555555-5555-5555-5555-555555555555")
DOC_B_ID = uuid.UUID("66666666-6666-6666-6666-666666666666")


@pytest.fixture
def db_session_org_a():
    """Provides a session with Org A tenant context set via RLS."""
    session = SessionLocal()
    session.execute(text(f"SET LOCAL app.current_tenant_id = '{ORG_A_ID}';"))
    session.execute(text("SET LOCAL app.bypass_rls = 'off';"))
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def db_session_org_b():
    """Provides a session with Org B tenant context set via RLS."""
    session = SessionLocal()
    session.execute(text(f"SET LOCAL app.current_tenant_id = '{ORG_B_ID}';"))
    session.execute(text("SET LOCAL app.bypass_rls = 'off';"))
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def test_org_a_can_access_own_documents(db_session_org_a):
    """Scenario 1 & 2: User belongs to Org A and queries Org A documents."""
    docs = db_session_org_a.query(Document).filter(
        Document.organization_id == ORG_A_ID
    ).all()

    assert len(docs) == 1
    assert docs[0].id == DOC_A_ID
    assert docs[0].filename == "acme_confidential_product_spec.pdf"
    assert docs[0].organization_id == ORG_A_ID


def test_org_b_can_access_own_documents(db_session_org_b):
    """User belongs to Org B and queries Org B documents."""
    docs = db_session_org_b.query(Document).filter(
        Document.organization_id == ORG_B_ID
    ).all()

    assert len(docs) == 1
    assert docs[0].id == DOC_B_ID
    assert docs[0].filename == "globex_patent_portfolio_2026.pdf"
    assert docs[0].organization_id == ORG_B_ID


def test_org_a_cannot_access_org_b_document_by_id(db_session_org_a):
    """Scenario 4 & 5: Org A user attempts to query Org B document by specific ID."""
    # 1. Application-level tenant-scoped query
    doc = db_session_org_a.query(Document).filter(
        Document.id == DOC_B_ID,
        Document.organization_id == ORG_A_ID
    ).first()
    assert doc is None, "Cross-tenant access breach: Org A retrieved Org B document via application query!"

    # 2. Defense-in-depth: Even without application filter, RLS blocks Org B document
    doc_rls = db_session_org_a.query(Document).filter(
        Document.id == DOC_B_ID
    ).first()
    assert doc_rls is None, "Cross-tenant RLS failure: Org B document returned to Org A session!"


def test_org_a_session_sees_only_org_a_rows(db_session_org_a):
    """Verifies that an un-scoped SELECT * query only yields Org A rows under RLS."""
    all_visible_docs = db_session_org_a.query(Document).all()
    for doc in all_visible_docs:
        assert doc.organization_id == ORG_A_ID
        assert doc.id != DOC_B_ID

    all_visible_users = db_session_org_a.query(User).all()
    for u in all_visible_users:
        assert u.organization_id == ORG_A_ID
        assert u.id != USER_B_ID


def test_vector_similarity_search_cannot_leak_across_tenants(db_session_org_a):
    """
    Critical RAG Security Test:
    Executes a vector cosine distance query with a vector that is extremely close
    to Globex's (Org B) chunk. Verifies that only Acme Corp (Org A) chunks are returned.
    """
    # Vector close to Globex Chunk 0 (0.94) and Acme Chunk 0 (0.95)
    query_vector = [0.0] * 1536
    query_vector[0] = 0.945
    query_vector[1] = 0.5
    query_vector[2] = 0.866

    # pgvector cosine distance: embedding <=> query_vector
    # Scoped to Org A
    chunks = db_session_org_a.query(DocumentChunk).filter(
        DocumentChunk.organization_id == ORG_A_ID
    ).order_by(
        DocumentChunk.embedding.cosine_distance(query_vector)
    ).limit(5).all()

    assert len(chunks) > 0
    for chunk in chunks:
        assert chunk.organization_id == ORG_A_ID, f"Vector leak! Chunk belongs to org: {chunk.organization_id}"
        assert "Globex" not in chunk.content, "Vector leak! Retrieved Globex content into Acme search!"


def test_user_deletion_does_not_delete_documents():
    """
    Tests ON DELETE SET NULL on uploaded_by:
    Deleting a user preserves the organization's document.
    Executes within tenant context for temp_org.
    """
    session = SessionLocal()
    temp_org_id = uuid.uuid4()
    try:
        # Set tenant context to temporary organization
        session.execute(
            text("SELECT set_config('app.current_tenant_id', :org_id, true);"),
            {"org_id": str(temp_org_id)}
        )

        # Create temporary user and document
        temp_org = Organization(id=temp_org_id, name="Temp Test Org")
        from app.core.security import hash_password
        temp_user = User(
            id=uuid.uuid4(),
            organization_id=temp_org.id,
            email="temp@test.com",
            hashed_password=hash_password("password123"),
            name="Temp User",
            role="MEMBER"
        )
        temp_doc = Document(
            id=uuid.uuid4(),
            organization_id=temp_org.id,
            uploaded_by=temp_user.id,
            filename="temp_doc.pdf",
            storage_path="uploads/temp/doc.pdf",
            mime_type="application/pdf"
        )
        session.add_all([temp_org, temp_user, temp_doc])
        session.commit()

        # Delete the user inside tenant context
        session.execute(
            text("SELECT set_config('app.current_tenant_id', :org_id, true);"),
            {"org_id": str(temp_org_id)}
        )
        session.delete(temp_user)
        session.commit()

        # Check document still exists, but uploaded_by is NULL
        session.execute(
            text("SELECT set_config('app.current_tenant_id', :org_id, true);"),
            {"org_id": str(temp_org_id)}
        )
        reloaded_doc = session.get(Document, temp_doc.id)
        assert reloaded_doc is not None, "Document was erroneously deleted when user was deleted!"
        assert reloaded_doc.uploaded_by is None, "uploaded_by was not set to NULL on user deletion!"

        # Cleanup
        session.delete(temp_doc)
        session.delete(temp_org)
        session.commit()
    finally:
        session.close()


def test_unauthenticated_session_sees_zero_rows():
    """Verifies that an unauthenticated session (no tenant_id set) sees 0 rows under RLS."""
    session = SessionLocal()
    try:
        docs = session.query(Document).all()
        assert len(docs) == 0, "Unauthenticated session should see 0 documents!"

        chunks = session.query(DocumentChunk).all()
        assert len(chunks) == 0, "Unauthenticated session should see 0 chunks!"
    finally:
        session.close()


def test_seedoc_app_cannot_bypass_rls_via_session_variable():
    """
    REGRESSION TEST (Mission 2C Phase 2.6):
    Verifies that setting app.bypass_rls = 'on' does NOT allow the application role
    (seedoc_app) to bypass PostgreSQL Row Level Security.
    """
    session = SessionLocal()
    try:
        # Attempt to activate bypass_rls
        session.execute(text("SELECT set_config('app.bypass_rls', 'on', true);"))

        # Query documents without setting app.current_tenant_id
        docs = session.query(Document).all()
        assert len(docs) == 0, (
            f"VULNERABILITY DETECTED: seedoc_app bypassed RLS via app.bypass_rls and saw {len(docs)} documents!"
        )

        # Query users directly without tenant context
        users = session.query(User).all()
        assert len(users) == 0, (
            f"VULNERABILITY DETECTED: seedoc_app bypassed RLS on users table and saw {len(users)} users!"
        )
    finally:
        session.close()


def test_cross_tenant_insert_blocked_by_rls(db_session_org_a):
    """
    Verifies that an Org A session attempting to write data belonging
    to Org B is blocked by RLS WITH CHECK policy.
    """
    from sqlalchemy.exc import ProgrammingError, InternalError

    malicious_doc = Document(
        id=uuid.uuid4(),
        organization_id=ORG_B_ID,  # Attempting to inject into Org B
        filename="malicious_spoofed_file.pdf",
        storage_path="uploads/spoofed.pdf",
        mime_type="application/pdf",
        status="PENDING",
    )
    db_session_org_a.add(malicious_doc)
    with pytest.raises((ProgrammingError, InternalError, Exception)) as exc_info:
        db_session_org_a.flush()

    assert "violates row-level security policy" in str(exc_info.value).lower()
