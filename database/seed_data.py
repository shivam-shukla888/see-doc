"""
Seed script for local development and tenant-isolation verification.
Populates Organization A (Acme Corp) and Organization B (Globex Corp)
along with isolated users, documents, and vector-embedded chunks.
"""
import uuid
import sys
import os

# Ensure backend directory is in path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker
from app.db.models import Organization, User, Document, DocumentChunk

ADMIN_DATABASE_URL = os.getenv(
    "ADMIN_DATABASE_URL",
    "postgresql+psycopg://seedoc:seedoc_dev_password@localhost:5433/seedoc"
)
admin_engine = create_engine(ADMIN_DATABASE_URL)
AdminSession = sessionmaker(autocommit=False, autoflush=False, bind=admin_engine)

# Deterministic UUIDs for reproducible testing
ORG_A_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
USER_A_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
DOC_A_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")

ORG_B_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")
USER_B_ID = uuid.UUID("55555555-5555-5555-5555-555555555555")
DOC_B_ID = uuid.UUID("66666666-6666-6666-6666-666666666666")


def make_dummy_embedding(val: float, dim: int = 1536) -> list[float]:
    """Generates a normalized float vector of dimension dim."""
    vec = [0.0] * dim
    vec[0] = val
    vec[1] = 0.5
    vec[2] = 0.866
    return vec


def seed_database():
    session = AdminSession()
    try:
        # Enable admin bypass to insert across all tenants
        session.execute(text("SET LOCAL app.bypass_rls = 'on';"))

        # Clean existing test data if already present
        session.query(DocumentChunk).filter(
            DocumentChunk.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        session.query(Document).filter(
            Document.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        session.query(User).filter(
            User.organization_id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        session.query(Organization).filter(
            Organization.id.in_([ORG_A_ID, ORG_B_ID])
        ).delete(synchronize_session=False)
        session.commit()

        # Re-set bypass for subsequent transaction
        session.execute(text("SET LOCAL app.bypass_rls = 'on';"))

        # Organization A (Acme Corp)
        org_a = Organization(id=ORG_A_ID, name="Acme Corp")
        session.add(org_a)
        session.flush()

        from app.core.security import hash_password
        test_hash = hash_password("password123")

        user_a = User(
            id=USER_A_ID,
            organization_id=ORG_A_ID,
            email="alice@acme.com",
            hashed_password=test_hash,
            name="Alice Vance",
            role="ADMIN",
        )
        charlie_a = User(
            id=uuid.UUID("77777777-7777-7777-7777-777777777777"),
            organization_id=ORG_A_ID,
            email="charlie@acme.com",
            hashed_password=test_hash,
            name="Charlie Member",
            role="MEMBER",
        )
        session.add_all([user_a, charlie_a])
        session.flush()

        doc_a = Document(
            id=DOC_A_ID,
            organization_id=ORG_A_ID,
            uploaded_by=USER_A_ID,
            filename="acme_confidential_product_spec.pdf",
            storage_path="uploads/org_a/acme_confidential_product_spec.pdf",
            mime_type="application/pdf",
            status="COMPLETED",
        )
        session.add(doc_a)
        session.flush()

        chunk_a1 = DocumentChunk(
            id=uuid.uuid4(),
            document_id=DOC_A_ID,
            organization_id=ORG_A_ID,
            chunk_index=0,
            content="Acme proprietary quantum encryption protocol architecture.",
            embedding=make_dummy_embedding(0.95),
            metadata_json={"page": 1, "security": "confidential"},
        )
        chunk_a2 = DocumentChunk(
            id=uuid.uuid4(),
            document_id=DOC_A_ID,
            organization_id=ORG_A_ID,
            chunk_index=1,
            content="Acme Q3 financial performance exceeded revenue forecast by 25%.",
            embedding=make_dummy_embedding(0.20),
            metadata_json={"page": 2, "security": "restricted"},
        )
        session.add_all([chunk_a1, chunk_a2])

        # Organization B (Globex Corporation)
        org_b = Organization(id=ORG_B_ID, name="Globex Corporation")
        session.add(org_b)
        session.flush()

        user_b = User(
            id=USER_B_ID,
            organization_id=ORG_B_ID,
            email="bob@globex.com",
            hashed_password=test_hash,
            name="Bob Sterling",
            role="ADMIN",
        )
        session.add(user_b)
        session.flush()

        doc_b = Document(
            id=DOC_B_ID,
            organization_id=ORG_B_ID,
            uploaded_by=USER_B_ID,
            filename="globex_patent_portfolio_2026.pdf",
            storage_path="uploads/org_b/globex_patent_portfolio_2026.pdf",
            mime_type="application/pdf",
            status="COMPLETED",
        )
        session.add(doc_b)
        session.flush()

        chunk_b1 = DocumentChunk(
            id=uuid.uuid4(),
            document_id=DOC_B_ID,
            organization_id=ORG_B_ID,
            chunk_index=0,
            content="Globex Corporation autonomous robotics patents and design schematics.",
            embedding=make_dummy_embedding(0.94),  # Very close to Chunk A1 vector!
            metadata_json={"page": 1, "department": "R&D"},
        )
        chunk_b2 = DocumentChunk(
            id=uuid.uuid4(),
            document_id=DOC_B_ID,
            organization_id=ORG_B_ID,
            chunk_index=1,
            content="Globex supply chain risk mitigation protocols for East Asia.",
            embedding=make_dummy_embedding(0.15),
            metadata_json={"page": 2, "department": "Logistics"},
        )
        session.add_all([chunk_b1, chunk_b2])

        session.commit()
        print("Successfully seeded Organization A (Acme Corp) and Organization B (Globex Corporation).")

    except Exception as e:
        session.rollback()
        print(f"Error seeding database: {e}")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    seed_database()
