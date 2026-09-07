"""
Mission 2C Security & API Verification Test Suite.
Verifies FastAPI Authentication, Tenant Context, RBAC, RLS defense-in-depth,
and threat model mitigations across 12 rigorous security scenarios.
"""
import uuid
import sys
import os
import pytest
from datetime import timedelta
import jwt
from fastapi.testclient import TestClient

# Ensure backend directory is in sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.main import app
from app.config import settings
from app.core.security import create_access_token
from app.db.session import engine, SessionLocal
from app.db.models import Document
from sqlalchemy import text

client = TestClient(app)

# Deterministic Seed Data UUIDs
ORG_A_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
USER_A_ADMIN_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
USER_A_MEMBER_ID = uuid.UUID("77777777-7777-7777-7777-777777777777")
DOC_A_ID = uuid.UUID("33333333-3333-3333-3333-333333333333")

ORG_B_ID = uuid.UUID("44444444-4444-4444-4444-444444444444")
USER_B_ADMIN_ID = uuid.UUID("55555555-5555-5555-5555-555555555555")
DOC_B_ID = uuid.UUID("66666666-6666-6666-6666-666666666666")


@pytest.fixture
def token_org_a_admin() -> str:
    """Valid JWT for Alice (Org A, ADMIN)."""
    return create_access_token(user_id=USER_A_ADMIN_ID, org_id=ORG_A_ID, role="ADMIN")


@pytest.fixture
def token_org_a_member() -> str:
    """Valid JWT for Charlie (Org A, MEMBER)."""
    return create_access_token(user_id=USER_A_MEMBER_ID, org_id=ORG_A_ID, role="MEMBER")


@pytest.fixture
def token_org_b_admin() -> str:
    """Valid JWT for Bob (Org B, ADMIN)."""
    return create_access_token(user_id=USER_B_ADMIN_ID, org_id=ORG_B_ID, role="ADMIN")


# 1. Missing Authorization -> 401
def test_missing_authorization_header():
    response = client.get("/api/v1/documents")
    assert response.status_code == 401
    assert "not provided" in response.json()["detail"].lower()


# 2. Invalid JWT -> 401
def test_invalid_jwt_token():
    response = client.get(
        "/api/v1/documents",
        headers={"Authorization": "Bearer this.is.garbage.token"}
    )
    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()


# 3. Expired JWT -> 401
def test_expired_jwt_token():
    # Issue a token expired 10 minutes ago
    expired_token = create_access_token(
        user_id=USER_A_ADMIN_ID,
        org_id=ORG_A_ID,
        role="ADMIN",
        expires_delta=timedelta(minutes=-10)
    )
    response = client.get(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


# 4. Tampered JWT -> 401
def test_tampered_jwt_signature():
    valid_token = create_access_token(user_id=USER_A_ADMIN_ID, org_id=ORG_A_ID, role="ADMIN")
    # Tamper with the payload part of the JWT
    parts = valid_token.split(".")
    tampered_payload = parts[1][:-2] + "AA"
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

    response = client.get(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {tampered_token}"}
    )
    assert response.status_code == 401


# 5. Tenant A sees Tenant A documents only
def test_tenant_a_sees_only_tenant_a_documents(token_org_a_admin):
    response = client.get(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {token_org_a_admin}"}
    )
    assert response.status_code == 200
    docs = response.json()
    assert len(docs) == 1
    assert docs[0]["id"] == str(DOC_A_ID)
    assert docs[0]["organization_id"] == str(ORG_A_ID)
    assert docs[0]["filename"] == "acme_confidential_product_spec.pdf"


# 6. Tenant B sees Tenant B documents only
def test_tenant_b_sees_only_tenant_b_documents(token_org_b_admin):
    response = client.get(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {token_org_b_admin}"}
    )
    assert response.status_code == 200
    docs = response.json()
    assert len(docs) == 1
    assert docs[0]["id"] == str(DOC_B_ID)
    assert docs[0]["organization_id"] == str(ORG_B_ID)
    assert docs[0]["filename"] == "globex_patent_portfolio_2026.pdf"


# 7. Tenant A cannot access Tenant B document -> 404 (No disclosure!)
def test_tenant_a_cannot_access_tenant_b_document(token_org_a_admin):
    # Org A requests Org B's existing document by exact UUID
    response = client.get(
        f"/api/v1/documents/{DOC_B_ID}",
        headers={"Authorization": f"Bearer {token_org_a_admin}"}
    )
    # Must return 404 Not Found, NOT 403 (does not leak existence of Doc B)
    assert response.status_code == 404
    assert response.json()["detail"] == "Document not found"


# 8. X-Tenant-ID spoofing cannot change tenant
def test_x_tenant_id_spoofing_ignored(token_org_a_admin):
    # Malicious request sends Org A token but attempts to spoof X-Tenant-ID header for Org B
    response = client.get(
        "/api/v1/documents",
        headers={
            "Authorization": f"Bearer {token_org_a_admin}",
            "X-Tenant-ID": str(ORG_B_ID)
        }
    )
    assert response.status_code == 200
    docs = response.json()
    assert len(docs) == 1
    assert docs[0]["organization_id"] == str(ORG_A_ID)
    assert docs[0]["id"] != str(DOC_B_ID)


# 9. MEMBER cannot perform ADMIN operation -> 403 Forbidden
def test_member_cannot_perform_admin_delete(token_org_a_member):
    response = client.delete(
        f"/api/v1/documents/{DOC_A_ID}",
        headers={"Authorization": f"Bearer {token_org_a_member}"}
    )
    assert response.status_code == 403
    assert "requires 'admin' privileges" in response.json()["detail"].lower()


# 10. ADMIN can perform approved ADMIN operation -> 200 OK
def test_admin_can_perform_admin_delete(token_org_a_admin):
    # First create a temporary test document in Org A to delete
    session = SessionLocal()
    try:
        temp_doc_id = uuid.uuid4()
        session.execute(
            text("SELECT set_config('app.current_tenant_id', :org_id, true);"),
            {"org_id": str(ORG_A_ID)}
        )
        temp_doc = Document(
            id=temp_doc_id,
            organization_id=ORG_A_ID,
            uploaded_by=USER_A_ADMIN_ID,
            filename="to_be_deleted.pdf",
            storage_path="uploads/temp/delete_me.pdf",
            mime_type="application/pdf",
            status="PENDING",
        )
        session.add(temp_doc)
        session.commit()
    finally:
        session.close()

    # Call delete endpoint as ADMIN
    response = client.delete(
        f"/api/v1/documents/{temp_doc_id}",
        headers={"Authorization": f"Bearer {token_org_a_admin}"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "deleted"
    assert response.json()["document_id"] == str(temp_doc_id)


# 11. Connection pool tenant context does not leak
def test_connection_pool_tenant_context_does_not_leak(token_org_a_admin, token_org_b_admin):
    # Rapid sequential alternation between Tenant A and Tenant B across pooled connections
    for _ in range(5):
        resp_a = client.get(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {token_org_a_admin}"}
        )
        assert resp_a.status_code == 200
        assert resp_a.json()[0]["organization_id"] == str(ORG_A_ID)

        resp_b = client.get(
            "/api/v1/documents",
            headers={"Authorization": f"Bearer {token_org_b_admin}"}
        )
        assert resp_b.status_code == 200
        assert resp_b.json()[0]["organization_id"] == str(ORG_B_ID)


# 12. JWT with invalid algorithm is rejected (e.g. alg="none")
def test_jwt_with_invalid_algorithm_rejected():
    # Construct an unsigned token with alg="none"
    header = {"typ": "JWT", "alg": "none"}
    payload = {
        "sub": str(USER_A_ADMIN_ID),
        "org_id": str(ORG_A_ID),
        "role": "ADMIN",
        "exp": 9999999999,
        "iat": 1000000000
    }
    # Manually encode without signature
    import json, base64
    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    token_none = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}."

    response = client.get(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {token_none}"}
    )
    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()


# 13. Login flow with valid credentials -> returns signed JWT
def test_login_success():
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "alice@acme.com", "password": "password123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["organization_id"] == str(ORG_A_ID)
    assert data["role"] == "ADMIN"


# 14. Login with invalid password -> 401 Unauthorized
def test_login_wrong_password_rejected():
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "alice@acme.com", "password": "wrong_password"}
    )
    assert response.status_code == 401
    assert "incorrect" in response.json()["detail"].lower()


# 15. /auth/me returns profile strictly without hashed_password
def test_auth_me_returns_profile_without_secrets(token_org_a_admin):
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token_org_a_admin}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(USER_A_ADMIN_ID)
    assert data["email"] == "alice@acme.com"
    assert data["role"] == "ADMIN"
    assert "password" not in data
    assert "hashed_password" not in data


# 16. Login with nonexistent user fails closed with identical generic error
def test_login_nonexistent_user_rejected_with_same_error():
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent_user_999@acme.com", "password": "random_password"}
    )
    assert response.status_code == 401
    assert "incorrect email or password" in response.json()["detail"].lower()


# 17. Settings production secret guard fails closed
def test_settings_secret_key_production_guard():
    import pytest
    from app.config import Settings, INSECURE_DEV_SECRET

    # 1. Development with default fallback -> Allowed
    dev_settings = Settings(ENVIRONMENT="development", SECRET_KEY=INSECURE_DEV_SECRET)
    assert dev_settings.SECRET_KEY == INSECURE_DEV_SECRET

    # 2. Production with missing/empty secret -> Rejected
    with pytest.raises(ValueError) as exc_missing:
        Settings(ENVIRONMENT="production", SECRET_KEY="")
    assert "insecure configuration" in str(exc_missing.value).lower()
    # Ensure error message does not expose secrets
    assert "secret_key must be set" in str(exc_missing.value).lower()

    # 3. Production with known default fallback secret -> Rejected
    with pytest.raises(ValueError) as exc_fallback:
        Settings(ENVIRONMENT="production", SECRET_KEY=INSECURE_DEV_SECRET)
    assert "insecure configuration" in str(exc_fallback.value).lower()
    assert "default development fallback secret is not permitted" in str(exc_fallback.value).lower()

    # 4. Production with short secret (< 32 chars) -> Rejected
    with pytest.raises(ValueError) as exc_short:
        Settings(ENVIRONMENT="production", SECRET_KEY="short-secret-key-123")
    assert "at least 32 characters long" in str(exc_short.value).lower()

    # 5. Production with strong secret (>= 32 chars) -> Accepted
    valid_strong_secret = "test-prod-key-for-validation-" + ("a" * 32)
    prod_settings = Settings(ENVIRONMENT="production", SECRET_KEY=valid_strong_secret)
    assert prod_settings.ENVIRONMENT == "production"
    assert prod_settings.SECRET_KEY == valid_strong_secret


# 18. CORS configuration restricts methods and headers
def test_cors_preflight_configuration():
    response = client.options(
        "/api/v1/documents",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "DELETE",
            "Access-Control-Request-Headers": "Authorization, Content-Type",
        }
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    allow_methods = response.headers.get("access-control-allow-methods", "")
    assert "DELETE" in allow_methods
    assert "GET" in allow_methods


