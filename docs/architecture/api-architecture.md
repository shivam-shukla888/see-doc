# Seedoc: FastAPI Backend Architecture

## 1. Directory Structure

```text
backend/
├── app/
│   ├── main.py                     # App factory, CORS, router mounting
│   ├── config.py                   # Pydantic Settings
│   │
│   ├── core/                       # Security & context primitives
│   │   ├── security.py             # Argon2 password hashing & PyJWT encode/decode
│   │   └── context.py              # TenantContext model & contextvars
│   │
│   ├── db/                         # Database models & engine
│   │   ├── base.py                 # Declarative Base
│   │   ├── models.py               # SQLAlchemy entities
│   │   └── session.py              # Engine (seedoc_app runtime) & SessionLocal
│   │
│   ├── dependencies/               # Dependency injection
│   │   ├── auth.py                 # get_current_user, get_current_tenant
│   │   ├── rbac.py                 # require_role(Role.ADMIN)
│   │   └── database.py             # get_db, get_tenant_db
│   │
│   ├── schemas/                    # Pydantic validation schemas
│   │   ├── auth.py                 # LoginRequest, TokenResponse, TokenPayload
│   │   ├── user.py                 # UserResponse
│   │   └── document.py             # DocumentResponse
│   │
│   └── api/                        # Route controllers
│       └── v1/
│           ├── router.py           # APIRouter aggregator
│           └── endpoints/
│               ├── auth.py         # /login, /me
│               └── documents.py    # /documents, /documents/{id}
```

---

## 2. API v1 Endpoints Specification

### Authentication
* `POST /api/v1/auth/login`: Authenticate with email and password. Returns signed JWT containing `sub`, `org_id`, and `role`.
* `GET /api/v1/auth/me`: Authenticated user profile. Hashed password and internal tenant secrets are strictly omitted.

### Documents
* `GET /api/v1/documents`: List all documents belonging to the authenticated tenant.
* `GET /api/v1/documents/{document_id}`: Retrieve document metadata. If document belongs to another tenant, returns `404 Not Found`.
* `DELETE /api/v1/documents/{document_id}`: Delete a document. Guarded by RBAC: requires `ADMIN` role (`403 Forbidden` if called by `MEMBER`).
