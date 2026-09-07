# SEEDOC — MASTER ENGINEERING BLUEPRINT

Seedoc is a secure, multi-tenant enterprise AI knowledge platform.

This document is the physical repository source of truth for all architectural decisions, business goals, security requirements, technology governance, and engineering rules.

---

## 1. Priority of Truth

```text
1. Explicit user instruction
        ↓
2. Seedoc Master Blueprint (this document)
        ↓
3. Seedoc architecture / technical documentation (docs/architecture/**)
        ↓
4. Seedoc security documentation (docs/security/**)
        ↓
5. Existing implemented code
        ↓
6. Established project conventions
        ↓
7. General engineering knowledge
```

---

## 2. Business Goal & Core Product Scope

Seedoc provides a secure enterprise AI knowledge platform enabling organizations to:
```text
Upload internal knowledge
        ↓
Process documents
        ↓
Extract content
        ↓
Chunk content
        ↓
Generate embeddings
        ↓
Store searchable knowledge
        ↓
Retrieve authorized knowledge
        ↓
Use an LLM / AI agent
        ↓
Generate grounded answers
        ↓
Provide citations
```

---

## 3. Technology Governance

* **Frontend**: Next.js, React, TypeScript, Tailwind CSS
* **Backend API**: FastAPI, Python
* **Database**: PostgreSQL 17, pgvector
* **ORM & Migrations**: SQLAlchemy 2.0, Alembic
* **Queue & Cache**: Redis 8
* **Async Workers**: Celery
* **Vector Dimension**: Fixed at `VECTOR(1536)` (OpenAI standard)
* **Authentication**: Custom Bearer JWT (FastAPI + PyJWT + Argon2) with clean interfaces for future OIDC/JWKS migration
* **Containerization**: Docker Compose

---

## 4. Multi-Tenancy & Security Invariants

* **Tenant Boundary**: `Organization = Tenant`. Every tenant-owned resource must have an `organization_id`.
* **Invariant 1**: The client cannot choose arbitrary tenant access; `X-Tenant-ID` header is untrusted.
* **Invariant 2**: The LLM cannot decide tenant authorization; data is filtered before reaching LLM context.
* **Invariant 3**: Application queries must be tenant-scoped (`WHERE organization_id = :org_id`).
* **Invariant 4**: PostgreSQL Row-Level Security (RLS) remains the defense-in-depth boundary via `FORCE ROW LEVEL SECURITY`.
* **Invariant 5**: The application runtime must connect as non-superuser `seedoc_app`, never as a PostgreSQL superuser.
* **Invariant 6**: A request must never inherit another request's tenant context across pooled database connections (`SET LOCAL app.current_tenant_id` is mandatory).
* **Invariant 7**: Authentication failure must fail closed (`401/403` and zero data access).
* **Invariant 8**: Generic RLS bypass (`app.bypass_rls`) is strictly forbidden for the application role; pre-tenant credential lookup must use a least-privilege `SECURITY DEFINER` function.
* **Invariant 9**: The application must fail closed in production if JWT secret keys are missing, default, or weak (< 32 chars).
* **Invariant 10**: Password verification and login failure responses must minimize timing discrepancies to mitigate account enumeration.

---

## 5. Security Pillars

* **Authentication (AuthN)**: *"Who are you?"* (JWT signature, expiry, user ID).
* **Authorization (AuthZ)**: *"What are you allowed to do?"* (Resource-level access).
* **Tenant Isolation**: *"Which organization's sandbox are you in?"* (Organization UUID).
* **Role-Based Access Control (RBAC)**: *"What role do you have in your organization?"* (`ADMIN`, `MEMBER`).

---

## 6. Engineering Workflow

```text
READ → INSPECT → COMPARE → IDENTIFY GAPS → PLAN → ASK APPROVAL → IMPLEMENT → TEST → VERIFY → DOCUMENT
```

No hallucination policy: Never invent requirements not supported by documentation, code, or explicit user instruction.
