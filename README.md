# Seedoc

Secure multi-tenant enterprise AI knowledge platform.

## Goal

Build a production-like RAG platform that allows organizations
to securely search and chat with their internal documents.

## Architecture Hierarchy

```text
Seedoc
  ↓
Multi-tenant application
  ↓
Organization
  ↓
Users
  ↓
Documents
  ↓
Document chunks
  ↓
Embeddings
  ↓
Vector retrieval
```

## Security Foundation

> **Golden Tenant-Isolation Rule:**  
> **Every tenant-owned query must be scoped to the authenticated user's organization.**

### Security Pillars
* **Authentication**: Verifies user identity (e.g. JWT/OAuth2).
* **Authorization**: Determines permissible actions.
* **Tenant Isolation**: Guarantees complete separation of organization datasets.
* **RBAC**: Enforces organizational roles (`ADMIN`, `MEMBER`).

## Local Development & Database Setup

1. **Start Services**:
   ```bash
   docker compose up -d
   ```
2. **Apply Database Migrations**:
   ```bash
   alembic upgrade head
   ```
3. **Apply Row-Level Security**:
   ```bash
   # Run database/rls_policies.sql and database/app_role.sql against PostgreSQL
   ```
4. **Seed Sample Multi-Tenant Data**:
   ```bash
   python database/seed_data.py
   ```
5. **Run Security & Isolation Tests**:
   ```bash
   pytest tests/test_tenant_isolation.py -v
   ```

