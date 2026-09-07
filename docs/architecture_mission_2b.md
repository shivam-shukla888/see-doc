# Seedoc: Multi-Tenant Database Architecture & Security Model

## 1. System Hierarchy

```text
Seedoc
  ↓
Multi-Tenant Application
  ↓
Organizations (Tenants)
  ↓
Users (Organization Members)
  ↓
Documents (Uploaded enterprise assets)
  ↓
Document Chunks (Segmented text units)
  ↓
Embeddings (pgvector representations)
  ↓
Vector Retrieval (Scoped semantic search)
```

---

## 2. Core Tenant Isolation Rule

> **Golden Security Rule:**  
> **Every tenant-owned query must be scoped to the authenticated user's organization.**  
> Under no circumstances should the LLM or client application determine data boundaries. Isolation is strictly enforced at the application data layer and backed by PostgreSQL Row-Level Security (RLS) kernel policies.

---

## 3. Key Concepts: The 4 Security Pillars

| Security Pillar | Question Answered | How It Works in Seedoc |
| :--- | :--- | :--- |
| **Authentication (AuthN)** | *"Who are you?"* | Validates the user's credentials (e.g., JWT, session token, OAuth2) and resolves the user's unique identity. |
| **Authorization (AuthZ)** | *"What are you allowed to do?"* | Validates whether the authenticated user has permission to execute an action (e.g., read, upload, delete). |
| **Tenant Isolation** | *"Which organization's sandbox are you in?"* | Ensures absolute data separation between distinct enterprise customers. Even an `ADMIN` in Org A can never view or modify data in Org B. |
| **Role-Based Access Control (RBAC)** | *"What role do you have inside your organization?"* | Defines permissions within a tenant boundary (`ADMIN` can manage users/settings; `MEMBER` can upload and search documents). |

---

## 4. Database Schema Specification

### `organizations`
Represents customer organizations (tenants).
* `id` (UUID, PK, `gen_random_uuid()`)
* `name` (VARCHAR(255), NOT NULL)
* `created_at`, `updated_at` (TIMESTAMPTZ, NOT NULL)

### `users`
Represents members belonging to an organization.
* `id` (UUID, PK, `gen_random_uuid()`)
* `organization_id` (UUID, FK $\to$ `organizations.id` `ON DELETE CASCADE`)
* `email` (VARCHAR(255), NOT NULL)
* `name` (VARCHAR(255), NOT NULL)
* `role` (VARCHAR(50), CHECK `role IN ('ADMIN', 'MEMBER')`)
* `created_at`, `updated_at` (TIMESTAMPTZ, NOT NULL)
* **Constraints**: `UNIQUE (organization_id, email)`
* **Indexes**: `idx_users_organization_id`

### `documents`
Represents uploaded enterprise files.
* `id` (UUID, PK, `gen_random_uuid()`)
* `organization_id` (UUID, FK $\to$ `organizations.id` `ON DELETE CASCADE`)
* `uploaded_by` (UUID, FK $\to$ `users.id` `ON DELETE SET NULL`)
* `filename` (VARCHAR(255), NOT NULL)
* `storage_path` (TEXT, NOT NULL)
* `mime_type` (VARCHAR(100), NOT NULL)
* `status` (VARCHAR(50), CHECK `status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')`)
* `created_at`, `updated_at` (TIMESTAMPTZ, NOT NULL)
* **Indexes**: `idx_documents_organization_id`, `idx_documents_uploaded_by`

### `document_chunks`
Represents segmented chunks and their vector embeddings for RAG.
* `id` (UUID, PK, `gen_random_uuid()`)
* `document_id` (UUID, FK $\to$ `documents.id` `ON DELETE CASCADE`)
* `organization_id` (UUID, FK $\to$ `organizations.id` `ON DELETE CASCADE` - **denormalized for fast filtering & RLS**)
* `chunk_index` (INTEGER, CHECK `chunk_index >= 0`)
* `content` (TEXT, NOT NULL)
* `embedding` (VECTOR(1536), NULLABLE)
* `metadata` (JSONB, NOT NULL DEFAULT `'{}'::jsonb`)
* `created_at` (TIMESTAMPTZ, NOT NULL)
* **Constraints**: `UNIQUE (document_id, chunk_index)`
* **Indexes**: `idx_document_chunks_organization_id`, `idx_document_chunks_document_id`

---

## 5. Row-Level Security (RLS) Implementation

PostgreSQL Row-Level Security is enabled and **forced** on all tenant tables (`FORCE ROW LEVEL SECURITY`).
All application traffic connects as `seedoc_app` (a non-superuser account). The session variable `app.current_tenant_id` scopes data access:

```sql
CREATE POLICY tenant_isolation_documents ON documents
    FOR ALL
    USING (
        current_setting('app.bypass_rls', true) = 'on'
        OR organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', true) = 'on'
        OR organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    );
```
