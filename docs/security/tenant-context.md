# Tenant Context & Connection Pool Safety

## 1. Request Lifecycle Flow

```text
HTTP Request (Header: Authorization: Bearer <token>)
      │
      ▼
1. FastAPI Dependency: get_current_user
      │  - Validates JWT signature, expiration, sub, org_id, and role
      │  - Verifies user exists in database and belongs to claimed organization
      │
      ▼
2. TenantContext Binding
      │  - Initializes immutable TenantContext(user_id, organization_id, role)
      │  - Stores into Python contextvars (isolated per request async task)
      │
      ▼
3. FastAPI Dependency: get_tenant_db
      │  - Checks out database connection from pool
      │  - Starts transaction
      │  - Executes: SELECT set_config('app.current_tenant_id', :org_id, true);
      │  - Injects tenant context directly into PostgreSQL kernel RLS
      │
      ▼
4. Route Handler Execution
      │  - Applies application filter: WHERE organization_id = current_user.organization_id
      │  - PostgreSQL RLS enforces secondary defense-in-depth shield
      │
      ▼
5. Transaction Cleanup & Pool Return
      │  - Transaction commits or rolls back
      │  - Because `is_local = true` was used, setting is automatically erased
      │  - Connection returned to pool clean with zero state bleeding
```

---

## 2. Why `SET LOCAL` / `set_config(..., true)` is Mandatory
In modern web applications, database connections are **pooled** to avoid the heavy cost of establishing a new TCP connection on every HTTP request.
* If a tenant context variable was set globally on a connection (`SET app.current_tenant_id = 'org-A'`), that connection would remain "polluted" with Org A's ID indefinitely.
* When Request 2 (belonging to Org B) reuses that connection from the pool, any query that forgot an explicit filter would execute within Org A's security context!
* **The Solution**:
  `SELECT set_config('app.current_tenant_id', :org_id, true);`
  The 3rd argument `true` ensures that PostgreSQL binds the setting **strictly to the current transaction**. The instant the transaction completes (`COMMIT` or `ROLLBACK`), the setting ceases to exist.

---

## 3. Prohibition of Generic `app.bypass_rls`
Generic session toggles such as `SELECT set_config('app.bypass_rls', 'on', true);` are strictly prohibited for the application role `seedoc_app`.
* **The Vulnerability**: If the application user possesses permission to deactivate RLS across the session, any SQL injection vulnerability or ORM misconfiguration exposes all tenants simultaneously.
* **The Architecture**: All database policies enforce `organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid` with zero bypass flags.
* **Authentication Lookup**: Pre-tenant operations (e.g. looking up a user's password hash by email during login) execute via a dedicated PostgreSQL `SECURITY DEFINER` function (`get_user_auth_by_email`), returning exclusively the authentication credentials and executing under a fixed `search_path = public, pg_temp`. The application runtime user cannot bypass RLS on arbitrary queries.

