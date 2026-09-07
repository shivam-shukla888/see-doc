# ADR-001: Authentication Provider Architecture

## Status
**ACCEPTED** (Approved by User in Mission 2C Phase 2)

---

## Context
Seedoc is a secure, multi-tenant enterprise AI knowledge platform. Every API request must be authenticated, resolving both the individual user's identity and their organizational tenant boundary. In future phases, enterprise customers will require Integration with corporate Single Sign-On (SSO) such as Okta, Azure AD, or Ping Identity via SAML 2.0 or OpenID Connect (OIDC).

However, during Stage 1 foundation, introducing a heavy external Identity Provider (e.g., Auth0 SaaS or Keycloak cluster) increases operational complexity, requires internet or heavy container dependencies, and slows development.

---

## Decision
We adopt a **Two-Stage Authentication Strategy**:
1. **Stage 1 (Current Foundation)**: Implement **Custom Bearer JWT authentication** within the FastAPI backend using `PyJWT` and `Argon2id` password hashing.
   * Standard claims: `sub` (user UUID), `org_id` (organization UUID), `role` (`ADMIN` or `MEMBER`), `iat`, `exp` (60 minutes).
   * Refresh tokens (7 days) are conceptually defined, with active refresh endpoints deferred to Phase 3.
2. **Stage 2 (Enterprise SSO Expansion)**: The authentication verification dependency is decoupled from token generation. When enterprise OIDC/JWKS is integrated, FastAPI's `get_current_user` dependency will simply point to the IdP's JWKS endpoint to verify tokens, leaving business logic, tenant context, and database RLS completely unchanged.

---

## Alternatives Considered
* **Auth0**: Enterprise-grade SaaS IdP. High vendor lock-in and cost for enterprise SSO; requires internet connectivity and complex local mock workflows.
* **Keycloak**: Self-hosted open-source OIDC server. Highly robust but requires dedicated Java runtime, separate database, and ~1GB memory overhead.
* **Supabase Auth**: GoTrue auth system. Bound to Supabase platform paradigms which conflict with Seedoc's standalone PostgreSQL 17 + pgvector architecture.

---

## Security Implications & Safeguards
* **Algorithm Restriction**: Enforces `HS256` explicitly; unconditionally rejects `alg="none"` or arbitrary algorithm parameters.
* **Tenant Integrity**: `X-Tenant-ID` headers are untrusted. Tenant context is bound strictly from the cryptographically verified `org_id` claim in the JWT.
* **Password Storage**: Uses modern Argon2id with memory/time cost parameters via `argon2-cffi`. Plaintext passwords are never logged or stored.
* **Least-Privilege Authentication Lookup**: Credential lookups during `/login` are executed via a dedicated PostgreSQL `SECURITY DEFINER` function (`get_user_auth_by_email`), returning strictly authentication fields without requiring or enabling generic `app.bypass_rls`.
* **Login Timing Defense**: Non-existent user lookups execute dummy Argon2id verification work to equalize latency against valid account password checks.
* **Production Secret Guard**: Startup fails closed if `ENVIRONMENT == "production"` and `SECRET_KEY` is missing or uses the development default fallback.
* **CORS Hardening**: CORS policy explicitly restricts allowed methods (`GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`) and headers (`Authorization`, `Content-Type`).


---

## Consequences
* **Positive**: 100% portable, zero external IdP dependencies, runs entirely in local Docker/Python environment, instantaneous test suite.
* **Negative**: User registration, password reset flows, and email verification must be managed by the application until an external IdP is linked.
