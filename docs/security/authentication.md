# Authentication Architecture in Seedoc

## 1. Core Principle: "Who Are You?"
Authentication establishes and verifies the identity of the client making the request. In Seedoc:
* Every user belongs to exactly one **Organization** (Tenant).
* Users authenticate via `/api/v1/auth/login` by providing their `email` and plaintext `password`.
* Passwords are verified against the stored `hashed_password` using **Argon2id**.
* Upon successful authentication, the API returns a signed **Bearer Access Token (JWT)** with an expiration of 60 minutes.

---

## 2. JWT Claim Specification
Seedoc adheres to standard RFC 7519 JWT claims:

| Claim | Key Name | Type | Description |
| :--- | :--- | :--- | :--- |
| **Subject** | `sub` | `string` (UUID) | Unique user identifier (`users.id`) |
| **Organization** | `org_id` | `string` (UUID) | Unique tenant identifier (`organizations.id`) |
| **Role** | `role` | `string` | User's role: `ADMIN` or `MEMBER` |
| **Issued At** | `iat` | `integer` (epoch) | Token issuance timestamp |
| **Expiration** | `exp` | `integer` (epoch) | Token expiration timestamp (now + 60 minutes) |

---

## 3. Cryptographic Hygiene & Safeguards
1. **Algorithm Hardening**: The decoding engine strictly white-lists `HS256`. Tokens specifying `alg="none"` or alternative algorithms are rejected immediately.
2. **Untrusted Header Rule**: Any `X-Tenant-ID` header sent by the client is completely ignored for authentication and tenant resolution.
3. **Stale Claim Check**: Upon validating the JWT cryptographic signature, `get_current_user` queries the database under tenant scope to confirm the user has not been deactivated or removed from that organization.
4. **Secret Handling & Production Fail-Closed Guard**: Plaintext passwords, hashed passwords, JWT secrets, and bearer tokens are strictly omitted from standard logs. In production (`ENVIRONMENT == "production"`), the application validator refuses to start if `SECRET_KEY` is missing, equals the development fallback, or is shorter than 32 characters.
5. **Pre-Tenant Authentication via Least-Privilege Function**: User authentication lookup during `/login` does NOT bypass PostgreSQL Row Level Security (RLS). Instead, it calls a narrowly-scoped PostgreSQL `SECURITY DEFINER` function (`get_user_auth_by_email`) that returns only the fields required for authentication (`id`, `organization_id`, `hashed_password`, `role`). Generic application RLS bypass (`app.bypass_rls`) is strictly prohibited.
6. **Login Timing Enumeration Mitigation**: When a non-existent email is submitted to `/login`, the backend performs equivalent Argon2id verification work against a constant pre-computed dummy hash (`DUMMY_PASSWORD_HASH`), equalizing response latency and preventing account enumeration.
7. **CORS Policy**: CORS is restricted to explicit origins (`settings.CORS_ORIGINS`), whitelisted methods (`GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`), and whitelisted headers (`Authorization`, `Content-Type`).

