-- Seedoc Row-Level Security (RLS) Policies
-- Enforces defense-in-depth tenant isolation at the PostgreSQL kernel level.

-- 1. Enable and FORCE RLS on tenant-owned tables
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

ALTER TABLE document_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_chunks FORCE ROW LEVEL SECURITY;

-- 2. Organizations policy
DROP POLICY IF EXISTS tenant_isolation_organizations ON organizations;
CREATE POLICY tenant_isolation_organizations ON organizations
    FOR ALL
    USING (
        id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    )
    WITH CHECK (
        id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    );

-- 3. Users policy
DROP POLICY IF EXISTS tenant_isolation_users ON users;
CREATE POLICY tenant_isolation_users ON users
    FOR ALL
    USING (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    );

-- 4. Documents policy
DROP POLICY IF EXISTS tenant_isolation_documents ON documents;
CREATE POLICY tenant_isolation_documents ON documents
    FOR ALL
    USING (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    );

-- 5. Document Chunks policy
DROP POLICY IF EXISTS tenant_isolation_chunks ON document_chunks;
CREATE POLICY tenant_isolation_chunks ON document_chunks
    FOR ALL
    USING (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    );

-- 6. Narrowly-scoped SECURITY DEFINER authentication lookup function
-- Executed by seedoc_app to locate user credentials across tenants during login without bypassing RLS.
CREATE OR REPLACE FUNCTION public.get_user_auth_by_email(p_email TEXT)
RETURNS TABLE (
    id UUID,
    organization_id UUID,
    hashed_password VARCHAR(255),
    role VARCHAR(50)
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT u.id, u.organization_id, u.hashed_password, u.role
    FROM users u
    WHERE u.email = p_email
    LIMIT 1;
END;
$$;

REVOKE ALL ON FUNCTION public.get_user_auth_by_email(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_user_auth_by_email(TEXT) TO seedoc_app;
