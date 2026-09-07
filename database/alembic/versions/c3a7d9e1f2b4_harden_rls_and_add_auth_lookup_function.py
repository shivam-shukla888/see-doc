"""harden_rls_and_add_auth_lookup_function

Revision ID: c3a7d9e1f2b4
Revises: 5d1fc09b65a7
Create Date: 2026-09-07 20:55:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3a7d9e1f2b4'
down_revision: Union[str, Sequence[str], None] = '5d1fc09b65a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Update RLS policies to remove app.bypass_rls condition
    # Organizations
    op.execute("""
        DROP POLICY IF EXISTS tenant_isolation_organizations ON organizations;
        CREATE POLICY tenant_isolation_organizations ON organizations
            FOR ALL
            USING (
                id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
    """)

    # Users
    op.execute("""
        DROP POLICY IF EXISTS tenant_isolation_users ON users;
        CREATE POLICY tenant_isolation_users ON users
            FOR ALL
            USING (
                organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
    """)

    # Documents
    op.execute("""
        DROP POLICY IF EXISTS tenant_isolation_documents ON documents;
        CREATE POLICY tenant_isolation_documents ON documents
            FOR ALL
            USING (
                organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
    """)

    # Document Chunks
    op.execute("""
        DROP POLICY IF EXISTS tenant_isolation_chunks ON document_chunks;
        CREATE POLICY tenant_isolation_chunks ON document_chunks
            FOR ALL
            USING (
                organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
    """)

    # 2. Create the narrowly-scoped SECURITY DEFINER authentication lookup function
    op.execute("""
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
    """)

    # 3. Restrict privileges: Revoke from PUBLIC, grant EXECUTE specifically to seedoc_app
    op.execute("""
        REVOKE ALL ON FUNCTION public.get_user_auth_by_email(TEXT) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION public.get_user_auth_by_email(TEXT) TO seedoc_app;
    """)


def downgrade() -> None:
    # Drop the authentication lookup function
    op.execute("DROP FUNCTION IF EXISTS public.get_user_auth_by_email(TEXT);")

    # Restore policies with app.bypass_rls condition
    op.execute("""
        DROP POLICY IF EXISTS tenant_isolation_organizations ON organizations;
        CREATE POLICY tenant_isolation_organizations ON organizations
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'on'
                OR id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                current_setting('app.bypass_rls', true) = 'on'
                OR id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );

        DROP POLICY IF EXISTS tenant_isolation_users ON users;
        CREATE POLICY tenant_isolation_users ON users
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'on'
                OR organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                current_setting('app.bypass_rls', true) = 'on'
                OR organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );

        DROP POLICY IF EXISTS tenant_isolation_documents ON documents;
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

        DROP POLICY IF EXISTS tenant_isolation_chunks ON document_chunks;
        CREATE POLICY tenant_isolation_chunks ON document_chunks
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'on'
                OR organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            )
            WITH CHECK (
                current_setting('app.bypass_rls', true) = 'on'
                OR organization_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
            );
    """)
