-- Create dedicated application runtime user (non-superuser)
-- Essential for PostgreSQL Row-Level Security (RLS) enforcement,
-- because PostgreSQL superusers always bypass RLS.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'seedoc_app') THEN
    CREATE ROLE seedoc_app WITH LOGIN PASSWORD 'seedoc_dev_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO seedoc_app;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO seedoc_app;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO seedoc_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO seedoc_app;
