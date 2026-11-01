-- Removes capture.sql's triggers and schema.
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS m8cap_capture ON public.%I', r.tablename);
    END LOOP;
END $$;
DROP SCHEMA IF EXISTS m8cap CASCADE;
