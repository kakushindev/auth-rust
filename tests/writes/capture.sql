-- Row-change capture for the write differential (tests/writes): every
-- INSERT/UPDATE/DELETE on a public table, in order, as JSON. Test stacks
-- only; uncapture.sql removes it before the schema guard runs.
CREATE SCHEMA IF NOT EXISTS m8cap;
CREATE TABLE IF NOT EXISTS m8cap.changes (
    id bigserial PRIMARY KEY,
    tbl text NOT NULL,
    op text NOT NULL,
    old jsonb,
    new jsonb
);
CREATE OR REPLACE FUNCTION m8cap.capture() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO m8cap.changes (tbl, op, old, new) VALUES (
        TG_TABLE_NAME, TG_OP,
        CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
        CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END
    );
    RETURN NULL;
END $$;
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
        EXECUTE format(
            'CREATE TRIGGER m8cap_capture AFTER INSERT OR UPDATE OR DELETE ON public.%I '
            'FOR EACH ROW EXECUTE FUNCTION m8cap.capture()', r.tablename);
    END LOOP;
END $$;
