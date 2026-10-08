-- CryptSat MDM schema v1.
-- Tenant isolation is enforced here, not only in the application: every tenant table has row-level
-- security keyed on the transaction-local setting app.tenant_id, which the service sets per request.

-- ---------------------------------------------------------------- tenants
CREATE TABLE tenants (
    id            text PRIMARY KEY CHECK (id ~ '^[a-z][a-z0-9-]{1,30}$'),
    name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    country       text NOT NULL CHECK (country ~ '^[A-Z]{2}$'),
    region        text NOT NULL DEFAULT '',          -- data-residency region (open legal question per ministry)
    enterprise    text UNIQUE CHECK (enterprise IS NULL OR enterprise ~ '^enterprises/[A-Za-z0-9_-]+$'),
    paused        boolean NOT NULL DEFAULT false,    -- kill switch: blocks policy pushes, tokens and commands
    paused_reason text,
    stage         text NOT NULL DEFAULT 'pilot' CHECK (stage IN ('pilot', 'r5', 'r25', 'r100')),
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Devices hand-picked for the pilot ring.
CREATE TABLE pilot_devices (
    tenant_id text NOT NULL REFERENCES tenants(id),
    device_id text NOT NULL,
    PRIMARY KEY (tenant_id, device_id)
);

-- Serial numbers of tablets that must never be managed (the existing field fleet on RustDesk).
-- If one ever shows up enrolled, it is flagged and excluded from every push and command.
CREATE TABLE protected_serials (
    tenant_id  text NOT NULL REFERENCES tenants(id),
    serial     text NOT NULL CHECK (length(serial) BETWEEN 1 AND 64),
    note       text NOT NULL DEFAULT '',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, serial)
);

-- ---------------------------------------------------------------- devices (mirror of AMAPI state)
CREATE TABLE devices (
    tenant_id           text NOT NULL REFERENCES tenants(id),
    id                  text NOT NULL,              -- last segment of the AMAPI device name
    amapi_name          text NOT NULL,              -- enterprises/{e}/devices/{id}
    serial              text,
    state               text,
    policy_name         text,                       -- policy the device is assigned
    applied_policy_name text,                       -- policy the device reports as applied
    policy_compliant    boolean,
    last_status_at      timestamptz,
    enrolled_at         timestamptz,
    protected_flag      boolean NOT NULL DEFAULT false,
    synced_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

-- ---------------------------------------------------------------- policies (versioned, immutable)
CREATE TABLE policy_versions (
    tenant_id  text NOT NULL REFERENCES tenants(id),
    name       text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,40}$'),
    version    integer NOT NULL CHECK (version > 0),
    body       jsonb NOT NULL,
    note       text NOT NULL DEFAULT '',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name, version)
);

-- A dry run fixes exactly which devices an apply may touch. Apply refuses without one.
CREATE TABLE dry_runs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   text NOT NULL,
    policy_name text NOT NULL,
    version     integer NOT NULL,
    stage       text NOT NULL,
    device_ids  jsonb NOT NULL,
    diff        jsonb NOT NULL,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    applied_at  timestamptz,
    applied_by  text,
    FOREIGN KEY (tenant_id, policy_name, version) REFERENCES policy_versions (tenant_id, name, version)
);

-- ---------------------------------------------------------------- commands (no wipe, enforced twice)
CREATE TABLE commands (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    text NOT NULL,
    device_id    text NOT NULL,
    type         text NOT NULL CHECK (type IN ('LOCK', 'REBOOT')),
    requested_by text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices (tenant_id, id)
);

-- ---------------------------------------------------------------- enrolment tokens (value never stored)
CREATE TABLE enrolment_tokens (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     text NOT NULL,
    policy_name   text NOT NULL,
    version       integer NOT NULL,
    amapi_name    text,
    token_sha256  char(64) NOT NULL,
    one_time_only boolean NOT NULL,
    expires_at    timestamptz NOT NULL,
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, policy_name, version) REFERENCES policy_versions (tenant_id, name, version)
);

-- ---------------------------------------------------------------- audit (append-only, hash-chained per tenant)
-- tenant_id is a chain id: a tenant id, or '_platform' for platform-level events. Not a foreign key so the
-- platform chain can exist and so audit rows can never be removed by a cascading delete.
CREATE TABLE audit_log (
    tenant_id text NOT NULL,
    seq       bigint NOT NULL CHECK (seq > 0),
    at        timestamptz NOT NULL,
    actor     text NOT NULL,
    action    text NOT NULL,
    detail    jsonb NOT NULL,
    prev      char(64) NOT NULL,
    hash      char(64) NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);

-- ---------------------------------------------------------------- immutability
CREATE FUNCTION reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION reject_change();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION reject_change();
CREATE TRIGGER policy_versions_immutable BEFORE UPDATE OR DELETE ON policy_versions
    FOR EACH ROW EXECUTE FUNCTION reject_change();
CREATE TRIGGER commands_immutable BEFORE UPDATE OR DELETE ON commands
    FOR EACH ROW EXECUTE FUNCTION reject_change();

-- ---------------------------------------------------------------- row-level security
CREATE FUNCTION current_tenant() RETURNS text LANGUAGE sql STABLE AS
    $$ SELECT nullif(current_setting('app.tenant_id', true), '') $$;
CREATE FUNCTION platform_scope() RETURNS boolean LANGUAGE sql STABLE AS
    $$ SELECT coalesce(current_setting('app.scope', true), '') = 'platform' $$;

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
-- Platform scope (super-admin operations only) may list and create tenants; a tenant scope sees only itself.
CREATE POLICY tenants_select ON tenants FOR SELECT USING (platform_scope() OR id = current_tenant());
CREATE POLICY tenants_insert ON tenants FOR INSERT WITH CHECK (platform_scope());
CREATE POLICY tenants_update ON tenants FOR UPDATE
    USING (platform_scope() OR id = current_tenant()) WITH CHECK (platform_scope() OR id = current_tenant());

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['pilot_devices', 'protected_serials', 'devices', 'policy_versions',
                             'dry_runs', 'commands', 'enrolment_tokens', 'audit_log'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant()) '
                       'WITH CHECK (tenant_id = current_tenant())', t);
    END LOOP;
END $$;

-- ---------------------------------------------------------------- grants for the service role
GRANT USAGE ON SCHEMA public TO cryptsat_app;
GRANT SELECT, INSERT, UPDATE         ON tenants           TO cryptsat_app;
GRANT SELECT, INSERT, DELETE         ON pilot_devices     TO cryptsat_app;
GRANT SELECT, INSERT                 ON protected_serials TO cryptsat_app;
GRANT SELECT, INSERT, UPDATE         ON devices           TO cryptsat_app;
GRANT SELECT, INSERT                 ON policy_versions   TO cryptsat_app;
GRANT SELECT, INSERT                 ON dry_runs          TO cryptsat_app;
GRANT UPDATE (applied_at, applied_by) ON dry_runs         TO cryptsat_app;
GRANT SELECT, INSERT                 ON commands          TO cryptsat_app;
GRANT SELECT, INSERT                 ON enrolment_tokens  TO cryptsat_app;
GRANT SELECT, INSERT                 ON audit_log         TO cryptsat_app;
