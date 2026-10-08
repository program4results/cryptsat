-- Single sign-on: who may do what is stored here, not in identity-provider claims, so access is the same
-- whichever provider each ministry ends up using, and every grant and revocation is audited.

CREATE TABLE role_grants (
    subject    text NOT NULL CHECK (length(subject) BETWEEN 3 AND 320),  -- verified email, or 'sub:<subject>'
    kind       text NOT NULL CHECK (kind IN ('human', 'service')),
    tenant_id  text NOT NULL,                                           -- a tenant id, or '*' for platform
    role       text NOT NULL CHECK (role IN ('viewer', 'operator', 'admin', 'reader', 'super_admin')),
    granted_by text NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (subject, tenant_id, role),
    CHECK ((tenant_id = '*') = (role = 'super_admin')),
    -- Service identities (the sl.p4sgi adapter) can only ever read.
    CHECK (kind = 'human' OR role = 'reader'),
    CHECK (subject = lower(subject))
);

-- One row per distinct token seen, so each sign-in is audited once rather than on every request.
CREATE TABLE auth_sessions (
    token_sha256 char(64) PRIMARY KEY,
    subject      text NOT NULL,
    outcome      text NOT NULL,
    first_seen   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX auth_sessions_expires ON auth_sessions (expires_at);

CREATE FUNCTION auth_scope() RETURNS boolean LANGUAGE sql STABLE AS
    $$ SELECT coalesce(current_setting('app.scope', true), '') = 'auth' $$;

ALTER TABLE role_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_grants FORCE ROW LEVEL SECURITY;
-- The sign-in lookup (auth scope) and super-admins (platform scope) see all grants; a tenant scope sees its own.
CREATE POLICY grants_select ON role_grants FOR SELECT
    USING (auth_scope() OR platform_scope() OR tenant_id = current_tenant());
CREATE POLICY grants_insert ON role_grants FOR INSERT WITH CHECK (platform_scope());
CREATE POLICY grants_delete ON role_grants FOR DELETE USING (platform_scope());

ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY sessions_auth ON auth_sessions USING (auth_scope()) WITH CHECK (auth_scope());

GRANT SELECT, INSERT, DELETE ON role_grants   TO cryptsat_app;
GRANT SELECT, INSERT, DELETE ON auth_sessions TO cryptsat_app;
