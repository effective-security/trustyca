BEGIN;

--- WARNING:
--- ALL times must be created as TYPE TIMESTAMP(3) WITH TIME ZONE

CREATE OR REPLACE FUNCTION trustyca.create_constraint_if_not_exists (
    s_name text, t_name text, c_name text, constraint_sql text
)
RETURNS void AS
$$
BEGIN
    -- Look for our constraint
    IF NOT EXISTS (SELECT constraint_name
                   FROM information_schema.constraint_column_usage
                   WHERE table_schema = s_name AND table_name = t_name AND constraint_name = c_name) THEN
        EXECUTE constraint_sql;
    END IF;
END;
$$ LANGUAGE plpgsql;

ALTER FUNCTION trustyca.create_constraint_if_not_exists(text, text, text, text) OWNER TO trustyca;

--
-- Login
--
CREATE TABLE IF NOT EXISTS trustyca.login
(
    id BIGINT NOT NULL,
    external_id VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    provider INTEGER NOT NULL,
    email VARCHAR(160) COLLATE pg_catalog."default" NOT NULL,
    email_verified BOOLEAN NOT NULL,
    name VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    access_token TEXT COLLATE pg_catalog."default" NOT NULL,
    refresh_token TEXT COLLATE pg_catalog."default" NOT NULL,
    token_expires_at TIMESTAMP(3) WITH TIME ZONE,
    count INTEGER NOT NULL DEFAULT 0,
    last_at TIMESTAMP(3) WITH TIME ZONE,
    CONSTRAINT login_pkey PRIMARY KEY (id)
);

ALTER TABLE trustyca.login
    OWNER TO trustyca;

CREATE INDEX IF NOT EXISTS idx_login_email
    ON trustyca.login USING btree
    (email COLLATE pg_catalog."default")
    ;

CREATE INDEX IF NOT EXISTS idx_login_last_at
    ON trustyca.login USING btree
    (last_at)
    ;

CREATE UNIQUE INDEX IF NOT EXISTS idx_login_provider_email
    ON trustyca.login USING btree
    (provider,email COLLATE pg_catalog."default")
    ;

SELECT trustyca.create_constraint_if_not_exists(
    'trustyca',
    'login',
    'unique_login_provider_email',
    'ALTER TABLE trustyca.login ADD CONSTRAINT unique_login_provider_email UNIQUE USING INDEX idx_login_provider_email;');

--
-- USERS
--
CREATE TABLE IF NOT EXISTS trustyca.user
(
    id bigint NOT NULL,
    email VARCHAR(160) COLLATE pg_catalog."default" NOT NULL,
    email_verified boolean NOT NULL,
    name VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT user_pkey PRIMARY KEY (id)
);

ALTER TABLE trustyca.user
    OWNER TO trustyca;

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_email
    ON trustyca.user USING btree
    (email COLLATE pg_catalog."default")
    ;

SELECT trustyca.create_constraint_if_not_exists(
    'trustyca',
    'user',
    'unique_user_email',
    'ALTER TABLE trustyca.user ADD CONSTRAINT unique_user_email UNIQUE USING INDEX idx_user_email;');

--
-- Orgs
--

CREATE TABLE IF NOT EXISTS trustyca.org
(
    id bigint NOT NULL,
    alias VARCHAR(32) COLLATE pg_catalog."default" NOT NULL,
    name VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    description TEXT COLLATE pg_catalog."default" NULL,
    status INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT org_pkey PRIMARY KEY (id)
);

ALTER TABLE trustyca.org
    OWNER TO trustyca;

CREATE UNIQUE INDEX IF NOT EXISTS idx_org_alias
    ON trustyca.org USING btree
    (alias);

SELECT create_constraint_if_not_exists(
    'trustyca',
    'org',
    'unique_org_alias',
    'ALTER TABLE trustyca.org ADD CONSTRAINT unique_org_alias UNIQUE USING INDEX idx_org_alias;');

--
-- Projects
--
-- A project owns a collection of resources governed by a common access
-- policy. Membership, invite, event and CA data-plane tables carry
-- (org_id, project_id); project_id IS NULL means the row is org scope.
--
CREATE TABLE IF NOT EXISTS trustyca.project
(
    id BIGINT NOT NULL,
    org_id BIGINT NOT NULL REFERENCES trustyca.org ON DELETE CASCADE,
    alias VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    name VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    description TEXT COLLATE pg_catalog."default" NULL,
    status INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT project_pkey PRIMARY KEY (id),
    CONSTRAINT unique_project_org_alias UNIQUE (org_id, alias),
    -- allows composite FKs (org_id, project_id) that guarantee a project
    -- reference always belongs to the referencing row's org
    CONSTRAINT unique_project_org_id UNIQUE (org_id, id)
);

ALTER TABLE trustyca.project
    OWNER TO trustyca;

CREATE INDEX IF NOT EXISTS idx_project_org_status
    ON trustyca.project USING btree
    (org_id, status);

--
-- Memberships
--
-- An explicit role assignment (org_id, project_id, user_id, role):
-- project_id IS NULL: explicit org-wide grant, inherited by every current and
-- future project of the org.
-- project_id IS NOT NULL: explicit grant restricted to the project. Grants are
-- additive: effective project permissions are the union of the inherited
-- org-wide grant and the project grant.
-- A user has at most one row per scope, hence NULLS NOT DISTINCT.
-- The composite FK guarantees the project belongs to the membership's org.
--
CREATE TABLE IF NOT EXISTS trustyca.membership
(
    id BIGINT NOT NULL,
    org_id BIGINT NOT NULL REFERENCES trustyca.org ON DELETE CASCADE,
    project_id BIGINT NULL,
    user_id BIGINT NOT NULL REFERENCES trustyca.user ON DELETE CASCADE,
    role INTEGER NOT NULL,
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT membership_pkey PRIMARY KEY (id),
    CONSTRAINT unique_membership_org_project_user UNIQUE NULLS NOT DISTINCT (org_id, project_id, user_id),
    CONSTRAINT fk_membership_project FOREIGN KEY (org_id, project_id)
        REFERENCES trustyca.project (org_id, id) ON DELETE CASCADE
);

ALTER TABLE trustyca.membership
    OWNER TO trustyca;

CREATE INDEX IF NOT EXISTS idx_membership_org_project
    ON trustyca.membership USING btree
    (org_id, project_id);

CREATE INDEX IF NOT EXISTS idx_membership_user_id
    ON trustyca.membership USING btree
    (user_id);

--
-- Invites
--
-- project_id IS NULL: org-wide invite; otherwise the invite grants a project
-- membership when accepted. Expired invites grant nothing and are skipped on
-- acceptance.
--
CREATE TABLE IF NOT EXISTS trustyca.invite
(
    id BIGINT NOT NULL,
    org_id BIGINT NOT NULL REFERENCES trustyca.org ON DELETE CASCADE,
    project_id BIGINT NULL,
    inviter_id BIGINT NOT NULL REFERENCES trustyca.user ON DELETE CASCADE,
    email VARCHAR(160) COLLATE pg_catalog."default" NOT NULL,
    role INTEGER NOT NULL,
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP(3) WITH TIME ZONE NULL,
    CONSTRAINT invite_pkey PRIMARY KEY (id),
    CONSTRAINT unique_invite_org_project_email UNIQUE NULLS NOT DISTINCT (org_id, project_id, email),
    CONSTRAINT fk_invite_project FOREIGN KEY (org_id, project_id)
        REFERENCES trustyca.project (org_id, id) ON DELETE CASCADE
);

ALTER TABLE trustyca.invite
    OWNER to trustyca;


CREATE INDEX IF NOT EXISTS idx_invite_org_project
    ON trustyca.invite USING btree
    (org_id, project_id);

CREATE INDEX IF NOT EXISTS idx_invite_email
    ON trustyca.invite USING btree
    (email);

CREATE VIEW trustyca.vw_membership_info AS
SELECT 
    m.id, 
    m.org_id, 
    m.project_id,
    o.alias AS org_alias, 
    o.name AS org_name, 
    o.status AS org_status,
    COALESCE(t.alias, '') AS project_alias,
    COALESCE(t.name, '') AS project_name,
    u.id AS user_id, 
    u.email, 
    u.name,
    m.role, 
    m.created_at
FROM trustyca.membership m
LEFT JOIN trustyca.org o ON m.org_id = o.id
LEFT JOIN trustyca.project t ON m.project_id = t.id
LEFT JOIN trustyca.user u ON m.user_id = u.id;


--
-- API Keys
--
CREATE TABLE IF NOT EXISTS trustyca.apikey
(
    id bigint NOT NULL,
    org_id bigint NOT NULL REFERENCES trustyca.org ON DELETE CASCADE,
    project_id BIGINT NULL,
    key VARCHAR(128) COLLATE pg_catalog."default" NOT NULL,
    secret VARCHAR(128) COLLATE pg_catalog."default" NOT NULL,
    label VARCHAR(260) COLLATE pg_catalog."default" NOT NULL,
    scopes VARCHAR(64)[] COLLATE pg_catalog."default" NOT NULL DEFAULT '{}'::character varying[],
    metadata JSONB NULL DEFAULT '{}'::jsonb,
    status INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP(3) WITH TIME ZONE NULL,
    used_at TIMESTAMP(3) WITH TIME ZONE NULL,
    used_count INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT apikey_pkey PRIMARY KEY (id),
    CONSTRAINT apikey_key UNIQUE (key),
    -- a project scoped key must belong to a project of the same org;
    -- deleting the project deletes its keys
    CONSTRAINT fk_apikey_project FOREIGN KEY (org_id, project_id)
        REFERENCES trustyca.project (org_id, id) ON DELETE CASCADE
);

ALTER TABLE trustyca.apikey
    OWNER to trustyca;

-- list keys of an org or a project
CREATE INDEX IF NOT EXISTS idx_apikey_org_project
    ON trustyca.apikey USING btree
    (org_id, project_id);

--
--
-- Events
--
CREATE TABLE IF NOT EXISTS trustyca.event
(
    id BIGINT NOT NULL,
    org_id BIGINT REFERENCES trustyca.org ON DELETE CASCADE,
    project_id BIGINT NULL REFERENCES trustyca.project ON DELETE CASCADE,
    type INTEGER NOT NULL,
    title VARCHAR(256) COLLATE pg_catalog."default" NOT NULL,
    description TEXT COLLATE pg_catalog."default" NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    ref_id BIGINT NULL,
    email VARCHAR(160) COLLATE pg_catalog."default" NULL,
    source VARCHAR(256) COLLATE pg_catalog."default" NULL,
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT event_pkey PRIMARY KEY (id)
);

ALTER TABLE trustyca.event
    OWNER to trustyca;

CREATE INDEX IF NOT EXISTS idx_event_org_id
    ON trustyca.event USING btree
    (org_id);

CREATE INDEX IF NOT EXISTS idx_event_org_created_id_desc
    ON trustyca.event USING btree (org_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_event_org_project_created_id_desc
    ON trustyca.event USING btree (org_id, project_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_event_type
    ON trustyca.event USING btree
    (type);

CREATE INDEX IF NOT EXISTS idx_event_email
    ON trustyca.event USING btree
    (email);

CREATE INDEX IF NOT EXISTS idx_event_org_ref_id
    ON trustyca.event USING btree
    (org_id, ref_id);



--
-- CA DATA PLANE
--
-- Tenancy: every CA table carries (org_id, project_id).
--   org_id  IS NULL -> platform scope (the service's own bootstrap issuers)
--   project_id IS NULL -> org scope row, governed by org-wide permissions
-- Unique keys that include tenancy columns use NULLS NOT DISTINCT so that a
-- label is unique within its scope.
-- CA tables intentionally do NOT have FK to org/project: certificates, revocations
-- and issuers are audit records and must survive tenant deletion (orgs are
-- soft-deleted via status). The service validates tenancy on write.
--

--
-- Root Certificates (trust anchors published by CIS)
--
CREATE TABLE IF NOT EXISTS trustyca.root_certificate
(
    id BIGINT NOT NULL,
    org_id BIGINT NULL,
    skid VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    not_before TIMESTAMP(3) WITH TIME ZONE NOT NULL,
    not_after TIMESTAMP(3) WITH TIME ZONE NOT NULL,
    subject VARCHAR(260) COLLATE pg_catalog."default" NOT NULL,
    sha256 VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    trust INTEGER NOT NULL,
    pem TEXT COLLATE pg_catalog."default" NOT NULL,
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT root_certificate_pkey PRIMARY KEY (id),
    CONSTRAINT unique_root_certificate_sha256 UNIQUE (sha256)
);

ALTER TABLE trustyca.root_certificate
    OWNER TO trustyca;

CREATE INDEX IF NOT EXISTS idx_root_certificate_org
    ON trustyca.root_certificate USING btree
    (org_id);

CREATE INDEX IF NOT EXISTS idx_root_certificate_skid
    ON trustyca.root_certificate USING btree
    (skid COLLATE pg_catalog."default");

CREATE INDEX IF NOT EXISTS idx_root_certificate_notafter
    ON trustyca.root_certificate USING btree
    (not_after);

--
-- Issuers (Root, Intermediate and Issuing CAs owned by a tenant)
--
-- key_provider/key_id reference the private key in a crypto provider
-- (AWS KMS, GCP KMS, PKCS#11). key_protected holds dataprotection-wrapped
-- key material only for software keys (dev/test or imported keys).
-- config is JSON of the issuer runtime settings (AIA/CRL/OCSP URLs and timings,
-- allowed profiles), see pb.IssuerConfig.
-- crl_number is the monotonic CRL number, bumped with every published CRL.
--
CREATE TABLE IF NOT EXISTS trustyca.issuer
(
    id BIGINT NOT NULL,
    org_id BIGINT NULL,
    project_id BIGINT NULL,
    label VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    type INTEGER NOT NULL,
    status INTEGER NOT NULL,
    parent_id BIGINT NULL,
    skid VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    ikid VARCHAR(64) COLLATE pg_catalog."default" NOT NULL DEFAULT '',
    serial_number VARCHAR(64) COLLATE pg_catalog."default" NOT NULL DEFAULT '',
    subject VARCHAR(260) COLLATE pg_catalog."default" NOT NULL,
    issuer VARCHAR(260) COLLATE pg_catalog."default" NOT NULL DEFAULT '',
    sha256 VARCHAR(64) COLLATE pg_catalog."default" NOT NULL DEFAULT '',
    not_before TIMESTAMP(3) WITH TIME ZONE NULL,
    not_after TIMESTAMP(3) WITH TIME ZONE NULL,
    pem TEXT COLLATE pg_catalog."default" NOT NULL DEFAULT '',
    chain_pem TEXT COLLATE pg_catalog."default" NOT NULL DEFAULT '',
    root_pem TEXT COLLATE pg_catalog."default" NOT NULL DEFAULT '',
    csr_pem TEXT COLLATE pg_catalog."default" NOT NULL DEFAULT '',
    key_provider VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    key_id VARCHAR(260) COLLATE pg_catalog."default" NOT NULL,
    key_protected TEXT COLLATE pg_catalog."default" NULL,
    config JSONB NOT NULL DEFAULT '{}',
    crl_number BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT issuer_pkey PRIMARY KEY (id),
    CONSTRAINT unique_issuer_org_project_label UNIQUE NULLS NOT DISTINCT (org_id, project_id, label),
    CONSTRAINT unique_issuer_skid UNIQUE (skid)
);

ALTER TABLE trustyca.issuer
    OWNER TO trustyca;

CREATE INDEX IF NOT EXISTS idx_issuer_org_project_status
    ON trustyca.issuer USING btree
    (org_id, project_id, status);

CREATE INDEX IF NOT EXISTS idx_issuer_parent
    ON trustyca.issuer USING btree
    (parent_id);

CREATE INDEX IF NOT EXISTS idx_issuer_notafter
    ON trustyca.issuer USING btree
    (not_after);

--
-- Certificate profiles
--
-- config is JSON of pb.CertProfile (same shape as the YAML profiles in
-- etc/dev/ca-config.*.yaml). issuer_label binds the profile to an issuer of
-- the same org; '*' allows any issuer that lists the profile in
-- config.allowed_profiles.
-- Resolution at sign time: (org, project, label) -> (org, 0, label).
--
CREATE TABLE IF NOT EXISTS trustyca.certificate_profile
(
    id BIGINT NOT NULL,
    org_id BIGINT NULL,
    project_id BIGINT NULL,
    label VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    issuer_label VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    status INTEGER NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT certificate_profile_pkey PRIMARY KEY (id),
    CONSTRAINT unique_certificate_profile_org_project_label UNIQUE NULLS NOT DISTINCT (org_id, project_id, label)
);

ALTER TABLE trustyca.certificate_profile
    OWNER TO trustyca;

CREATE INDEX IF NOT EXISTS idx_certificate_profile_org_issuer
    ON trustyca.certificate_profile USING btree
    (org_id, issuer_label COLLATE pg_catalog."default");

--
-- Certificates (issued end-entity and subordinate CA certificates)
--
-- Immutable except for label/metadata/locations/status. Rows are never
-- deleted by tenant lifecycle; retention of expired rows is a separate task.
-- High volume table: all tenant indexes lead with (org_id, project_id) so the
-- table can later be partitioned BY HASH (org_id) without changing queries.
--
CREATE TABLE IF NOT EXISTS trustyca.certificate
(
    id BIGINT NOT NULL,
    org_id BIGINT NULL,
    project_id BIGINT NULL,
    skid VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    ikid VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    serial_number VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    not_before TIMESTAMP(3) WITH TIME ZONE NOT NULL,
    not_after TIMESTAMP(3) WITH TIME ZONE NOT NULL,
    subject VARCHAR(260) COLLATE pg_catalog."default" NOT NULL,
    issuer VARCHAR(260) COLLATE pg_catalog."default" NOT NULL,
    sha256 VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    profile VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    label VARCHAR(260) COLLATE pg_catalog."default" NOT NULL DEFAULT '',
    locations VARCHAR(260)[] COLLATE pg_catalog."default" NOT NULL DEFAULT '{}'::character varying[],
    metadata JSONB NOT NULL DEFAULT '{}',
    pem TEXT COLLATE pg_catalog."default" NOT NULL,
    issuers_pem TEXT COLLATE pg_catalog."default" NOT NULL,
    status INTEGER NOT NULL,
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT certificate_pkey PRIMARY KEY (id),
    CONSTRAINT unique_certificate_sha256 UNIQUE (sha256),
    CONSTRAINT unique_certificate_ikid_serial UNIQUE (ikid, serial_number)
);

ALTER TABLE trustyca.certificate
    OWNER TO trustyca;

-- listing newest first with keyset pagination on id
CREATE INDEX IF NOT EXISTS idx_certificate_org_project_id_desc
    ON trustyca.certificate USING btree
    (org_id, project_id, id DESC);

-- expiring certificates per tenant
CREATE INDEX IF NOT EXISTS idx_certificate_org_project_notafter
    ON trustyca.certificate USING btree
    (org_id, project_id, not_after);

-- listing per issuer
CREATE INDEX IF NOT EXISTS idx_certificate_ikid_id_desc
    ON trustyca.certificate USING btree
    (ikid COLLATE pg_catalog."default", id DESC);

CREATE INDEX IF NOT EXISTS idx_certificate_skid
    ON trustyca.certificate USING btree
    (skid COLLATE pg_catalog."default");

--
-- Revoked certificates
--
-- ikid, serial_number and not_after are denormalized from certificate so a
-- CRL is built with a single index range scan: ikid = ? AND not_after > now().
--
CREATE TABLE IF NOT EXISTS trustyca.revoked
(
    id BIGINT NOT NULL,
    org_id BIGINT NULL,
    project_id BIGINT NULL,
    certificate_id BIGINT NOT NULL REFERENCES trustyca.certificate ON DELETE CASCADE,
    ikid VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    serial_number VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    not_after TIMESTAMP(3) WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP(3) WITH TIME ZONE NOT NULL,
    reason INTEGER NOT NULL,
    reason_text VARCHAR(260) COLLATE pg_catalog."default" NOT NULL DEFAULT '',
    CONSTRAINT revoked_pkey PRIMARY KEY (id),
    CONSTRAINT unique_revoked_certificate UNIQUE (certificate_id)
);

ALTER TABLE trustyca.revoked
    OWNER TO trustyca;

CREATE INDEX IF NOT EXISTS idx_revoked_ikid_notafter
    ON trustyca.revoked USING btree
    (ikid COLLATE pg_catalog."default", not_after);

CREATE INDEX IF NOT EXISTS idx_revoked_org_project_id_desc
    ON trustyca.revoked USING btree
    (org_id, project_id, id DESC);

--
-- CRL (current CRL per issuer; replaced on every publish)
--
CREATE TABLE IF NOT EXISTS trustyca.crl
(
    id BIGINT NOT NULL,
    org_id BIGINT NULL,
    project_id BIGINT NULL,
    issuer_id BIGINT NOT NULL REFERENCES trustyca.issuer ON DELETE CASCADE,
    ikid VARCHAR(64) COLLATE pg_catalog."default" NOT NULL,
    crl_number BIGINT NOT NULL,
    this_update TIMESTAMP(3) WITH TIME ZONE NOT NULL,
    next_update TIMESTAMP(3) WITH TIME ZONE NOT NULL,
    issuer VARCHAR(260) COLLATE pg_catalog."default" NOT NULL,
    pem TEXT COLLATE pg_catalog."default" NOT NULL,
    locations VARCHAR(260)[] COLLATE pg_catalog."default" NOT NULL DEFAULT '{}'::character varying[],
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT crl_pkey PRIMARY KEY (id),
    CONSTRAINT unique_crl_ikid UNIQUE (ikid)
);

ALTER TABLE trustyca.crl
    OWNER TO trustyca;

CREATE INDEX IF NOT EXISTS idx_crl_next_update
    ON trustyca.crl USING btree
    (next_update);

COMMIT;
