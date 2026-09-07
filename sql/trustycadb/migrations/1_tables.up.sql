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
)
WITH (
    OIDS = FALSE
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
)
WITH (
    OIDS = FALSE
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
)
WITH (
    OIDS = FALSE
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
-- Org Members
--
CREATE TABLE IF NOT EXISTS trustyca.membership
(
    id BIGINT NOT NULL,
    org_id BIGINT NOT NULL REFERENCES trustyca.org ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES trustyca.user ON DELETE CASCADE,
    role INTEGER NOT NULL,
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT membership_pkey PRIMARY KEY (id),
    CONSTRAINT membership_org_user UNIQUE (org_id, user_id)
)
WITH (
    OIDS = FALSE
);

ALTER TABLE trustyca.membership
    OWNER TO trustyca;

CREATE INDEX IF NOT EXISTS idx_membership_org_id
    ON trustyca.membership USING btree
    (org_id ASC NULLS LAST);

CREATE INDEX IF NOT EXISTS idx_membership_user_id
    ON trustyca.membership USING btree
    (user_id ASC NULLS LAST);

--
-- Invites
--
CREATE TABLE IF NOT EXISTS trustyca.invite
(
    id BIGINT NOT NULL,
    org_id BIGINT NOT NULL REFERENCES trustyca.org ON DELETE CASCADE,
    inviter_id BIGINT NOT NULL REFERENCES trustyca.user ON DELETE CASCADE,
    email VARCHAR(160) COLLATE pg_catalog."default" NOT NULL,
    role INTEGER NOT NULL,
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT invites_pkey PRIMARY KEY (id)
)
WITH (
    OIDS = FALSE
);

ALTER TABLE trustyca.invite
    OWNER to trustyca;


CREATE INDEX IF NOT EXISTS idx_invite_org_id
    ON trustyca.invite USING btree
    (org_id);

CREATE INDEX IF NOT EXISTS idx_invite_email
    ON trustyca.invite USING btree
    (email);

CREATE UNIQUE INDEX IF NOT EXISTS idx_invite_org_id_email
    ON trustyca.invite USING btree
    (org_id,email COLLATE pg_catalog."default");

SELECT create_constraint_if_not_exists(
    'trustyca',
    'invite',
    'unique_invite_org_id_email',
    'ALTER TABLE trustyca.invite ADD CONSTRAINT unique_invite_org_id_email UNIQUE USING INDEX idx_invite_org_id_email;');

CREATE VIEW trustyca.vw_membership_info AS
SELECT 
    m.id, 
    m.org_id, 
    o.alias AS org_alias, 
    o.name AS org_name, 
    o.status AS org_status,
    u.id AS user_id, 
    u.email, 
    u.name,
    m.role, 
    m.created_at
FROM trustyca.membership m
LEFT JOIN trustyca.org o ON m.org_id = o.id
LEFT JOIN trustyca.user u ON m.user_id = u.id;


--
-- Events
--
CREATE TABLE IF NOT EXISTS trustyca.event
(
    id BIGINT NOT NULL,
    org_id BIGINT NOT NULL REFERENCES trustyca.org ON DELETE CASCADE,
    type INTEGER NOT NULL,
    title VARCHAR(256) COLLATE pg_catalog."default" NOT NULL,
    description TEXT COLLATE pg_catalog."default" NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    ref_id BIGINT NULL,
    email VARCHAR(160) COLLATE pg_catalog."default" NULL,
    source VARCHAR(256) COLLATE pg_catalog."default" NULL,
    created_at TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT event_pkey PRIMARY KEY (id)
)
WITH (
    OIDS = FALSE
);

ALTER TABLE trustyca.event
    OWNER to trustyca;

CREATE INDEX IF NOT EXISTS idx_event_org_id
    ON trustyca.event USING btree
    (org_id);

CREATE INDEX idx_event_org_created_id_desc
    ON trustyca.event USING btree (org_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_event_type
    ON trustyca.event USING btree
    (type);

CREATE INDEX IF NOT EXISTS idx_event_email
    ON trustyca.event USING btree
    (email);

CREATE INDEX IF NOT EXISTS idx_event_org_ref_id
    ON trustyca.event USING btree
    (org_id, ref_id);

COMMIT;
