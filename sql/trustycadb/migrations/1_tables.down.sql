BEGIN;

-- CA data plane
DROP TABLE IF EXISTS trustyca.crl;
DROP TABLE IF EXISTS trustyca.revoked;
DROP TABLE IF EXISTS trustyca.certificate;
DROP TABLE IF EXISTS trustyca.certificate_profile;
DROP TABLE IF EXISTS trustyca.issuer;
DROP TABLE IF EXISTS trustyca.root_certificate;

-- Access layer
DROP TABLE IF EXISTS trustyca.event;
DROP TABLE IF EXISTS trustyca.invite;
DROP VIEW IF EXISTS trustyca.vw_membership_info;
DROP TABLE IF EXISTS trustyca.membership;
DROP TABLE IF EXISTS trustyca.project;
DROP TABLE IF EXISTS trustyca.org;
DROP TABLE IF EXISTS trustyca.login;
DROP TABLE IF EXISTS trustyca."user";

DROP FUNCTION IF EXISTS trustyca.create_constraint_if_not_exists(text, text, text, text);
DROP FUNCTION IF EXISTS create_constraint_if_not_exists(text, text, text, text);

COMMIT;
