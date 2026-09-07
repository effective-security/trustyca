BEGIN;

-- this is needed before migration to Postgres 15
ALTER DATABASE trustycadb OWNER TO trustyca;

-- Ensure app schema exists even if bootstrap scripts were skipped/partial
CREATE SCHEMA IF NOT EXISTS trustyca AUTHORIZATION trustyca;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA trustyca TO trustyca;
GRANT USAGE ON SCHEMA public TO trustyca;

--
--
--
COMMIT;
