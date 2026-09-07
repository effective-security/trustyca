\set ON_ERROR_STOP on

SELECT pg_terminate_backend (pg_stat_activity.pid)
FROM pg_stat_activity
WHERE
    pg_stat_activity.datname = 'trustycadb'
    AND pid <> pg_backend_pid ();

DROP DATABASE IF EXISTS trustycadb;

-- Cluster-level cleanup (schema objects are gone with the database)
DROP USER IF EXISTS trustyca;
DROP ROLE IF EXISTS frontend;
DROP ROLE IF EXISTS backend;

\list
\dn
