\set ON_ERROR_STOP on

-- Database: trustycadb
-- Cloud/RDS bootstrap. Mirror of create_local_db.sql with deployment-specific auth.


SELECT
    EXISTS(SELECT datname  FROM pg_catalog.pg_database WHERE datname = 'trustycadb') as trustycadb_exists \gset

\if :trustycadb_exists
\echo 'trustycadb already exists!'
\c trustycadb
\list
\dn
\q
\endif

-- template0: see https://blog.dbi-services.com/what-the-hell-are-these-template0-and-template1-databases-in-postgresql/
CREATE DATABASE trustycadb
WITH
    OWNER = postgres ENCODING = 'UTF8' LC_COLLATE = 'en_US.UTF-8' LC_CTYPE = 'en_US.UTF-8' TEMPLATE template0 CONNECTION
LIMIT = -1;

-- Roles/users are cluster-wide
CREATE ROLE frontend NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN;
CREATE ROLE backend NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN;

-- Password should be set/rotated by your secrets process for RDS
CREATE USER trustyca NOCREATEDB IN GROUP backend PASSWORD 'trustyca?local#&';

ALTER ROLE trustyca SET search_path TO trustyca, public;
ALTER DATABASE trustycadb OWNER TO trustyca;

-- Schema objects are database-local; must connect first
\c trustycadb

CREATE SCHEMA IF NOT EXISTS trustyca AUTHORIZATION trustyca;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA trustyca TO trustyca;
GRANT USAGE ON SCHEMA public TO trustyca;

\list
\dn
