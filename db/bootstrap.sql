-- Run once per environment as a database administrator, BEFORE migrations.
-- Passwords are set from the secret store (ALTER ROLE ... PASSWORD), never committed here.
--
-- cryptsat_owner  owns the schema and runs migrations. The service never connects as this role.
-- cryptsat_app    is what the service connects as. It is not the table owner and has NOBYPASSRLS,
--                 so row-level security always applies to it.

CREATE ROLE cryptsat_owner LOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE cryptsat_app   LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

-- Per environment, e.g.:
-- CREATE DATABASE cryptsat OWNER cryptsat_owner;
