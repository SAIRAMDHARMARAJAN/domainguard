-- DomainGuard v7 / 01: warehouse, database, schemas, file format, internal stage.
-- Run as ACCOUNTADMIN (or a role that can create warehouses and databases). Safe to rerun.
CREATE WAREHOUSE IF NOT EXISTS DG_WH
  WAREHOUSE_SIZE = 'XSMALL'
  AUTO_SUSPEND = 60            -- stop billing 60 seconds after the last query
  AUTO_RESUME = TRUE
  INITIALLY_SUSPENDED = TRUE;

CREATE DATABASE IF NOT EXISTS DOMAINGUARD;
USE DATABASE DOMAINGUARD;

CREATE SCHEMA IF NOT EXISTS REF;      -- companies, protected domains, verification
CREATE SCHEMA IF NOT EXISTS BRONZE;   -- raw, as staged
CREATE SCHEMA IF NOT EXISTS SILVER;   -- cleaned and scored features, analyst feedback
CREATE SCHEMA IF NOT EXISTS GOLD;     -- verdicts, briefs, takedown drafts
CREATE SCHEMA IF NOT EXISTS OPS;      -- load log, email log, preferences, metrics

CREATE FILE FORMAT IF NOT EXISTS BRONZE.DG_JSON TYPE = JSON COMPRESSION = GZIP STRIP_OUTER_ARRAY = FALSE;
CREATE STAGE IF NOT EXISTS BRONZE.DG_STAGE FILE_FORMAT = BRONZE.DG_JSON;
