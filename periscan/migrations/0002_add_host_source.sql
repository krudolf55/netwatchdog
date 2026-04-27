-- 0002_add_host_source.sql
-- Track whether a host was added via config file or CLI.
-- 'config' = defined in YAML, 'cli' = added manually.

ALTER TABLE hosts ADD COLUMN source TEXT NOT NULL DEFAULT 'cli';
