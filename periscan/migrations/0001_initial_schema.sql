-- 0001_initial_schema.sql
-- Core tables for periscan port monitoring.

CREATE TABLE hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address  TEXT NOT NULL UNIQUE,
    hostname    TEXT,
    label       TEXT,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE scan_jobs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type     TEXT NOT NULL CHECK(scan_type IN ('quick','full')),
    status        TEXT NOT NULL CHECK(status IN ('pending','running','completed','failed')),
    triggered_by  TEXT NOT NULL DEFAULT 'scheduler',
    started_at    TEXT,
    completed_at  TEXT,
    hosts_scanned INTEGER,
    ports_scanned TEXT,
    error_message TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE port_states (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port         INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    protocol     TEXT NOT NULL DEFAULT 'tcp' CHECK(protocol IN ('tcp','udp')),
    state        TEXT NOT NULL CHECK(state IN ('open','closed','filtered','unfiltered','open|filtered')),
    service_name TEXT,
    service_info TEXT,
    scan_job_id  INTEGER NOT NULL REFERENCES scan_jobs(id),
    last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE port_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port         INTEGER NOT NULL,
    protocol     TEXT NOT NULL DEFAULT 'tcp',
    state        TEXT NOT NULL,
    service_name TEXT,
    service_info TEXT,
    scan_job_id  INTEGER NOT NULL REFERENCES scan_jobs(id),
    observed_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX idx_port_history_host_port ON port_history(host_id, port, protocol, observed_at DESC);

CREATE TABLE change_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id          INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port             INTEGER NOT NULL,
    protocol         TEXT NOT NULL DEFAULT 'tcp',
    previous_state   TEXT,
    current_state    TEXT NOT NULL,
    previous_service TEXT,
    current_service  TEXT,
    scan_job_id      INTEGER NOT NULL REFERENCES scan_jobs(id),
    detected_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    notified         INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_change_events_host ON change_events(host_id, detected_at DESC);
CREATE INDEX idx_change_events_notified ON change_events(notified, detected_at);

CREATE TABLE notification_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    channel          TEXT NOT NULL,
    change_event_ids TEXT NOT NULL,
    status           TEXT NOT NULL CHECK(status IN ('sent','failed')),
    error_message    TEXT,
    sent_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
