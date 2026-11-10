"""Миграция 0001_initial — MVP-ядро схемы (ТЗ раздел 6).

Создаётся как исполняемый модуль на шаге MVP-02; пока — справочная SQL-раскладка.
Все метки времени — UTC (TEXT ISO-8601).
"""

MIGRATION_ID = 1
DESCRIPTION = "Initial MVP schema"

SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT,
    role                TEXT NOT NULL CHECK (role IN ('admin','support','user','none')),
    enabled             INTEGER NOT NULL DEFAULT 1,
    totp_secret_enc     TEXT,
    telegram_id         INTEGER,
    traffic_used        INTEGER NOT NULL DEFAULT 0,
    traffic_total       INTEGER,
    traffic_limit       INTEGER,
    expiration          TEXT,
    disable_reasons     TEXT NOT NULL DEFAULT '[]',
    share_token         TEXT UNIQUE,
    share_enabled       INTEGER NOT NULL DEFAULT 0,
    share_password_hash TEXT,
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS servers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    uid                 TEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL,
    host                TEXT NOT NULL,
    ssh_port            INTEGER NOT NULL DEFAULT 22,
    username            TEXT NOT NULL,
    password_enc        TEXT,
    private_key_enc     TEXT,
    protocols           TEXT NOT NULL DEFAULT '{}',
    self_service_enabled INTEGER NOT NULL DEFAULT 0,
    sort_order          INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_connections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id       INTEGER NOT NULL REFERENCES servers(id),
    protocol        TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    created_by      TEXT,
    created_source  TEXT NOT NULL DEFAULT 'panel',
    counters_json   TEXT NOT NULL DEFAULT '{}',
    baselines_json  TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    UNIQUE (server_id, protocol, client_id)
);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at  TEXT,
    revoked_at  TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    object      TEXT,
    ip          TEXT,
    result      TEXT NOT NULL DEFAULT 'ok',
    details     TEXT
);

CREATE TABLE IF NOT EXISTS peer_creations (
    operation_id    TEXT PRIMARY KEY,
    server_id       INTEGER NOT NULL,
    protocol        TEXT NOT NULL,
    client_id       TEXT,
    params_json     TEXT NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lifecycle_uncertain (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id    TEXT NOT NULL,
    server_id       INTEGER NOT NULL,
    protocol        TEXT NOT NULL,
    description     TEXT NOT NULL,
    resolved        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounting_recoveries (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id           INTEGER,
    tombstone_json          TEXT NOT NULL,
    counters_verified_final INTEGER NOT NULL DEFAULT 0,
    reason                  TEXT NOT NULL,
    created_at              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    path        TEXT NOT NULL,
    sha256      TEXT,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_connections_user ON user_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_connections_server ON user_connections(server_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""
