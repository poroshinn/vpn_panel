"""Миграция 0002_accounting — учётные поля (MVP-07, FR-3.5.x).

``user_connections``: явные колонки учёта вместо JSON (нормальная структура
для агрегатов и индексов), хэш эпохи, lifetime-итоги, флаг верифицированности.
``users``: месяц последнего календарного сброса квоты (UTC).

Все добавления идемпотентны (мигратор может ретраить DDL после сбоя).
"""

MIGRATION_ID = 2
DESCRIPTION = "Accounting fields: epochs, baselines, lifetime totals, quota reset month"

SQL = """
ALTER TABLE user_connections ADD COLUMN epoch_hash TEXT;
ALTER TABLE user_connections ADD COLUMN rx_base INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_connections ADD COLUMN tx_base INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_connections ADD COLUMN lifetime_rx INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_connections ADD COLUMN lifetime_tx INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_connections ADD COLUMN last_sample_at TEXT;
ALTER TABLE user_connections ADD COLUMN counters_verified_final INTEGER NOT NULL DEFAULT 1;

ALTER TABLE users ADD COLUMN traffic_reset_month TEXT;

CREATE INDEX IF NOT EXISTS idx_connections_epoch ON user_connections(server_id, protocol);
CREATE INDEX IF NOT EXISTS idx_recoveries_conn ON accounting_recoveries(connection_id);
"""
