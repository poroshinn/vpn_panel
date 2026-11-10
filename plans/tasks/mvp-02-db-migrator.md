# MVP-02: БД, мигратор, начальная схема

**Веха:** M1 · **FR:** FR-3.15.1, FR-3.15.5, FR-3.15.6 · **Статус:** ⬜ не начато

## Цель
Асинхронный слой SQLite (WAL, один writer через `asyncio.Lock`), встроенный мигратор
`schema_version` с pre-migrate снапшотом, миграция `0001_initial` с MVP-ядром схемы.

## Что сделать
1. `app/db/database.py` — aiosqlite-обёртка: WAL, транзакции, `asyncio.Lock` на запись,
   helper'ы `fetch_one/fetch_all/execute`; путь из `DB_FILE`.
2. `app/db/migrator.py` — упорядоченные миграции из `app/db/migrations/`; таблица
   `schema_version`; перед применением — снапшот БД в `backups/pre-migrate/`;
   только forward; сбой миграции ⇒ панель не стартует с понятной диагностикой.
3. `app/db/migrations/0001_initial.py` — таблицы (см. `docs/architecture.md` §3):
   `users`, `servers`, `user_connections`, `settings`, `api_tokens`, `audit_log`,
   `peer_creations`, `lifecycle_uncertain`, `accounting_recoveries`,
   `recovery_snapshots`, `schema_version`.
4. Все метки времени — UTC (TEXT ISO-8601 или INTEGER epoch).

## Тесты
- `tests/integration/test_migrator.py`: применение с нуля; idempotent-повтор не ломает;
  forward integrity check; pre-migrate снапшот создаётся.
- `tests/integration/test_db_locks.py`: конкурентная запись — без «database is locked».

## Вне скоупа шага
Репозитории/сервисы доменов (создаются в своих задачах), индексы под этапные фичи.

## Критерий приёмки
Старт панели применяет миграции автоматически; повторный старт — no-op; `pytest -q` зелёный.
