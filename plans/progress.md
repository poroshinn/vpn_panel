# Журнал прогресса

> Обновлять после каждого шага разработки. Одна задача из `plans/tasks/` = один шаг.
> Следующий шаг — только после подтверждения пользователем.

## Этап 1 — MVP

| # | Задача | Веха | Статус | Дата | Заметки |
|---|---|---|---|---|---|
| 01 | [mvp-01-skeleton.md](tasks/mvp-01-skeleton.md) | M1 | ✅ done (скелет) | 2026-11-10 | Скелет проекта создан заранее; логгер/санитайзер уточнить при выполнении |
| 02 | [mvp-02-db-migrator.md](tasks/mvp-02-db-migrator.md) | M1 | ✅ done | 2026-11-10 | aiosqlite WAL + asyncio.Lock; мигратор forward-only с pre-migrate снапшотом (только для непустой БД); 15 тестов зелёные |
| 03 | [mvp-03-auth-roles.md](tasks/mvp-03-auth-roles.md) | M2 | ✅ done | 2026-11-10 | argon2id + AES-256-GCM (мастер-ключ автогенерируется в `data/master.key`); HMAC cookie-сессии (absolute/idle TTL); первый admin/admin с обязательной сменой пароля; brute-force прогрессия 30с×2^n на пару логин+IP, IP-блок на 20 неудач; CAPTCHA-стор с атомарным потреблением; require_role по матрице §2.2; инвалидация сессий на disable/role-change/none + logout-blacklist; audit_log (БД + зеркало `logs/audit-*.log`); 51 тест зелёный |
| 04 | [mvp-04-ssh-layer.md](tasks/mvp-04-ssh-layer.md) | M3 | ✅ done | 2026-11-10 | ADR-0002: Paramiko (всё через to_thread); пул с переиспользованием соединений и семафором каналов; TOFU known-hosts (файл 0600, mismatch → HostKeyMismatchError); circuit breaker (closed/open/half-open, 3 неудачи, 30с); пробы: TCP-ping (чистый asyncio), docker ps, статистика хоста единым bash-скриптом (JSON, частичный парсинг); секреты только enc, ошибки SSH нормализованы без секретов; 92 теста зелёных |
| 05 | [mvp-05-servers.md](tasks/mvp-05-servers.md) | M4 | ⬜ todo | — | |
| 06 | [mvp-06-protocols-peers.md](tasks/mvp-06-protocols-peers.md) | M5 | ⬜ todo | — | |
| 07 | [mvp-07-accounting.md](tasks/mvp-07-accounting.md) | M6 | ⬜ todo | — | |
| 08 | [mvp-08-users.md](tasks/mvp-08-users.md) | M7 | ⬜ todo | — | |
| 09 | [mvp-09-ui-sse-i18n.md](tasks/mvp-09-ui-sse-i18n.md) | M8 | ⬜ todo | — | |
| 10 | [mvp-10-sharing.md](tasks/mvp-10-sharing.md) | M9 | ⬜ todo | — | |
| 11 | [mvp-11-backups.md](tasks/mvp-11-backups.md) | M10 | ⬜ todo | — | |
| 12 | [mvp-12-api-tokens.md](tasks/mvp-12-api-tokens.md) | M11 | ⬜ todo | — | |
| 13 | [mvp-13-observability-alerts.md](tasks/mvp-13-observability-alerts.md) | M12 | ⬜ todo | — | Финал MVP: acceptance по разделу 8 ТЗ |

## Этапы 2–3

Задачи будут декомпозированы из `plans/roadmap.md` после закрытия MVP.

## Заметки

- 2026-11-10 — создан стартовый набор: документация, планы, скелет кода (MVP-01).
- 2026-11-10 — MVP-02: `Database` — WAL, busy_timeout, writer-lock, `transaction()`
  (атомарные коммит/откат); мигратор — валидация id (дубли/неположительные ⇒
  `MigrationError`), pre-migrate снапшот только для непустых БД, диагностика сбоя
  с указанием пути снапшота; conftest сбрасывает кэш `get_settings()` между тестами.
  Тесты: `tests/integration/test_migrator.py` (10), `tests/integration/test_db_locks.py` (5).
  Дымовой прогон: первый старт применяет v1, повторный — no-op.
- 2026-11-10 — MVP-03: security (argon2id, AES-256-GCM, автогенерация master key),
  сессии (HMAC-SHA256 cookie, TTL absolute/idle), auth-сервис (первый admin,
  brute-force прогрессия + IP-блок), CAPTCHA-стор (атомарное потребление),
  require_role/матрица §2.2, audit (БД + файл-зеркало), роутер `/api/auth/*` +
  страницы логина/смены пароля. Санитайзер логгера переписан на рендер итогового
  сообщения (не ломает %d-форматы httpx). 51 тест зелёный; дымовой прогон: логин
  admin/admin → must_change_password=true.
- 2026-11-10 — MVP-04: ADR-0002 принят (Paramiko поверх threading; asyncssh отклонён).
  Слой `app/ssh/`: `known_hosts.py` — TOFU-хранилище (`host:port`, SHA-256 отпечатки
  в формате OpenSSH, атомарная запись через tmp+replace, права 0600, first_seen
  сохраняется при повторном pin); `circuit_breaker.py` — closed/open/half-open с
  инъекцией часов для тестов, одна проба в half-open; `pool.py` — одно
  Paramiko-соединение на ноду, семафор exec-каналов (4), таймауты через
  `asyncio.wait_for`, расшифровка секретов только в момент connect, `SSHError`
  без секретов; `probes.py` — `probe_tcp_all` (параллельный asyncio-ping),
  `parse_host_stats` (JSON + флаг partial при недостающих ключах),
  `parse_docker_ps`, `NodeProber` (частичные результаты, изоляция ошибок нод).
  В config добавлены `ssh_breaker_reset_seconds`, `ssh_connect_timeout`,
  `ssh_command_timeout`. Тесты: unit (CB 10, парсеры 8, TOFU 8) + integration
  (mock paramiko-транспорта: пул, breaker, no-echo секретов, TOFU mismatch,
  параллельность проб). Итог: 92 теста зелёные, ruff чист.
