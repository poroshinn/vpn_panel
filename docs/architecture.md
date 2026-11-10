# Архитектура — Amnezia Web Panel

> Источник истины — ТЗ v1.2 (разделы 2, 6). Этот документ фиксирует технические
> решения по компоновке кода и данным. Изменения — через ADR в `docs/decisions/`.

## 1. Общая модель

**Один процесс панели** (FastAPI/uvicorn, один writer в SQLite). Панель — оркестратор:
на удалённых нодах ничего не хранит постоянно, работает по SSH (Paramiko/asyncssh)
с Docker-контейнерами протоколов.

```
┌───────────────────────────── Панель (один процесс) ─────────────────────────────┐
│                                                                                 │
│  web/ (Jinja2 + Vanilla JS + SSE)      api/ (/api/v1, Bearer + сессии)          │
│            │                                     │                              │
│  auth/ (сессии, роли, CAPTCHA, brute-force, токены)                              │
│            │                                                                    │
│  servers/ ── ssh/ (пул conn, known-hosts, circuit breaker, пробы) ──► ноды SSH   │
│      │                                                                           │
│  protocols/ (установка AWG/WG, peers, конфиги)                                   │
│      │                                                                           │
│  accounting/ (счётчики, эпохи, квоты, финализация)                               │
│      │                                                                           │
│  db/ (SQLite WAL, asyncio.Lock, мигратор)  ◄── backups/ (снапшоты, restore)      │
│                                                                                  │
│  core/ (config, security, logging+санитайзер, rate-limit) — используется всеми   │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## 2. Слои и модули

| Модуль | Ответственность | Ключевые FR |
|---|---|---|
| `app/core/` | config (env), security (argon2id, AES-256-GCM), logging (санитайзер, ротация 7 дней), rate-limit | NFR-2, FR-3.10.14, FR-3.1.13 |
| `app/db/` | aio-доступ SQLite (WAL), транзакции, мигратор `schema_version` + pre-migrate снапшот | FR-3.15.1, FR-3.15.5 |
| `app/auth/` | логин, подписанные cookie-сессии (abs 7д / idle 24ч), роли, CAPTCHA, brute-force, Bearer-токены (SHA-256), TOTP (opt) | FR-2.3 ТЗ §2.3 |
| `app/ssh/` | пул соединений, TOFU known-hosts (`ssh_known_hosts`), circuit breaker, параллельные пробы (ping, статусы, статистика хоста) | FR-3.1.5, FR-3.1.8, FR-3.1.9, FR-3.1.11 |
| `app/servers/` | CRUD серверов, uid, сортировка, онбординг/верификация, перезагрузка | FR-3.1.1–3.1.6 |
| `app/protocols/` | маркетплейс пресетов AWG/WG, мульти-инстансы (`awg2`, `awg2__2`), peers CRUD, конфиги `.conf`/QR/`vpn://` | FR-3.2.1–3.2.3, FR-3.4.x |
| `app/accounting/` | `wg show transfer`, эпохи (container ID/boot ID/ifindex/inode), базлайны, квоты (UTC), финализация, fail-closed | FR-3.5.x, FR-3.11.4 |
| `app/users/` | CRUD пользователей, роли, привязка подключений, инвалидация сессий/токенов | FR-3.6.x |
| `app/sharing/` | share-токены, страница `/share/{token}`, пароль на share | FR-3.8.x |
| `app/backups/` | SQLite-снапшоты, gzip, автобэкап в Telegram, in-panel restore с protected-профилем | FR-3.10.10, FR-3.11.1–3.11.4 |
| `app/api/` | роутеры `/api/v1`, единые ошибки `error_code`, Swagger/ReDoc | FR-3.12.x |
| `app/web/` | Jinja2-шаблоны, статика, SSE, i18n en/ru | FR-3.13.x, FR-3.14.x |

**Зависимости направлены вниз**: `api/web → services → ssh/db/core`. Слой `core` не
зависит ни от кого.

## 3. Схема данных (SQLite `panel.db`)

Полный перечень — ТЗ раздел 6. Миграция `0001_initial` создаёт MVP-ядро:

```
schema_version       — версия схемы + история миграций
users                — id, username, password_hash(argon2id), role, enabled, totp_secret_enc,
                       telegram_id, traffic_used/total/limit, expiration(UTC),
                       disable_reasons, share_token, share_enabled, share_password_hash
servers              — id, uid, name, host, ssh_port, username,
                       password_enc / private_key_enc (AES-256-GCM),
                       protocols (JSON: ключ_инстанса → {port, public_endpoint, ...}),
                       self_service_enabled, sort_order
user_connections     — id, user_id, server_id, protocol(ключ инстанса), client_id, name,
                       created_by, created_source, counters/baselines (учётные поля)
settings             — key-value (appearance, captcha, telegram, auto_backup, alerts, ...)
api_tokens           — id, name, token_hash(SHA-256), owner_id, expires_at, revoked_at
audit_log            — структурированные события, ретеншн 90 дней
peer_creations       — operation_id, параметры, статус (идемпотентность создания peer'ов)
lifecycle_uncertain  — неопределённые SSH-исходы (ограждение)
accounting_recoveries— tombstones, финализации, allow_unverified-факты
recovery_snapshots   — пред-restore/pre-migrate снапшоты + аудит
```

### Правила учёта трафика (fail-closed)

- каждое соединение с нодой сопровождается метаданными **эпохи** до и после чтения
  счётчиков: hash(container ID, start time, PID, host boot ID, ifindex, inode/ctime);
- смена эпохи или сброс счётчика ⇒ событие `traffic_accounting_gap`,
  `counters_verified_final=false`, итоги пользователя **не** обнуляются;
- базлайны и lifetime-итоги переживают перезапуск панели; календарный сброс квот — UTC.

## 4. Ключевые сквозные механизмы

- **Идемпотентность**: `operation_id` на создание peer'а и restore; ретрай того же ID
  безопасен (`peer_creations`, `recovery_snapshots`).
- **Lifecycle-lock**: взаимный exclude между созданием peer'а, восстановлением,
  raw-config-правкой и ownership-операциями (in-process `asyncio.Lock`).
- **Секреты**: шифрование at rest AES-256-GCM под `PANEL_MASTER_KEY`; расшифровка
  только в памяти; no-echo в API/логах/ошибках; санитайзер логгера.
- **SSE**: `/api/v1/events` — статусы серверов, прогресс операций, счётчики;
  polling — fallback.
- **Аудит**: гибрид — таблица `audit_log` (90 дней) + зеркало `logs/audit-YYYY-MM-DD.log`
  (7 дней).
- **Graceful degradation**: диск < порога ⇒ алерт; < аварийного ⇒ read-only для мутаций.

## 5. Развёртывание

- Docker Compose, volume `amnezia_data` (`panel.db`, `ssh_known_hosts`, `backups/`, `logs/`).
- Переменные: `SECRET_KEY`, `PANEL_MASTER_KEY` (генерируется при первом старте, если
  не задан, и сохраняется в volume), `DB_FILE`, `APP_PORT`.
- Миграции применяются автоматически при старте (после pre-migrate снапшота).
