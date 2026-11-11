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
| 05 | [mvp-05-servers.md](tasks/mvp-05-servers.md) | M4 | ✅ done | 2026-11-10 | Сервис `app/servers/service.py` (CRUD, стабильный uid, reorder, онбординг-верификация через SSH, reboot), API `/api/v1/servers` (роли §2.2, guard удаления, audit), страницы дашборда/сервера/мастера; 102 теста зелёных |
| 06 | [mvp-06-protocols-peers.md](tasks/mvp-06-protocols-peers.md) | M5 | ✅ done | 2026-11-10 | Пресеты (awg-3x/2x/legacy, wg; junk S1/S2/I1–I5, BBR, compose-шаблон), installer (мульти-инстансы `awg2__2`, идемпотентный compose up/down, неопределённые исходы → `lifecycle_uncertain`, 502), peers (operation_id-идемпотентность в `peer_creations`, ретрай с сохранённым client_id, lifecycle-lock на (server, instance), rename/enable/disable/delete, tombstone в `accounting_recoveries`), configs (.conf-санитайзер, QR PNG, vpn:// roundtrip), API `/presets`, `/servers/{id}/protocols`, `/servers/{id}/connections`, `/connections/{id}/config?format=conf|qr`; 124 теста зелёных |
| 07 | [mvp-07-accounting.md](tasks/mvp-07-accounting.md) | M6 | ✅ done | 2026-11-10 | Fail-closed учёт трафика: миграция 0002 (epoch_hash, базлайны rx/tx, lifetime, last_sample_at, counters_verified_final, traffic_reset_month); `app/accounting/` — epochs (SHA-256 хэш эпохи из container/PID/started/boot_id/ifindex/inode:ctime, парсер `awg show transfer`), collector (опрос метаданных до/после transfer, дедупликация владельцев алиасов), service (фоновый цикл 60с [30–300], базлайны переживают рестарт, gap-детекция epoch_changed/counter_reset → tombstone `accounting_recoveries` без обнуления итогов, квоты UTC + auto-disable `quota`, месячный сброс), finalization (FR-3.11.4: чтение счётчиков при отвязке, дельта + tombstone verified, fail-closed 409 can_force / allow_unverified); API `/api/v1/accounting`, `/users/{id}/accounting|quota`, `/accounting/reset-month`, `/servers/{id}/connections/{id}/finalize` (роли §2.2, audit); 147 тестов зелёных, ruff чист по новым файлам |
| 08 | [mvp-08-users.md](tasks/mvp-08-users.md) | M7 | ✅ done | 2026-11-11 | Пользователи панели: `app/users/service.py` (CRUD FR-3.6.1 — роль/пароль обязателен кроме none/telegram/квота/expiration, защита последнего admin), enable/disable одной кнопкой с автоинвалидацией FR-3.6.4 (сессии — сверка с БД на каждом запросе, Bearer-токены — hook `TokenRevocationHook` для MVP-11), привязка подключений FR-3.6.2 и отвязка владельца FR-3.6.3 (активный peer → stop на ноде + финализация; нечитаемый счётчик → 409 can_force / allow_unverified), экспорт подключений FR-3.6.5 (admin/support); API `/api/v1/users/...` (роли §2.2, audit-события user.created/updated/enabled/disabled/deleted, connection.assigned/unlinked, user.export); 7 integration-тестов (CRUD, мгновенная инвалидация сессии на disable и role=none, unlink через stop с verified-финализацией, fail-closed 409, матрица экспорта, audit); 154 теста зелёных, ruff чист по новым файлам |
| 09 | [mvp-09-ui-sse-i18n.md](tasks/mvp-09-ui-sse-i18n.md) | M8 | ✅ done | 2026-11-11 | i18n (en/ru, fallback en, CLDR-плурализация, cookie→Accept-Language→en); SSE /api/v1/events (EventHub, queue 256, дроп при переполнении, keep-alive 15с, retry 3с); дизайн-система (CSS-переменные, светлая/тёмная тема через cookie, мобильная tab-панель, base.html); страницы: дашборд (SSE+polling-fallback), сервер (ping/статистика), /my (свои подключения, conf/QR), настройки (вкладки: внешний вид, CAPTCHA/бэкапы/алерты — заглушки); noindex/no-follow meta на всех страницах + /robots.txt Disallow:/; статика с max-age; 193 теста зелёных, ruff чист |
| 10 | [mvp-10-sharing.md](tasks/mvp-10-sharing.md) | M9 | ⬜ todo | — | |
| 11 | [mvp-11-backups.md](tasks/mvp-11-backups.md) | M10 | ⬜ todo | — | |
| 12 | [mvp-12-api-tokens.md](tasks/mvp-12-api-tokens.md) | M11 | ⬜ todo | — | |
| 13 | [mvp-13-observability-alerts.md](tasks/mvp-13-observability-alerts.md) | M12 | ⬜ todo | — | Финал MVP: acceptance по разделу 8 ТЗ |

## Этапы 2–3

Задачи будут декомпозированы из `plans/roadmap.md` после закрытия MVP.

## Заметки

- 2026-11-11 — MVP-09: `app/i18n/catalog.py` (Catalog с fallback на en,
  CLDR-плурализация ru one/few/many, detect_locale: cookie `awp_lang` →
  Accept-Language → en; format_datetime_utc/format_bytes), ключи в
  `app/i18n/{en,ru}.json`. `app/web/sse.py` — EventHub (process-local
  pub/sub, asyncio.Queue maxsize=256, дроп при переполнении,Event.to_sse);
  `app/api/routes/events.py` — GET /api/v1/events (require_session,
  StreamingResponse, keep-alive каждые 15с, retry:3000,unsubscribe в finally).
  Дизайн-система: `app/web/static/panel.css` (CSS-переменные, [data-theme=dark],
  адаптив @media 640px — нижняя tab-панель вместо горизонтальной навигации),
  `app/web/static/sse.js` (EventSource + подключение именованных типов
  server.status/operation.progress/traffic.sample, fallback на polling после
  4 ошибок). `base.html` — общий каркас (навигация по роли, переключатель
  темы через cookie `awp_theme`, noindex/no-folloow meta). Страницы:
  dashboard.html (карточки, SSE-обновление ping с polling-фолбэком),
  server_detail.html (ping, host-stats, reboot для admin), my.html
  (таблица подключений пользователя + conf-скачивание/QR-модалка через
  /api/v1/.../config), settings.html (вкладки: внешний вид — язык/тема;
  CAPTCHA/бэкапы/алерты — заглушки «позже»). login.html/change_password.html
  переведены на base.html (skip_header). pages.py — _render() инжектит
  t/plural/fmt_dt/locale/theme во все шаблоны; /robots.txt; /static/* с
  Cache-Control: max-age=3600 (Cache-Control: no-store для SSE-ответа).
  Тесты: unit test_i18n.py (19: категории plural ru/en, fallback, детекция
  локали, форматирование) + test_sse_hub.py (8: подписка/publish/отписка/
  переполнение/мульти-подписчики/JSON-валидность/конкурентность) +
  integration test_ui_sse_i18n.py (12: SSE 401 без сессии, i18n ru-cookie/
  Accept-Language, /my только свои подключения + 302 аноним, 403 на чужой
  конфиг, robots.txt, noindex-мета, статика cache-policy, вкладки настроек).
  Отладка: httpx ASGITransport буферизует весь ответ — интеграционный тест
  чтения бесконечного SSE-потока зависал; поведение хаба покрыто unit-тестами,
  в integration оставлены только 401/auth/регистрация роута. Итог: 193 теста
  зелёных; ruff по затронутым файлам чист.

- 2026-11-11 — MVP-08: сервис `app/users/service.py` + API `app/api/routes/users.py`,
  подключены в `app/main.py` (`app.state.user_service`). Ключевые решения:
  (1) инвалидация FR-3.6.4 — сессии режутся уже существующей сверкой с БД в
  `app/auth/dependencies.py` (enabled/role/none), для Bearer-токенов заложен hook
  `TokenRevocationHook` (конструктор UserService), вызывается на disable, role=none
  и delete; (2) отвязка FR-3.6.3 — `unlink_owner` делегирует финализацию
  `FinalizationService.finalize_peer` (inject callable), перед этим best-effort
  `set_peer_enabled(stop)` для активного peer'а; внешний lifecycle-lock НЕ берётся
  (Lock не реентерабельный — вложенный `set_peer_enabled` на том же
  (server, instance) дал бы deadlock), каждая внутренняя операция держит свой lock;
  (3) unlink = завершение подключения с tombstone (схема user_id NOT NULL —
  «перепривязка» без финализации делает `assign_connection`). Отладка: 403 в
  тесте disable возникал из-за подмены cookie при логине u2 в том же клиенте —
  разделены два `AsyncClient`; вход при role=none — 400 `role_none` (по коду
  auth-сервиса). Вне скоупа: группы, self-service, share-setup, страницы
  «Пользователи» (UI — MVP-09).
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
- 2026-11-10 — MVP-05: `ServerService` — create (секреты AES-GCM at rest, автосортировка
  в конец), update (закрытие SSH-соединения при смене кредов), delete с guard'ом
  «сервер имеет подключения» (409, force=true убирает подключения явно — FK без
  CASCADE в схеме 0001), reorder по списку `uid`, `verify_server` (онбординг-скрипт:
  docker ps + /etc/passwd, детекция сохраняется в `servers.protocols`), `reboot_server`
  (shutdown -r, закрытие пула). API `/api/v1/servers`: list/get — admin+support,
  мутации — admin, ping/stats — admin+support, ошибки — единый JSON. Страницы:
  дашборд с polling ping-индикаторами, мастер `/servers/new` (create + verify),
  страница сервера (контейнеры, действия, статистика). Тесты (10 новых): CRUD/uid,
  guard, reorder персистентный, онбординг на mock-SSH, сбой верификации, матрица
  ролей, 401 аноним, audit create/delete. Итог: 102 теста зелёных; ruff по
  затронутым файлам чист (в pyproject добавлен ignore B008 — идиоматика FastAPI).
  Замечание: системный `python3` — 3.9, тесты запускать через `.venv/bin/python`.
- 2026-11-10 — MVP-06: `app/protocols/presets.py` — маркетплейс из 4 пресетов
  (awg-3x / awg-2x / awg-legacy / wg), junk-словарь AWG по умолчанию, валидация
  ключей, `instance_key` (мульти-инстансы `awg2__2`), render_compose (ports,
  cap_add NET_ADMIN, volume, BBR через sysctls). `installer.py` — установка
  через heredoc-запись compose + `docker compose up -d`, auto-slot для
  мульти-инстансов (учитывает и базовый ключ), guard одиночных протоколов;
  SSH-сбой/ненулевой exit → запись в `lifecycle_uncertain` + 502 (fail-closed).
  `peers.py` — операции в `peer_creations` (pending/done/failed/uncertain);
  идемпотентный ретрай повторяет сохранённый client_id (без дубликатов);
  lifecycle-lock (asyncio.Lock на (server_id, instance)) для create/rename/
  enable/disable/delete/raw-config; атомарные транзакции для записей
  user_connections; удаление пишет tombstone в `accounting_recoveries`
  (для MVP-07). `configs.py` — санитайзер raw-конфига (allow-list ключей
  WG/AWG), build_client_conf, vpn:// (base64 JSON-дескриптор Amnezia, roundtrip),
  QR PNG через qrcode[pil]. API: GET /api/v1/presets; POST/GET/DELETE
  /api/v1/servers/{id}/protocols; POST/GET /servers/{id}/connections;
  PATCH/DELETE /connections/{id}; enable/disable; GET /connections (свои);
  GET /connections/{id}/config (?format=conf|qr, доступ admin/support/владелец).
  Роли §2.2: мутации протоколов — admin; peers — admin+support; конфиги —
  владелец. Тесты: unit (12: пресеты, compose, conf/vpn://-roundtrip, QR) +
  integration (10: install/uninstall/мульти-инстансы/guard/uncertain,
  идемпотентность create/delete, ретрай после uncertain, параллельный rename,
  tombstone, audit, матрица ролей, endpoint конфига) на wildcard-mock SSH.
  Исправлено: slot-вычисление учитывало занятый базовый ключ; ретрай
  генерировал новый client_id; create_peer возвращал запись без id. Итог:
  124 теста зелёных; ruff по новым файлам чист (замечания в старых файлах —
  вне скоупа шага).
- 2026-11-10 — MVP-07: `app/accounting/` — `epochs.py` (парсер transfer-вывода
  с точными int RX/TX; EpochMeta + epoch_hash = SHA-256 конкатенации
  container_id/started_at/pid/boot_id/ifindex/socket_inode/socket_ctime;
  EPOCH_META_SCRIPT единым SSH-вызовом; частичный сбор допустим — появление/
  исчезновение компонента меняет хэш), `collector.py` (мета ДО → transfer →
  мета ПОСЛЕ; race → socket_ctime="raced"; параллельный обход нод; дедупликация
  владельцев одного физического peer'а по алиасам `awg2__2`→`awg2`), `service.py`
  (AccountingService: фоновый тик 60с, MIN=30/MAX=300, config `accounting_poll_interval`;
  первый семпл = только базлайн; delta = raw − base при совпадении эпохи;
  epoch_changed/counter_reset → `traffic_accounting_gap` + counters_verified_final=0,
  итоги НЕ обнуляются (правило 5); `_apply_quotas`: expiration + traffic_limit →
  disable_reasons с добавлением/снятием "quota", reconcile доступа через
  PeerService.set_peer_enabled best-effort; `monthly_reset` — UTC-ключ `%Y-%m`,
  идемпотентен, базлайны не трогает), `finalization.py` (finalize_peer: verified
  коммит дельты + tombstone reason='finalized'; счётчики нечитаемы →
  FinalizationError('counter_unreadable', can_force) → API 409; allow_unverified →
  tombstone без дельты reason='finalized_unverified'). API: сводка self/admin+support,
  quota/reset-month/finalize — admin, единый JSON ошибок, audit-события.
  Миграция 0002 (только forward). Тесты: unit (парсер/эпохи/дедупликация/месяцы) +
  integration (9: цикл опроса с базлайном и дельтой, gap при смене эпохи, gap при
  reset счётчиков, квота-автоотключение с reconcile, месячный сброс идемпотентный,
  финализация happy/unreadable/allow_unverified, базлайны переживают пересоздание
  сервиса, матрица ролей эндпоинтов). Отладка: причина «corrupted stdout» в моке —
  позиционная передача raw-строки в параметр rx хелпера set_transfer (мок-артефакт,
  не продуктовый баг); тесты мигратора переведены с жёсткой версии 1 на
  относительную проверку. Итог: 147 тестов зелёных; ruff по новым файлам чист.
