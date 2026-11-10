# MVP-06: Протоколы AWG/WG — установка и peers

**Веха:** M5 · **FR:** FR-3.2.1–3.2.3, FR-3.4.1–3.4.4, FR-3.4.8 · **Статус:** ✅ выполнено (2026-11-10)

## Цель
Маркетплейс пресетов AWG/WG, мульти-инстансы, полный CRUD peers с идемпотентными
операциями, выдача конфигураций (.conf, QR, vpn://).

## Что сделать
1. `app/protocols/presets/` — пресеты установки AWG (3.x/2.0/legacy: порт, junk S1/S2/
   I1–I5, BBR) и WG; docker-compose-шаблоны для ноды.
2. `app/protocols/installer.py` — установка/удаление инстанса через SSH+Docker;
   мульти-инстансы (`awg2`, `awg2__2`); ключ инстанса = протокол-ключ в `servers.protocols`.
3. `app/protocols/peers.py`:
   - CRUD peer'а (создание/переименование/enable/disable/удаление);
   - **идемпотентность**: `operation_id` в `peer_creations`; ретрай после неопределённого
     SSH-исхода безопасен; неопределённые исходы → `lifecycle_uncertain`;
   - **lifecycle-lock**: `asyncio.Lock` между созданием/удалением/raw-config/ownership;
   - атомарная запись таблиц клиентов (FR-3.4.8).
4. `app/protocols/configs.py` — генерация `.conf`, QR (PNG), `vpn://`-ключ Amnezia.
5. API `/api/v1/servers/{id}/protocols/...`, `/api/v1/connections/...`.

## Тесты
- unit: генерация .conf/QR/vpn:// (fixture-ключи); пресеты.
- integration: создание peer'а на mock-ноде; повтор того же `operation_id` не создаёт
  дубликат; неопределённый SSH-исход → запись в `lifecycle_uncertain`, ретрай разрешён;
  rename без гонок (параллельные запросы); audit-события.

## Вне скоупа шага
Учёт трафика (MVP-07), Xray/Telemt (этап 2), UI-страницы (MVP-08 — каркас уже есть).

## Критерий приёмка
Пресет ставится/удаляется на mock-ноде; peer создаётся идемпотентно; конфиги/QR отдаются;
`pytest -q` зелёный.
