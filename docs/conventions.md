# Конвенции проекта

## 1. Python

- Python 3.11–3.13; полная типизация (`from __future__ import annotations` не требуется).
- Форматирование: `ruff format` + `ruff check` (line-length 100).
- Async: весь I/O (SSH, БД, файлы, HTTP) — только `async def`; блокирующие вызовы —
  через `asyncio.to_thread`.
- Именование: модули `snake_case`, классы `PascalCase`, константы `UPPER_SNAKE`.
- Один сервис = один файл в своём домене (`app/servers/service.py` и т.п.).
- Никаких глобальных мутируемых синглтонов без явной инициализации в `app.state`.

## 2. Работа с БД

- Доступ — только через `app/db/database.py` (aiosqlite, WAL, `asyncio.Lock` на запись).
- Транзакции: атомарные коммиты; fsync — для критичных операций (учёт, restore).
- Миграции — только forward, в `app/db/migrations/NNNN_description.py`; перед
  применением — pre-migrate снапшот в `backups/pre-migrate/`.
- Все метки времени — ISO-8601 UTC (`datetime.now(timezone.utc)`), хранение — TEXT UTC
  или INTEGER epoch; никогда — локальное время.

## 3. API

- Машины эндпоинты — под `/api/v1/`; HTML-страницы — корневые пути.
- Ошибки — единый JSON:
  ```json
  {"error_code": "quota_exhausted", "message": "human readable", "details": {}}
  ```
  Коды ошибок — `snake_case`, константы в `app/api/errors.py`.
- Аутентификация: cookie-сессия **или** `Authorization: Bearer awp_...`; авторизация —
  по матрице ролей (ТЗ §2.2, источник истины).
- Мутирующие браузерные запросы — same-origin метаданные; критичные — CSRF-nonce.
- Никогда не возвращать секреты (SSH-пароли/ключи, хэши, токены) в ответах — даже
  замаскированно, кроме однократного показа нового Bearer/share-токена.

## 4. Секреты и логирование

- Хэши: пароли — argon2id; Bearer/share-токены — SHA-256.
- Секреты серверов — AES-256-GCM (`app/core/security.py`), ключ `PANEL_MASTER_KEY`.
- Логгер: текстовые файлы `logs/panel-YYYY-MM-DD.log`, ретеншн 7 дней, **санитайзер на
  уровне логгера** (маскирует паттерны секретов). В лог запрещено: SSH-пароли/ключи,
  Bearer-токены, share-пароли, приватные ключи peers.
- Audit: таблица `audit_log` (90 дней) + зеркало `logs/audit-YYYY-MM-DD.log`.

## 5. Тестирование

- pytest; разметка: `tests/unit/`, `tests/integration/`, `tests/e2e/` (Playwright — позже).
- Фикстуры: временный `panel.db` на тест; fake-SSH для тестов сервисов (без реальных нод).
- Каждая задача из `plans/tasks/` несёт свои тесты; прогон перед закрытием шага:
  `pytest -q`.
- Тесты миграций: forward-применение + integrity check после.
- Тесты безопасности обязательны: no-echo секретов, rate-limit, матрица ролей.

## 6. Frontend

- Vanilla JS (ES-модули), без фреймворков и сборщиков; Jinja2-шаблоны.
- Живые данные — SSE (`EventSource`), fallback — polling.
- i18n: ключи в `app/i18n/{en,ru}.json`; fallback — английский; плурализация CLDR.
- Тема: тёмная/светлая; SVG-иконки; адаптивность.

## 7. Git и процесс

- Одна задача из `plans/tasks/` = один логический коммит (или несколько).
- После закрытия шага — обновить `plans/progress.md`.
- Новая зависимость — только с записью в `pyproject.toml` и ADR в `docs/decisions/`.
