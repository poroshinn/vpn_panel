# MVP-01: Скелет проекта, конфиг, логгер

**Веха:** M1 · **FR:** FR-3.10.14, FR-3.15.2, FR-3.15.3 · **Статус:** ✅ выполнено (скелет создан заранее)

## Цель
Запускаемый FastAPI-скелет: конфигурация из env, структурированный текстовый логгер
с санитайзером и ротацией 7 дней, health-check, Docker-обвязка.

## Что сделать
1. `app/core/config.py` — pydantic-settings: `SECRET_KEY`, `PANEL_MASTER_KEY` (опционально
   на этом шаге, обязательность — в MVP-03), `DB_FILE`, `APP_PORT`, `LOG_LEVEL`,
   `LOG_DIR`, `BACKUP_DIR`.
2. `app/core/logging.py` — текстовые файлы `logs/panel-YYYY-MM-DD.log`, ретеншн 7 дней,
   **санитайзер** (фильтр, маскирующий секретоподобные паттерны: `password=`, токены,
   `PRIVATE KEY`).
3. `app/main.py` — FastAPI-фабрика, `/health` (живость + проверка БД), подключение
   статиков, lifespan: инициализация БД + применение миграций.
4. `Dockerfile`, `docker-compose.yml` (volume `amnezia_data`), `.env.example`.
5. `pyproject.toml` + `requirements.txt`.

## Тесты
- `tests/unit/test_logging_sanitizer.py`: санитайзер маскирует секреты; grep не находит.
- `tests/integration/test_health.py`: `GET /health` → 200; БД недоступна → 503.

## Вне скоупа шага
Аутентификация, роли, любые доменные модули, UI.

## Критерий приёмки
`uvicorn app.main:app` стартует; `/health` отвечает; лог пишется в файл с ротацией;
`pytest -q` зелёный.
