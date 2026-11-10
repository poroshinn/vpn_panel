# Amnezia Web Panel — веб-панель управления VPN-инфраструктурой

Аналог Amnezia Web Panel: управление удалёнными серверами Ubuntu по SSH
(Docker-контейнеры протоколов), учёт трафика и квот, роли, self-service, шеринг
конфигураций, бэкапы.

> Источник истины — **«Техническое задание — Amnezia Web Panel.md»** (v1.2).
> Контекст для ИИ-агентов — [`AGENTS.md`](AGENTS.md).

## Быстрый старт (dev)

```bash
# 1. Виртуальное окружение (Python 3.11–3.13)
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 2. Переменные окружения
cp .env.example .env
# заполните SECRET_KEY: .venv/bin/python -c "import secrets; print(secrets.token_urlsafe(48))"

# 3. Запуск
.venv/bin/uvicorn app.main:app --reload --port 8000
# миграции применяются автоматически при старте

# 4. Проверка
curl http://localhost:8000/health

# 5. Тесты
.venv/bin/pytest -q
```

## Docker

```bash
cp .env.example .env
docker compose up -d --build
```

Volume `amnezia_data` хранит `panel.db`, `ssh_known_hosts`, бэкапы и логи.

## Структура

```
app/            исходный код (см. AGENTS.md §4)
docs/           архитектура, конвенции, глоссарий, ADR
plans/          roadmap, атомарные задачи, журнал прогресса
tests/          pytest
```

## Пошаговая разработка с ИИ

1. Откройте [`plans/progress.md`](plans/progress.md) → возьмите первую задачу со
   статусом ⬜ → откройте её файл в [`plans/tasks/`](plans/tasks/).
2. Скармливайте агенту: `AGENTS.md` + файл задачи + при необходимости разделы ТЗ.
3. Агент выполняет задачу целиком (код + тесты) и обновляет `plans/progress.md`.
4. После вашего подтверждения — следующий шаг.

## Ключевые правила (кратко)

- UTC везде; секреты не покидают процесс; логи — текстовые файлы 7 дней с санитайзером;
  миграции только forward; идемпотентные мутации с `operation_id`; API-ошибки —
  единый JSON с `error_code`. Полный список — `AGENTS.md` §3.
