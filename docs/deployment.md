# Развёртывание MVP на сервере

Инструкция по запуску Amnezia Web Panel на продакшн-сервере (Ubuntu 22.04/24.04).
Два варианта: **Docker Compose (рекомендуется)** и **bare-metal (venv + systemd)**.

---

## 1. Требования

| Компонент | Требование |
|---|---|
| ОС | Ubuntu 20.04+ (для bare-metal с Docker-нодами протоколов — Ubuntu с Docker) |
| Python | 3.11–3.13 (bare-metal) либо Docker 24+ / compose plugin (Docker-вариант) |
| RAM / диск | 512 МБ RAM, ≥1 ГБ свободного места на диске с БД (при <200 МБ включится алерт, при <50 МБ — read-only режим) |
| Сеть | Панель слушает `127.0.0.1:8000` (за reverse-proxy) или `0.0.0.0:8000` |

---

## 2. Переменные окружения

Скопируйте шаблон и заполните:

```bash
cp .env.example .env
```

| Переменная | Обязательна | Описание |
|---|---|---|
| `SECRET_KEY` | ✅ | Ключ подписи cookie-сессий. Сгенерировать: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `PANEL_MASTER_KEY` | ✅ (рекомендуется задать явно) | Мастер-ключ AES-256-GCM для шифрования SSH-секретов серверов. Если не задан — генерируется при первом старте и сохраняется в volume. **Не совпадать с `SECRET_KEY`. Потеря ключа = потеря доступа к серверам.** |
| `DB_FILE` | — | Путь к SQLite-БД (по умолч. `data/panel.db`; внутри контейнера — в volume) |
| `APP_PORT` | — | Порт панели (по умолч. `8000`) |
| `LOG_LEVEL` | — | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `LOG_DIR` / `BACKUP_DIR` | — | Каталоги логов и бэкапов (по умолч. `logs`, `backups`) |
| `LOG_RETENTION_DAYS` | — | Ретеншн логов, дней (по умолч. 7) |
| `RATE_LIMIT_API_PER_WINDOW` | — | Лимит запросов `/api/*` за окно (по умолч. 300/60с) |
| `HEALTH_ALLOWLIST` | — | CIDR-список IP, которым виден `/health` (по умолч. только loopback: `127.0.0.0/8,::1`). Для мониторинга извне добавьте IP: `127.0.0.0/8,::1,10.0.0.0/8` |

Токен Telegram-бота и chat_id для алертов **не задаются через env** — они
настраиваются в UI: Настройки → Алерты (хранятся в БД, никогда не возвращаются
в API-ответах).

---

## 3. Вариант A — Docker Compose (рекомендуется)

```bash
# 1. Клонировать репозиторий и зайти в каталог
git clone <repo-url> vpn_panel && cd vpn_panel

# 2. Настроить окружение
cp .env.example .env
# заполните SECRET_KEY (и PANEL_MASTER_KEY — см. §2)

# 3. Собрать и запустить
docker compose up -d --build

# 4. Проверить
docker compose logs -f panel
curl http://127.0.0.1:8000/health        # → {"status":"ok"} (только с самого сервера)
```

### Что где лежит

- **Volume `amnezia_data`** (`/app/data` в контейнере): `panel.db` (+WAL),
  сгенерированный мастер-ключ, `ssh_known_hosts`.
- **Bind-mount `./logs:/app/logs`** — текстовые логи `panel-YYYY-MM-DD.log`.
- **Bind-mount `./backups:/app/backups`** — снапшоты БД.

### Обновление

```bash
git pull
docker compose up -d --build
# миграции применяются автоматически при старте (forward-only, со снапшотом БД)
```

### Бэкап перед обновлением (вручную)

```bash
docker compose exec panel python -c "
import asyncio
from app.db.database import Database
from app.backups.snapshot import create_snapshot
async def main():
    db = Database()
    await db.connect()
    print(await create_snapshot(db))
    await db.close()
asyncio.run(main())
"
```

Либо через UI/API после запуска: `POST /api/v1/snapshot` (admin).

---

## 4. Вариант B — Bare-metal (venv + systemd)

```bash
# 1. Системные пакеты
sudo apt update && sudo apt install -y python3.12 python3.12-venv git

# 2. Код и окружение (отдельный пользователь — хорошая практика)
sudo useradd -m -s /bin/bash panel
sudo -iu panel
git clone <repo-url> vpn_panel && cd vpn_panel
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 3. Окружение
cp .env.example .env
# заполните SECRET_KEY и PANEL_MASTER_KEY

# 4. Первый запуск вручную (проверка)
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
# миграции применяются автоматически; Ctrl+C после проверки /health
```

### systemd-юнит

`/etc/systemd/system/vpn-panel.service`:

```ini
[Unit]
Description=Amnezia Web Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=panel
Group=panel
WorkingDirectory=/home/panel/vpn_panel
EnvironmentFile=/home/panel/vpn_panel/.env
ExecStart=/home/panel/vpn_panel/.venv/bin/uvicorn app.main:app \
    --host 127.0.0.1 --port 8000 \
    --workers 1
Restart=on-failure
RestartSec=5
# Железное правило: один процесс панели (SQLite — один writer)
# Никогда не увеличивайте --workers

[Install]
WantedBy=multi-user.target
```

> **Важно:** `EnvironmentFile` в systemd не поддерживает экспортируемый
> `KEY=value`-синтаксис pydantic полностью — при проблемах задайте переменные
> через `Environment=` либо используйте `EnvironmentFile` с простыми
> `KEY=value`-строками (как в `.env.example` — это совместимо).

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-panel
sudo systemctl status vpn-panel
curl http://127.0.0.1:8000/health
```

---

## 5. Reverse-proxy и HTTPS (nginx)

Панель сама не терминирует TLS. Поставьте nginx + certbot:

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

`/etc/nginx/sites-available/vpn-panel`:

```nginx
server {
    listen 80;
    server_name panel.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # SSE (FR-3.13.11): отключить буферизацию и держать соединение
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 24h;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }

    client_max_body_size 20m;   # загрузка файлов бэкапов при restore
}
```

```bash
sudo ln -s /etc/nginx/sites-available/vpn-panel /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d panel.example.com   # HTTPS автоматически
```

После включения HTTPS:

- сессии уходят только по secure-cookie — заходите по `https://`;
- в **Настройки → Алерты** укажите `alert_ssl_cert_path` — путь к
  fullchain-сертификату на хосте панели (например, `data/fullchain.pem`
  в volume при Docker — скопируйте или смонтируйте), монитор раз в минуту
  предупредит о истечении за 14 дней;
- для мониторинга `/health` извне добавьте IP мониторинга в `HEALTH_ALLOWLIST`
  в `.env` и перезапустите панель.

---

## 5.1. Доступ с внешнего интернета

Панель по умолчанию слушает `127.0.0.1:8000` (bare-metal) — извне недоступна.
Варианты:

**Вариант 1 — домен + nginx (рекомендуется, см. §5):**
направьте DNS A-запись домена (`panel.example.com`) на публичный IP сервера,
настройте nginx + certbot по §5. Панель станет доступна по
`https://panel.example.com`. Это единственный вариант с нормальным HTTPS.

**Вариант 2 — открыть порт напрямую (без reverse-proxy):**

```bash
# bare-metal: слушать все интерфейсы
ExecStart=... uvicorn app.main:app --host 0.0.0.0 --port 8000
# (или в systemd: EnvironmentFile задаёт APP_PORT; хост меняется в юните)

# docker-compose уже публикует порт наружу: "${APP_PORT:-8000}:8000"
```

⚠️ Без nginx TLS-терминации нет — логин и cookie-сессии пойдут по HTTP.
Допустимо только для теста или если TLS терминирует что-то перед панелью
(Cloudflare и т.п.). Обязательно смените пароль admin и включите CAPTCHA
(Настройки → CAPTCHA).

**Вариант 3 — Cloudflare Tunnel (без открытых портов):**

```bash
cloudflared tunnel --url http://127.0.0.1:8000
```

Не требует пробрасывать порты на роутере/фаерволе; на платном плане Cloudflare
даёт HTTPS.

**Вариант 4 — разовый доступ через SSH-туннель (для отладки):**

```bash
ssh -L 8000:127.0.0.1:8000 user@server-ip
# затем в браузере: http://localhost:8000
```

Проверка с внешней машины: `curl http://<server-ip>:8000/health` — вернёт 404,
пока ваш IP не добавлен в `HEALTH_ALLOWLIST` (это норма, §8.8 ТЗ; сама панель
при этом доступна).

## 6. Первый вход

1. Откройте `https://panel.example.com/`.
2. Войдите со стартовой учёткой **admin / admin** —
   панель принудительно потребует сменить пароль
   (`must_change_password`, [`change_password.html`](app/web/templates/change_password.html:1)).
3. Смените пароль на сильный. Дальнейшие пользователи создаются
   admin'ом в разделе Пользователи.

---

## 7. Настройка алертов Telegram (FR-3.10.13)

1. Создайте бота у [@BotFather](https://t.me/BotFather) → получите токен.
2. Узнайте `chat_id` (например, через [@userinfobot](https://t.me/userinfobot)
   или написав боту и проверив `getUpdates`).
3. UI → **Настройки → Алерты** (admin): введите токен и chat_id → Сохранить →
   **Тест** (придёт контрольное сообщение; ошибка доставки → HTTP 502).
4. Включите нужные тумблеры:
   - `server_down` — нода недоступна по TCP N минут (по умолч. 5);
   - `quota_exhausted` — исчерпание квоты;
   - `ssl_expiry` — истечение TLS-сертификата панели ≤14 дней;
   - `backup_failed` — провал автобэкапа в Telegram;
   - `accounting_gap` — не чаще 1 раза/час при разрывах учёта трафика.
5. Повторные алерты одного типа дедуплицируются (≤1/час), чтобы не спамить.

---

## 8. Мониторинг и обслуживание

- **`GET /health`** — живость процесса и БД (`503`, если БД недоступна);
  для посторонних IP — `404` (эндпоинт скрыт, ТЗ §8.8). Управляется
  `HEALTH_ALLOWLIST`.
- **`GET /api/v1/system/status`** (admin, Bearer-токен API или сессия) —
  uptime, версия схемы, размер БД, статус фоновых задач.
- **Настройки → Диск** (`GET /api/v1/settings/disk`) — свободное место;
  при `<200 МБ` — Telegram-алерт, при `<50 МБ` — панель уходит в read-only
  (запись в БД блокируется с ошибкой `disk_full_read_only`).
- **Логи**: `logs/panel-YYYY-MM-DD.log`, хранятся 7 дней, секреты
  санитизируются на уровне логгера.
- **Бэкапы**: UI → Настройки → Бэкапы; автобэкап в Telegram настраивается
  там же (ежедневно в заданное время, FR-3.10.10). Снапшоты перед каждой
  миграцией создаются автоматически.

### Обновление bare-metal

```bash
sudo -iu panel && cd vpn_panel
git pull
.venv/bin/pip install -r requirements.txt
sudo systemctl restart vpn-panel
```

---

## 9. Checklist готовности к продакшн

- [ ] `SECRET_KEY` сгенерирован, не `change-me`
- [ ] `PANEL_MASTER_KEY` задан и сохранён в менеджере секретов (потеря = потеря SSH-секретов)
- [ ] Пароль стартового `admin` сменён
- [ ] HTTPS включён (nginx + certbot), HTTP → HTTPS редирект
- [ ] `/health` доступен только с allowlist-адресов
- [ ] Каталог с БД и `backups/` включены в регулярный бэкап (или настроен автобэкап в Telegram)
- [ ] Telegram-алерты настроены и «Тест» прошёл
- [ ] `systemctl`/`docker compose` — авторестарт (`restart: unless-stopped` / `Restart=on-failure`)
- [ ] Ровно **один** экземпляр панели работает с этой БД (один writer SQLite)
