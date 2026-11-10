"""Константы кодов ошибок API (правило 9 AGENTS.md)."""

from __future__ import annotations

# Аутентификация
NOT_AUTHENTICATED = "not_authenticated"
INVALID_SESSION = "invalid_session"
INVALID_CREDENTIALS = "invalid_username_or_password"
ACCOUNT_DISABLED = "account_disabled"
ROLE_NONE = "role_none"
LOGIN_DELAYED = "login_delayed"
IP_BLOCKED = "ip_blocked"
CAPTCHA_FAILED = "captcha_failed"
CAPTCHA_EXPIRED = "captcha_expired"
WEAK_PASSWORD = "weak_password"
PASSWORD_CHANGE_REQUIRED = "password_change_required"

# Авторизация
INSUFFICIENT_ROLE = "insufficient_role"

# Общие
NOT_FOUND = "not_found"
VALIDATION_ERROR = "validation_error"
INTERNAL_ERROR = "internal_error"
