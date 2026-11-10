"""Unit-тесты app/auth/sessions.py: подпись, сроки жизни, повреждение."""

from __future__ import annotations

import pytest

from app.auth.sessions import SessionData, SessionError


def _session() -> SessionData:
    return SessionData(user_id=1, username="admin", role="admin", must_change_password=False)


def test_token_roundtrip() -> None:
    tok = _session().to_token()
    restored = SessionData.from_token(tok)
    assert restored.user_id == 1
    assert restored.username == "admin"
    assert restored.role == "admin"


def test_tampered_signature_rejected() -> None:
    tok = _session().to_token()
    payload, sig = tok.split(".", 1)
    bad_sig = ("0" if sig[0] != "0" else "1") + sig[1:]
    with pytest.raises(SessionError):
        SessionData.from_token(f"{payload}.{bad_sig}")


def test_malformed_token_rejected() -> None:
    with pytest.raises(SessionError):
        SessionData.from_token("garbage-without-dot")


def test_absolute_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session()
    monkeypatch.setattr("app.core.config.get_settings", lambda: _settings(abs_ttl=100, idle_ttl=10**9))
    old = SessionData(
        user_id=session.user_id, username=session.username, role=session.role,
        issued_at=0, last_seen=1,
    )
    with pytest.raises(SessionError):
        SessionData.from_token(old.to_token())


def test_idle_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.core.config.get_settings", lambda: _settings(abs_ttl=10**9, idle_ttl=100))
    old = SessionData(user_id=1, username="admin", role="admin", issued_at=0, last_seen=10**8)
    with pytest.raises(SessionError):
        SessionData.from_token(old.to_token())


def _settings(abs_ttl: int, idle_ttl: int):
    from app.core.config import Settings

    s = Settings(secret_key="test-secret-key")
    s.session_abs_ttl_seconds = abs_ttl  # type: ignore[misc]
    s.session_idle_ttl_seconds = idle_ttl  # type: ignore[misc]
    return s
