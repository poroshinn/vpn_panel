"""Генерация клиентских конфигураций (FR-3.4.2): ``.conf``, QR (PNG), ``vpn://``.

Вход — raw-конфиг peer'а с ноды (WG/AWG INI) + параметры инстанса из
``servers.protocols`` (junk-параметры AWG переносятся в [Interface]).
QR рендерится ``qrcode[pil]`` (зависимость уже в pyproject, ADR не требуется).
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

import qrcode
from qrcode.constants import ERROR_CORRECT_L

from app.protocols.presets import Preset, PresetError


class ConfigError(Exception):
    """Ошибка генерации конфигурации."""


class ConfigFormatError(ConfigError):
    def __init__(self) -> None:
        super().__init__("raw config is not a valid WG/AWG INI")


_ALLOWED_INTERFACE_KEYS = {
    "PrivateKey", "Address", "DNS", "Jc", "Jmin", "Jmax", "S1", "S2",
    "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5", "MTU",
}
_ALLOWED_PEER_KEYS = {
    "PublicKey", "PresharedKey", "AllowedIPs", "Endpoint",
    "PersistentKeepalive", "PresharedKeyDir",
}


def _parse_sections(raw: str) -> dict[str, dict[str, str]]:
    """Разбор INI-подобного конфига WG/AWG → секции с параметрами."""
    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip().lower()
            current = sections.setdefault(name, {})
            continue
        if current is None or "=" not in line:
            raise ConfigFormatError()
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not key:
            raise ConfigFormatError()
        current[key] = value
    if "interface" not in sections or "peer" not in sections:
        raise ConfigFormatError()
    return sections


def _filter_keys(section: dict[str, str], allowed: set[str]) -> list[tuple[str, str]]:
    out = []
    for key, value in section.items():
        if key in allowed:
            out.append((key, value))
    return out


def sanitize_raw_config(raw: str) -> str:
    """Проверка raw-конфига на корректный WG/AWG INI (без исполняемого содержимого)."""
    sections = _parse_sections(raw)
    if not sections["interface"].get("PrivateKey"):
        raise ConfigFormatError()
    if not sections["peer"].get("PublicKey"):
        raise ConfigFormatError()
    return raw


def build_client_conf(raw: str, *, instance: str) -> str:
    """Клиентский ``.conf`` из raw-конфига ноды (FR-3.4.2).

    Пробрасываются только известные безопасные ключи; [Peer] дополняется
    ``AllowedIPs = 0.0.0.0/0`` при отсутствии.
    """
    sections = _parse_sections(raw)
    iface = _filter_keys(sections["interface"], _ALLOWED_INTERFACE_KEYS)
    peer = _filter_keys(sections["peer"], _ALLOWED_PEER_KEYS)
    lines = [f"# Amnezia Web Panel — client config for {instance}", "[Interface]"]
    lines += [f"{k} = {v}" for k, v in iface]
    lines.append("")
    lines.append("[Peer]")
    peer_keys = {k: v for k, v in peer}
    if "AllowedIPs" not in peer_keys:
        peer.append(("AllowedIPs", "0.0.0.0/0"))
    lines += [f"{k} = {v}" for k, v in peer]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ vpn://

def build_vpn_key(raw: str, *, instance: str, host: str, port: int) -> str:
    """``vpn://``-ключ Amnezia (FR-3.4.2): base64(url-safe) от JSON-дескриптора.

    Формат — упрощённый MVP-дескриптор контейнера AWG/WG; Amnezia-клиент
    импортирует его как конфигурацию VPN.
    """
    sections = _parse_sections(raw)
    iface = dict(_filter_keys(sections["interface"], _ALLOWED_INTERFACE_KEYS))
    peer = dict(_filter_keys(sections["peer"], _ALLOWED_PEER_KEYS))
    peer.setdefault("Endpoint", f"{host}:{port}")

    protocol = "awg" if any(k.startswith(("Jc", "S1", "H1", "I1")) for k in iface) else "wg"
    descriptor = {
        "containers": [
            {
                "awg": {
                    "last_config": "",
                    "port_out": str(port),
                    "transport_proto": "udp",
                    "config": {
                        "H1": iface.get("H1", ""),
                        "H2": iface.get("H2", ""),
                        "H3": iface.get("H3", ""),
                        "H4": iface.get("H4", ""),
                        "I1": iface.get("I1", ""),
                        "I2": iface.get("I2", ""),
                        "I3": iface.get("I3", ""),
                        "I4": iface.get("I4", ""),
                        "I5": iface.get("I5", ""),
                        "Jc": iface.get("Jc", ""),
                        "Jmin": iface.get("Jmin", "40"),
                        "Jmax": iface.get("Jmax", "1000"),
                        "S1": iface.get("S1", ""),
                        "S2": iface.get("S2", ""),
                    } if protocol == "awg" else {},
                    "clientProtocol": protocol,
                },
                "container": f"{protocol}_{instance}",
            }
        ],
        "defaultContainer": f"{protocol}_{instance}",
        "description": instance,
        "hostName": host,
        "clientConfig": {
            "peer": peer,
            "interface": iface,
        },
        "protocol": protocol,
    }
    import json

    payload = json.dumps(descriptor, ensure_ascii=False, separators=(",", ":"))
    return "vpn://" + base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")


def decode_vpn_key(key: str) -> dict[str, Any]:
    """Обратная расшифровка ``vpn://`` (для тестов/отладки)."""
    if not key.startswith("vpn://"):
        raise ConfigError("not a vpn:// key")
    try:
        payload = base64.urlsafe_b64decode(key.removeprefix("vpn://").encode("ascii"))
        import json

        data = json.loads(payload.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise ConfigError("invalid vpn:// payload") from exc
    return data if isinstance(data, dict) else {}


# --------------------------------------------------------------------- QR

def render_qr_png(content: str) -> bytes:
    """PNG QR-кода содержимого (конфиг или vpn://) — FR-3.4.2."""
    import io

    qr = qrcode.QRCode(error_correction=ERROR_CORRECT_L, border=2, box_size=6)
    qr.add_data(content)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()


# ------------------------------------------------------------- фасад

def client_bundle(
    raw: str,
    *,
    instance: str,
    host: str,
    port: int,
    preset: Preset | None = None,
) -> dict[str, Any]:
    """Полный комплект выдачи (FR-3.4.2): conf, vpn://, QR (base64 PNG).

    Если ``preset`` передан, дополнительно валидируется соответствие протокола.
    """
    if preset is not None:
        try:
            expected = preset.container_base
        except PresetError as exc:  # pragma: no cover — preset всегда валиден
            raise ConfigError(str(exc)) from exc
        if not instance.startswith(expected):
            raise ConfigError("instance does not match preset")
    conf = build_client_conf(raw, instance=instance)
    vpn_key = build_vpn_key(raw, instance=instance, host=host, port=port)
    qr_b64 = base64.b64encode(render_qr_png(vpn_key)).decode("ascii")
    return {"conf": conf, "vpn_key": vpn_key, "qr_png_base64": qr_b64}
