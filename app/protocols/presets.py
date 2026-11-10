"""Пресеты установки протоколов (FR-3.2.1, FR-3.2.3) — «маркетплейс» шаблонов.

Пресет — декларативное описание установки протокола на ноде: docker-compose
шаблон, имя контейнера, порт, junk-параметры AWG (S1/S2/I1–I5), BBR.
Установка/удаление выполняется :mod:`app.protocols.installer` по SSH.

Ключ инстанса в ``servers.protocols``: ``awg``, ``awg2``, ``awg2__2`` (мульти-
инстансы, FR-3.2.2), ``wg``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Поддерживаемые протоколы MVP (Xray/Telemt — этап 2, FR-3.2.x)
PROTOCOL_AWG = "awg"
PROTOCOL_WG = "wg"


class PresetError(Exception):
    """Ошибка пресета (неизвестный протокол/некорректные параметры)."""


@dataclass(frozen=True)
class Preset:
    """Шаблон установки протокола-инстанса."""

    protocol: str                       # базовый протокол: awg | wg
    preset_id: str                      # идентификатор пресета в маркетплейсе
    title: str                          # человекочитаемое название
    image: str                          # docker-образ
    container_base: str                 # база ключа инстанса (awg2, wg)
    default_port: int
    supports_multi_instance: bool = True
    supports_junk: bool = False         # AWG junk S1/S2/I1–I5
    supports_bbr: bool = False
    description: str = ""
    # Стандартные junk-значения AmneziaWG (по умолчанию пресета awg2)
    default_junk: dict[str, str] = field(default_factory=dict)


AWG_JUNK_DEFAULTS = {
    "Jc": "4",
    "S1": "86",
    "S2": "119",
    "H1": "1",
    "H2": "2",
    "H3": "3",
    "H4": "4",
    "I1": "<b 0x00000000>",
    "I2": "<b 0x50000000>",
    "I3": "<b 0xa0000000>",
    "I4": "<b 0xe0000000>",
    "I5": "<b 0xf0000000>",
}

PRESETS: dict[str, Preset] = {
    p.preset_id: p
    for p in (
        Preset(
            protocol=PROTOCOL_AWG,
            preset_id="awg-3x",
            title="AmneziaWG 3.x",
            image="amnezia/awg:3.x",
            container_base="awg",
            default_port=32897,
            supports_junk=True,
            supports_bbr=True,
            default_junk=AWG_JUNK_DEFAULTS,
            description="AmneziaWG 3.x (современное ядро, junk-пакеты, BBR)",
        ),
        Preset(
            protocol=PROTOCOL_AWG,
            preset_id="awg-2x",
            title="AmneziaWG 2.0",
            image="amnezia/awg:2.0",
            container_base="awg2",
            default_port=32898,
            supports_junk=True,
            supports_bbr=False,
            default_junk=AWG_JUNK_DEFAULTS,
            description="AmneziaWG 2.0 (пользовательский бэкенд)",
        ),
        Preset(
            protocol=PROTOCOL_AWG,
            preset_id="awg-legacy",
            title="AmneziaWG legacy",
            image="amnezia/awg:legacy",
            container_base="awg1",
            default_port=32899,
            supports_junk=True,
            supports_bbr=False,
            description="AmneziaWG legacy (старые ядра)",
        ),
        Preset(
            protocol=PROTOCOL_WG,
            preset_id="wg",
            title="WireGuard",
            image="amnezia/wg",
            container_base="wg",
            default_port=443,
            supports_multi_instance=False,
            description="Классический WireGuard (один инстанс на ноду)",
        ),
    )
}


def get_preset(preset_id: str) -> Preset:
    """Пресет по идентификатору; неизвестный → :class:`PresetError`."""
    preset = PRESETS.get(preset_id)
    if preset is None:
        raise PresetError(f"unknown preset: {preset_id}")
    return preset


def list_presets() -> list[dict]:
    """Маркетплейс пресетов (для UI/API)."""
    return [
        {
            "preset_id": p.preset_id,
            "protocol": p.protocol,
            "title": p.title,
            "description": p.description,
            "default_port": p.default_port,
            "supports_multi_instance": p.supports_multi_instance,
            "supports_junk": p.supports_junk,
            "supports_bbr": p.supports_bbr,
        }
        for p in PRESETS.values()
    ]


def instance_key(preset: Preset, slot: int = 1) -> str:
    """Ключ инстанса: ``awg`` / ``awg2`` / ``awg2__2`` (FR-3.2.2).

    ``slot`` — порядковый номер инстанса протокола на ноде (1-based).
    """
    if slot < 1:
        raise PresetError("instance slot must be >= 1")
    base = preset.container_base
    return base if slot == 1 else f"{base}__{slot}"


def validate_junk(preset: Preset, junk: dict[str, str] | None) -> dict[str, str]:
    """Валидация junk-параметров (только известные ключи AWG)."""
    allowed = {"Jc", "S1", "S2", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"}
    if junk is None:
        return dict(preset.default_junk) if preset.supports_junk else {}
    if not preset.supports_junk and junk:
        raise PresetError(f"protocol {preset.protocol} does not support junk params")
    unknown = set(junk) - allowed
    if unknown:
        raise PresetError(f"unknown junk keys: {sorted(unknown)}")
    return dict(junk)


# ------------------------------------------------------------- compose-шаблон

COMPOSE_TEMPLATE = """\
services:
  {instance}:
    image: {image}
    container_name: {instance}
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    sysctls:
      - net.ipv4.ip_forward=1
    ports:
      - "{port}:{port}/udp"
    volumes:
      - {instance}_data:/etc/{instance}
    environment:
      - WG_HOST={host}
{bbr_env}\
    command: server
volumes:
  {instance}_data:
"""


def render_compose(
    preset: Preset,
    instance: str,
    *,
    port: int,
    host: str,
    bbr: bool = False,
) -> str:
    """docker-compose-файл для установки инстанса на ноду."""
    if port < 1 or port > 65535:
        raise PresetError(f"invalid port: {port}")
    bbr_env = ""
    if bbr:
        if not preset.supports_bbr:
            raise PresetError(f"preset {preset.preset_id} does not support BBR")
        bbr_env = (
            "    sysctls_extra:\n"
            "      - net.ipv4.tcp_congestion_control=bbr\n"
            "      - net.core.default_qdisc=fq\n"
        )
    return COMPOSE_TEMPLATE.format(
        instance=instance,
        image=preset.image,
        port=port,
        host=host,
        bbr_env=bbr_env,
    )
