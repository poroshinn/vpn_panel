"""Unit-тесты пресетов и генерации конфигураций (MVP-06, FR-3.2.1, FR-3.4.2)."""

from __future__ import annotations

import base64

import pytest

from app.protocols.configs import (
    ConfigError,
    ConfigFormatError,
    build_client_conf,
    build_vpn_key,
    client_bundle,
    decode_vpn_key,
    render_qr_png,
    sanitize_raw_config,
)
from app.protocols.presets import (
    PresetError,
    get_preset,
    instance_key,
    list_presets,
    render_compose,
    validate_junk,
)

RAW_CONF = """\
[Interface]
PrivateKey = kK3kJ2vXyW8mSoJlUfTq0A0vQ3Pp4nRzZ1hBcDdEeFf=
Address = 10.8.1.2/32
DNS = 1.1.1.1
Jc = 4
S1 = 86
S2 = 119
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <b 0x00000000>

[Peer]
PublicKey = pQbLmNoPqRsTuVwXyZ0123456789abcdefghijkm=
Endpoint = 203.0.113.10:32897
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""


# --------------------------------------------------------------- presets


def test_preset_lookup_and_marketplace() -> None:
    preset = get_preset("awg-3x")
    assert preset.protocol == "awg"
    assert preset.supports_junk
    items = list_presets()
    assert {i["preset_id"] for i in items} >= {"awg-3x", "awg-2x", "awg-legacy", "wg"}


def test_unknown_preset() -> None:
    with pytest.raises(PresetError):
        get_preset("xray")


def test_instance_key_multi_instance() -> None:
    preset = get_preset("awg-2x")
    assert instance_key(preset, 1) == "awg2"
    assert instance_key(preset, 2) == "awg2__2"
    with pytest.raises(PresetError):
        instance_key(preset, 0)


def test_validate_junk() -> None:
    preset = get_preset("awg-3x")
    junk = validate_junk(preset, {"S1": "100"})
    assert junk["S1"] == "100"
    # неизвестный ключ отклоняется
    with pytest.raises(PresetError):
        validate_junk(preset, {"Evil": "1"})
    # WG не поддерживает junk
    wg = get_preset("wg")
    with pytest.raises(PresetError):
        validate_junk(wg, {"S1": "100"})
    # дефолты AWG подставляются автоматически
    assert validate_junk(preset, None)["Jc"] == "4"


def test_render_compose() -> None:
    preset = get_preset("awg-2x")
    compose = render_compose(preset, "awg2", port=32898, host="203.0.113.10")
    assert "container_name: awg2" in compose
    assert "32898:32898/udp" in compose
    # BBR в пресете без поддержки — ошибка
    with pytest.raises(PresetError):
        render_compose(preset, "awg2", port=1, host="h", bbr=True)
    # некорректный порт
    with pytest.raises(PresetError):
        render_compose(preset, "awg2", port=0, host="h")


# ---------------------------------------------------------------- configs


def test_sanitize_valid_and_invalid() -> None:
    assert sanitize_raw_config(RAW_CONF) == RAW_CONF
    with pytest.raises(ConfigFormatError):
        sanitize_raw_config("garbage without sections")
    with pytest.raises(ConfigFormatError):
        sanitize_raw_config("[Interface]\nPrivateKey = x=\n")  # нет [Peer]


def test_build_client_conf() -> None:
    conf = build_client_conf(RAW_CONF, instance="awg2")
    assert conf.startswith("# Amnezia Web Panel")
    assert "[Interface]" in conf and "[Peer]" in conf
    assert "PrivateKey = kK3kJ2vXyW8mSoJlUfTq0A0vQ3Pp4nRzZ1hBcDdEeFf=" in conf
    assert "Jc = 4" in conf  # junk-параметры AWG перенесены
    # опасные/неизвестные ключи не пробрасываются
    raw_bad = RAW_CONF + "Evil = drop\n"
    conf_bad = build_client_conf(raw_bad, instance="awg2")
    assert "Evil" not in conf_bad


def test_build_vpn_key_roundtrip() -> None:
    key = build_vpn_key(RAW_CONF, instance="awg2", host="203.0.113.10", port=32897)
    assert key.startswith("vpn://")
    data = decode_vpn_key(key)
    assert data["protocol"] == "awg"  # junk-параметры → AWG
    assert data["hostName"] == "203.0.113.10"
    assert data["containers"][0]["awg"]["config"]["S1"] == "86"
    assert data["clientConfig"]["interface"]["PrivateKey"].endswith("=")


def test_vpn_key_wg_protocol() -> None:
    raw = RAW_CONF.split("[Peer]")[0].replace(
        "Jc = 4\n", ""
    ).replace("S1 = 86\n", "").replace("S2 = 119\n", "")
    raw = raw.replace("H1 = 1\n", "").replace("H2 = 2\n", "").replace(
        "H3 = 3\n", ""
    ).replace("H4 = 4\n", "").replace("I1 = <b 0x00000000>\n", "")
    raw = raw + "[Peer]\nPublicKey = pQbLmNoPqRsTuVwXyZ0123456789abcdefghijkm=\n"
    key = build_vpn_key(raw, instance="wg", host="h", port=51820)
    assert decode_vpn_key(key)["protocol"] == "wg"


def test_decode_invalid_vpn_key() -> None:
    with pytest.raises(ConfigError):
        decode_vpn_key("not-vpn")
    with pytest.raises(ConfigError):
        decode_vpn_key("vpn://%%%invalid-base64%%%")


def test_render_qr_png() -> None:
    png = render_qr_png("vpn://test")
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    assert len(png) > 100


def test_client_bundle() -> None:
    preset = get_preset("awg-2x")
    bundle = client_bundle(
        RAW_CONF, instance="awg2", host="203.0.113.10", port=32897, preset=preset
    )
    assert set(bundle) == {"conf", "vpn_key", "qr_png_base64"}
    # QR — валидный PNG в base64
    png = base64.b64decode(bundle["qr_png_base64"])
    assert png.startswith(b"\x89PNG")
    # инстанс не соответствует пресету → ошибка
    with pytest.raises(ConfigError):
        client_bundle(RAW_CONF, instance="wg", host="h", port=1, preset=preset)
