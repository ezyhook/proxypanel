"""AmneziaWG: kind amneziawg (wireproxy-awg), проверки конфига, компонент, configtest при apply."""
import asyncio
import re

import pytest

from conftest import PRIV, PUB
from test_updates import _tar

AWG_IFACE = f"[Interface]\nAddress = 10.8.1.2/32\nPrivateKey = {PRIV}\nJc = 4\nJmin = 40\nJmax = 70\n" \
            "S1 = 52\nS2 = 76\nH1 = 1820461437\nH2 = 512371092\nH3 = 1137802413\nH4 = 2063945151\n"
AWG_PEER = f"[Peer]\nPublicKey = {PUB}\nEndpoint = awg.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"


def err(app, text):
    with pytest.raises(app.ConfigError) as e:
        app.parse_config(text)
    return str(e.value)


@pytest.mark.parametrize("spec", ["kind: amneziawg", "kind: awg", "cmd: 'wireproxy-awg -c {config}'"])
def test_kind_and_default_cmd(app, write, spec):
    write("awg.conf", AWG_IFACE + AWG_PEER)
    t = app.parse_config(f"tunnels:\n  a: {{{spec}, port: 1088, http_port: 1188, config: awg.conf}}\n")["tunnels"]["a"]
    assert t["kind"] == "amneziawg" and t["cmd"] == "wireproxy-awg -c {config}"
    assert t["_http_mode"] == "wireproxy"  # HTTP-вход — сам клиент, без моста


def test_render_sets_ports_and_keeps_awg_params(app, write):
    write("awg.conf", AWG_IFACE + AWG_PEER)
    cfg = app.parse_config("tunnels:\n  a: {kind: amneziawg, port: 1088, http_port: 1188, config: awg.conf}\n")
    t = cfg["tunnels"]["a"]
    text = app.render_config("a", t, cfg)[app.config_out("a", t)]
    assert app.ini_values(text, "Socks5", "BindAddress") == ["127.0.0.1:1088"]
    assert app.ini_values(text, "http", "BindAddress") == ["127.0.0.1:1188"]
    assert app.ini_values(text, "Interface", "H4") == ["2063945151"]
    assert app.tunnel_cmd("a", t, cfg) == f"wireproxy-awg -c {app.RUN_DIR / 'a.conf'}"


def test_ports_from_file(app, write):
    write("awg.conf", AWG_IFACE + AWG_PEER + "[Socks5]\nBindAddress = 127.0.0.1:1099\n")
    t = app.parse_config("tunnels:\n  a: {kind: amneziawg, config: awg.conf}\n")["tunnels"]["a"]
    assert t["port"] == 1099 and t["_ports_from_file"] == ["port"]


def test_plain_wireproxy_with_awg_params_is_error(app, write):
    write("awg.conf", AWG_IFACE + AWG_PEER)
    assert "kind: amneziawg" in err(app, "tunnels:\n  a: {kind: wireproxy, port: 1083, config: awg.conf}\n")
    # то же через WGConfig = (экспорт awg-quick подключён к конфигу wireproxy)
    write("wp.conf", "WGConfig = awg.conf\n")
    assert "kind: amneziawg" in err(app, "tunnels:\n  a: {kind: wireproxy, port: 1083, config: wp.conf}\n")
    # закомментированные параметры — обычный WireGuard
    write("wg.conf", f"[Interface]\nPrivateKey = {PRIV}\n# Jc = 4\n" + AWG_PEER)
    app.parse_config("tunnels:\n  a: {kind: wireproxy, port: 1083, config: wg.conf}\n")


def test_obfuscator_rejected(app, write):
    write("awg.conf", AWG_IFACE + AWG_PEER)
    assert "obfuscator не нужен AmneziaWG" in err(
        app, "tunnels:\n  a: {kind: amneziawg, port: 1088, config: awg.conf, obfuscator: {key: k}}\n")


def test_via_hint_mentions_native(app, write):
    write("awg.conf", AWG_IFACE + AWG_PEER)
    e = err(app, "tunnels:\n  s: {port: 1081, cmd: 'ssh -N -D {port} h'}\n"
                 "  a: {kind: amneziawg, port: 1088, via: s, config: awg.conf}\n")
    assert "работает по UDP" in e


# ── компонент ──
def test_component_asset_and_archive_bin(app, tmp_path):
    comp = app.COMPONENTS["wireproxy-awg"]
    pat = re.compile(comp["asset"]["amd64"])
    assert [a for a in ["checksums.txt", "wireproxy_linux_amd64.tar.gz", "wireproxy_linux_386.tar.gz"]
            if pat.match(a)] == ["wireproxy_linux_amd64.tar.gz"]
    a = tmp_path / "wireproxy_linux_amd64.tar.gz"
    a.write_bytes(_tar({"wireproxy": b"AWG", "LICENSE": b"l"}))
    assert app._extract(a, a.name, comp["archive_bin"]) == b"AWG"
    assert comp["bin"] == "wireproxy-awg"  # в ~/main/bin рядом с обычным wireproxy, не вместо него


def test_affected_units_separate_from_wireproxy(app, write):
    write("awg.conf", AWG_IFACE + AWG_PEER)
    write("wg.conf", f"[Interface]\nPrivateKey = {PRIV}\n" + AWG_PEER)
    cfg = app.parse_config("tunnels:\n  a: {kind: amneziawg, port: 1088, config: awg.conf}\n"
                           "  w: {kind: wireproxy, port: 1083, config: wg.conf}\n")
    assert app.affected_units(cfg, "wireproxy-awg") == ["pp-a.service"]
    assert app.affected_units(cfg, "wireproxy") == ["pp-w.service"]


# ── configtest при apply ──
@pytest.fixture
def fake_awg(app, conf_dir, monkeypatch):
    """Подменный wireproxy-awg в BIN_DIR: на -n печатает то, что задано в FAKE_OUT, с кодом FAKE_RC."""
    calls = []

    async def sctl(*args):
        calls.append(args)
        return 0, "", ""

    async def no_units(units):
        return {}

    monkeypatch.setattr(app, "sctl", sctl)
    monkeypatch.setattr(app, "units_status", no_units)
    app.BIN_DIR.mkdir(parents=True, exist_ok=True)
    b = app.BIN_DIR / "wireproxy-awg"

    def set_result(rc: int, out: str) -> None:
        b.write_text(f"#!/bin/sh\necho '{out}' >&2\nexit {rc}\n")
        b.chmod(0o755)

    (app.UNIT_DIR / "pp-a.service").unlink(missing_ok=True)  # каждый тест — свежий unit
    (conf_dir / "awg.conf").write_text(AWG_IFACE + AWG_PEER)
    app.CONF_FILE.write_text("tunnels:\n  a: {kind: amneziawg, port: 41088, config: awg.conf}\n")
    yield set_result, calls
    b.unlink(missing_ok=True)


def test_apply_blocks_bad_awg_config(app, fake_awg):
    set_result, calls = fake_awg
    set_result(1, "2026/11/06 16:20:58 values of the H1-H4 fields must be unique")
    r = asyncio.run(app.apply_config())
    assert r["blocked"] == ["a"]
    assert any("values of the H1-H4 fields must be unique" in w and "2026/" not in w for w in r["warnings"])
    assert ("enable", "--now", "pp-a.service") not in calls  # заведомо плохой конфиг не запускаем


@pytest.mark.parametrize("rc,out", [(0, "Config OK"), (1, "lookup awg.example.com on 8.8.8.8:53: no such host")])
def test_apply_ok_or_no_dns_does_not_block(app, fake_awg, rc, out):
    set_result, calls = fake_awg
    set_result(rc, out)
    r = asyncio.run(app.apply_config())
    assert r["blocked"] == [] and ("enable", "--now", "pp-a.service") in calls
