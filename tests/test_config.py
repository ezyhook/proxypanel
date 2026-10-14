"""Разбор и проверка proxies.yaml."""
import json

import pytest

from conftest import PRIV, PSK, PUB


def parse(app, text):
    return app.parse_config(text)


def err(app, text):
    with pytest.raises(app.ConfigError) as e:
        app.parse_config(text)
    return str(e.value)


def test_empty_config_is_valid(app):
    cfg = parse(app, "")
    assert cfg["tunnels"] == {}
    assert cfg["singbox"]["enabled"] is False  # комбинатор — опция


def test_simple_ssh_tunnel(app):
    cfg = parse(app, "tunnels:\n  vps: {port: 1081, cmd: 'autossh -M 0 -N -D 127.0.0.1:{port} host'}\n")
    t = cfg["tunnels"]["vps"]
    assert t["exit"] and t["kind"] == "autossh" and not t["native"]


@pytest.mark.parametrize("name", ["Bad", "x" * 41, "a.b", "singbox", "panel", "x-obfs", "x-http", "-x"])
def test_bad_tunnel_names(app, name):
    assert "недопустимое имя" in err(app, f"tunnels:\n  '{name}': {{port: 1081, cmd: x}}\n")


@pytest.mark.parametrize("port", ["true", "0", "70000", "'1081'"])
def test_bad_ports(app, port):
    assert "неверный port" in err(app, f"tunnels:\n  a: {{port: {port}, cmd: x}}\n")


def test_duplicate_ports_and_panel_port(app):
    assert "уже занят" in err(app, "tunnels:\n  a: {port: 1081, cmd: x}\n  b: {port: 1081, cmd: y}\n")
    assert "уже занят (панель)" in err(app, "tunnels:\n  a: {port: 8800, cmd: x}\n")


def test_panel_listen_must_be_loopback(app):
    assert "panel.listen" in err(app, "panel: {listen: 0.0.0.0}\n")
    parse(app, "panel: {listen: localhost}\n")


@pytest.mark.parametrize("snippet,msg", [
    ("health: {interval: 0}", "health.interval"),
    ("health: {timeout: fast}", "health.timeout"),
    ("notify: {fail_threshold: 1.5}", "notify.fail_threshold"),
    ("updates: {check_interval_h: -1}", "updates.check_interval_h"),
])
def test_numeric_settings(app, snippet, msg):
    assert msg in err(app, snippet + "\n")


def test_field_types(app):
    assert "requires — список" in err(app, "tunnels:\n  a: {port: 1081, cmd: x, requires: b}\n")
    assert "restart_sec" in err(app, "tunnels:\n  a: {port: 1081, cmd: x, restart_sec: soon}\n")
    assert "в одну строку" in err(app, 'tunnels:\n  a: {port: 1081, cmd: x, description: "a\\nExecStartPre=evil"}\n')


def test_requires_and_via_references(app):
    assert "неизвестный" in err(app, "tunnels:\n  a: {port: 1081, cmd: x, requires: [nope]}\n")
    assert "цикл в via" in err(app, "tunnels:\n  a: {port: 1081, via: b, cmd: ssh h}\n  b: {port: 1082, via: a, cmd: ssh h}\n")
    assert "только с комбинатором" in err(
        app, "tunnels:\n  a: {port: 1081, cmd: ssh h}\n  b: {port: 1082, via: g, outbound: {type: direct}}\n"
             "groups:\n  g: {type: urltest, members: [a], port: 1090}\n")


def test_via_hysteria_over_ssh_is_rejected_with_hint(app):
    msg = err(app, "tunnels:\n  a: {port: 1081, cmd: ssh -N -D 1081 h}\n"
                   "  b: {port: 1082, kind: hysteria2, via: a, cmd: hysteria client -c x.yaml}\n")
    assert "UDP" in msg and "native" in msg


def test_udp_native_over_ssh_warns(app):
    cfg = parse(app, "tunnels:\n  a: {port: 1081, cmd: ssh -N -D 1081 h}\n"
                     "  b: {port: 1082, via: a, outbound: {type: hysteria2, server: x, server_port: 1, password: p}}\n")
    assert any("UDP" in w for w in cfg["_warnings"])


# ── sing-box: inline, JSON-объект, полный JSON ──
def test_singbox_inline_kind(app):
    cfg = parse(app, "tunnels:\n  s: {kind: sing-box, port: 1091, outbound: {type: socks, server: a, server_port: 1}}\n")
    t = cfg["tunnels"]["s"]
    assert t["native"] and t["kind"] == "sing-box" and t["_proto"] == "socks"
    assert "kind: sing-box" in err(app, "tunnels:\n  s: {kind: wireproxy, port: 1, outbound: {type: direct}}\n")
    assert "нужен port" in err(app, "tunnels:\n  s: {outbound: {type: direct}}\n")
    assert "tag/detour" in err(app, "tunnels:\n  s: {port: 1091, outbound: {type: direct, tag: x}}\n")


def test_singbox_json_object_becomes_native(app, write):
    write("o.json", json.dumps({"type": "vless", "tag": "proxy", "server": "a", "server_port": 443}))
    cfg = parse(app, "tunnels:\n  s: {port: 1092, config: o.json}\n")  # kind не указан — поймёт по .json
    t = cfg["tunnels"]["s"]
    assert t["native"] and t["outbound"]["type"] == "vless" and "tag" not in t["outbound"]
    assert t["_native_file"].endswith("o.json")


def test_singbox_json_endpoint_and_full_config(app, write):
    write("wg.json", json.dumps({"type": "wireguard", "address": ["10.0.0.2/32"], "private_key": PRIV,
                                 "peers": [{"address": "1.2.3.4", "port": 51820, "public_key": PUB}]}))
    write("full.json", json.dumps({"inbounds": [{"type": "mixed", "listen_port": 7777}],
                                   "outbounds": [{"type": "direct", "tag": "d"}]}))
    cfg = parse(app, "tunnels:\n  w: {kind: sing-box, port: 1093, config: wg.json}\n"
                     "  f: {kind: sing-box, config: full.json}\n")
    assert "endpoint" in cfg["tunnels"]["w"]
    f = cfg["tunnels"]["f"]
    assert f["_sb_full"] and f["port"] == 7777 and f["_ports_from_file"] == ["port"]


def test_singbox_json_errors(app, write):
    write("bad.json", '{"type": "socks" "server": 1}')
    write("arr.json", "[1, 2]")
    assert "строка 1" in err(app, "tunnels:\n  s: {kind: sing-box, port: 1, config: bad.json}\n")
    assert "ни объект" in err(app, "tunnels:\n  s: {kind: sing-box, port: 1, config: arr.json}\n")
    assert "не оба" in err(app, "tunnels:\n  s: {kind: sing-box, port: 1, config: arr.json, outbound: {type: direct}}\n")


# ── порты из файла клиента ──
def test_wireproxy_ports_from_file(app, write):
    write("wp.conf", "[Interface]\nAddress = 10.0.0.2/32\n[Socks5]\nBindAddress = 127.0.0.1:1101\n"
                     "[http]\nBindAddress = 127.0.0.1:1201\n")
    t = parse(app, "tunnels:\n  w: {kind: wireproxy, config: wp.conf}\n")["tunnels"]["w"]
    assert (t["port"], t["http_port"], t["_http_mode"]) == (1101, 1201, "wireproxy")


def test_ports_differ_warns_and_yaml_wins(app, write):
    write("hy.yaml", "server: x:443\nsocks5:\n  listen: 127.0.0.1:1102\n")
    cfg = parse(app, "tunnels:\n  h: {kind: hysteria2, port: 1103, config: hy.yaml}\n")
    assert cfg["tunnels"]["h"]["port"] == 1103
    assert any("1103" in w and "1102" in w for w in cfg["_warnings"])


def test_missing_config_file(app):
    assert "не читается config" in err(app, "tunnels:\n  h: {kind: hysteria2, port: 1, config: nope.yaml}\n")


# ── WireGuard: wg-quick стиль и PSK ──
def test_wireguard_wgquick_aliases(app):
    cfg = parse(app, f"""tunnels:
  w:
    port: 1094
    endpoint:
      type: wireguard
      Address: 10.0.0.2/32, fd00::2/128
      PrivateKey: {PRIV}
      peers:
        - PublicKey: {PUB}
          PresharedKey: {PSK}
          Endpoint: vps.example.com:51820
          AllowedIPs: 0.0.0.0/0, ::/0
          PersistentKeepalive: 25
""")
    ep = cfg["tunnels"]["w"]["endpoint"]
    p = ep["peers"][0]
    assert ep["address"] == ["10.0.0.2/32", "fd00::2/128"] and ep["private_key"] == PRIV
    assert p == {"public_key": PUB, "pre_shared_key": PSK, "address": "vps.example.com", "port": 51820,
                 "allowed_ips": ["0.0.0.0/0", "::/0"], "persistent_keepalive_interval": 25}


def test_psk_validation_and_duplicates(app):
    base = f"tunnels:\n  w:\n    port: 1094\n    endpoint:\n      type: wireguard\n      private_key: {PRIV}\n      peers:\n"
    assert "44 символа" in err(app, base + f"        - {{public_key: {PUB}, psk: short}}\n")
    assert "оставьте одно" in err(app, base + f"        - {{public_key: {PUB}, psk: {PSK}, pre_shared_key: {PSK}}}\n")


# ── обфускатор ──
def test_obfuscator_wraps_wireguard_only(app, write):
    write("wp.conf", "[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = vps:19999\n")
    cfg = parse(app, "tunnels:\n  w: {kind: wireproxy, port: 1083, config: wp.conf, obfuscator: {key: k}}\n")
    t = cfg["tunnels"]["w"]
    assert t["_obfs_target"] == "vps:19999" and t["_obfs_port"] == app.OBFS_PORT_BASE
    assert "только WireGuard" in err(app, "tunnels:\n  s: {port: 1, outbound: {type: socks, server: a, server_port: 1}, "
                                          "obfuscator: {key: k}}\n")
    assert "неизвестные ключи" in err(app, "tunnels:\n  w: {kind: wireproxy, port: 1083, config: wp.conf, "
                                           "obfuscator: {key: k, evil: 1}}\n")


def test_obfuscator_values_cannot_inject_lines(app, write):
    write("wp.conf", "[Peer]\nEndpoint = vps:1\n")
    assert "в одну строку" in err(app, 'tunnels:\n  w: {kind: wireproxy, port: 1083, config: wp.conf, '
                                       'obfuscator: {key: k, target: "a:1\\nkey = other"}}\n')


# ── приложения и компоненты ──
def test_apps_validation(app):
    base = "tunnels:\n  a: {port: 1081, cmd: x}\napps:\n"
    parse(app, base + "  tg: {tunnel: a, cmd: telegram-desktop}\n")
    assert "нет такого выхода" in err(app, base + "  tg: {tunnel: nope, cmd: x}\n")
    assert "mode" in err(app, base + "  tg: {tunnel: a, cmd: x, mode: magic}\n")
    assert "в одну строку" in err(app, base + '  tg: {tunnel: a, cmd: "x\\ny"}\n')


def test_component_names(app):
    assert "имя компонента" in err(app, "updates:\n  components:\n    \"x'y\": {repo: a/b, bin: x}\n")
