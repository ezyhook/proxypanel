"""Генерация units, конфигов клиентов, sing-box и ярлыков."""
import json

from conftest import PRIV, PUB


def cfg_of(app, text):
    return app.parse_config(text)


def test_unit_has_workdir_backoff_and_deps(app):
    cfg = cfg_of(app, "tunnels:\n  a: {port: 1081, cmd: ssh -N h}\n  b: {port: 1082, via: a, cmd: ssh -N h2}\n")
    u = app.render_unit("b", cfg["tunnels"]["b"], cfg)
    assert "Requires=pp-a.service" in u and "After=pp-a.service" in u
    assert f"WorkingDirectory={app.CONF_DIR}" in u
    assert "RestartSteps=6" in u and "RestartMaxDelaySec=60" in u
    assert "WantedBy=default.target" in u


def test_sd_quote(app):
    assert app.sd_quote("/a/b.sh") == "/a/b.sh"
    assert app.sd_quote("/my dir/b.sh") == '"/my dir/b.sh"'


def test_ssh_via_proxycommand(app):
    cfg = cfg_of(app, "tunnels:\n  a: {port: 1081, cmd: ssh -N h}\n  b: {port: 1082, via: a, cmd: 'ssh -N -D {port} h2'}\n")
    cmd = app.tunnel_cmd("b", cfg["tunnels"]["b"], cfg)
    assert cmd == "ssh -o 'ProxyCommand=nc -X 5 -x 127.0.0.1:1081 %h %p' -N -D 1082 h2"


def test_sidecar_units(app):
    assert "PartOf=pp-x.service" in app.render_obfs_unit("x")
    assert "[Install]" not in app.render_obfs_unit("x")
    h = app.render_http_unit("x")
    assert "BindsTo=pp-x.service" in h and "PartOf=pp-x.service" in h


def test_wireproxy_render_ports_http_and_obfs(app, write):
    write("wp.conf", f"[Interface]\nPrivateKey = {PRIV}\n[Peer]\nPublicKey = {PUB}\n"
                     "PresharedKey = keep-me\nEndpoint = vps:19999\n")
    cfg = cfg_of(app, "tunnels:\n  w: {kind: wireproxy, port: 1083, http_port: 1183, config: wp.conf, "
                      "obfuscator: {key: k, masking: STUN}}\n")
    t = cfg["tunnels"]["w"]
    out = app.render_config("w", t, cfg)
    text = out[app.RUN_DIR / "w.conf"]
    assert "Endpoint = 127.0.0.1:52000" in text
    assert "[Socks5]\nBindAddress = 127.0.0.1:1083" in text
    assert "[http]\nBindAddress = 127.0.0.1:1183" in text
    assert "PresharedKey = keep-me" in text  # PSK панель не трогает
    obfs = app.render_obfs_conf("w", t)
    assert "target = vps:19999" in obfs and "masking = STUN" in obfs and "source-if = 127.0.0.1" in obfs


def test_wireproxy_wgconfig_include(app, write):
    write("wg.conf", "[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = 203.0.113.10:19999\n")
    write("wp.conf", "WGConfig = wg.conf\n\n[Socks5]\nBindAddress = 127.0.0.1:1\n")
    cfg = cfg_of(app, "tunnels:\n  w: {kind: wireproxy, port: 1093, config: wp.conf, obfuscator: {key: k}}\n")
    t = cfg["tunnels"]["w"]
    out = app.render_config("w", t, cfg)
    inc = app.RUN_DIR / "w.wg.conf"
    assert f"WGConfig = {inc}" in out[app.RUN_DIR / "w.conf"]
    assert "Endpoint = 127.0.0.1:52000" in out[inc]
    assert t["_obfs_target"] == "203.0.113.10:19999"


def test_wireproxy_relative_wgconfig_made_absolute(app, write):
    write("wg.conf", "[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = a:1\n")
    write("wp.conf", "WGConfig = wg.conf\n")
    cfg = cfg_of(app, "tunnels:\n  w: {kind: wireproxy, port: 1093, config: wp.conf}\n")
    text = app.render_config("w", cfg["tunnels"]["w"], cfg)[app.RUN_DIR / "w.conf"]
    assert f"WGConfig = {app.CONF_DIR / 'wg.conf'}" in text  # копия лежит в run/, а не рядом с wg.conf


def test_hysteria_render_listens(app, write):
    write("hy.yaml", "server: x:443\nauth: p\n")
    cfg = cfg_of(app, "tunnels:\n  h: {kind: hysteria2, port: 1082, http_port: 1182, config: hy.yaml}\n")
    text = app.render_config("h", cfg["tunnels"]["h"], cfg)[app.RUN_DIR / "h.yaml"]
    assert "listen: 127.0.0.1:1082" in text and "listen: 127.0.0.1:1182" in text


def test_singbox_full_render(app, write):
    write("full.json", json.dumps({
        "inbounds": [{"type": "mixed", "tag": "mine", "listen": "0.0.0.0", "listen_port": 7777}],
        "outbounds": [{"type": "vless", "tag": "proxy", "server": "a", "server_port": 443},
                      {"type": "direct", "tag": "direct"}]}))
    cfg = cfg_of(app, "tunnels:\n  up: {port: 1081, cmd: ssh -N h}\n"
                      "  f: {kind: sing-box, port: 1094, http_port: 1194, via: up, config: full.json}\n")
    d = json.loads(app.render_config("f", cfg["tunnels"]["f"], cfg)[app.RUN_DIR / "f.json"])
    assert [(i["type"], i["listen"], i["listen_port"]) for i in d["inbounds"]] == [
        ("mixed", "127.0.0.1", 1094), ("http", "127.0.0.1", 1194)]
    outs = {o["tag"]: o for o in d["outbounds"]}
    assert outs["proxy"]["detour"] == "pp-via" and "detour" not in outs["direct"]
    assert outs["pp-via"]["server_port"] == 1081


def test_build_native_with_obfs_and_via(app):
    cfg = cfg_of(app, f"""tunnels:
  up: {{port: 1081, cmd: ssh -N h}}
  v:
    port: 1085
    via: up
    outbound: {{type: vless, server: a, server_port: 443, uuid: bf000d23-0752-40b4-affe-68f7707a9661}}
  w:
    port: 1084
    http_port: 1184
    obfuscator: {{key: k}}
    endpoint:
      type: wireguard
      address: [10.0.0.2/32]
      private_key: {PRIV}
      peers: [{{address: vps, port: 19999, public_key: {PUB}}}]
""")
    v = app.build_native("v", cfg["tunnels"]["v"], cfg)
    assert v["outbounds"][0]["detour"] == "via" and v["outbounds"][1]["server_port"] == 1081
    w = app.build_native("w", cfg["tunnels"]["w"], cfg)
    peer = w["endpoints"][0]["peers"][0]
    assert (peer["address"], peer["port"]) == ("127.0.0.1", app.OBFS_PORT_BASE)
    assert {i["listen_port"] for i in w["inbounds"]} == {1084, 1184}
    assert cfg["tunnels"]["w"]["_obfs_target"] == "vps:19999"


def test_chain_display(app, write):
    write("wp.conf", "[Peer]\nEndpoint = vps:1\n")
    cfg = cfg_of(app, "tunnels:\n  w: {kind: wireproxy, port: 1083, config: wp.conf, obfuscator: {key: k}}\n"
                      "  c: {port: 1085, via: w, outbound: {type: socks, server: a, server_port: 1}}\n")
    assert app.chain_of(cfg, "c") == ["wg-obfuscator", "w", "c"]


def test_ini_helpers(app):
    text = "# c\n[Peer]\nEndpoint = a:1\n;Endpoint = no\n[Peer]\nendpoint=b:2\n"
    assert app.ini_values(text, "peer", "ENDPOINT") == ["a:1", "b:2"]
    out = app.ini_set(text, "Peer", "Endpoint", "x:3")
    assert out.count("Endpoint = x:3") == 2 and ";Endpoint = no" in out
    assert app.ini_set("", "Socks5", "BindAddress", "127.0.0.1:1", add_section=True).strip() == \
        "[Socks5]\nBindAddress = 127.0.0.1:1"


def test_desktop_entry_quoting(app):
    assert app.desktop_arg("telegram-desktop") == "telegram-desktop"
    assert app.desktop_arg("50%") == "50%%"
    assert app.desktop_arg("some app") == '"some app"'
    e = app.render_desktop("x", {"tunnel": "de-wg", "cmd": 'app --title "Hi there" --rate 5%', "mode": "proxychains"}, {})
    exec_line = next(line for line in e.splitlines() if line.startswith("Exec="))
    assert exec_line == f'Exec={app.PP_RUN} --force de-wg app --title "Hi there" --rate 5%% %U'


def test_combiner_groups_ports(app):
    cfg = cfg_of(app, "singbox: {enabled: true, default: auto}\n"
                      "tunnels:\n  a: {port: 1081, cmd: x}\n  b: {port: 1082, cmd: y}\n"
                      "groups:\n  auto: {type: urltest, port: 1090, members: [a, b]}\n")
    sb = app.build_singbox(cfg)
    assert sb["outbounds"][0] == {"type": "selector", "tag": "select", "outbounds": ["auto", "a", "b", "direct"],
                                  "default": "auto"}
    assert {"inbound": ["in-auto"], "outbound": "auto"} in sb["route"]["rules"]
    assert any(i["listen_port"] == 1090 for i in sb["inbounds"])
