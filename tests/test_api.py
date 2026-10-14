"""HTTP API: защита от чужих сайтов, сохранение конфига, проверка портов."""
import socket

import pytest
from fastapi.testclient import TestClient

H = {"X-PP": "1"}


@pytest.fixture
def client(app, conf_dir, monkeypatch):
    async def no_systemd(*args):  # systemctl в тестах не трогаем
        return 0, "", ""

    async def no_units(units):
        return {}

    monkeypatch.setattr(app, "sctl", no_systemd)
    monkeypatch.setattr(app, "units_status", no_units)
    app.CONF_FILE.write_text("tunnels: {}\n")
    return TestClient(app.app, base_url="http://127.0.0.1:8800")  # без with — фоновые циклы не стартуют


def test_guard_host_and_header(client):
    assert client.get("/api/state").status_code == 403  # без X-PP (CSRF)
    assert client.get("/api/state", headers={**H, "Host": "evil.example"}).status_code == 403  # DNS rebinding
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 403
    assert client.get("/api/state", headers=H).status_code == 200
    assert client.get("/api/state", headers={**H, "Host": "localhost:8800"}).status_code == 200


def test_put_config_validates_and_force(client, app):
    r = client.put("/api/config", headers=H, json={"text": "tunnels: [\n"})
    assert r.status_code == 400 and "YAML" in r.json()["detail"]
    assert app.CONF_FILE.read_text() == "tunnels: {}\n"
    r = client.put("/api/config", headers=H, json={"text": "tunnels: [\n", "force": True})
    assert r.status_code == 200 and r.json()["error"]
    assert app.CONF_FILE.read_text() == "tunnels: [\n"
    assert app.CONF_FILE.with_suffix(".yaml.bak").read_text() == "tunnels: {}\n"
    assert oct(app.CONF_FILE.stat().st_mode & 0o777) == "0o600"


def test_put_config_ok_reports_pending(client, app):
    r = client.put("/api/config", headers=H, json={"text": "tunnels:\n  a: {port: 1081, cmd: x}\n"})
    body = r.json()
    assert r.status_code == 200 and body["changed"] and body["pending_apply"]
    s = client.get("/api/state", headers=H).json()
    assert s["pending_apply"] and s["tunnels"][0]["name"] == "a"


def test_state_with_config_error(client, app):
    app.CONF_FILE.write_text("tunnels:\n  a: {port: nope, cmd: x}\n")
    s = client.get("/api/state", headers=H).json()
    assert "неверный port" in s["config_error"]


def test_unknown_unit_and_action(client):
    assert client.post("/api/units/nope/start", headers=H).status_code == 404
    assert client.post("/api/units/x/explode", headers=H).status_code == 400


def test_websocket_rejects_foreign_origin(client):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect), \
            client.websocket_connect("/api/logs/panel/ws", headers={"Origin": "http://evil.example"}) as ws:
        ws.receive_text()


# ── проверка портов ──
def test_port_busy_real_listener(app):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    try:
        assert app.port_busy(srv.getsockname()[1])
    finally:
        srv.close()


def test_port_busy_ignores_time_wait(app):
    """Порт остановленного туннеля, через который шёл трафик, не считается занятым (TIME_WAIT)."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    cli = socket.create_connection(("127.0.0.1", port))
    conn, _ = srv.accept()
    conn.close()  # сервер закрывает первым → TIME_WAIT на стороне сервера
    cli.recv(1)
    cli.close()
    srv.close()
    assert not app.port_busy(port)
