#!/usr/bin/env python3
"""ProxyPanel — локальная панель для управления и комбинирования SOCKS-туннелей.

Раскладка (корень ~/main, переопределяется переменной PP_MAIN):
  ~/main/bin/                          бинарники: sing-box, hysteria, wireproxy, wg-obfuscator
  ~/main/.config/proxypanel/           proxies.yaml, конфиги клиентов, state.json, run/*.sh
  ~/main/.local/share/proxypanel/      само приложение и venv
  ~/.config/systemd/user/pp-*.service  units (systemd читает их только оттуда)

Что умеет:
  * основной режим — раздельный: каждый туннель = свой процесс, свой SOCKS-порт, свой
    systemd user unit (автозагрузка, рестарт, зависимости, journald); приложения ходят
    каждое в свой порт;
  * native-туннели: outbound/endpoint sing-box (vless/hysteria2/wireguard/...) — панель
    собирает для каждого отдельный процесс sing-box;
  * обёртка wg-obfuscator для WireGuard-туннелей (wireproxy или native wireguard):
    панель сама поднимает обфускатор и направляет на него Endpoint;
  * цепочки «туннель через туннель» (via): ssh через ProxyCommand, native через detour;
  * опция: комбинатор sing-box — единый вход с автовыбором поверх тех же портов;
  * health-check, журнал событий, уведомления на рабочий стол (notify-send);
  * проверка обновлений и установка бинарников с GitHub в ~/main/bin (sha256 + откат).

CLI:
  app.py                    веб-панель
  app.py apply              сгенерировать units и конфиг sing-box, применить
  app.py check              проверить обновления бинарников
  app.py install NAME...    установить/обновить (all — все, missing — только отсутствующие)
  app.py rollback NAME      вернуть предыдущую версию
"""
from __future__ import annotations

__version__ = "0.9.0"

import asyncio
import collections
import copy
import hashlib
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import yaml
from fastapi import Body, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

# ─────────────────────────── пути и константы ───────────────────────────
HOME = Path.home()
MAIN = Path(os.environ.get("PP_MAIN", HOME / "main"))
BIN_DIR = Path(os.environ.get("PP_BIN_DIR", MAIN / "bin"))
CONF_DIR = Path(os.environ.get("PP_CONF_DIR", MAIN / ".config/proxypanel"))
CONF_FILE = CONF_DIR / "proxies.yaml"
RUN_DIR = CONF_DIR / "run"
SECRET_FILE = CONF_DIR / ".clash_secret"
SINGBOX_JSON = CONF_DIR / "singbox.json"
STATE_FILE = CONF_DIR / "state.json"
UNIT_DIR = Path(os.environ.get("PP_UNIT_DIR", HOME / ".config/systemd/user"))
APPS_DIR = Path(os.environ.get("PP_APPS_DIR", HOME / ".local/share/applications"))
ENV_DIR = RUN_DIR / "env"            # для pp-run: порты каждого туннеля
PCHAINS_DIR = RUN_DIR / "proxychains"  # для pp-run --force
PP_RUN = BIN_DIR / "pp-run"
STATIC_DIR = Path(__file__).resolve().parent / "static"
GITHUB_API = os.environ.get("PP_GITHUB_API", "https://api.github.com").rstrip("/")

PREFIX = "pp-"
SINGBOX_UNIT = "pp-singbox.service"
PANEL_UNIT = "pp-panel.service"
ENTRY = "@entry"  # ключ health для единой точки входа sing-box
RESERVED = {"select", "direct", "singbox", "panel", "in", "local"}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ACTIONS = {"start", "stop", "restart", "enable", "disable"}
SSH_PROGS = {"ssh", "autossh"}
UDP_KINDS = {"hysteria", "hysteria2", "wireproxy", "wireguard", "wg-obfuscator", "tuic"}
UDP_OUT_TYPES = {"hysteria", "hysteria2", "tuic", "wireguard"}
# cmd по умолчанию, если задан только config + kind
KIND_CMDS = {
    "wireproxy": "wireproxy -c {config}",
    "hysteria": "hysteria client -c {config}",
    "hysteria2": "hysteria client -c {config}",
    "sing-box": "sing-box run -c {config}",
    "wg-obfuscator": "wg-obfuscator -c {config}",
}
# параметры wg-obfuscator, которые можно передать в obfuscator: {...}
OBFS_KEYS = {"masking", "in-timeout", "resolve-interval", "max-dummy", "idle-timeout", "max-clients",
             "verbose", "fwmark"}
OBFS_PORT_BASE = 52000
CLI_MODE = False
COMP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
LOOPBACK = {"127.0.0.1", "localhost", "::1"}

DEFAULTS: dict[str, Any] = {
    "panel": {"listen": "127.0.0.1", "port": 8800},
    "singbox": {  # комбинатор: единый вход + автовыбор. Опция, по умолчанию выключен
        "enabled": False,
        "bin": "",  # пусто: ~/main/bin/sing-box, затем PATH
        "listen": "127.0.0.1",
        "port": 1080,
        "clash_api_port": 9090,
        "secret": "",
        "default": "",
        "test_url": "https://www.gstatic.com/generate_204",
        "test_interval": "3m",
        "log_level": "warn",
        "rules": [],
    },
    "health": {
        "interval": 30,
        "ip_interval": 300,
        "timeout": 8,
        "url": "https://www.gstatic.com/generate_204",
        "ip_url": "https://ipinfo.io/json",
    },
    "notify": {
        "enabled": True,
        "on_crash": True,      # процесс упал, systemd перезапустил
        "on_down": True,       # процесс жив, но через туннель не ходит трафик
        "on_recover": True,
        "on_update": True,     # вышла новая версия бинарника
        "on_ip_change": False,  # сменился exit IP точки входа
        "fail_threshold": 2,   # сколько проверок подряд должно провалиться
        "cooldown": 300,       # не чаще раза в N секунд на одно событие
    },
    "updates": {
        "enabled": True,
        "check_interval_h": 12,
        "auto_install": False,
        "proxy": "auto",       # auto: напрямую, при ошибке — через 127.0.0.1:<singbox.port>; direct; socks5h://...
        "prerelease": False,
        "github_token": "",
        "disabled": [],
        "components": {},      # переопределение/добавление компонентов, см. COMPONENTS
    },
    "tunnels": {},
    "groups": {},
    "apps": {},  # ярлыки в меню: программа через туннель (pp-run)
}

# Откуда брать бинарники. asset — regex имени файла релиза для архитектуры.
COMPONENTS: dict[str, dict[str, Any]] = {
    "sing-box": {
        "repo": "SagerNet/sing-box", "bin": "sing-box", "version_args": ["version"],
        "asset": {"amd64": r"^sing-box-[\d.]+(-[\w.]+)?-linux-amd64\.tar\.gz$",
                  "arm64": r"^sing-box-[\d.]+(-[\w.]+)?-linux-arm64\.tar\.gz$"},
    },
    "hysteria": {
        "repo": "HyNetworks/hysteria", "bin": "hysteria", "version_args": ["version"],
        "tag_re": r"^app/v",
        "asset": {"amd64": r"^hysteria-linux-amd64$", "arm64": r"^hysteria-linux-arm64$"},
    },
    "wireproxy": {
        "repo": "windtf/wireproxy", "bin": "wireproxy", "version_args": ["--version"],
        "asset": {"amd64": r"^wireproxy_linux_amd64\.tar\.gz$", "arm64": r"^wireproxy_linux_arm64\.tar\.gz$"},
    },
    "wg-obfuscator": {
        "repo": "ClusterM/wg-obfuscator", "bin": "wg-obfuscator", "version_args": ["--version"],
        "asset": {"amd64": r"^wg-obfuscator-v[\d.]+-linux-x64\.tar\.gz$",
                  "arm64": r"^wg-obfuscator-v[\d.]+-linux-arm64\.tar\.gz$"},
    },
}
CHECKSUM_FILES = ("checksums.txt", "hashes.txt", "sha256sums.txt", "SHA256SUMS")
ARCH_MAP = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


class ConfigError(ValueError):
    pass


# ─────────────────────────────── конфиг ────────────────────────────────
def deep_merge(base: dict, over: dict | None) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _prog(cmd: str) -> str:
    try:
        first = shlex.split(cmd)[0]
    except (ValueError, IndexError):
        first = (cmd.split() or [""])[0]
    return Path(first).name


def _conf_path(p: str) -> Path:
    q = Path(os.path.expanduser(p))
    return q if q.is_absolute() else CONF_DIR / q


def ini_values(text: str, section: str, key: str) -> list[str]:
    """Значения key во всех секциях [section] INI-подобного файла (wireproxy / wg-quick)."""
    out, cur = [], ""  # "" — строки до первой секции
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1].strip().lower()
        elif cur == section.lower() and "=" in s and not s.startswith(("#", ";")):
            k, v = s.split("=", 1)
            if k.strip().lower() == key.lower():
                out.append(v.strip())
    return out


def ini_set(text: str, section: str, key: str, value: str, add_section: bool = False) -> str:
    """Заменить key = ... в секциях [section]; при add_section — дописать секцию, если её нет."""
    lines, cur, found = text.splitlines(), "", False
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1].strip().lower()
        elif (cur == section.lower() and "=" in s and not s.startswith(("#", ";"))
              and s.split("=", 1)[0].strip().lower() == key.lower()):
            lines[i] = f"{key} = {value}"
            found = True
    if not found and add_section:
        lines += ["", f"[{section}]", f"{key} = {value}"]
    return "\n".join(lines) + "\n"


# wg-quick / привычные написания → поля sing-box (endpoint type: wireguard)
WG_PEER_ALIASES = {
    "presharedkey": "pre_shared_key", "psk": "pre_shared_key",
    "publickey": "public_key",
    "allowedips": "allowed_ips",
    "persistentkeepalive": "persistent_keepalive_interval", "keepalive": "persistent_keepalive_interval",
    "persistentkeepaliveinterval": "persistent_keepalive_interval",
}
WG_IFACE_ALIASES = {"privatekey": "private_key", "listenport": "listen_port"}


def _alias_key(k: str) -> str:
    return re.sub(r"[_\-\s]", "", str(k)).lower()


def normalize_wireguard(name: str, obj: dict) -> list[str]:
    """Приводит wg-quick-стиль к sing-box: PresharedKey/preshared_key → pre_shared_key,
    Endpoint: host:port → address+port, Address строкой → список. Возвращает заметки о переименованиях."""
    notes: list[str] = []

    def fix(d: dict, aliases: dict) -> None:
        for k in list(d):
            new = aliases.get(_alias_key(k))
            if new and new != k:
                if new in d:
                    raise ConfigError(f"туннель {name}: заданы и {k}, и {new} — оставьте одно")
                d[new] = d.pop(k)
                notes.append(f"{k} → {new}")
    fix(obj, WG_IFACE_ALIASES)
    for k in list(obj):
        if _alias_key(k) == "address" and k != "address":
            obj["address"] = obj.pop(k)
    if isinstance(obj.get("address"), str):
        obj["address"] = [a.strip() for a in obj["address"].split(",") if a.strip()]
    for i, peer in enumerate(obj.get("peers") or []):
        if not isinstance(peer, dict):
            raise ConfigError(f"туннель {name}: peers[{i}] должен быть словарём")
        fix(peer, WG_PEER_ALIASES)
        ep_key = next((k for k in peer if _alias_key(k) == "endpoint"), None)
        if ep_key is not None:  # wg-quick: Endpoint = host:port
            ep = str(peer.pop(ep_key))
            host, _, port = ep.rpartition(":")
            if not host or not port.isdigit():
                raise ConfigError(f"туннель {name}: peers[{i}].endpoint должен быть host:port, а не {ep!r}")
            peer.setdefault("address", host.strip("[]"))
            peer.setdefault("port", int(port))
            notes.append("endpoint → address/port")
        if isinstance(peer.get("allowed_ips"), str):
            peer["allowed_ips"] = [a.strip() for a in peer["allowed_ips"].split(",") if a.strip()]
        psk = peer.get("pre_shared_key")
        if psk is not None and not re.fullmatch(r"[A-Za-z0-9+/]{43}=", str(psk)):
            raise ConfigError(f"туннель {name}: peers[{i}].pre_shared_key — 32 байта в base64 (44 символа, "
                              f"как выдаёт «wg genpsk»), а сейчас {len(str(psk))} символов")
    return notes


SB_ENDPOINT_TYPES = {"wireguard", "tailscale"}
PLACEHOLDER_RE = re.compile(r"\{(port|http_port|via_port|obfs_port)\}")


def _load_singbox_json(name: str, text: str) -> Any:
    # подстановки {port} и т.п. стоят вне кавычек — для разбора заменяем их числом
    try:
        return json.loads(PLACEHOLDER_RE.sub("0", text))
    except json.JSONDecodeError as e:
        raise ConfigError(f"туннель {name}: JSON: {e.msg}, строка {e.lineno}, столбец {e.colno}") from None


def _port_of(addr: Any) -> int | None:
    m = re.search(r":(\d{1,5})\s*$", str(addr or ""))
    return int(m[1]) if m and 0 < int(m[1]) < 65536 else None


def file_ports(t: dict) -> tuple[int | None, int | None]:
    """(SOCKS, HTTP) порты, записанные в самом файле клиента — чтобы не дублировать их в proxies.yaml."""
    text, kind = t["_config_text"], (t["kind"] if t["kind"] in KIND_CMDS else _prog(t["cmd"]))
    if "{port}" in text and "{http_port}" in text:
        return None, None
    if kind == "wireproxy":
        s = ini_values(text, "Socks5", "BindAddress")
        h = ini_values(text, "http", "BindAddress")
        return (_port_of(s[0]) if s else None), (_port_of(h[0]) if h else None)
    if kind in ("hysteria", "hysteria2"):
        try:
            d = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            return None, None
        if not isinstance(d, dict):
            return None, None
        socks5, http = d.get("socks5"), d.get("http")
        return (_port_of(socks5.get("listen")) if isinstance(socks5, dict) else None,
                _port_of(http.get("listen")) if isinstance(http, dict) else None)
    if t.get("_sb_full"):
        try:
            d = json.loads(PLACEHOLDER_RE.sub("0", text))
        except json.JSONDecodeError:
            return None, None
        sp = hp = None
        for ib in (d.get("inbounds") or []) if isinstance(d, dict) else []:
            if not isinstance(ib, dict):
                continue
            p = ib.get("listen_port") or None
            if ib.get("type") in ("mixed", "socks") and sp is None:
                sp = p
            elif ib.get("type") == "http" and hp is None:
                hp = p
        return sp, hp
    return None, None


def _sync_ports_from_file(name: str, t: dict, cfg: dict) -> None:
    """port/http_port не заданы в proxies.yaml — берём из файла клиента; заданы и расходятся — предупреждаем."""
    sp, hp = file_ports(t)
    for key, val, what in (("port", sp, "SOCKS"), ("http_port", hp, "HTTP")):
        if val is None:
            continue
        if t.get(key) is None:
            t[key] = val
            t.setdefault("_ports_from_file", []).append(key)
        elif t[key] != val:
            cfg["_warnings"].append(f"{name}: {what}-порт в proxies.yaml ({t[key]}) и в {Path(t['_config_src']).name} "
                                    f"({val}) разные — главный proxies.yaml, в файле панель подставит {t[key]}")


def parse_config(text: str) -> dict:
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"YAML: {e}") from None
    if not isinstance(raw, dict):
        raise ConfigError("корень конфига должен быть словарём")
    cfg = deep_merge(DEFAULTS, raw)
    cfg["tunnels"] = cfg.get("tunnels") or {}
    cfg["groups"] = cfg.get("groups") or {}
    cfg["_warnings"] = []
    tunnels, groups = cfg["tunnels"], cfg["groups"]
    sb_on = bool(cfg["singbox"]["enabled"])

    ports: dict[int, str] = {}

    def take_port(port: Any, owner: str) -> None:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ConfigError(f"{owner}: неверный port {port!r}")
        if port in ports:
            raise ConfigError(f"{owner}: порт {port} уже занят ({ports[port]})")
        ports[port] = owner

    _validate_settings(cfg)
    take_port(cfg["panel"]["port"], "панель")
    if not isinstance(tunnels, dict) or not isinstance(groups, dict):
        raise ConfigError("tunnels и groups должны быть словарями")
    for name, t in tunnels.items():
        if not isinstance(name, str) or not NAME_RE.match(name) or name in RESERVED \
                or name.endswith(("-obfs", "-http")):
            raise ConfigError(f"недопустимое имя туннеля {name!r}: a-z 0-9 - _, до 40 символов, "
                              "без суффиксов -obfs/-http (они заняты служебными unit'ами)")
        if not isinstance(t, dict):
            raise ConfigError(f"туннель {name}: ожидается словарь")
        for key in ("description", "kind"):
            if key in t and (not isinstance(t[key], str) or "\n" in t[key] or "\r" in t[key]):
                raise ConfigError(f"туннель {name}: {key} — строка в одну строку")
        rs = t.get("restart_sec", 3)
        if isinstance(rs, bool) or not isinstance(rs, int) or not 0 <= rs <= 3600:
            raise ConfigError(f"туннель {name}: restart_sec — целое число секунд 0…3600")
        kind = t.get("kind")
        conf = t.get("config")
        if conf is not None:  # файл клиента: wireproxy .conf, hysteria .yaml, sing-box .json …
            if not isinstance(conf, str) or not conf.strip():
                raise ConfigError(f"туннель {name}: config — путь к файлу")
            src = _conf_path(conf)
            try:
                t["_config_text"] = src.read_text()
            except OSError as e:
                raise ConfigError(f"туннель {name}: не читается config {src}: {e.strerror}") from None
            t["_config_src"] = str(src)
        inline = "outbound" in t or "endpoint" in t
        if inline and kind not in (None, "sing-box"):
            raise ConfigError(f"туннель {name}: outbound/endpoint — это туннель sing-box, укажите kind: sing-box "
                              f"(сейчас kind: {kind})")
        if inline and conf is not None:
            raise ConfigError(f"туннель {name}: либо outbound/endpoint прямо в конфиге, "
                              "либо config: файл.json — не оба")
        # sing-box из JSON: один outbound/endpoint (= как inline) или полный конфиг sing-box
        if not inline and conf is not None and not t.get("cmd") and (
                kind == "sing-box" or (kind is None and str(conf).lower().endswith(".json"))):
            data = _load_singbox_json(name, t["_config_text"])
            if isinstance(data, dict) and data.get("type") and not {"inbounds", "outbounds", "endpoints"} & set(data):
                if "tag" in data or "detour" in data:
                    data = {k: v for k, v in data.items() if k not in ("tag", "detour")}  # из экспорта — не мешаем
                t["endpoint" if data["type"] in SB_ENDPOINT_TYPES else "outbound"] = data
                t["_native_file"] = t.pop("_config_src")
                t.pop("_config_text")
                inline = True
            elif isinstance(data, dict) and ({"inbounds", "outbounds", "endpoints"} & set(data)):
                t["_sb_full"] = True
                t["kind"] = kind = "sing-box"
            else:
                raise ConfigError(f"туннель {name}: {conf} — ни объект outbound/endpoint (с полем type), "
                                  "ни конфиг sing-box (inbounds/outbounds)")
        native = inline
        t["native"] = native
        if native:
            if "outbound" in t and "endpoint" in t:
                raise ConfigError(f"туннель {name}: укажите либо outbound, либо endpoint")
            obj = t.get("outbound") if "outbound" in t else t.get("endpoint")
            if not isinstance(obj, dict) or not obj.get("type"):
                raise ConfigError(f"туннель {name}: outbound/endpoint — объект sing-box с полем type")
            if "tag" in obj or "detour" in obj:
                raise ConfigError(f"туннель {name}: не пишите tag/detour — их задаёт панель (detour = via)")
            if obj.get("type") == "wireguard":
                normalize_wireguard(name, obj)
            if t.get("cmd"):
                raise ConfigError(f"туннель {name}: у sing-box-туннеля с outbound/endpoint нет cmd — "
                                  "панель сама соберёт и запустит sing-box")
            if t.get("port") is None:
                raise ConfigError(f"туннель {name}: нужен port — это локальный SOCKS-вход туннеля")
            t["kind"] = "sing-box"
            t["_proto"] = str(obj["type"])
        else:
            if not t.get("cmd"):
                if conf is not None and t.get("kind") in KIND_CMDS:
                    t["cmd"] = KIND_CMDS[t["kind"]]
                else:
                    raise ConfigError(f"туннель {name}: нужен cmd (или config + kind из: {', '.join(KIND_CMDS)})")
            if not isinstance(t["cmd"], str) or not t["cmd"].strip():
                raise ConfigError(f"туннель {name}: cmd должен быть строкой")
            if "{config}" in t["cmd"] and conf is None:
                raise ConfigError(f"туннель {name}: в cmd есть {{config}}, но не задан config")
            t.setdefault("kind", _prog(t["cmd"]))
            if "_config_text" in t:
                _sync_ports_from_file(name, t, cfg)
        if t.get("port") is not None:
            take_port(t["port"], name)
        if native:
            t["socks"] = True
        else:
            t.setdefault("socks", t.get("port") is not None)
            if t["socks"] and t.get("port") is None:
                raise ConfigError(f"туннель {name}: socks: true требует port")
        t["exit"] = bool(t["socks"])
        hp = t.get("http_port")
        if hp is not None:
            if not t["exit"]:
                raise ConfigError(f"туннель {name}: http_port имеет смысл только у SOCKS-туннеля (нужен port)")
            take_port(hp, f"{name} (http)")
        # где доступен HTTP-прокси и кто его обслуживает
        if native:
            t["_http_port"], t["_http_mode"] = (hp or t["port"]), "native"  # mixed-вход sing-box понимает и HTTP
        elif hp is not None:
            k = t["kind"] if t["kind"] in KIND_CMDS else _prog(t["cmd"])
            if "_config_text" in t and k == "wireproxy":
                mode = "wireproxy"
            elif "_config_text" in t and k in ("hysteria", "hysteria2"):
                mode = "hysteria"
            elif t.get("_sb_full"):
                mode = "singbox-json"  # допишем http-inbound в его конфиг
            else:
                mode = "bridge"  # отдельный мост HTTP→SOCKS на sing-box
            t["_http_port"], t["_http_mode"] = hp, mode
        t["requires"] = t.get("requires") or []
        if not isinstance(t["requires"], list):
            raise ConfigError(f"туннель {name}: requires — список имён туннелей")
        for r in t["requires"]:
            if r not in tunnels:
                raise ConfigError(f"туннель {name}: requires ссылается на неизвестный {r!r}")
        env = t.get("env") or {}
        if not isinstance(env, dict) or any(not ENV_RE.match(str(k)) for k in env):
            raise ConfigError(f"туннель {name}: env должен быть словарём ИМЯ: значение")
        t["env"] = env

    # ── группы (только для комбинатора) ──
    exits = {n for n, t in tunnels.items() if t["exit"]}
    for g, gd in groups.items():
        if not isinstance(g, str) or not NAME_RE.match(g) or g in RESERVED or g in tunnels:
            raise ConfigError(f"недопустимое имя группы {g!r}")
        if not isinstance(gd, dict) or gd.get("type") not in ("urltest", "selector"):
            raise ConfigError(f"группа {g}: type должен быть urltest или selector")
        members = gd.get("members") or []
        if not isinstance(members, list) or not members:
            raise ConfigError(f"группа {g}: members — непустой список")
        tol = gd.get("tolerance", 50)
        if isinstance(tol, bool) or not isinstance(tol, int) or tol < 0:
            raise ConfigError(f"группа {g}: tolerance — целое число мс")
        for m in members:
            if m not in exits and m not in groups and m != "direct":
                raise ConfigError(f"группа {g}: {m!r} не SOCKS-туннель и не группа")
        if gd.get("port") is not None and sb_on:
            take_port(gd["port"], f"группа {g}")

    # ── обёртка wg-obfuscator ──
    for name, t in tunnels.items():
        ob = t.get("obfuscator")
        if ob is None:
            continue
        if not isinstance(ob, dict) or not isinstance(ob.get("key"), str) or not ob["key"]:
            raise ConfigError(f"туннель {name}: obfuscator.key — обязательная строка")
        bad = set(ob) - OBFS_KEYS - {"key", "target", "listen_port"}
        if bad:
            raise ConfigError(f"туннель {name}: неизвестные ключи obfuscator: {', '.join(sorted(bad))}")
        for k, v in ob.items():  # значения идут в INI-конфиг обфускатора построчно — без переводов строк
            if isinstance(v, (dict, list)) or any(c in str(v) for c in "\r\n"):
                raise ConfigError(f"туннель {name}: obfuscator.{k} — одно значение в одну строку")
        if t.get("via"):
            raise ConfigError(f"туннель {name}: obfuscator и via несовместимы — обфускатор сам ходит к серверу по UDP")
        obj = t.get("endpoint") if t["native"] else None
        if t["native"]:
            if not obj or obj.get("type") != "wireguard":
                raise ConfigError(f"туннель {name}: obfuscator оборачивает только WireGuard (endpoint type: wireguard)")
            peers = obj.get("peers") or []
            if len(peers) != 1:
                raise ConfigError(f"туннель {name}: с obfuscator у wireguard должен быть ровно один peer")
            target = ob.get("target") or (f"{peers[0].get('address')}:{peers[0].get('port')}"
                                          if peers[0].get("address") and peers[0].get("port") else None)
        else:
            if t["kind"] != "wireproxy" and _prog(t["cmd"]) != "wireproxy":
                raise ConfigError(f"туннель {name}: obfuscator оборачивает только WireGuard — wireproxy "
                                  "или sing-box endpoint wireguard (для отдельного процесса — kind: wg-obfuscator)")
            if "_config_text" not in t:
                raise ConfigError(f"туннель {name}: для obfuscator укажите config: (файл wireproxy) — "
                                  "панель сама направит Endpoint на обфускатор")
            eps = _wireproxy_endpoints(name, t)
            if len(eps) > 1 and not ob.get("target"):
                raise ConfigError(f"туннель {name}: несколько [Peer] — задайте obfuscator.target явно")
            target = ob.get("target") or (eps[0] if eps else None)
        if not target:
            raise ConfigError(f"туннель {name}: не найден адрес сервера — задайте obfuscator.target: host:port")
        t["_obfs_target"] = str(target)
    used_obfs = {o["listen_port"] for o in (t.get("obfuscator") for t in tunnels.values())
                 if isinstance(o, dict) and o.get("listen_port")}
    nxt = OBFS_PORT_BASE
    for name in sorted(n for n, t in tunnels.items() if t.get("obfuscator")):
        lp = tunnels[name]["obfuscator"].get("listen_port")
        if lp is None:
            while nxt in ports or nxt in used_obfs:
                nxt += 1
            lp = nxt
        take_port(lp, f"{name}-obfs")
        tunnels[name]["_obfs_port"] = lp

    # ── цепочки (via) ──
    for name, t in tunnels.items():
        via = t.get("via")
        if via is None:
            continue
        if via == name:
            raise ConfigError(f"туннель {name}: via указывает сам на себя")
        if via in tunnels:
            up = tunnels[via]
            if not up["exit"]:
                raise ConfigError(f"туннель {name}: у {via} нет SOCKS-порта — через него нельзя")
            t["_via_port"], t["_via_unit"] = up["port"], unit_of(via)
        elif via in groups:
            if not sb_on or not groups[via].get("port"):
                raise ConfigError(f"туннель {name}: via на группу {via} работает только с комбинатором и port у группы")
            t["_via_port"], t["_via_unit"] = groups[via]["port"], SINGBOX_UNIT
        else:
            raise ConfigError(f"туннель {name}: via {via!r} — нет такого туннеля или группы")
        if t["native"]:
            obj = t.get("outbound") or t.get("endpoint")
            up = tunnels.get(via)
            if obj["type"] in UDP_OUT_TYPES and up and not up["native"] and _prog(up["cmd"]) in SSH_PROGS:
                cfg["_warnings"].append(
                    f"{name}: {obj['type']} работает по UDP, а SOCKS у ssh -D ({via}) UDP не передаёт — "
                    "цепочка не заработает; пустите его через hysteria или native vless/trojan/shadowsocks")
        else:
            prog = _prog(t["cmd"])
            if "{via" in t["cmd"] or uses(t.get("_config_text", ""), "{via"):
                t["_via_mode"] = "placeholder"
            elif prog in SSH_PROGS:
                t["_via_mode"] = "ssh"
            elif t.get("_sb_full"):
                t["_via_mode"] = "singbox-json"  # detour на SOCKS верхнего туннеля у всех прокси-outbound'ов
            else:
                hint = ("этот клиент работает по UDP и не умеет ходить через SOCKS — опишите его как native-туннель "
                        "(outbound/endpoint sing-box), тогда via заработает") if t["kind"] in UDP_KINDS or prog in {
                            "hysteria", "wireproxy", "wg-obfuscator"} else \
                    "используйте подстановки {via}, {via_host}, {via_port} или {via_url} в cmd или config"
                raise ConfigError(f"туннель {name}: via для «{prog}» не настраивается автоматически — {hint}")
    for name in tunnels:
        seen: list[str] = []
        cur: str | None = name
        while cur is not None:
            if cur in seen:
                raise ConfigError("цикл в via: " + " → ".join(seen + [cur]))
            seen.append(cur)
            n2 = tunnels[cur].get("via")
            cur = n2 if n2 in tunnels else None

    sb = cfg["singbox"]
    if sb_on:
        for p in (sb["port"], sb["clash_api_port"]):
            take_port(p, "sing-box")
        options = list(groups) + [n for n in tunnels if tunnels[n]["exit"]] + ["direct"]
        if sb.get("default") and sb["default"] not in options:
            raise ConfigError(f"singbox.default: {sb['default']!r} нет среди {options}")
        if not isinstance(sb.get("rules") or [], list):
            raise ConfigError("singbox.rules должен быть списком")
    if not isinstance(cfg["updates"].get("components") or {}, dict):
        raise ConfigError("updates.components должен быть словарём")

    # ── приложения (ярлыки pp-run) ──
    targets = run_targets(cfg)
    cfg["apps"] = cfg.get("apps") or {}
    for a, ad in cfg["apps"].items():
        if not isinstance(a, str) or not NAME_RE.match(a):
            raise ConfigError(f"недопустимое имя приложения {a!r}")
        if not isinstance(ad, dict) or not isinstance(ad.get("cmd"), str) or not ad["cmd"].strip():
            raise ConfigError(f"приложение {a}: нужен cmd")
        if ad.get("tunnel") not in targets:
            raise ConfigError(f"приложение {a}: tunnel {ad.get('tunnel')!r} — нет такого выхода "
                              f"(доступны: {', '.join(targets) or 'нет'})")
        if ad.get("mode", "auto") not in ("auto", "proxychains"):
            raise ConfigError(f"приложение {a}: mode — auto или proxychains")
        for key in ("cmd", "title", "icon"):
            if any(c in str(ad.get(key, "")) for c in "\r\n"):
                raise ConfigError(f"приложение {a}: {key} — в одну строку")
    for c in cfg["updates"]["components"]:
        if not isinstance(c, str) or not COMP_NAME_RE.match(c):
            raise ConfigError(f"updates.components: недопустимое имя компонента {c!r}")
    return cfg


def _validate_settings(cfg: dict) -> None:
    """Числовые и служебные настройки: ошибки здесь иначе всплывали бы позже как 500."""
    def num(path: str, lo: float, hi: float, integer: bool = False) -> None:
        sec, key = path.split(".")
        v = cfg[sec].get(key)
        ok = not isinstance(v, bool) and isinstance(v, int if integer else (int, float)) and lo <= v <= hi
        if not ok:
            raise ConfigError(f"{path}: ожидается {'целое ' if integer else ''}число {lo:g}…{hi:g}, а не {v!r}")
    num("health.interval", 3, 86400)
    num("health.ip_interval", 10, 86400 * 7)
    num("health.timeout", 1, 120)
    num("notify.fail_threshold", 1, 100, integer=True)
    num("notify.cooldown", 0, 86400 * 7)
    num("updates.check_interval_h", 0.1, 24 * 30)
    p = cfg["panel"]
    if str(p.get("listen")) not in LOOPBACK:
        # панель управляет процессами и правит конфиг — с сетью её открывать нельзя (это RCE от вашего имени)
        raise ConfigError(f"panel.listen: только 127.0.0.1/localhost/::1, а не {p.get('listen')!r} "
                          "(панель без пароля — открывать её в сеть небезопасно)")
    for sec in ("tunnels", "groups", "apps"):
        if cfg.get(sec) is not None and not isinstance(cfg[sec], dict):
            raise ConfigError(f"{sec} — словарь")


def run_targets(cfg: dict) -> dict[str, dict]:
    """Куда может ходить pp-run: туннели с SOCKS, группы с портом, единый вход комбинатора."""
    out: dict[str, dict] = {}
    for n, t in cfg["tunnels"].items():
        if t["exit"]:
            out[n] = {"socks": t["port"], "http": t.get("_http_port"), "unit": unit_of(n),
                      "title": t.get("description") or n}
    if cfg["singbox"]["enabled"]:
        out["singbox"] = {"socks": cfg["singbox"]["port"], "http": cfg["singbox"]["port"], "unit": SINGBOX_UNIT,
                          "title": "комбинатор (единый вход)"}
        for g, gd in cfg["groups"].items():
            if gd.get("port"):
                out[g] = {"socks": gd["port"], "http": gd["port"], "unit": SINGBOX_UNIT, "title": f"группа {g}"}
    return out


def _wireproxy_endpoints(name: str, t: dict) -> list[str]:
    """Endpoint сервера из wireproxy-конфига (или из подключённого WGConfig)."""
    text = t["_config_text"]
    eps = ini_values(text, "Peer", "Endpoint")
    if not eps:
        inc = ini_values(text, "Interface", "WGConfig") or ini_values(text, "", "WGConfig")
        if inc:
            p = _conf_path(inc[0])
            try:
                t["_wg_include"] = (str(p), p.read_text())
            except OSError as e:
                raise ConfigError(f"туннель {name}: не читается WGConfig {p}: {e.strerror}") from None
            eps = ini_values(t["_wg_include"][1], "Peer", "Endpoint")
    return eps


def load_config() -> dict:
    if not CONF_FILE.exists():
        raise ConfigError(f"нет файла {CONF_FILE}")
    return parse_config(CONF_FILE.read_text())


def try_config() -> dict | None:
    try:
        return load_config()
    except ConfigError:
        return None


def clash_secret(cfg: dict) -> str:
    if cfg["singbox"].get("secret"):
        return str(cfg["singbox"]["secret"])
    if not SECRET_FILE.exists():
        CONF_DIR.mkdir(parents=True, exist_ok=True)
        SECRET_FILE.write_text(secrets.token_hex(16))
        SECRET_FILE.chmod(0o600)
    return SECRET_FILE.read_text().strip()


def chain_of(cfg: dict, name: str) -> list[str]:
    """Сетевой путь трафика от ноутбука: [первый хоп, ..., name]; обфускатор — перед своим туннелем."""
    hops = [name]
    cur = cfg["tunnels"][name].get("via")
    while cur is not None and cur not in hops:
        hops.insert(0, cur)
        cur = cfg["tunnels"][cur].get("via") if cur in cfg["tunnels"] else None
    path: list[str] = []
    for h in hops:
        if cfg["tunnels"].get(h, {}).get("_obfs_port"):
            path.append("wg-obfuscator")
        path.append(h)
    return path


# ─────────────────────── генерация units и конфигов ──────────────────────
def unit_of(name: str) -> str:
    return SINGBOX_UNIT if name == "singbox" else f"{PREFIX}{name}.service"


def obfs_unit(name: str) -> str:
    return f"{PREFIX}{name}-obfs.service"


def all_units(cfg: dict) -> dict[str, str]:
    """unit -> подпись для событий."""
    out: dict[str, str] = {}
    for n, t in cfg["tunnels"].items():
        out[unit_of(n)] = n
        if t.get("_obfs_port"):
            out[obfs_unit(n)] = f"{n} · wg-obfuscator"
        if t.get("_http_mode") == "bridge":
            out[http_unit(n)] = f"{n} · http"
    if cfg["singbox"]["enabled"]:
        out[SINGBOX_UNIT] = "singbox"
    return out


def config_out(name: str, t: dict) -> Path:
    suffix = Path(t["_config_src"]).suffix or ".conf"
    return RUN_DIR / f"{name}{suffix}"


def subst(s: str, name: str, t: dict, cfg: dict) -> str:
    rep: dict[str, Any] = {"{port}": t.get("port", ""), "{confdir}": CONF_DIR, "{home}": HOME,
                           "{main}": MAIN, "{bin}": BIN_DIR, "{name}": name}
    if "_config_src" in t:
        rep["{config}"] = config_out(name, t)
    if t.get("_http_port"):
        rep["{http_port}"] = t["_http_port"]
    if t.get("_obfs_port"):
        rep["{obfs}"] = f"127.0.0.1:{t['_obfs_port']}"
    if t.get("_via_port"):
        vp = t["_via_port"]
        rep.update({"{via}": f"127.0.0.1:{vp}", "{via_host}": "127.0.0.1", "{via_port}": vp,
                    "{via_url}": f"socks5://127.0.0.1:{vp}"})
    for k, v in rep.items():
        s = s.replace(k, str(v))
    return s


def uses(text: str, token: str) -> bool:
    """Есть ли подстановка в незакомментированных строках."""
    return any(token in line for line in text.splitlines() if not line.lstrip().startswith(("#", ";")))


def render_config(name: str, t: dict, cfg: dict) -> dict[Path, str]:
    """Файл(ы) конфигурации клиента: подстановки + синхронизация портов/Endpoint."""
    src = t["_config_text"]
    text = subst(src, name, t, cfg)
    out: dict[Path, str] = {}
    kind = t["kind"] if t["kind"] in KIND_CMDS else _prog(t["cmd"])
    if kind == "wireproxy":
        for inc in ini_values(text, "Interface", "WGConfig") + ini_values(text, "", "WGConfig"):
            if inc and not os.path.isabs(os.path.expanduser(inc)):
                text = re.sub(rf"(?mi)^(\s*WGConfig\s*=\s*){re.escape(inc)}\s*$",
                              lambda m, inc=inc: m[1] + str(_conf_path(inc)), text)
        if t.get("port") and not uses(src, "{port}"):
            text = ini_set(text, "Socks5", "BindAddress", f"127.0.0.1:{t['port']}", add_section=True)
        if t.get("_http_mode") == "wireproxy" and not uses(src, "{http_port}"):
            text = ini_set(text, "http", "BindAddress", f"127.0.0.1:{t['_http_port']}", add_section=True)
        if t.get("_obfs_port") and not uses(src, "{obfs}"):
            obfs = f"127.0.0.1:{t['_obfs_port']}"
            if ini_values(text, "Peer", "Endpoint"):
                text = ini_set(text, "Peer", "Endpoint", obfs)
            elif t.get("_wg_include"):
                _, inc_text = t["_wg_include"]
                inc_out = RUN_DIR / f"{name}.wg.conf"
                out[inc_out] = ini_set(inc_text, "Peer", "Endpoint", obfs)
                text = ini_set(text, "Interface", "WGConfig", str(inc_out))
                if str(inc_out) not in text:  # WGConfig был вне секции [Interface]
                    text = re.sub(r"(?mi)^\s*WGConfig\s*=.*$", f"WGConfig = {inc_out}", text)
    elif kind in ("hysteria", "hysteria2"):
        fix_socks = t.get("port") and not uses(src, "{port}")
        fix_http = t.get("_http_mode") == "hysteria" and not uses(src, "{http_port}")
        if fix_socks or fix_http:
            try:
                d = yaml.safe_load(text)
                if isinstance(d, dict):
                    if fix_socks:
                        d["socks5"] = {**(d.get("socks5") or {}), "listen": f"127.0.0.1:{t['port']}"}
                    if fix_http:
                        d["http"] = {**(d.get("http") or {}), "listen": f"127.0.0.1:{t['_http_port']}"}
                    text = yaml.safe_dump(d, allow_unicode=True, sort_keys=False)
            except yaml.YAMLError:
                pass
    elif t.get("_sb_full"):
        text = render_singbox_full(name, t, text)
    out[config_out(name, t)] = text
    return out


SB_NONPROXY_OUT = {"direct", "block", "dns", "selector", "urltest"}


def render_singbox_full(name: str, t: dict, text: str) -> str:
    """Полный конфиг sing-box пользователя: запускаем как есть, но вход — на порт из proxies.yaml."""
    d = _load_singbox_json(name, text)
    inb = d.setdefault("inbounds", [])
    if t.get("port"):
        main = next((i for i in inb if i.get("type") in ("mixed", "socks")), None)
        if main is None:
            main = {"type": "mixed", "tag": "pp-in"}
            inb.insert(0, main)
        main.update(listen="127.0.0.1", listen_port=t["port"])
    if t.get("_http_mode") == "singbox-json":
        h = next((i for i in inb if i.get("type") == "http"), None)
        if h is None:
            h = {"type": "http", "tag": "pp-in-http"}
            inb.append(h)
        h.update(listen="127.0.0.1", listen_port=t["_http_port"])
    if t.get("_via_mode") == "singbox-json":
        outs = d.setdefault("outbounds", [])
        if not any(o.get("tag") == "pp-via" for o in outs):
            outs.append({"type": "socks", "tag": "pp-via", "server": "127.0.0.1",
                         "server_port": t["_via_port"], "version": "5"})
        for o in outs + list(d.get("endpoints") or []):
            if o.get("type") not in SB_NONPROXY_OUT and o.get("tag") != "pp-via" and "detour" not in o:
                o["detour"] = "pp-via"
    return json.dumps(d, indent=2, ensure_ascii=False) + "\n"


def build_native(name: str, t: dict, cfg: dict) -> dict:
    """Отдельный процесс sing-box на один native-туннель: SOCKS-вход → outbound (→ detour)."""
    obj = copy.deepcopy(t.get("outbound") or t.get("endpoint"))
    obj["tag"] = "out"
    outbounds: list[dict] = []
    if t.get("_obfs_port"):
        obj["peers"][0]["address"] = "127.0.0.1"
        obj["peers"][0]["port"] = t["_obfs_port"]
    if t.get("_via_port"):
        obj["detour"] = "via"
        outbounds.append({"type": "socks", "tag": "via", "server": "127.0.0.1",
                          "server_port": t["_via_port"], "version": "5"})
    outbounds.append({"type": "direct", "tag": "direct"})
    conf: dict[str, Any] = {
        "log": {"level": cfg["singbox"]["log_level"], "timestamp": False},
        "dns": {"servers": [{"type": "local", "tag": "local"}]},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": t["port"]}],
        "route": {"final": "out", "default_domain_resolver": "local"},
    }
    if t.get("http_port"):
        conf["inbounds"].append({"type": "http", "tag": "in-http", "listen": "127.0.0.1",
                                 "listen_port": t["http_port"]})
    if "endpoint" in t:
        conf["endpoints"] = [obj]
        conf["outbounds"] = outbounds
    else:
        conf["outbounds"] = [obj] + outbounds
    return conf


def render_obfs_conf(name: str, t: dict) -> str:
    ob = t["obfuscator"]
    lines = [f"# Сгенерировано ProxyPanel для {name}", f"[{name}]", "source-if = 127.0.0.1",
             f"source-lport = {t['_obfs_port']}", f"target = {t['_obfs_target']}", f"key = {ob['key']}"]
    lines += [f"{k} = {ob[k]}" for k in sorted(OBFS_KEYS) if k in ob]
    return "\n".join(lines) + "\n"


def _script(body: str, env: dict | None = None) -> str:
    envs = "".join(f"export {k}={shlex.quote(str(v))}\n" for k, v in (env or {}).items())
    body = body if "\n" in body else f"exec {body}"
    return (
        "#!/usr/bin/env bash\n"
        "# Сгенерировано ProxyPanel — правьте proxies.yaml, а не этот файл.\n"
        f'export PATH="{BIN_DIR}:$HOME/.local/bin:$HOME/bin:/usr/local/sbin:/usr/local/bin:$PATH"\n'
        f"{envs}{body}\n"
    )


def tunnel_cmd(name: str, t: dict, cfg: dict) -> str:
    if t["native"]:
        return f"{shlex.quote(singbox_bin(cfg) or 'sing-box')} run -c {shlex.quote(str(RUN_DIR / (name + '.json')))}"
    cmd = subst(t["cmd"].strip(), name, t, cfg)
    if t.get("_via_mode") == "ssh":
        prog, _, rest = cmd.partition(" ")
        opt = shlex.quote(f"ProxyCommand=nc -X 5 -x 127.0.0.1:{t['_via_port']} %h %p")
        cmd = f"{prog} -o {opt} {rest}".rstrip()
    return cmd


def render_script(name: str, t: dict, cfg: dict) -> str:
    return _script(tunnel_cmd(name, t, cfg), t["env"])


def sd_quote(path: Path | str) -> str:
    """Путь для ExecStart=/WorkingDirectory= systemd: в кавычках, если есть пробелы."""
    p = str(path)
    return f'"{p}"' if re.search(r'[\s"\\]', p) else p


def _unit_text(desc: str, script: Path, deps: list[str], restart_sec: int = 3,
               part_of: str | None = None, install: bool = True, wants: list[str] | None = None,
               bound_to: str | None = None) -> str:
    deps_s = " ".join(dict.fromkeys(deps))
    lines = ["[Unit]", f"Description={desc}", "StartLimitIntervalSec=0"]
    if deps_s:
        lines += [f"Requires={deps_s}", f"After={deps_s}"]
    if wants:
        lines.append(f"Wants={' '.join(wants)}")
    if bound_to:
        lines += [f"BindsTo={bound_to}", f"After={bound_to}"]
    if part_of:
        lines.append(f"PartOf={part_of}")
    lines += ["", "[Service]", "Type=simple", f"ExecStart={sd_quote(script)}",
              # относительные пути в cmd и конфигах клиентов считаются от каталога конфигов
              f"WorkingDirectory={sd_quote(CONF_DIR)}",
              "Restart=always", f"RestartSec={restart_sec}",
              # при падениях подряд пауза растёт до минуты, а не долбит каждые 3 секунды
              "RestartSteps=6", "RestartMaxDelaySec=60"]
    if install:
        lines += ["", "[Install]", "WantedBy=default.target"]
    return "\n".join(lines) + "\n"


def render_unit(name: str, t: dict, cfg: dict) -> str:
    deps = [unit_of(r) for r in t["requires"]]
    if t.get("_via_unit"):
        deps.append(t["_via_unit"])
    if t.get("_obfs_port"):
        deps.append(obfs_unit(name))
    desc = f"ProxyPanel tunnel: {name}" + (f" ({t['description']})" if t.get("description") else "")
    wants = [http_unit(name)] if t.get("_http_mode") == "bridge" else None
    return _unit_text(desc, RUN_DIR / f"{name}.sh", deps, int(t.get("restart_sec", 3)), wants=wants)


def http_unit(name: str) -> str:
    return f"{PREFIX}{name}-http.service"


def build_http_bridge(name: str, t: dict, cfg: dict) -> dict:
    """Мост HTTP-прокси → SOCKS туннеля для клиентов без встроенного HTTP (ssh -D и т.п.)."""
    return {
        "log": {"level": cfg["singbox"]["log_level"], "timestamp": False},
        "inbounds": [{"type": "http", "tag": "in", "listen": "127.0.0.1", "listen_port": t["_http_port"]}],
        "outbounds": [{"type": "socks", "tag": "out", "server": "127.0.0.1", "server_port": t["port"], "version": "5"}],
        "route": {"final": "out"},
    }


def render_http_unit(name: str) -> str:
    # Стартует вместе с туннелем (Wants), живёт и перезапускается вместе с ним.
    return _unit_text(f"ProxyPanel: HTTP-мост для {name}", RUN_DIR / f"{name}-http.sh", [],
                      part_of=unit_of(name), install=False, bound_to=unit_of(name))


def render_obfs_unit(name: str) -> str:
    # Без [Install]: стартует вместе с туннелем (Requires), останавливается вместе с ним (PartOf).
    return _unit_text(f"ProxyPanel: wg-obfuscator для {name}", RUN_DIR / f"{name}-obfs.sh", [],
                      part_of=unit_of(name), install=False)


def render_singbox_unit(binary: str) -> str:
    return (
        "[Unit]\nDescription=ProxyPanel: sing-box combiner\nStartLimitIntervalSec=0\n\n"
        f"[Service]\nType=simple\nExecStart={sd_quote(binary)} run -c {sd_quote(SINGBOX_JSON)}\n"
        "Restart=always\nRestartSec=3\nRestartSteps=6\nRestartMaxDelaySec=60\n\n[Install]\nWantedBy=default.target\n"
    )


def singbox_bin(cfg: dict | None) -> str | None:
    # Имя без пути ищем как туннели: сначала ~/main/bin, потом PATH (у systemd-сервиса PATH короткий)
    b = os.path.expanduser(str((cfg or DEFAULTS)["singbox"].get("bin") or "sing-box"))
    return _find_prog(b)


def build_singbox(cfg: dict) -> dict:
    """Комбинатор (опция): единый вход + группы поверх SOCKS-портов отдельных туннелей."""
    sb, tunnels, groups = cfg["singbox"], cfg["tunnels"], cfg["groups"]
    exits = [n for n, t in tunnels.items() if t["exit"]]
    options = list(groups) + exits + ["direct"]
    outbounds: list[dict] = [
        {"type": "selector", "tag": "select", "outbounds": options, "default": sb.get("default") or options[0]},
    ]
    inbounds: list[dict] = [{"type": "mixed", "tag": "in", "listen": sb["listen"], "listen_port": sb["port"]}]
    rules: list[dict] = []
    for g, gd in groups.items():
        ob: dict[str, Any] = {"type": gd["type"], "tag": g, "outbounds": list(gd["members"])}
        if gd["type"] == "urltest":
            ob.update(url=gd.get("url", sb["test_url"]),
                      interval=gd.get("interval", sb["test_interval"]),
                      tolerance=int(gd.get("tolerance", 50)))
        elif gd.get("default"):
            ob["default"] = gd["default"]
        outbounds.append(ob)
        if gd.get("port"):
            inbounds.append({"type": "mixed", "tag": f"in-{g}", "listen": sb["listen"], "listen_port": gd["port"]})
            rules.append({"inbound": [f"in-{g}"], "outbound": g})
    for n in exits:
        outbounds.append({"type": "socks", "tag": n, "server": "127.0.0.1",
                          "server_port": tunnels[n]["port"], "version": "5"})
    outbounds.append({"type": "direct", "tag": "direct"})
    return {
        "log": {"level": sb["log_level"], "timestamp": False},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules + list(sb.get("rules") or []), "final": "select"},
        "experimental": {
            "clash_api": {"external_controller": f"127.0.0.1:{sb['clash_api_port']}", "secret": clash_secret(cfg)},
            "cache_file": {"enabled": True, "path": str(CONF_DIR / "singbox-cache.db")},
        },
    }


def write_if_changed(path: Path, content: str | bytes, mode: int | None = None) -> bool:
    data = content.encode() if isinstance(content, str) else content
    if path.exists() and path.read_bytes() == data:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    # создаём сразу с нужными правами: иначе файл с ключами пару миллисекунд был бы 0644
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode if mode is not None else 0o644)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        if mode is not None:
            os.chmod(tmp, mode)  # umask мог срезать биты
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return True


def secure_dirs() -> None:
    """В каталоге конфигов лежат ключи WireGuard, пароли — только для владельца."""
    for d in (CONF_DIR, RUN_DIR):
        d.mkdir(parents=True, exist_ok=True)
        try:
            d.chmod(0o700)
        except OSError:
            pass


# ─────────────────────────────── процессы ──────────────────────────────
async def run(*args: str, timeout: float = 30, env: dict | None = None) -> tuple[int, str, str]:
    try:
        p = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL, env=env)
    except (FileNotFoundError, PermissionError, OSError) as e:
        return 127, "", f"{args[0]}: {e}"
    try:
        out, err = await asyncio.wait_for(p.communicate(), timeout)
    except asyncio.TimeoutError:
        p.kill()
        return 124, "", f"{' '.join(args)}: таймаут"
    return p.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


async def sctl(*args: str) -> tuple[int, str, str]:
    return await run("systemctl", "--user", *args)


async def units_status(units: list[str]) -> dict[str, dict]:
    if not units:
        return {}
    _, out, _ = await sctl("show", "--timestamp=unix", *units, "-p",
                            "Id,LoadState,ActiveState,SubState,MainPID,UnitFileState,"
                            "ActiveEnterTimestamp,NRestarts")
    res: dict[str, dict] = {}
    for block in out.strip().split("\n\n"):
        d = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if "Id" not in d:
            continue
        ts = d.get("ActiveEnterTimestamp", "")
        res[d["Id"]] = {
            "loaded": d.get("LoadState") == "loaded",
            "active": d.get("ActiveState", "unknown"),
            "sub": d.get("SubState", ""),
            "pid": int(d.get("MainPID") or 0),
            "enabled": d.get("UnitFileState", ""),
            "since": int(ts[1:]) if ts.startswith("@") and ts[1:].isdigit() else None,
            "restarts": int(d.get("NRestarts") or 0),
        }
    return res


USER_TOUCH: dict[str, float] = {}


def touch(*units: str) -> None:
    """Пометить units как изменённые пользователем — мониторинг не будет считать это аварией."""
    now = time.time()
    for u in units:
        USER_TOUCH[u] = now


# ─────────────────────────── события и уведомления ──────────────────────────
EVENTS: collections.deque = collections.deque(maxlen=300)
NOTIFY_LAST: dict[str, float] = {}
NOTIFY_STATE: dict[str, Any] = {"available": None, "last_error": None}
_BG: set[asyncio.Task] = set()
ICONS = {"crash": "dialog-warning", "down": "network-error", "recover": "network-transmit-receive",
         "update": "software-update-available", "ip_change": "network-workgroup", "test": "dialog-information"}


def _spawn(coro) -> None:
    try:
        task = asyncio.get_running_loop().create_task(coro)
    except RuntimeError:
        coro.close()
        return
    _BG.add(task)
    task.add_done_callback(_BG.discard)


def event(level: str, source: str, msg: str, kind: str | None = None, key: str | None = None) -> None:
    """level: info|ok|warn|error. kind — тип уведомления (crash/down/recover/update/ip_change)."""
    EVENTS.appendleft({"ts": time.time(), "level": level, "source": source, "msg": msg})
    print(f"[{level}] {source}: {msg}", file=sys.stderr, flush=True)
    if kind and not CLI_MODE:
        _spawn(desktop_notify(kind, key or f"{kind}:{source}", f"ProxyPanel: {source}", msg,
                              "critical" if level == "error" else "normal"))


def _session_env() -> dict[str, str]:
    env = dict(os.environ)
    bus = f"/run/user/{os.getuid()}/bus"
    if "DBUS_SESSION_BUS_ADDRESS" not in env and os.path.exists(bus):
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    return env


async def desktop_notify(kind: str, key: str, title: str, body: str, urgency: str = "normal",
                         force: bool = False) -> bool:
    cfg = try_config()
    n = (cfg or DEFAULTS)["notify"]
    if not force and (not n["enabled"] or not n.get(f"on_{kind}", True)):
        return False
    now = time.time()
    if not force and kind not in ("recover", "update") and now - NOTIFY_LAST.get(key, 0) < n["cooldown"]:
        return False
    NOTIFY_LAST[key] = now
    exe = shutil.which("notify-send")
    NOTIFY_STATE["available"] = exe is not None
    if not exe:
        NOTIFY_STATE["last_error"] = "notify-send не найден (sudo apt install libnotify-bin)"
        return False
    env = _session_env()
    base = [exe, "-a", "ProxyPanel", "-i", ICONS.get(kind, "dialog-information"), "-u", urgency]
    try:
        proc = await asyncio.create_subprocess_exec(
            *base, "--action=open=Открыть панель", title, body,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
    except OSError as e:
        NOTIFY_STATE["last_error"] = f"notify-send: {e}"
        return False
    try:
        # с --action notify-send ждёт клика или закрытия уведомления
        out, err = await asyncio.wait_for(proc.communicate(), 600)
    except asyncio.TimeoutError:
        proc.kill()
        return True
    if proc.returncode != 0:  # старый notify-send без --action, или нет графической сессии
        rc, _, err2 = await run(*base, title, body, timeout=10, env=env)
        if rc != 0:
            NOTIFY_STATE["last_error"] = (err2 or err.decode(errors="replace")).strip()[:300]
            return False
        NOTIFY_STATE["last_error"] = None
        return True
    NOTIFY_STATE["last_error"] = None
    if out.decode().strip() == "open":
        panel = (cfg or DEFAULTS)["panel"]
        url = f"http://127.0.0.1:{panel['port']}/"
        for opener in (["xdg-open", url], ["gio", "open", url]):
            if (await run(*opener, timeout=10, env=env))[0] == 0:
                break
    return True


# ──────────────────────── pp-run и ярлыки приложений ────────────────────────
DESKTOP_DIRS = [HOME / ".local/share/applications", Path("/usr/share/applications"),
                Path("/var/lib/snapd/desktop/applications"), Path("/var/lib/flatpak/exports/share/applications"),
                HOME / ".local/share/flatpak/exports/share/applications"]


def find_icon(cmd: str) -> str:
    """Иконка из установленного .desktop той же программы — чтобы ярлык выглядел привычно."""
    prog = _prog(cmd)

    def same(p: str) -> bool:  # google-chrome ~ google-chrome-stable, telegram-desktop ~ /snap/bin/telegram-desktop
        return p == prog or p.startswith(prog + "-") or prog.startswith(p + "-")

    for d in DESKTOP_DIRS:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.desktop")):
            if f.name.startswith("pp-app-"):
                continue
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            m_exec = re.search(r"(?m)^Exec=(.*)$", text)
            if not m_exec:
                continue
            words = [w for w in m_exec[1].split() if "=" not in w and w != "env"]  # без «env VAR=...»
            if not words or not (same(Path(words[0]).name) or same(f.stem.split("_")[0])):
                continue
            m = re.search(r"(?m)^Icon=(.+)$", text)
            if m:
                return m[1].strip()
    return "network-vpn"


DESKTOP_RESERVED = set(" \t\n\"'\\><~|&;$*?#()`")


def desktop_arg(a: str) -> str:
    """Аргумент Exec= по спецификации Desktop Entry: спецсимволы — в двойных кавычках, % → %%."""
    a = a.replace("%", "%%")
    if not a or any(c in DESKTOP_RESERVED for c in a):
        a = '"' + re.sub(r'(["`$\\])', r"\\\1", a) + '"'
        a = a.replace("\\", "\\\\")  # + общее экранирование строк .desktop (применяется до разбора кавычек)
    return a


def render_desktop(app: str, ad: dict, cfg: dict) -> str:
    t = ad["tunnel"]
    title = ad.get("title") or f"{app.replace('-', ' ').capitalize()} · {t}"
    try:
        words = shlex.split(ad["cmd"])
    except ValueError:
        words = ad["cmd"].split()
    argv = [str(PP_RUN)] + (["--force"] if ad.get("mode") == "proxychains" else []) + [t] + words
    return ("[Desktop Entry]\nType=Application\n"
            f"Name={title}\nComment=Запуск через туннель {t} (ProxyPanel)\n"
            f"Exec={' '.join(desktop_arg(w) for w in argv)} %U\n"
            f"Icon={ad.get('icon') or find_icon(ad['cmd'])}\n"
            "Terminal=false\nCategories=Network;\nX-ProxyPanel=1\n")


def write_run_helpers(cfg: dict, report: dict) -> None:
    """run/env/*.env (порты для pp-run), run/proxychains/*.conf, ярлыки apps → меню."""
    targets = run_targets(cfg)
    ENV_DIR.mkdir(parents=True, exist_ok=True)
    PCHAINS_DIR.mkdir(parents=True, exist_ok=True)
    for n, tg in targets.items():
        write_if_changed(ENV_DIR / f"{n}.env",
                         f"PP_NAME={shlex.quote(n)}\nPP_SOCKS_PORT={tg['socks']}\nPP_HTTP_PORT={tg['http'] or ''}\n"
                         f"PP_UNIT={tg['unit']}\nPP_TITLE={shlex.quote(str(tg['title']))}\n")
        write_if_changed(PCHAINS_DIR / f"{n}.conf",
                         f"# ProxyPanel: {n}\nstrict_chain\nproxy_dns\nquiet_mode\n"
                         "localnet 127.0.0.0/255.0.0.0\n\n[ProxyList]\n"
                         f"socks5 127.0.0.1 {tg['socks']}\n")
    for d, ext in ((ENV_DIR, ".env"), (PCHAINS_DIR, ".conf")):
        for f in d.glob(f"*{ext}"):
            if f.stem not in targets:
                f.unlink(missing_ok=True)
    apps = cfg.get("apps") or {}
    if apps and not PP_RUN.exists():
        report["warnings"].append(f"нет {PP_RUN} — переустановите панель (install.sh), иначе ярлыки не запустятся")
    if apps or APPS_DIR.exists():
        APPS_DIR.mkdir(parents=True, exist_ok=True)
        for a, ad in apps.items():
            write_if_changed(APPS_DIR / f"pp-app-{a}.desktop", render_desktop(a, ad, cfg), 0o644)
        for f in APPS_DIR.glob("pp-app-*.desktop"):
            if f.stem[len("pp-app-"):] not in apps:
                f.unlink(missing_ok=True)


# ─────────────────────────── проверка перед запуском ─────────────────────────
def _search_path() -> str:
    return os.pathsep.join([str(BIN_DIR), str(HOME / ".local/bin"), str(HOME / "bin"), "/usr/local/sbin",
                            "/usr/local/bin", os.environ.get("PATH", "/usr/bin:/bin")])


def _find_prog(prog: str) -> str | None:
    if "/" in prog:
        return prog if os.access(prog, os.X_OK) else None
    return shutil.which(prog, path=_search_path())


def port_busy(port: int, udp: bool = False) -> bool:
    """Занят ли порт по-настоящему (кем-то слушается).
    SO_REUSEADDR — как у самих клиентов (Go ставит его на listen): иначе порт остановленного туннеля
    ещё ~60 с считается занятым из-за соединений в TIME_WAIT, хотя туннель спокойно займёт его снова."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sk:
        if not udp:
            sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sk.bind(("127.0.0.1", port))
            return False
        except OSError:
            return True


def _listener(port: int, udp: bool = False) -> tuple[str, int] | None:
    """(имя процесса, pid), который слушает порт — по ss."""
    try:
        out = subprocess.run(["ss", "-H", "-lunp" if udp else "-ltnp", f"sport = :{port}"],
                             capture_output=True, text=True, timeout=3).stdout
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', out)
    return (m[1], int(m[2])) if m else None


def pid_unit(pid: int | None) -> str | None:
    """systemd-unit процесса (по cgroup): pp-xxx.service, если это процесс панели."""
    if not pid:
        return None
    try:
        cg = Path(f"/proc/{pid}/cgroup").read_text()
    except OSError:
        return None
    m = re.search(r"/(pp-[^/]+\.service)", cg)
    return m[1] if m else None


def preflight(cfg: dict, st: dict[str, dict]) -> dict[str, list[str]]:
    """Что помешает туннелю запуститься: нет программы, нет файла, порт занят чужим процессом."""
    out: dict[str, list[str]] = {}
    sb_ok = singbox_bin(cfg) is not None

    def busy(port: int, what: str, udp: bool = False) -> str | None:
        if not port_busy(port, udp):
            return None
        who = _listener(port, udp)
        if who and pid_unit(who[1]):  # порт держит процесс панели (сам туннель / обфускатор / мост при рестарте)
            return None
        owner = f"{who[0]} (pid {who[1]})" if who else ""
        return (f"порт {port}{' (UDP)' if udp else ''} {what} уже занят"
                + (f": {owner}" if owner else " другим процессом"))

    for n, t in cfg["tunnels"].items():
        p: list[str] = []
        running = (st.get(unit_of(n)) or {}).get("active") == "active"
        if (t["native"] or t.get("_http_mode") == "bridge") and not sb_ok:
            p.append("нет sing-box — установите в разделе «Компоненты»")
        if not t["native"]:
            cmd = tunnel_cmd(n, t, cfg)
            try:
                words = shlex.split(cmd)
            except ValueError:
                words = cmd.split()
            words = [w for w in words if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w)]  # VAR=… перед командой
            if words and words[0] not in ("exec", "env") and not _find_prog(words[0]):
                p.append(f"программа «{words[0]}» не найдена — установите её (раздел «Компоненты» или PATH)")
            for w in words[1:]:
                path = w.split("=", 1)[-1]
                if (path.startswith((str(HOME), str(MAIN), str(CONF_DIR))) and not path.startswith(str(RUN_DIR))
                        and not os.path.exists(path) and re.search(r"\.(conf|ya?ml|json|toml|key|pem)$", path)):
                    p.append(f"нет файла {path}")
        if t.get("_obfs_port") and not _find_prog("wg-obfuscator"):
            p.append("нет wg-obfuscator — установите в разделе «Компоненты»")
        if not running:
            for port, what, udp in ((t.get("port"), "SOCKS", False), (t.get("http_port"), "HTTP", False),
                                    (t.get("_obfs_port"), "обфускатора", True)):
                if port and (msg := busy(port, what, udp)):
                    p.append(msg)
        if p:
            out[n] = p
    sb = cfg["singbox"]
    if sb["enabled"]:
        p = [] if sb_ok else ["нет sing-box — установите в разделе «Компоненты»"]
        if (st.get(SINGBOX_UNIT) or {}).get("active") != "active":
            for port, what in ((sb["port"], "единого входа"), (sb["clash_api_port"], "Clash API")):
                if msg := busy(port, what):
                    p.append(msg)
            for g, gd in cfg["groups"].items():
                if gd.get("port") and (msg := busy(gd["port"], f"группы {g}")):
                    p.append(msg)
        if p:
            out["singbox"] = p
    return out


# ─────────────────────────────── apply ─────────────────────────────────
async def _singbox_check(binary: str | None, conf: dict, label: str) -> None:
    if not binary:
        return
    tmp = RUN_DIR / f".check-{label}.json"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(conf, ensure_ascii=False))
    rc, out, err = await run(binary, "check", "-c", str(tmp))
    tmp.unlink(missing_ok=True)
    if rc != 0:
        msg = re.sub(r"\x1b\[[0-9;]*m", "", (err or out)).strip()  # без цветовых кодов терминала
        msg = msg.replace(str(tmp), f"конфиг {label}")
        raise ConfigError(f"sing-box check ({label}) не прошёл:\n{msg}")


def conf_hash() -> str | None:
    try:
        return hashlib.sha256(CONF_FILE.read_bytes()).hexdigest()
    except OSError:
        return None


APPLY_LOCK = asyncio.Lock()


async def apply_config() -> dict:
    # два одновременных «Применить» (кнопка + «Применить и запустить», CLI) писали бы одни и те же файлы
    async with APPLY_LOCK:
        return await _apply_config()


async def _apply_config() -> dict:
    applied = conf_hash()
    cfg = load_config()
    secure_dirs()
    report: dict[str, list] = {"created": [], "restarted": [], "removed": [], "warnings": list(cfg["_warnings"]),
                               "blocked": []}
    wanted: dict[str, tuple[bool, bool, bool]] = {}  # unit -> (new, changed, autostart)
    binary = singbox_bin(cfg)
    st_before = await units_status(list(all_units(cfg)))
    problems = preflight(cfg, st_before)
    blocked_units: dict[str, str] = {}  # unit -> текст проблемы
    for n, plist in problems.items():
        blocked_units[SINGBOX_UNIT if n == "singbox" else unit_of(n)] = f"{n} не запускаю: " + "; ".join(plist)
    need_sb = cfg["singbox"]["enabled"] or any(t["native"] for t in cfg["tunnels"].values())
    if need_sb and not binary:
        report["warnings"].append("sing-box не найден — установите его в разделе «Компоненты»")
    if any(t.get("_obfs_port") for t in cfg["tunnels"].values()) and not (
            os.access(BIN_DIR / "wg-obfuscator", os.X_OK) or shutil.which("wg-obfuscator")):
        report["warnings"].append("wg-obfuscator не найден — установите его в разделе «Компоненты»")

    # сначала всё проверяем, потом пишем — чтобы не оставить половину изменений
    natives = {n: build_native(n, t, cfg) for n, t in cfg["tunnels"].items() if t["native"]}
    bridges = {n: build_http_bridge(n, t, cfg) for n, t in cfg["tunnels"].items() if t.get("_http_mode") == "bridge"}
    if bridges and not binary:
        report["warnings"].append("HTTP-мосту нужен sing-box — установите его в разделе «Компоненты»")
    for n, conf in natives.items():
        await _singbox_check(binary, conf, n)
    for n, conf in bridges.items():
        await _singbox_check(binary, conf, f"{n}-http")
    combiner = build_singbox(cfg) if cfg["singbox"]["enabled"] else None
    if combiner:
        await _singbox_check(binary, combiner, "комбинатор")

    for name, t in cfg["tunnels"].items():
        changed = False
        if t["native"]:
            changed |= write_if_changed(RUN_DIR / f"{name}.json",
                                        json.dumps(natives[name], indent=2, ensure_ascii=False) + "\n", 0o600)
        elif "_config_src" in t:
            for path, text in render_config(name, t, cfg).items():
                changed |= write_if_changed(path, text, 0o600)
        if t.get("_obfs_port"):
            oc = write_if_changed(RUN_DIR / f"{name}-obfs.conf", render_obfs_conf(name, t), 0o600)
            os_ = write_if_changed(RUN_DIR / f"{name}-obfs.sh",
                                   _script(f"wg-obfuscator -c {shlex.quote(str(RUN_DIR / (name + '-obfs.conf')))}"),
                                   0o700)
            opath = UNIT_DIR / obfs_unit(name)
            onew = not opath.exists()
            ou = write_if_changed(opath, render_obfs_unit(name))
            wanted[opath.name] = (onew, oc or os_ or ou, False)  # стартует вместе с туннелем
        if name in bridges:
            hc = write_if_changed(RUN_DIR / f"{name}-http.json",
                                  json.dumps(bridges[name], indent=2, ensure_ascii=False) + "\n", 0o600)
            bridge_conf = shlex.quote(str(RUN_DIR / f"{name}-http.json"))
            hs = write_if_changed(RUN_DIR / f"{name}-http.sh",
                                  _script(f"{shlex.quote(binary or 'sing-box')} run -c {bridge_conf}"), 0o700)
            hpath = UNIT_DIR / http_unit(name)
            hnew = not hpath.exists()
            hu = write_if_changed(hpath, render_http_unit(name))
            wanted[hpath.name] = (hnew, hc or hs or hu, False)  # стартует вместе с туннелем
        changed |= write_if_changed(RUN_DIR / f"{name}.sh", render_script(name, t, cfg), 0o700)
        upath = UNIT_DIR / unit_of(name)
        new = not upath.exists()
        changed |= write_if_changed(upath, render_unit(name, t, cfg))
        wanted[upath.name] = (new, changed, bool(t.get("autostart", True)))

    if combiner:
        c1 = write_if_changed(SINGBOX_JSON, json.dumps(combiner, indent=2, ensure_ascii=False) + "\n", 0o600)
        upath = UNIT_DIR / SINGBOX_UNIT
        new = not upath.exists()
        c2 = write_if_changed(upath, render_singbox_unit(binary or str(BIN_DIR / "sing-box")))
        wanted[SINGBOX_UNIT] = (new, c1 or c2, True)

    if UNIT_DIR.exists():
        for p in sorted(UNIT_DIR.glob(f"{PREFIX}*.service")):
            if p.name in wanted or p.name == PANEL_UNIT:
                continue
            touch(p.name)
            await sctl("disable", "--now", p.name)
            p.unlink(missing_ok=True)
            base = p.stem[len(PREFIX):]
            for f in RUN_DIR.glob(f"{base}.*"):
                f.unlink(missing_ok=True)
            report["removed"].append(p.stem)

    write_run_helpers(cfg, report)

    rc, _, err = await sctl("daemon-reload")
    if rc != 0:
        report["warnings"].append(f"daemon-reload: {err.strip()}")

    touch(*wanted)
    # обёртки — первыми: туннель после рестарта сразу найдёт обфускатор
    def sidecar_first(kv: tuple) -> bool:
        return not kv[0].endswith(("-obfs.service", "-http.service"))

    for unit, (new, changed, autostart) in sorted(wanted.items(), key=sidecar_first):
        if unit in blocked_units:
            # заведомо не запустится: не плодим цикл падений; если уже крутится в рестартах — останавливаем
            looping = (st_before.get(unit) or {}).get("active") in ("activating", "failed")
            if looping:
                await sctl("stop", unit)
            if looping or (new and autostart):
                report["warnings"].append(blocked_units[unit])
                report["blocked"].append(unit.removeprefix(PREFIX).removesuffix(".service"))
            if new:
                report["created"].append(unit)
                if autostart:  # после исправления проблемы туннель поднимется сам при загрузке
                    await sctl("enable", unit)
            continue
        if new:
            report["created"].append(unit)
            if autostart:
                rc, _, err = await sctl("enable", "--now", unit)
                if rc != 0:
                    report["warnings"].append(f"{unit}: {err.strip()}")
        elif changed:
            await sctl("try-restart", unit)
            report["restarted"].append(unit)
    kick(*cfg["tunnels"], ENTRY)
    load_state()  # в CLI состояние ещё не загружено — не затираем installed/updates
    STATE["applied_hash"] = applied
    save_state()
    if report["created"] or report["restarted"] or report["removed"]:
        event("info", "конфиг", "применён: " + ", ".join(
            f"{k} {len(v)}" for k, v in report.items() if v and k != "warnings"))
    return report


# ─────────────────────────────── health ────────────────────────────────
HEALTH: dict[str, dict] = {}
HSTATE: dict[str, dict] = {}
_FORCE_IP: set[str] = set()
_KICK: asyncio.Event | None = None
IP_FIELDS = ("ip", "country", "city", "org")


def kick(*names: str) -> None:
    _FORCE_IP.update(names)
    if _KICK is not None:
        _KICK.set()


async def probe(port: int, h: dict, with_ip: bool, http_port: int | None = None) -> dict:
    # Жёсткий таймаут: SOCKS-рукопожатие в httpcore читается без таймаута, и туннель,
    # который принял соединение, но молчит (мёртвый WireGuard), подвесил бы весь цикл проверок.
    limit = float(h["timeout"]) * (2 if with_ip else 1) + 2
    try:
        return await asyncio.wait_for(_probe(port, h, with_ip, http_port), limit + (h["timeout"] if http_port else 0))
    except asyncio.TimeoutError:
        return {"checked_at": time.time(), "ok": False,
                "error": f"таймаут {limit:.0f} с: туннель принял соединение, но не отвечает"}


async def _probe(port: int, h: dict, with_ip: bool, http_port: int | None = None) -> dict:
    r: dict[str, Any] = {"checked_at": time.time()}
    try:
        async with httpx.AsyncClient(proxy=f"socks5h://127.0.0.1:{port}", timeout=h["timeout"],
                                     trust_env=False) as c:
            t0 = time.perf_counter()
            resp = await c.get(h["url"])
            r["rtt_ms"] = round((time.perf_counter() - t0) * 1000)
            r["ok"] = resp.status_code < 400
            if with_ip:
                # сервис IP мог ответить 429/HTML — это не повод считать туннель упавшим
                try:
                    j = (await c.get(h["ip_url"], headers={"Accept": "application/json"})).json()
                    if isinstance(j, dict):
                        r.update({k: j.get(k) for k in IP_FIELDS})
                except Exception as e:
                    r["ip_error"] = f"{type(e).__name__}: {e}"[:200]
    except Exception as e:
        r.update(ok=False, error=f"{type(e).__name__}: {e}"[:300])
    if http_port:  # отдельный HTTP-вход (мост / [http] wireproxy / http hysteria)
        try:
            async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{http_port}", timeout=h["timeout"],
                                         trust_env=False) as c:
                r["http_ok"] = (await c.get(h["url"])).status_code < 400
        except Exception as e:
            r.update(http_ok=False, http_error=f"{type(e).__name__}: {e}"[:200])
    return r


def _label(n: str, cfg: dict) -> str:
    return f"вход :{cfg['singbox']['port']}" if n == ENTRY else n


def health_transition(cfg: dict, n: str, r: dict, prev: dict) -> None:
    st = HSTATE.setdefault(n, {"fails": 0, "down": False})
    thr = int(cfg["notify"]["fail_threshold"])
    label = _label(n, cfg)
    if r.get("ok") is True:
        if st["down"]:
            event("ok", label, f"снова работает ({r.get('rtt_ms')} ms)", kind="recover")
        st.update(fails=0, down=False)
        if n == ENTRY and prev.get("ip") and r.get("ip") and prev["ip"] != r["ip"]:
            event("info", label, f"сменился exit IP: {prev['ip']} → {r['ip']} {r.get('country') or ''}",
                  kind="ip_change")
    elif r.get("ok") is False:
        st["fails"] += 1
        if not st["down"] and st["fails"] >= thr:
            st["down"] = True
            event("error", label, f"не отвечает: {r.get('error', '?')}", kind="down")
    else:
        st.update(fails=0, down=False)


async def health_cycle() -> None:
    cfg = load_config()
    h = cfg["health"]
    targets: dict[str, tuple[str, int]] = {}  # name -> (unit, SOCKS-порт)
    http_ports: dict[str, int] = {}
    for n, t in cfg["tunnels"].items():
        if t["exit"]:
            targets[n] = (unit_of(n), t["port"])
            if t.get("_http_port") and t["_http_port"] != t["port"]:
                http_ports[n] = t["_http_port"]
    if cfg["singbox"]["enabled"]:
        targets[ENTRY] = (SINGBOX_UNIT, cfg["singbox"]["port"])
    st = await units_status(sorted({u for u, _ in targets.values()}))
    now = time.time()
    jobs: dict[str, tuple[Any, bool]] = {}
    for n, (unit, port) in targets.items():
        if st.get(unit, {}).get("active") != "active":
            HEALTH[n] = {"ok": None, "checked_at": now}
            HSTATE.pop(n, None)
            continue
        prev = HEALTH.get(n, {})
        need_ip = n in _FORCE_IP or "ip" not in prev or now - prev.get("ip_at", 0) >= h["ip_interval"]
        jobs[n] = (probe(port, h, need_ip, http_ports.get(n)), need_ip)
    _FORCE_IP.difference_update(jobs)
    results = await asyncio.gather(*(j[0] for j in jobs.values()))
    for (n, (_, need_ip)), r in zip(jobs.items(), results, strict=True):
        prev = HEALTH.get(n, {})
        if need_ip and r.get("ok") and "ip_error" not in r:
            r["ip_at"] = r["checked_at"]
        else:
            for k in (*IP_FIELDS, "ip_at"):
                if k in prev and k not in r:
                    r[k] = prev[k]
        health_transition(cfg, n, r, prev)
        HEALTH[n] = r


async def health_loop() -> None:
    global _KICK
    _KICK = asyncio.Event()
    while True:
        try:
            await health_cycle()
        except ConfigError:
            pass
        except Exception as e:
            print(f"health: {type(e).__name__}: {e}", file=sys.stderr)
        cfg = try_config()
        interval = cfg["health"]["interval"] if cfg else 30
        try:
            await asyncio.wait_for(_KICK.wait(), timeout=interval)
            await asyncio.sleep(1.5)
        except asyncio.TimeoutError:
            pass
        _KICK.clear()


# ─────────────────────── мониторинг процессов (systemd) ─────────────────────
PREV_UNITS: dict[str, dict] = {}
CRASHES: dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=20))
LOOPING: dict[str, dict] = {}  # unit -> {since, last_restart, reason}: о цикле сообщаем один раз


async def last_log_line(unit: str) -> str:
    """Последняя содержательная строка журнала unit — обычно там причина падения."""
    _, out, _ = await run("journalctl", "--user", "-u", unit, "-n", "12", "--no-pager", "-o", "cat", timeout=5)
    skip = ("Started ", "Stopped ", "Scheduled restart", "Main process exited", "Failed with result",
            "Consumed ", "Starting ", "Stopping ", "Deactivated successfully")
    lines = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.strip().startswith(skip)
             and not re.match(r"^pp-.*\.service: ", ln.strip())]
    return (lines[-1] if lines else "")[:220]


async def monitor_cycle(first: bool) -> None:
    cfg = load_config()
    units = all_units(cfg)
    st = await units_status(list(units))
    now = time.time()
    for u, name in units.items():
        cur, prev = st.get(u), PREV_UNITS.get(u)
        PREV_UNITS[u] = cur or {}
        if first or not cur or not prev or not cur.get("loaded"):
            continue
        if now - USER_TOUCH.get(u, 0) < 20:
            LOOPING.pop(u, None)  # пользователь сам стартовал/остановил — начинаем с чистого листа
            continue
        restarted = cur["restarts"] > prev.get("restarts", 0)
        if restarted:
            CRASHES[u].append(now)
            if u in LOOPING:  # уже сообщили — молчим, только запоминаем
                LOOPING[u]["last_restart"] = now
                continue
            recent = sum(1 for x in CRASHES[u] if now - x < 300)
            reason = await last_log_line(u)
            tail = f": {reason}" if reason else " — смотрите логи"
            if recent >= 3:
                LOOPING[u] = {"since": now, "last_restart": now, "reason": reason}
                event("error", name, f"падает в цикле ({recent} рестартов за 5 мин){tail}",
                      kind="crash", key=f"crashloop:{name}")
            else:
                event("warn", name, f"процесс упал, systemd перезапустил{tail}", kind="crash")
        elif u in LOOPING and cur["active"] == "active" and now - LOOPING[u]["last_restart"] > 90:
            LOOPING.pop(u)
            event("ok", name, "перестал падать — работает стабильно", kind="recover")
        elif prev.get("active") == "active" and cur["active"] in ("failed", "inactive"):
            reason = await last_log_line(u)
            event("error", name, f"остановился ({cur['active']}/{cur['sub']})" + (f": {reason}" if reason else ""),
                  kind="crash")


async def monitor_loop() -> None:
    first = True
    while True:
        try:
            await monitor_cycle(first)
            first = False
        except ConfigError:
            pass
        except Exception as e:
            print(f"monitor: {type(e).__name__}: {e}", file=sys.stderr)
        await asyncio.sleep(5)


# ───────────────────────────── Clash API ───────────────────────────────
async def clash(method: str, path: str, timeout: float = 5, **kw: Any) -> Any:
    cfg = load_config()
    url = f"http://127.0.0.1:{cfg['singbox']['clash_api_port']}{path}"
    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as c:
        r = await c.request(method, url, headers={"Authorization": f"Bearer {clash_secret(cfg)}"}, **kw)
        r.raise_for_status()
        return r.json() if r.content else None


# ─────────────────────────── состояние на диске ──────────────────────────
STATE: dict[str, Any] = {"installed": {}, "updates": {}, "updates_meta": {}, "notified": {}}


def load_state() -> None:
    try:
        STATE.update(json.loads(STATE_FILE.read_text()))
    except (OSError, ValueError):
        pass


def save_state() -> None:
    try:
        write_if_changed(STATE_FILE, json.dumps(STATE, indent=2, ensure_ascii=False), 0o600)
    except OSError as e:
        print(f"state: {e}", file=sys.stderr)


# ──────────────────────────── обновления бинарников ─────────────────────────
INSTALL_LOCK = asyncio.Lock()
_VERSION_CACHE: dict[tuple[str, float], str | None] = {}
VER_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)")


def components(cfg: dict | None) -> dict[str, dict]:
    upd = (cfg or DEFAULTS)["updates"]
    comps = deep_merge(COMPONENTS, upd.get("components") or {})
    return {k: v for k, v in comps.items() if k not in (upd.get("disabled") or [])}


def host_arch() -> str:
    a = ARCH_MAP.get(platform.machine().lower())
    if not a:
        raise RuntimeError(f"архитектура {platform.machine()} не поддерживается")
    return a


def parse_ver(s: str | None) -> tuple | None:
    if not s:
        return None
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?(-[0-9A-Za-z.]+)?", s)
    if not m:
        return None
    return int(m[1]), int(m[2]), int(m[3] or 0), 0 if m[4] else 1


async def binary_version(path: str, args: list[str]) -> str | None:
    try:
        key = (path, os.stat(path).st_mtime)
    except OSError:
        return None
    if key in _VERSION_CACHE:
        return _VERSION_CACHE[key]
    _, out, err = await run(path, *args, timeout=8)
    m = VER_RE.search(out + "\n" + err)
    _VERSION_CACHE[key] = m[1] if m else None
    return _VERSION_CACHE[key]


async def installed_info(name: str, comp: dict) -> dict:
    local = BIN_DIR / comp["bin"]
    path = str(local) if os.access(local, os.X_OK) else shutil.which(comp["bin"])
    info: dict[str, Any] = {"path": path, "managed": path == str(local),
                            "rollback": os.access(BIN_DIR / f"{comp['bin']}.old", os.X_OK)}
    if path:
        info["version"] = await binary_version(path, comp.get("version_args", ["--version"]))
        if not info["version"] and info["managed"]:
            info["version"] = (STATE["installed"].get(name) or {}).get("version")
    return info


def _proxies(cfg: dict) -> list[str | None]:
    p = cfg["updates"].get("proxy") or "auto"
    if p == "direct":
        return [None]
    if p == "auto":
        # напрямую → через комбинатор → через каждый туннель (сначала те, что сейчас отвечают)
        out: list[str | None] = [None]
        if cfg["singbox"]["enabled"]:
            out.append(f"socks5h://127.0.0.1:{cfg['singbox']['port']}")
        exits = [(n, t["port"]) for n, t in cfg["tunnels"].items() if t["exit"]]
        def rank(e: tuple[str, int]) -> tuple[bool, float]:
            h = HEALTH.get(e[0], {})
            return h.get("ok") is not True, h.get("rtt_ms") or 1e9
        exits.sort(key=rank)
        out += [f"socks5h://127.0.0.1:{port}" for _, port in exits]
        return out
    return [p]


def _gh_headers(cfg: dict, api: bool) -> dict[str, str]:
    h = {"User-Agent": "ProxyPanel"}
    if api:
        h["Accept"] = "application/vnd.github+json"
        if cfg["updates"].get("github_token"):
            h["Authorization"] = f"Bearer {cfg['updates']['github_token']}"
    return h


def _client(proxy: str | None, timeout: float) -> httpx.AsyncClient:
    # Напрямую — с учётом системных настроек (HTTPS_PROXY, SSL_CERT_FILE); через туннель — без них.
    if proxy is None:
        return httpx.AsyncClient(timeout=timeout, follow_redirects=True, trust_env=True)
    return httpx.AsyncClient(timeout=timeout, follow_redirects=True, trust_env=False, proxy=proxy)


async def gh_get(cfg: dict, url: str, api: bool = True) -> tuple[httpx.Response, str]:
    last: Exception | None = None
    for proxy in _proxies(cfg):
        try:
            async with _client(proxy, 20) as c:
                r = await c.get(url, headers=_gh_headers(cfg, api))
                if r.status_code == 403 and "rate limit" in r.text.lower():
                    raise RuntimeError("лимит GitHub API (60 запросов/час) — задайте updates.github_token")
                r.raise_for_status()
                return r, (proxy.replace("socks5h://127.0.0.1:", "через :") if proxy else "напрямую")
        except RuntimeError:
            raise
        except Exception as e:
            last = e
    raise RuntimeError(f"GitHub недоступен: {type(last).__name__}: {last}")


async def gh_download(cfg: dict, url: str, dest: Path, limit: int = 300 * 2**20) -> tuple[str, int]:
    last: Exception | None = None
    for proxy in _proxies(cfg):
        try:
            h = hashlib.sha256()
            size = 0
            async with _client(proxy, 60) as c, c.stream("GET", url, headers=_gh_headers(cfg, False)) as r:
                r.raise_for_status()
                with dest.open("wb") as f:
                    async for chunk in r.aiter_bytes(1 << 16):
                        size += len(chunk)
                        if size > limit:
                            raise RuntimeError("файл больше 300 МБ — подозрительно, отмена")
                        h.update(chunk)
                        f.write(chunk)
            return h.hexdigest(), size
        except RuntimeError:
            raise
        except Exception as e:
            last = e
    raise RuntimeError(f"не удалось скачать {url}: {type(last).__name__}: {last}")


async def check_component(cfg: dict, name: str, comp: dict) -> dict:
    arch = host_arch()
    pat = re.compile(comp["asset"][arch])
    tag_re = re.compile(comp.get("tag_re") or ".")
    r, route = await gh_get(cfg, f"{GITHUB_API}/repos/{comp['repo']}/releases?per_page=30")
    for rel in r.json():
        if rel.get("draft") or (rel.get("prerelease") and not cfg["updates"]["prerelease"]):
            continue
        if not tag_re.search(rel.get("tag_name", "")):
            continue
        assets = rel.get("assets") or []
        asset = next((a for a in assets if pat.match(a["name"])), None)
        if not asset:
            continue
        sums = next((a for a in assets if a["name"] in CHECKSUM_FILES or a["name"] == asset["name"] + ".sha256"), None)
        m = VER_RE.search(rel["tag_name"])
        return {
            "tag": rel["tag_name"], "version": m[1] if m else rel["tag_name"],
            "asset": asset["name"], "url": asset["browser_download_url"], "size": asset.get("size"),
            "digest": asset.get("digest"), "sums_url": sums["browser_download_url"] if sums else None,
            "html_url": rel.get("html_url"), "published": rel.get("published_at"),
            "checked_at": time.time(), "route": route,
        }
    raise RuntimeError(f"в последних релизах {comp['repo']} нет файла для linux-{arch}")


async def check_updates(cfg: dict) -> dict:
    meta = STATE.setdefault("updates_meta", {})
    errors = []
    for name, comp in components(cfg).items():
        try:
            STATE["updates"][name] = await check_component(cfg, name, comp)
            meta["route"] = STATE["updates"][name]["route"]
        except Exception as e:
            STATE["updates"][name] = {**STATE["updates"].get(name, {}), "error": str(e)[:300],
                                      "checked_at": time.time()}
            errors.append(f"{name}: {e}")
    meta.update(checked_at=time.time(), error="; ".join(errors)[:600] or None)
    save_state()
    for name, comp in components(cfg).items():
        latest = STATE["updates"].get(name, {})
        if latest.get("error"):
            continue
        inst = await installed_info(name, comp)
        if inst.get("path") and update_available(inst.get("version"), latest.get("version")) \
                and STATE["notified"].get(name) != latest["version"]:
            STATE["notified"][name] = latest["version"]
            event("info", name, f"доступна версия {latest['version']} (установлена {inst.get('version') or '?'})",
                  kind="update", key=f"update:{name}:{latest['version']}")
    save_state()
    return STATE["updates"]


def update_available(installed: str | None, latest: str | None) -> bool:
    a, b = parse_ver(installed), parse_ver(latest)
    return bool(a and b and b > a)


def _expected_sha(info: dict, sums_text: str | None) -> str | None:
    d = info.get("digest") or ""
    if d.startswith("sha256:"):
        return d.split(":", 1)[1].lower()
    if sums_text:
        for line in sums_text.splitlines():
            parts = line.replace("*", " ").split()
            if len(parts) >= 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]) and Path(parts[-1]).name == info["asset"]:
                return parts[0].lower()
            if len(parts) >= 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[-1]) and Path(parts[0]).name == info["asset"]:
                return parts[-1].lower()
    return None


def _extract(archive: Path, asset: str, binname: str) -> bytes:
    if asset.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar")):
        with tarfile.open(archive) as tf:
            files = [m for m in tf.getmembers() if m.isfile()]
            m = next((m for m in files if Path(m.name).name == binname), None)
            if m is None:
                execs = [m for m in files if m.mode & 0o111]
                m = execs[0] if len(execs) == 1 else None
            if m is None:
                raise RuntimeError(f"в архиве нет файла {binname}: {[x.name for x in files][:10]}")
            f = tf.extractfile(m)
            assert f
            return f.read()
    if asset.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            n = next((n for n in zf.namelist() if Path(n).name == binname), None)
            if n is None:
                raise RuntimeError(f"в архиве нет файла {binname}")
            return zf.read(n)
    return archive.read_bytes()


def affected_units(cfg: dict | None, binname: str) -> list[str]:
    if not cfg:
        return []
    word = re.compile(rf"(^|[\s/]){re.escape(binname)}(\s|$)")
    units = []
    for n, t in cfg["tunnels"].items():
        if (t["native"] and binname == "sing-box") or (not t["native"] and word.search(t["cmd"])):
            units.append(unit_of(n))
        if t.get("_obfs_port") and binname == "wg-obfuscator":
            units.append(obfs_unit(n))
        if t.get("_http_mode") == "bridge" and binname == "sing-box":
            units.append(http_unit(n))
    if binname == "sing-box" and cfg["singbox"]["enabled"]:
        units.append(SINGBOX_UNIT)
    return units


async def _relink_and_restart(cfg: dict | None, binname: str) -> tuple[list[str], list[str]]:
    warnings: list[str] = []
    applied_before = UNIT_DIR.exists() and any(p.name != PANEL_UNIT for p in UNIT_DIR.glob(f"{PREFIX}*.service"))
    load_state()
    pending = conf_hash() != STATE.get("applied_hash")
    if cfg and applied_before and not pending:  # на свежей установке пример-конфиг не применяем
        try:
            await apply_config()  # перепишет ExecStart sing-box, если бинарь переехал в ~/main/bin
        except ConfigError as e:
            warnings.append(f"конфиг не применён: {e}")
    elif cfg and applied_before and pending:
        warnings.append("в конфиге есть неприменённые изменения — нажмите «Применить», чтобы туннели "
                        "перешли на новый бинарь")
    units = affected_units(cfg, binname)
    touch(*units)
    for u in units:
        await sctl("try-restart", u)
    kick(*((cfg or {}).get("tunnels") or {}), ENTRY)
    return units, warnings


async def install_component(name: str) -> dict:
    cfg = try_config() or parse_config("")
    comps = components(cfg)
    if name not in comps:
        raise HTTPException(404, f"нет компонента {name!r}")
    comp = comps[name]
    async with INSTALL_LOCK:
        info = await check_component(cfg, name, comp)  # всегда свежие URL и контрольная сумма
        STATE["updates"][name] = info
        BIN_DIR.mkdir(parents=True, exist_ok=True)
        tmpdir = BIN_DIR / ".pp-tmp"
        shutil.rmtree(tmpdir, ignore_errors=True)
        tmpdir.mkdir()
        try:
            dl = tmpdir / info["asset"]
            sha, size = await gh_download(cfg, info["url"], dl)
            sums = None
            if not (info.get("digest") or "").startswith("sha256:") and info.get("sums_url"):
                sums = (await gh_get(cfg, info["sums_url"], api=False))[0].text
            expected = _expected_sha(info, sums)
            if expected and expected != sha:
                raise RuntimeError(f"sha256 не совпадает: ожидалось {expected}, получено {sha}")
            verified = bool(expected)
            data = _extract(dl, info["asset"], comp["bin"])
            new = BIN_DIR / f".{comp['bin']}.new"
            new.write_bytes(data)
            new.chmod(0o755)
            rc, out, err = await run(str(new), *comp.get("version_args", ["--version"]), timeout=10)
            got = VER_RE.search(out + "\n" + err)
            if not got:
                new.unlink(missing_ok=True)
                raise RuntimeError(f"новый бинарь не запускается: {(err or out).strip()[:200] or f'код {rc}'}")
            dest = BIN_DIR / comp["bin"]
            if dest.exists():
                os.replace(dest, BIN_DIR / f"{comp['bin']}.old")
            os.replace(new, dest)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        STATE["installed"][name] = {"version": got[1], "tag": info["tag"], "sha256": sha, "size": size,
                                    "verified": verified, "installed_at": time.time()}
        save_state()
        units, warnings = await _relink_and_restart(try_config(), comp["bin"])
        if not verified:
            warnings.append("у релиза нет контрольной суммы — sha256 не проверен")
        event("ok", name, f"установлен {got[1]}" + (" (sha256 ✓)" if verified else "") +
              (f", перезапущено: {', '.join(units)}" if units else ""))
        return {"name": name, "version": got[1], "verified": verified, "restarted": units, "warnings": warnings}


async def rollback_component(name: str) -> dict:
    cfg = try_config()
    comps = components(cfg)
    if name not in comps:
        raise HTTPException(404, f"нет компонента {name!r}")
    b = comps[name]["bin"]
    cur, old, tmp = BIN_DIR / b, BIN_DIR / f"{b}.old", BIN_DIR / f".{b}.swap"
    async with INSTALL_LOCK:
        if not old.exists():
            raise HTTPException(400, "предыдущей версии нет")
        if cur.exists():
            os.replace(cur, tmp)
        os.replace(old, cur)
        if tmp.exists():
            os.replace(tmp, old)  # можно «откатить откат»
        STATE["installed"].pop(name, None)
        save_state()
        units, warnings = await _relink_and_restart(cfg, b)
        ver = await binary_version(str(cur), comps[name].get("version_args", ["--version"]))
        event("warn", name, f"откат на {ver or 'предыдущую версию'}")
        return {"name": name, "version": ver, "restarted": units, "warnings": warnings}


async def updates_loop() -> None:
    await asyncio.sleep(45)
    while True:
        cfg = try_config()
        hours = 12.0
        if cfg and cfg["updates"]["enabled"]:
            hours = float(cfg["updates"]["check_interval_h"])
            last = STATE.get("updates_meta", {}).get("checked_at") or 0
            if time.time() - last >= hours * 3600 - 60:
                try:
                    await check_updates(cfg)
                    if cfg["updates"]["auto_install"]:
                        for name, comp in components(cfg).items():
                            inst = await installed_info(name, comp)
                            if inst.get("managed") and update_available(
                                    inst.get("version"), STATE["updates"].get(name, {}).get("version")):
                                try:
                                    await install_component(name)
                                except Exception as e:
                                    event("error", name, f"автообновление не удалось: {e}")
                except Exception as e:
                    print(f"updates: {e}", file=sys.stderr)
        await asyncio.sleep(min(3600.0, max(300.0, hours * 3600 / 4)))


# ─────────────────────────────── FastAPI ───────────────────────────────
@asynccontextmanager
async def lifespan(_: FastAPI):
    load_state()
    NOTIFY_STATE["available"] = shutil.which("notify-send") is not None
    tasks = [asyncio.create_task(f()) for f in (health_loop, monitor_loop, updates_loop)]
    event("info", "панель", "запущена")
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title="ProxyPanel", version=__version__, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


def _host_ok(host_header: str) -> bool:
    h = host_header.strip().lower()
    h = h[: h.index("]") + 1] if h.startswith("[") and "]" in h else h.split(":")[0]
    return h in ALLOWED_HOSTS


@app.middleware("http")
async def guard(request: Request, call_next):
    # Защита от DNS rebinding (Host) и CSRF (кастомный заголовок не отправить с чужого сайта без CORS).
    if not _host_ok(request.headers.get("host", "")):
        return PlainTextResponse("forbidden host", status_code=403)
    if request.url.path.startswith("/api/") and request.headers.get("x-pp") != "1":
        return PlainTextResponse("missing X-PP header", status_code=403)
    return await call_next(request)


@app.exception_handler(ConfigError)
async def _cfg_err(_: Request, e: ConfigError):
    return JSONResponse({"detail": str(e)}, status_code=400)


@app.exception_handler(RuntimeError)
async def _rt_err(_: Request, e: RuntimeError):
    return JSONResponse({"detail": str(e)}, status_code=502)


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"})


def _known(cfg: dict, name: str, for_logs: bool = False) -> str:
    if name == "singbox" and cfg["singbox"]["enabled"]:
        return SINGBOX_UNIT
    if name in cfg["tunnels"]:
        return unit_of(name)
    base = name[:-5] if name.endswith(("-obfs", "-http")) else None
    if base in cfg["tunnels"] and name.endswith("-obfs") and cfg["tunnels"][base].get("_obfs_port"):
        return obfs_unit(base)
    if base in cfg["tunnels"] and name.endswith("-http") and cfg["tunnels"][base].get("_http_mode") == "bridge":
        return http_unit(base)
    raise HTTPException(404, f"нет туннеля {name!r}")


@app.get("/api/state")
async def state():
    base = {"events": list(EVENTS)[:80], "notify": NOTIFY_STATE, "paths": {
        "main": str(MAIN), "bin": str(BIN_DIR), "conf": str(CONF_DIR)}}
    try:
        cfg = load_config()
    except ConfigError as e:
        return {**base, "config_error": str(e), "tunnels": [], "groups": None, "warnings": [],
                "pending_apply": False}
    st = await units_status(list(all_units(cfg)) + [PANEL_UNIT])
    problems = await asyncio.to_thread(preflight, cfg, st)

    def loop_info(unit: str) -> dict | None:
        li = LOOPING.get(unit)
        return {"since": li["since"], "reason": li["reason"]} if li else None

    tunnels = [{
        "name": n,
        "kind": t.get("kind", ""),
        "proto": t.get("_proto"),
        "source": (Path(t["_native_file"]).name if t.get("_native_file") else
                   ("полный конфиг " + Path(t["_config_src"]).name) if t.get("_sb_full") else None),
        "ports_from_file": t.get("_ports_from_file") or [],
        "description": t.get("description", ""),
        "port": t.get("port"),
        "socks": t["socks"],
        "exit": t["exit"],
        "native": t["native"],
        "via": t.get("via"),
        "chain": chain_of(cfg, n),
        "requires": t["requires"],
        "url": f"socks5://127.0.0.1:{t['port']}" if t["exit"] else None,
        "http_url": f"http://127.0.0.1:{t['_http_port']}" if t.get("_http_port") else None,
        "http": ({"mode": t["_http_mode"], "port": t["_http_port"],
                  "unit": st.get(http_unit(n)) if t["_http_mode"] == "bridge" else None}
                 if t.get("_http_port") else None),
        "config": str(config_out(n, t)) if "_config_src" in t else (
            str(RUN_DIR / f"{n}.json") if t["native"] else None),
        "obfs": {"unit": st.get(obfs_unit(n)), "port": t["_obfs_port"], "target": t["_obfs_target"],
                 "masking": t["obfuscator"].get("masking", "AUTO")} if t.get("_obfs_port") else None,
        "unit": st.get(unit_of(n)),
        "health": HEALTH.get(n),
        "problems": problems.get(n, []),
        "looping": loop_info(unit_of(n)) or loop_info(obfs_unit(n)) or loop_info(http_unit(n)),
    } for n, t in cfg["tunnels"].items()]

    groups, delays = None, {}
    if cfg["singbox"]["enabled"]:
        try:
            data = await clash("GET", "/proxies")
            groups = []
            for name, p in data.get("proxies", {}).items():
                hist = p.get("history") or []
                if hist and hist[-1].get("delay"):
                    delays[name] = hist[-1]["delay"]
                if p.get("type") in ("Selector", "URLTest", "Fallback") and name != "GLOBAL":
                    groups.append({"name": name, "type": p["type"], "now": p.get("now"), "all": p.get("all", [])})
            groups.sort(key=lambda g: (g["name"] != "select", g["name"]))
        except Exception:
            groups = None
    return {
        **base,
        "config_error": None,
        "pending_apply": conf_hash() != STATE.get("applied_hash"),
        "warnings": cfg["_warnings"],
        "systemd_ok": bool(st),  # systemctl show отвечает и для несуществующих unit — пусто только без systemd
        "singbox": {
            "enabled": cfg["singbox"]["enabled"],
            "listen": cfg["singbox"]["listen"],
            "port": cfg["singbox"]["port"],
            "group_ports": {g: gd.get("port") for g, gd in cfg["groups"].items() if gd.get("port")},
            "installed": singbox_bin(cfg) is not None,
            "unit": st.get(SINGBOX_UNIT),
            "health": HEALTH.get(ENTRY),
            "problems": problems.get("singbox", []),
            "looping": loop_info(SINGBOX_UNIT),
        },
        "tunnels": tunnels,
        "groups": groups,
        "delays": delays,
        "apps": [{"name": a, "tunnel": ad["tunnel"], "cmd": ad["cmd"], "mode": ad.get("mode", "auto"),
                  "title": ad.get("title") or f"{a.replace('-', ' ').capitalize()} · {ad['tunnel']}",
                  "desktop": (APPS_DIR / f"pp-app-{a}.desktop").exists()} for a, ad in cfg["apps"].items()],
        "pp_run": {"path": str(PP_RUN), "installed": PP_RUN.exists(), "targets": list(run_targets(cfg))},
    }


@app.post("/api/units/{name}/{action}")
async def unit_action(name: str, action: str):
    if action not in ACTIONS:
        raise HTTPException(400, f"неизвестное действие {action!r}")
    cfg = load_config()
    unit = _known(cfg, name)
    applied = None
    if action in ("start", "restart", "enable"):
        st = (await units_status([unit])).get(unit) or {}
        if not st.get("loaded"):  # unit ещё не создан — конфиг сохранён, но не применён
            applied = await apply_config()
            cfg = load_config()
        if action != "enable":
            base = "singbox" if unit == SINGBOX_UNIT else unit.removeprefix(PREFIX).removesuffix(".service")
            base = base.removesuffix("-obfs").removesuffix("-http")
            plist = preflight(cfg, await units_status(list(all_units(cfg)))).get(base)
            if plist:
                raise HTTPException(409, f"{name} не запущен: " + "; ".join(plist))
    touch(unit)
    rc, out, err = await sctl(action, unit)
    if rc != 0:
        raise HTTPException(500, (err or out).strip() or f"systemctl {action} {unit}: код {rc}")
    if action in ("start", "restart"):
        kick(ENTRY if name == "singbox" else name, ENTRY)
    elif action == "stop":
        kick()
    return {"ok": True, "applied": applied}


@app.post("/api/check/{name}")
async def check_now(name: str):
    cfg = load_config()
    if name != "all":
        _known(cfg, name, for_logs=True)
    kick(*(list(cfg["tunnels"]) + [ENTRY] if name == "all" else [ENTRY if name == "singbox" else name]))
    return {"ok": True}


@app.post("/api/select")
async def select(body: dict = Body(...)):
    group, target = str(body.get("group", "")), str(body.get("name", ""))
    try:
        await clash("PUT", f"/proxies/{quote(group, safe='')}", json={"name": target})
    except httpx.HTTPStatusError as e:
        raise HTTPException(400, f"sing-box: {e.response.text}") from None
    except httpx.HTTPError as e:
        raise HTTPException(502, f"sing-box недоступен: {e}") from None
    kick(ENTRY)
    event("info", group, f"выбран выход {target}")
    return {"ok": True}


@app.get("/api/logs/{name}", response_class=PlainTextResponse)
async def logs(name: str, lines: int = 300):
    unit = PANEL_UNIT if name == "panel" else _known(load_config(), name, for_logs=True)
    _, out, err = await run("journalctl", "--user", "-u", unit, "-n", str(min(max(lines, 1), 5000)),
                            "--no-pager", "-o", "short-iso")
    return out or err


@app.websocket("/api/logs/{name}/ws")
async def logs_ws(ws: WebSocket, name: str):
    origin = ws.headers.get("origin", "")
    if not _host_ok(ws.headers.get("host", "")) or (origin and not _host_ok(origin.split("://", 1)[-1])):
        await ws.close(code=1008)
        return
    try:
        unit = PANEL_UNIT if name == "panel" else _known(load_config(), name, for_logs=True)
    except (HTTPException, ConfigError):
        await ws.close(code=1008)
        return
    await ws.accept()
    try:
        proc = await asyncio.create_subprocess_exec(
            "journalctl", "--user", "-u", unit, "-f", "-n", "200", "--no-pager", "-o", "short-iso",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    except FileNotFoundError:
        await ws.send_text("journalctl не найден")
        await ws.close()
        return

    async def pump():
        assert proc.stdout
        async for line in proc.stdout:
            await ws.send_text(line.decode(errors="replace").rstrip("\n"))

    pump_task = asyncio.create_task(pump())
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        pump_task.cancel()
        if proc.returncode is None:
            proc.kill()


@app.get("/api/config")
async def get_config():
    return {"path": str(CONF_FILE), "text": CONF_FILE.read_text() if CONF_FILE.exists() else ""}


@app.put("/api/config")
async def put_config(body: dict = Body(...)):
    """Сохранить proxies.yaml. С ошибкой проверки — 400, если не задан force (тогда пишем как есть)."""
    text = str(body.get("text", ""))
    force = bool(body.get("force"))
    error, warnings = None, []
    try:
        warnings = parse_config(text)["_warnings"]
    except ConfigError as e:
        if not force:
            raise
        error = str(e)
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    if CONF_FILE.exists() and CONF_FILE.read_text() != text:
        shutil.copy2(CONF_FILE, CONF_FILE.with_suffix(".yaml.bak"))
    changed = write_if_changed(CONF_FILE, text, 0o600)
    if changed:
        event("info", "конфиг", "сохранён" + (" с ошибкой: " + error.splitlines()[0][:120] if error else ""))
    return {"ok": True, "changed": changed, "error": error, "warnings": warnings,
            "path": str(CONF_FILE), "saved_at": time.time(),
            "pending_apply": conf_hash() != STATE.get("applied_hash")}


@app.post("/api/apply")
async def api_apply():
    return await apply_config()


@app.get("/api/updates")
async def api_updates():
    cfg = try_config()
    rows = []
    for name, comp in components(cfg).items():
        inst = await installed_info(name, comp)
        latest = STATE["updates"].get(name) or {}
        rows.append({
            "name": name, "repo": comp["repo"], "bin": comp["bin"], "installed": inst,
            "latest": {k: latest.get(k) for k in ("version", "tag", "asset", "size", "html_url", "published",
                                                  "error", "checked_at")},
            "update": bool(inst.get("path")) and update_available(inst.get("version"), latest.get("version")),
            "used_by": affected_units(cfg, comp["bin"]),
        })
    return {"components": rows, "meta": STATE.get("updates_meta", {}), "busy": INSTALL_LOCK.locked(),
            "bin_dir": str(BIN_DIR), "enabled": bool(cfg and cfg["updates"]["enabled"]),
            "paths": {"main": str(MAIN), "home": str(HOME)}}


@app.post("/api/updates/check")
async def api_updates_check():
    await check_updates(try_config() or parse_config(""))
    return await api_updates()


@app.post("/api/updates/{name}/install")
async def api_install(name: str):
    try:
        return await install_component(name)
    except RuntimeError as e:
        event("error", name, f"установка не удалась: {e}")
        raise


@app.post("/api/updates/{name}/rollback")
async def api_rollback(name: str):
    return await rollback_component(name)


@app.get("/api/events")
async def api_events():
    return list(EVENTS)


@app.post("/api/notify/test")
async def api_notify_test():
    ok = await asyncio.wait_for(desktop_notify(
        "test", "test", "ProxyPanel", "Тестовое уведомление: так будут выглядеть сообщения о туннелях",
        force=True), timeout=15) if shutil.which("notify-send") else False
    if not ok:
        raise HTTPException(500, NOTIFY_STATE.get("last_error") or "уведомление не показано")
    return {"ok": True}


# ──────────────────────────────── main ─────────────────────────────────
async def _cli_install(names: list[str]) -> int:
    load_state()
    cfg = try_config() or parse_config("")
    comps = components(cfg)
    if names in (["all"], ["missing"]):
        mode = names[0]
        names = []
        for n, c in comps.items():
            inst = await installed_info(n, c)
            if mode == "all" or not inst.get("path"):
                names.append(n)
    rc = 0
    for n in names:
        try:
            r = await install_component(n)
            print(f"✓ {n} {r['version']}" + ("" if r["verified"] else "  (без проверки sha256)"))
            for w in r["warnings"]:
                print(f"  ! {w}")
        except Exception as e:
            print(f"✗ {n}: {getattr(e, 'detail', e)}")
            rc = 1
    return rc


async def _cli_check() -> int:
    load_state()
    cfg = try_config() or parse_config("")
    await check_updates(cfg)
    for name, comp in components(cfg).items():
        inst = await installed_info(name, comp)
        lat = STATE["updates"].get(name, {})
        mark = "↑" if update_available(inst.get("version"), lat.get("version")) else " "
        print(f"{mark} {name:14} установлено: {inst.get('version') or '—':12} "
              f"последняя: {lat.get('version') or lat.get('error', '—')}  {inst.get('path') or ''}")
    return 0


def main() -> None:
    global CLI_MODE
    args = sys.argv[1:]
    if args:
        CLI_MODE = True
        cmd = args[0]
        if cmd in ("-V", "--version"):
            print(f"ProxyPanel {__version__}")
            return
        try:
            if cmd == "apply":
                print(json.dumps(asyncio.run(apply_config()), ensure_ascii=False, indent=2))
            elif cmd == "check":
                sys.exit(asyncio.run(_cli_check()))
            elif cmd == "install" and len(args) > 1:
                sys.exit(asyncio.run(_cli_install(args[1:])))
            elif cmd == "rollback" and len(args) == 2:
                load_state()
                print(asyncio.run(rollback_component(args[1])))
            else:
                sys.exit(__doc__)
        except ConfigError as e:
            sys.exit(f"Ошибка конфига: {e}")
        except HTTPException as e:
            sys.exit(f"Ошибка: {e.detail}")
        except RuntimeError as e:
            sys.exit(f"Ошибка: {e}")
        return
    try:
        panel = load_config()["panel"]
    except ConfigError as e:
        print(f"Внимание: {e}. Панель стартует с настройками по умолчанию.", file=sys.stderr)
        panel = DEFAULTS["panel"]
    import uvicorn
    uvicorn.run(app, host=panel["listen"], port=int(panel["port"]), log_level="warning")


if __name__ == "__main__":
    main()
