"""Компоненты: выбор файла релиза, версии, контрольные суммы, распаковка."""
import hashlib
import io
import re
import tarfile
import zipfile

import pytest

# Настоящие имена файлов из релизов (октябрь 2026)
ASSETS = {
    "sing-box": ["sing-box-1.14.3-linux-amd64-glibc.tar.gz", "sing-box-1.14.3-linux-amd64v3.tar.gz",
                 "sing-box-1.14.3-linux-amd64.tar.gz", "sing-box-1.14.3-linux-arm64.tar.gz"],
    "hysteria": ["hashes.txt", "hysteria-linux-amd64-avx", "hysteria-linux-amd64", "hysteria-linux-arm64"],
    "wireproxy": ["checksums.txt", "wireproxy_linux_amd64.tar.gz", "wireproxy_linux_arm64.tar.gz"],
    "wg-obfuscator": ["wg-obfuscator-v1.6-docker-amd64.tar", "wg-obfuscator-v1.6-linux-x64.tar.gz",
                      "wg-obfuscator-v1.6-linux-x86.tar.gz", "wg-obfuscator-v1.6-linux-arm64.tar.gz"],
}
EXPECTED = {
    ("sing-box", "amd64"): "sing-box-1.14.3-linux-amd64.tar.gz",
    ("sing-box", "arm64"): "sing-box-1.14.3-linux-arm64.tar.gz",
    ("hysteria", "amd64"): "hysteria-linux-amd64",
    ("wireproxy", "arm64"): "wireproxy_linux_arm64.tar.gz",
    ("wg-obfuscator", "amd64"): "wg-obfuscator-v1.6-linux-x64.tar.gz",
}


@pytest.mark.parametrize("comp,arch", list(EXPECTED))
def test_asset_patterns_pick_plain_build(app, comp, arch):
    pat = re.compile(app.COMPONENTS[comp]["asset"][arch])
    assert [a for a in ASSETS[comp] if pat.match(a)] == [EXPECTED[(comp, arch)]]


def test_versions(app):
    assert app.parse_ver("sing-box version 1.14.3") == (1, 14, 3, 1)
    assert app.update_available("2.6.0", "2.13.0")
    assert not app.update_available("1.14.3", "1.14.3")
    assert app.update_available("1.15.0-beta.2", "1.15.0")  # релиз новее беты
    assert not app.update_available(None, "1.0.0")


def test_expected_sha(app):
    h = "a" * 64
    assert app._expected_sha({"digest": f"sha256:{h.upper()}", "asset": "x"}, None) == h
    sums = f"{'b' * 64}  build/hysteria-linux-amd64\n{'c' * 64} *other\n"
    assert app._expected_sha({"asset": "hysteria-linux-amd64"}, sums) == "b" * 64
    assert app._expected_sha({"asset": "nope"}, sums) is None


def _tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_extract(app, tmp_path):
    a = tmp_path / "sb.tar.gz"
    a.write_bytes(_tar({"sing-box-1.14.3-linux-amd64/LICENSE": b"l", "sing-box-1.14.3-linux-amd64/sing-box": b"BIN"}))
    assert app._extract(a, a.name, "sing-box") == b"BIN"
    z = tmp_path / "x.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("dir/wireproxy", b"WP")
    assert app._extract(z, z.name, "wireproxy") == b"WP"
    raw = tmp_path / "hysteria-linux-amd64"
    raw.write_bytes(b"HY")
    assert app._extract(raw, raw.name, "hysteria") == b"HY"
    bad = tmp_path / "bad.tar.gz"
    bad.write_bytes(_tar({"README": b"r", "LICENSE": b"l"}))
    with pytest.raises(RuntimeError):
        app._extract(bad, bad.name, "wg-obfuscator")
    assert hashlib.sha256(b"BIN").hexdigest()  # sanity


def test_affected_units(app):
    cfg = app.parse_config("tunnels:\n  h: {port: 1082, cmd: hysteria client -c x}\n"
                           "  s: {port: 1083, outbound: {type: direct}}\n"
                           "  b: {port: 1084, http_port: 1184, cmd: ssh -N h}\n")
    assert app.affected_units(cfg, "hysteria") == ["pp-h.service"]
    assert set(app.affected_units(cfg, "sing-box")) == {"pp-s.service", "pp-b-http.service"}
