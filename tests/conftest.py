"""Общая подготовка: app.py читает пути из окружения при импорте — направляем их во временный каталог."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_TMP = Path(tempfile.mkdtemp(prefix="proxypanel-tests-"))
os.environ["PP_MAIN"] = str(_TMP / "main")
os.environ["PP_UNIT_DIR"] = str(_TMP / "units")
os.environ["PP_APPS_DIR"] = str(_TMP / "apps")
sys.path.insert(0, str(ROOT))

import app as _app  # noqa: E402


@pytest.fixture
def app():
    return _app


@pytest.fixture
def conf_dir(app):
    """Чистый каталог конфигов на каждый тест."""
    d = app.CONF_DIR
    d.mkdir(parents=True, exist_ok=True)
    for p in d.iterdir():
        if p.is_file():
            p.unlink()
    yield d


@pytest.fixture
def write(conf_dir):
    def _write(name: str, text: str) -> Path:
        p = conf_dir / name
        p.write_text(text)
        return p
    return _write


# Ключи сгенерированы `sing-box generate wg-keypair` / `wg genpsk` только для тестов
PRIV = "CFWSbBS/z2hwXFVDNgcUkNZSRRhbwkYNf7YQrgAhjGA="
PUB = "hzqUmbOnlVYjTHdSrYI6PQ1mvZupFGrUyzLsKAdx73U="
PSK = "ovzleRYgh3+RoDqkk//Q8en512sIDOL+k+IPLurXrMU="
