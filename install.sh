#!/usr/bin/env bash
# Установка/обновление ProxyPanel для текущего пользователя (Ubuntu 24.04+/26.04).
# Запускать от обычного пользователя, НЕ от root:  ./install.sh
#
#   ~/main/bin                        бинарники (sing-box, hysteria, wireproxy, wg-obfuscator)
#   ~/main/.config/proxypanel         конфиги
#   ~/main/.local/share/proxypanel    приложение + venv
#
# Корень можно сменить:  PP_MAIN=/path ./install.sh
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
  echo "Запустите от обычного пользователя (sudo спросится, где нужно)." >&2
  exit 1
fi

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN="${PP_MAIN:-$HOME/main}"
BIN_DIR="$MAIN/bin"
CONF_DIR="$MAIN/.config/proxypanel"
APP_DIR="$MAIN/.local/share/proxypanel"
UNIT_DIR="$HOME/.config/systemd/user"
PY="$APP_DIR/venv/bin/python"
OLD_CONF="$HOME/.config/proxypanel"
OLD_APP="$HOME/.local/share/proxypanel"

echo "==> Системные пакеты"
missing=()
for pkg in python3-venv autossh libnotify-bin netcat-openbsd proxychains4; do
  dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
done
if ((${#missing[@]})); then
  echo "    ставлю: ${missing[*]}"
  sudo apt-get update -qq
  sudo apt-get install -y "${missing[@]}"
fi

mkdir -p "$BIN_DIR" "$MAIN/.config" "$APP_DIR/static" "$UNIT_DIR"

# ── миграция со старой раскладки (~/.config/proxypanel) ──
if [[ -d "$OLD_CONF" && ! -L "$OLD_CONF" ]]; then
  if [[ ! -e "$CONF_DIR" ]]; then
    echo "==> Переношу конфиги $OLD_CONF → $CONF_DIR"
    mv "$OLD_CONF" "$CONF_DIR"
    ln -s "$CONF_DIR" "$OLD_CONF"
    rm -rf "$CONF_DIR/run"   # скрипты пересоздадутся с новыми путями
  else
    echo "!!  Есть и $OLD_CONF, и $CONF_DIR — старый не трогаю, используется новый."
  fi
fi
mkdir -p "$CONF_DIR"
chmod 700 "$CONF_DIR"   # здесь будут ключи WireGuard и пароли

echo "==> Приложение → $APP_DIR"
install -m 0644 "$SRC/app.py" "$APP_DIR/app.py"
install -m 0644 "$SRC/static/index.html" "$APP_DIR/static/index.html"
install -m 0644 "$SRC/requirements.txt" "$APP_DIR/requirements.txt"

echo "==> pp-run → $BIN_DIR/pp-run (+ ссылка в ~/.local/bin, чтобы работал в терминале)"
install -m 0755 "$SRC/pp-run" "$BIN_DIR/pp-run"
mkdir -p "$HOME/.local/bin"
ln -sf "$BIN_DIR/pp-run" "$HOME/.local/bin/pp-run"

echo "==> Python venv и зависимости"
[[ -x "$PY" ]] || python3 -m venv "$APP_DIR/venv"
"$PY" -m pip install -q --upgrade pip
"$PY" -m pip install -q -r "$APP_DIR/requirements.txt"

FRESH=0
if [[ ! -f "$CONF_DIR/proxies.yaml" ]]; then
  echo "==> Создаю $CONF_DIR/proxies.yaml из примера — отредактируйте его"
  install -m 0600 "$SRC/proxies.example.yaml" "$CONF_DIR/proxies.yaml"
  for f in "$SRC"/examples/*; do  # образцы конфигов клиентов, на которые ссылается пример
    [[ -e "$CONF_DIR/$(basename "$f")" ]] || install -m 0600 "$f" "$CONF_DIR/$(basename "$f")"
  done
  FRESH=1
fi

echo "==> systemd unit панели"
ENV_MAIN=""
[[ "$MAIN" != "$HOME/main" ]] && ENV_MAIN="Environment=\"PP_MAIN=$MAIN\""
cat > "$UNIT_DIR/pp-panel.service" <<EOF
[Unit]
Description=ProxyPanel web UI
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart="$PY" "$APP_DIR/app.py"
Environment=PYTHONUNBUFFERED=1
$ENV_MAIN
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable pp-panel.service >/dev/null

echo "==> Linger: user-сервисы стартуют при загрузке, ещё до входа в систему"
if [[ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]]; then
  sudo loginctl enable-linger "$USER"
fi

echo "==> Бинарники: ставлю отсутствующие в $BIN_DIR (с GitHub)"
export PP_MAIN="$MAIN"
if ! "$PY" "$APP_DIR/app.py" install missing; then
  echo "!!  Не всё удалось скачать — GitHub может быть недоступен напрямую."
  echo "    Позже: панель → «Компоненты», там загрузка пойдёт и через ваш туннель (updates.proxy: auto)."
fi

if [[ $FRESH == 0 ]]; then
  echo "==> Применяю конфиг"
  "$PY" "$APP_DIR/app.py" apply >/dev/null || echo "!!  apply с ошибкой — откройте панель → «Конфиг»"
fi

systemctl --user restart pp-panel.service

# старое приложение больше не нужно
if [[ -d "$OLD_APP" && "$OLD_APP" != "$APP_DIR" ]]; then
  rm -rf "$OLD_APP"
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo
     echo "Подсказка: чтобы бинарники из $BIN_DIR были доступны в терминале, добавьте в ~/.profile:"
     echo "    export PATH=\"$BIN_DIR:\$PATH\""
     echo "(туннелям это не нужно — панель сама подставляет $BIN_DIR)";;
esac

if [[ $FRESH == 1 ]]; then
  cat <<EOF

Готово. Дальше:
  1. Положите конфиги клиентов (hysteria, wireproxy, wg-obfuscator) в $CONF_DIR
  2. Опишите туннели в панели → «Конфиг» (или в $CONF_DIR/proxies.yaml)
  3. «Сохранить и применить»
EOF
fi
echo
echo "Панель: http://127.0.0.1:8800"
