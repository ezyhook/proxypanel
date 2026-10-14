#!/usr/bin/env bash
# Удаляет units ProxyPanel и приложение. Конфиги (~/main/.config/proxypanel)
# и бинарники (~/main/bin) НЕ трогает.
set -euo pipefail
MAIN="${PP_MAIN:-$HOME/main}"
UNIT_DIR="$HOME/.config/systemd/user"
for u in "$UNIT_DIR"/pp-*.service; do
  [[ -e "$u" ]] || continue
  systemctl --user disable --now "$(basename "$u")" || true
  rm -f "$u"
done
systemctl --user daemon-reload
rm -rf "$MAIN/.local/share/proxypanel"
[[ -L "$HOME/.config/proxypanel" ]] && rm -f "$HOME/.config/proxypanel"
[[ -L "$HOME/.local/bin/pp-run" ]] && rm -f "$HOME/.local/bin/pp-run"
rm -f "$HOME"/.local/share/applications/pp-app-*.desktop
echo "Удалено. Остались: $MAIN/.config/proxypanel (конфиги) и $MAIN/bin (бинарники)."
echo "Linger выключить (если больше не нужен): sudo loginctl disable-linger $USER"
