#!/usr/bin/env sh
# install.sh — build and install vigilante for personal or server use.
#
#   ./install.sh            # build + install to /usr/local (may need sudo)
#   PREFIX=~/.local ./install.sh
#   ./install.sh systemd    # also install + enable the systemd unit (needs root)
set -eu

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${PREFIX:-/usr/local}"
BIN="$PREFIX/bin/vigilante"

echo "building vigilante..."
(cd "$REPO_DIR" && go build -trimpath -ldflags="-s -w" -o "$BIN" ./cmd/vigilante)
echo "installed $BIN"

case "${1:-}" in
  systemd)
    echo "installing systemd unit..."
    install -d /etc/vigilante /var/log/vigilante
    [ -f /etc/vigilante/vigilante.json ] || \
      cp "$REPO_DIR/deploy/vigilante.json.example" /etc/vigilante/vigilante.json
    install -m 644 "$REPO_DIR/deploy/vigilante.service" /etc/systemd/system/vigilante.service
    systemctl daemon-reload
    systemctl enable --now vigilante
    systemctl --no-pager status vigilante || true
    ;;
  *)
    echo "run './install.sh systemd' to install the service unit"
    echo "try: $BIN -mode demo -repo ."
    ;;
esac