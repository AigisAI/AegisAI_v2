#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEPLOY_ENV_FILE="$SCRIPT_DIR/.env"
ALLOY_CONFIG_SOURCE="$SCRIPT_DIR/alloy/config.alloy"
ALLOY_CONFIG_TARGET="/etc/alloy/config.alloy"
SYSTEMD_OVERRIDE_DIR="/etc/systemd/system/alloy.service.d"
SYSTEMD_OVERRIDE_FILE="$SYSTEMD_OVERRIDE_DIR/10-aegisai.conf"

if [ ! -f "$DEPLOY_ENV_FILE" ]; then
  echo "Missing deploy environment file: $DEPLOY_ENV_FILE" >&2
  exit 1
fi

if [ ! -f "$ALLOY_CONFIG_SOURCE" ]; then
  echo "Missing Alloy config template: $ALLOY_CONFIG_SOURCE" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This helper currently supports Debian or Ubuntu hosts only." >&2
  exit 1
fi

if ! command -v gpg >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y gpg wget
fi

sudo mkdir -p /etc/apt/keyrings
sudo wget -O /etc/apt/keyrings/grafana.asc https://apt.grafana.com/gpg-full.key
sudo chmod 644 /etc/apt/keyrings/grafana.asc
echo "deb [signed-by=/etc/apt/keyrings/grafana.asc] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list >/dev/null

sudo apt-get update
sudo apt-get install -y alloy

sudo mkdir -p /etc/alloy
sudo cp "$ALLOY_CONFIG_SOURCE" "$ALLOY_CONFIG_TARGET"
sudo chown root:root "$ALLOY_CONFIG_TARGET"
sudo chmod 640 "$ALLOY_CONFIG_TARGET"

sudo mkdir -p "$SYSTEMD_OVERRIDE_DIR"
cat <<EOF | sudo tee "$SYSTEMD_OVERRIDE_FILE" >/dev/null
[Service]
EnvironmentFile=$DEPLOY_ENV_FILE
EOF

if getent group docker >/dev/null 2>&1; then
  sudo usermod -aG docker alloy
fi

sudo systemctl daemon-reload
sudo systemctl enable alloy.service
sudo systemctl restart alloy
sudo systemctl --no-pager --full status alloy.service || true
