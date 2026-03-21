#!/bin/sh
set -e

REPO="civanmoreno/infraudit"
INSTALL_DIR="/usr/local/bin"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Architecture not supported: $ARCH" && exit 1 ;;
esac

echo "Downloading infraudit for linux/${ARCH}..."
curl -sLO "https://github.com/${REPO}/releases/latest/download/infraudit-linux-${ARCH}"
chmod +x "infraudit-linux-${ARCH}"
sudo mv "infraudit-linux-${ARCH}" "${INSTALL_DIR}/infraudit"

echo "Installed: $(infraudit --version)"
