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

# Install man page
MAN_DIR="/usr/share/man/man1"
if [ -d "$(dirname "$MAN_DIR")" ]; then
    echo "Installing man page..."
    curl -sLO "https://raw.githubusercontent.com/${REPO}/main/docs/infraudit.1"
    sudo install -Dm644 infraudit.1 "${MAN_DIR}/infraudit.1"
    sudo gzip -f "${MAN_DIR}/infraudit.1"
    rm -f infraudit.1
fi

echo "Installed: $(infraudit --version)"
echo "Run 'man infraudit' for documentation."
