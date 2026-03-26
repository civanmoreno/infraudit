#!/bin/sh
set -e

REPO="civanmoreno/infraudit"
INSTALL_DIR="/usr/local/bin"

# Detect if we need sudo
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "Error: not running as root and sudo is not installed."
        echo "Run this script as root or install sudo first."
        exit 1
    fi
fi

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
$SUDO mv "infraudit-linux-${ARCH}" "${INSTALL_DIR}/infraudit"

# Install man page
MAN_DIR="/usr/share/man/man1"
if [ -d "$(dirname "$MAN_DIR")" ]; then
    echo "Installing man page..."
    curl -sLO "https://raw.githubusercontent.com/${REPO}/main/docs/infraudit.1"
    $SUDO install -Dm644 infraudit.1 "${MAN_DIR}/infraudit.1"
    $SUDO gzip -f "${MAN_DIR}/infraudit.1"
    rm -f infraudit.1
fi

echo "Installed: $(infraudit --version)"
echo "Run 'man infraudit' for documentation."
