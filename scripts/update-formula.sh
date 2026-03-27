#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────
# Actualiza la Homebrew formula con la versión y checksums
# del release más reciente de GitHub.
#
# Uso:
#   ./scripts/update-formula.sh [version]
#
# Si no se pasa versión, usa la más reciente de GitHub.
# ──────────────────────────────────────────────────────────
set -euo pipefail

FORMULA="Formula/infraudit.rb"
REPO="civanmoreno/infraudit"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    VERSION=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4 | sed 's/^v//')
    echo "Detected latest version: $VERSION"
fi

echo "Downloading binaries for v${VERSION}..."

AMD64_URL="https://github.com/${REPO}/releases/download/v${VERSION}/infraudit-linux-amd64"
ARM64_URL="https://github.com/${REPO}/releases/download/v${VERSION}/infraudit-linux-arm64"

AMD64_SHA=$(curl -sL "$AMD64_URL" | sha256sum | cut -d' ' -f1)
ARM64_SHA=$(curl -sL "$ARM64_URL" | sha256sum | cut -d' ' -f1)

echo "AMD64 SHA256: $AMD64_SHA"
echo "ARM64 SHA256: $ARM64_SHA"

sed -i "s/version \".*\"/version \"${VERSION}\"/" "$FORMULA"
sed -i "s/PLACEHOLDER_AMD64_SHA256\|sha256 \"[a-f0-9]\{64\}\"/sha256 \"${AMD64_SHA}\"/" "$FORMULA"

# La segunda ocurrencia de sha256 es ARM64 — usar línea específica
python3 -c "
import re
with open('$FORMULA') as f:
    content = f.read()

# Reemplazar los sha256 en orden
shas = ['$AMD64_SHA', '$ARM64_SHA']
idx = 0
def replacer(match):
    global idx
    if idx < len(shas):
        result = f'sha256 \"{shas[idx]}\"'
        idx += 1
        return result
    return match.group(0)

content = re.sub(r'sha256 \"[a-fA-F0-9]+\"', replacer, content)
content = re.sub(r'sha256 \"PLACEHOLDER_\w+\"', replacer, content)

with open('$FORMULA', 'w') as f:
    f.write(content)
"

echo ""
echo "Formula updated: $FORMULA"
echo "Version: $VERSION"
echo ""
cat "$FORMULA"
