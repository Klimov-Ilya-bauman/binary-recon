#!/usr/bin/env bash
# Сборка .deb-пакета binary-recon.
set -euo pipefail

VERSION="${VERSION:-1.0.0}"
ARCH="$(dpkg --print-architecture)"
PKG_NAME="binary-recon_${VERSION}_${ARCH}"
BUILD_DIR="${PWD}/packaging/build/${PKG_NAME}"

echo "[1/5] Cleaning previous build..."
rm -rf "${PWD}/packaging/build"
mkdir -p "$BUILD_DIR"

echo "[2/5] Building C++ core..."
cd "${PWD}/core"
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release > /dev/null
make -j$(nproc) > /dev/null
cd "${PWD%/core/build}"

echo "[3/5] Staging files..."
# Структура: /usr/local/lib/binary-recon/core
#            /usr/local/bin/recon, recon-tui, recon-batch (symlinks)
#            /usr/share/doc/binary-recon/
install -d "$BUILD_DIR/usr/local/lib/binary-recon"
install -d "$BUILD_DIR/usr/local/bin"
install -d "$BUILD_DIR/usr/share/doc/binary-recon"
install -d "$BUILD_DIR/DEBIAN"

install -m 755 core/build/core "$BUILD_DIR/usr/local/lib/binary-recon/core"

# Wrapper-скрипты, вызывающие python entry points
for cmd in recon recon-tui recon-batch; do
    cat > "$BUILD_DIR/usr/local/bin/${cmd}" <<WRAP
#!/usr/bin/env bash
exec python3 -m recon$([ "$cmd" = "recon-tui" ] && echo ".tui.app" ||
                       [ "$cmd" = "recon-batch" ] && echo ".batch_cli" ||
                       echo "") "\$@"
WRAP
    chmod 755 "$BUILD_DIR/usr/local/bin/${cmd}"
done

cp README.md LICENSE "$BUILD_DIR/usr/share/doc/binary-recon/"

echo "[4/5] Writing DEBIAN/control..."
cat > "$BUILD_DIR/DEBIAN/control" <<CTRL
Package: binary-recon
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.9), python3-pip
Recommends: python3-textual, python3-rich, python3-jinja2
Maintainer: Klimov Ilya <klimov@example.com>
Description: Static analysis tool for ELF and PE executables
 Binary Recon parses ELF (Linux) and PE (Windows) binaries without
 executing them. It computes MD5/SHA-256/Shannon entropy, parses
 sections and imports, then runs seven detectors (AntiDebug,
 Network, Packer, Persistence, Injection, Crypto, Signatures)
 to produce a Risk Score 0-100.
 .
 Includes both a CLI (recon, recon-batch) and a Textual-based TUI
 (recon-tui).
CTRL

cat > "$BUILD_DIR/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
# Install the Python package from PyPI if not present
if ! python3 -c "import recon" 2>/dev/null; then
    echo "Installing Python dependencies (textual, rich, jinja2)..."
    pip3 install --break-system-packages textual rich jinja2 || true
fi
exit 0
POSTINST
chmod 755 "$BUILD_DIR/DEBIAN/postinst"

echo "[5/5] Building .deb..."
dpkg-deb --build --root-owner-group "$BUILD_DIR" \
    "${PWD}/packaging/build/${PKG_NAME}.deb"

echo ""
echo "✓ Package built: packaging/build/${PKG_NAME}.deb"
ls -lh "${PWD}/packaging/build/${PKG_NAME}.deb"
