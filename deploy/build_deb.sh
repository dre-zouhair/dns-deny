#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$WORKSPACE_ROOT"

ARCH="${1:-amd64}"
RUST_TARGET=""

# VARIANT selects what the admin server includes:
#   full      dashboard and JSON API (default)
#   no-api    dashboard only; /api/v1/* is not compiled in
#   api-only  JSON API only; no dashboard pages or static assets
VARIANT="${VARIANT:-full}"
case "$VARIANT" in
    full)
        VARIANT_SUFFIX=""
        PACKAGE_CONTENTS="Includes the web dashboard and the JSON API."
        ;;
    no-api)
        CARGO_BUILD_FLAGS="--no-default-features --features feat-web-ui ${CARGO_BUILD_FLAGS:-}"
        VARIANT_SUFFIX="_no-api"
        PACKAGE_CONTENTS="Includes the web dashboard; the JSON API is not included."
        ;;
    api-only)
        CARGO_BUILD_FLAGS="--no-default-features --features feat-json-api ${CARGO_BUILD_FLAGS:-}"
        VARIANT_SUFFIX="_api-only"
        PACKAGE_CONTENTS="Includes the JSON API; the web dashboard is not included."
        ;;
    *)
        echo "Unknown VARIANT '$VARIANT' (expected full, no-api or api-only)" >&2
        exit 1
        ;;
esac

if [ "$ARCH" = "arm64" ]; then
    RUST_TARGET="aarch64-unknown-linux-gnu"
    CONFIG_SRC="config/default.toml"
    echo "=== 1. Compiling dns-deny for $ARCH ($RUST_TARGET) ==="
    cargo build --release --target "$RUST_TARGET" ${CARGO_BUILD_FLAGS:-}
    BIN_PATH="target/$RUST_TARGET/release/dns-deny"
elif [ "$ARCH" = "armhf" ] || [ "$ARCH" = "armv6" ]; then
    ARCH="armhf"
    RUST_TARGET="arm-unknown-linux-gnueabihf"
    CONFIG_SRC="config/pi-zero.toml"
    echo "=== 1. Compiling dns-deny for $ARCH ($RUST_TARGET) ==="
    if command -v cross >/dev/null 2>&1; then
        cross build --release --target "$RUST_TARGET" ${CARGO_BUILD_FLAGS:-}
    else
        cargo build --release --target "$RUST_TARGET" ${CARGO_BUILD_FLAGS:-}
    fi
    BIN_PATH="target/$RUST_TARGET/release/dns-deny"
else
    CONFIG_SRC="config/default.toml"
    echo "=== 1. Compiling dns-deny in Release mode ==="
    cargo build --release ${CARGO_BUILD_FLAGS:-}
    BIN_PATH="target/release/dns-deny"
fi

# BUILD_PACKAGE=false builds the selected binary without packaging it.
if [ "${BUILD_PACKAGE:-true}" != "true" ]; then
    echo "Build successful: $BIN_PATH"
    exit 0
fi

echo "=== 2. Creating staging directories ==="
STAGING_DIR="deploy/staging_deb"
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR/DEBIAN"
mkdir -p "$STAGING_DIR/usr/bin"
mkdir -p "$STAGING_DIR/etc/dns-deny"
mkdir -p "$STAGING_DIR/var/lib/dns-deny/static"
mkdir -p "$STAGING_DIR/lib/systemd/system"

echo "=== 3. Copying files ==="
cp "$BIN_PATH" "$STAGING_DIR/usr/bin/"
chmod 755 "$STAGING_DIR/usr/bin/dns-deny"

cp "$CONFIG_SRC" "$STAGING_DIR/etc/dns-deny/config.toml"
# Read-only to service group: runtime configuration is persisted exclusively
# to SQLite state.db in /var/lib/dns-deny.
chmod 640 "$STAGING_DIR/etc/dns-deny/config.toml"

# Static files (Admin UI); an API-only binary never serves them.
if [ "$VARIANT" != "api-only" ]; then
    cp -r static/* "$STAGING_DIR/var/lib/dns-deny/static/"
    find "$STAGING_DIR/var/lib/dns-deny/static" -type d -exec chmod 755 {} +
    find "$STAGING_DIR/var/lib/dns-deny/static" -type f -exec chmod 644 {} +
fi

sed 's|/usr/local/bin/dns-deny|/usr/bin/dns-deny|g' deploy/dns-deny.service > "$STAGING_DIR/lib/systemd/system/dns-deny.service"
chmod 644 "$STAGING_DIR/lib/systemd/system/dns-deny.service"

echo "=== 4. Creating Debian packaging scripts and metadata ==="
cat << EOF > "$STAGING_DIR/DEBIAN/control"
Package: dns-deny
Version: 0.1.0
Section: net
Priority: optional
Architecture: $ARCH
Depends: libc6, libssl3 | libssl1.1, ca-certificates, systemd
Maintainer: DNS Deny Team <admin@yourorg.com>
Description: High-performance DNS filtering and blocking server built in Rust.
 $PACKAGE_CONTENTS
EOF

# conffiles (prevents overwriting user modifications on upgrade)
echo "/etc/dns-deny/config.toml" > "$STAGING_DIR/DEBIAN/conffiles"

cat << 'EOF' > "$STAGING_DIR/DEBIAN/postinst"
#!/bin/sh
set -e

if ! getent group dns-deny >/dev/null; then
    groupadd --system dns-deny
fi

if ! getent passwd dns-deny >/dev/null; then
    useradd --system \
            --gid dns-deny \
            --no-create-home \
            --home-dir /var/lib/dns-deny \
            --shell /usr/sbin/nologin \
            dns-deny
fi

mkdir -p /var/lib/dns-deny
chown -R dns-deny:dns-deny /var/lib/dns-deny
chmod 750 /var/lib/dns-deny

mkdir -p /etc/dns-deny
chown -R root:dns-deny /etc/dns-deny
chmod 750 /etc/dns-deny
# Read-only to service group: runtime configuration is persisted to state.db.
chmod 640 /etc/dns-deny/config.toml

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi

echo "=========================================================="
echo " dns-deny has been successfully installed!"
echo "=========================================================="
echo " - Config: /etc/dns-deny/config.toml (Modify key/ports here)"
echo " - Admin UI static files: /var/lib/dns-deny/static"
echo " - Database & state: /var/lib/dns-deny/"
echo ""
echo " To enable and start the service now, run:"
echo "   sudo systemctl enable --now dns-deny"
echo "=========================================================="
EOF
chmod 755 "$STAGING_DIR/DEBIAN/postinst"
if [ "$VARIANT" = "api-only" ]; then
    sed -i '/Admin UI static files/d' "$STAGING_DIR/DEBIAN/postinst"
fi

cat << 'EOF' > "$STAGING_DIR/DEBIAN/prerm"
#!/bin/sh
set -e

if [ -d /run/systemd/system ] && systemctl is-active --quiet dns-deny; then
    echo "Stopping dns-deny service..."
    systemctl stop dns-deny || true
    systemctl disable dns-deny || true
fi
EOF
chmod 755 "$STAGING_DIR/DEBIAN/prerm"

cat << 'EOF' > "$STAGING_DIR/DEBIAN/postrm"
#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
EOF
chmod 755 "$STAGING_DIR/DEBIAN/postrm"

echo "=== 5. Building Debian Package ==="
mkdir -p target
DEB_NAME="target/dns-deny_0.1.0${VARIANT_SUFFIX}_${ARCH}.deb"
if [ "$RUST_TARGET" = "arm-unknown-linux-gnueabihf" ]; then
    DEB_NAME="target/dns-deny_0.1.0_pi-zero${VARIANT_SUFFIX}_${ARCH}.deb"
fi
dpkg-deb --build "$STAGING_DIR" "$DEB_NAME"

echo "=== 6. Cleaning up staging directory ==="
rm -rf "$STAGING_DIR"

echo ""
echo "SUCCESS: Debian package created at $DEB_NAME"
