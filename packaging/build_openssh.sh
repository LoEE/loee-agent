#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OPENSSH_SRC="$ROOT_DIR/openssh"
PATCH_FILE="$ROOT_DIR/openssh-session-bind.patch"
BUILD_DIR="$ROOT_DIR/build/openssh"
INSTALL_DIR="$ROOT_DIR/build/install"
OUTPUT_DIR="$SCRIPT_DIR/openssh_loee/bin"

# Where to find/build static deps
DEPS_DIR="$ROOT_DIR/build/deps"

echo "=== Building OpenSSH with session-bind@pl.loee ==="

# Clean
rm -rf "$BUILD_DIR" "$INSTALL_DIR"
mkdir -p "$BUILD_DIR" "$INSTALL_DIR" "$OUTPUT_DIR" "$DEPS_DIR"

# --- Build static OpenSSL if not using system ---
build_openssl() {
    local openssl_dir="$DEPS_DIR/openssl"
    if [ -f "$openssl_dir/lib/libcrypto.a" ]; then
        echo "--- OpenSSL already built, skipping ---"
        return
    fi

    echo "--- Building OpenSSL (static) ---"
    local openssl_version="3.4.1"
    local openssl_tar="openssl-${openssl_version}.tar.gz"
    cd "$DEPS_DIR"
    if [ ! -f "$openssl_tar" ]; then
        curl -LO "https://github.com/openssl/openssl/releases/download/openssl-${openssl_version}/${openssl_tar}"
    fi
    rm -rf "openssl-${openssl_version}"
    tar xzf "$openssl_tar"
    cd "openssl-${openssl_version}"

    local os_target=""
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)  os_target="linux-x86_64" ;;
        Linux-aarch64) os_target="linux-aarch64" ;;
        Darwin-arm64)  os_target="darwin64-arm64-cc" ;;
        Darwin-x86_64) os_target="darwin64-x86_64-cc" ;;
        *) echo "Unsupported platform"; exit 1 ;;
    esac

    ./Configure "$os_target" \
        --prefix="$openssl_dir" \
        no-shared no-tests no-docs no-apps \
        -fPIC
    make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" > /dev/null 2>&1
    make install_sw > /dev/null 2>&1
    cd "$ROOT_DIR"
}

# --- Build static zlib ---
build_zlib() {
    local zlib_dir="$DEPS_DIR/zlib"
    if [ -f "$zlib_dir/lib/libz.a" ]; then
        echo "--- zlib already built, skipping ---"
        return
    fi

    echo "--- Building zlib (static) ---"
    local zlib_version="1.3.2"
    cd "$DEPS_DIR"
    if [ ! -f "zlib-${zlib_version}.tar.gz" ]; then
        curl -LO "https://zlib.net/zlib-${zlib_version}.tar.gz"
    fi
    rm -rf "zlib-${zlib_version}"
    tar xzf "zlib-${zlib_version}.tar.gz"
    cd "zlib-${zlib_version}"

    CFLAGS="-fPIC" ./configure --prefix="$zlib_dir" --static
    make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" > /dev/null 2>&1
    make install > /dev/null 2>&1
    cd "$ROOT_DIR"
}

# --- Apply patch ---
apply_patch() {
    echo "--- Applying session-bind@pl.loee patch ---"
    cd "$OPENSSH_SRC"
    # Reset any previous patch
    git checkout -- . 2>/dev/null || true
    git apply "$PATCH_FILE"
    cd "$ROOT_DIR"
}

# --- Build OpenSSH ---
build_openssh() {
    echo "--- Building OpenSSH ---"
    cd "$OPENSSH_SRC"

    autoreconf -fi 2>/dev/null || true

    local ssl_dir="$DEPS_DIR/openssl"
    local zlib_dir="$DEPS_DIR/zlib"

    local configure_flags=(
        --prefix="$INSTALL_DIR"
        --with-ssl-dir="$ssl_dir"
        --with-zlib="$zlib_dir"
        --without-pam
        --without-selinux
        --without-kerberos5
        --without-libedit
        --without-audit
    )

    # On macOS, disable sandbox (seatbelt) for portability
    if [ "$(uname -s)" = "Darwin" ]; then
        configure_flags+=(--without-sandbox)
    fi

    ./configure "${configure_flags[@]}" > /dev/null 2>&1
    make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" ssh > /dev/null 2>&1

    cd "$ROOT_DIR"
}

# --- Package ---
package_binary() {
    echo "--- Packaging ---"
    cp "$OPENSSH_SRC/ssh" "$OUTPUT_DIR/ssh"
    chmod 755 "$OUTPUT_DIR/ssh"

    # Verify it runs
    "$OUTPUT_DIR/ssh" -V 2>&1 || true

    echo "=== Binary at: $OUTPUT_DIR/ssh ==="
    ls -lh "$OUTPUT_DIR/ssh"
}

build_openssl
build_zlib
apply_patch
build_openssh
package_binary

echo "=== Done ==="
