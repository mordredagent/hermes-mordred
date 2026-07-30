#!/usr/bin/env bash
# Build and install the mordred-hermes-tpmkey helper.
#
# Linux TPM 2.0 counterpart to native/sekey-helper/build.sh. Run on a Linux
# host with a Rust toolchain (cargo) plus the tss-esapi build prerequisites:
# libtss2-dev, clang/libclang-dev, pkg-config. The tss-esapi backend is gated
# to cfg(target_os="linux"), so a non-Linux build still produces a helper that
# answers every command with the neutral UNAVAILABLE reason.
#
# Idempotent: re-running rebuilds and re-installs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALL_DIR="${MORDRED_TPMKEY_INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="mordred-hermes-tpmkey"
INSTALL_TARGET="$INSTALL_DIR/$BINARY_NAME"
INSTALL_TMP=""

cleanup_install_tmp() {
    if [[ -n "$INSTALL_TMP" && -e "$INSTALL_TMP" ]]; then
        rm -f "$INSTALL_TMP"
    fi
}

sync_path() {
    # GNU/Linux can flush the filesystem containing one path. BSD/macOS sync
    # accepts no path, so use its system-wide flush without masking real I/O
    # failures behind a second fallback attempt.
    if [[ "$(uname -s)" == "Darwin" ]]; then
        sync
    else
        sync -f "$1"
    fi
}

path_mode() {
    if [[ "$(uname -s)" == "Darwin" ]]; then
        stat -f '%Lp' "$1"
    else
        stat -c '%a' "$1"
    fi
}

trap cleanup_install_tmp EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

echo "==> cargo build --release --locked"
cargo build --release --locked

BUILT_BIN="target/release/$BINARY_NAME"
if [[ ! -f "$BUILT_BIN" ]]; then
    echo "ERROR: built binary not found at $BUILT_BIN" >&2
    exit 1
fi

echo "==> Installing to $INSTALL_TARGET"
mkdir -p "$INSTALL_DIR"
if [[ -L "$INSTALL_TARGET" || ( -e "$INSTALL_TARGET" && ! -f "$INSTALL_TARGET" ) ]]; then
    echo "ERROR: install target must be a regular file or absent: $INSTALL_TARGET" >&2
    exit 1
fi
INSTALL_TMP="$(mktemp "$INSTALL_DIR/.${BINARY_NAME}.tmp.XXXXXX")"
cp "$BUILT_BIN" "$INSTALL_TMP"
chmod 0755 "$INSTALL_TMP"
sync_path "$INSTALL_TMP"
# The temp lives in INSTALL_DIR, so mv is an atomic same-filesystem rename.
# A failed copy/sync never truncates the previously-working helper.
mv -f "$INSTALL_TMP" "$INSTALL_TARGET"
INSTALL_TMP=""
if [[ -L "$INSTALL_TARGET" || ! -f "$INSTALL_TARGET" ]]; then
    echo "ERROR: installed helper is not a regular file: $INSTALL_TARGET" >&2
    exit 1
fi
if [[ "$(path_mode "$INSTALL_TARGET")" != "755" ]]; then
    echo "ERROR: installed helper is not mode 0755: $INSTALL_TARGET" >&2
    exit 1
fi
# The rename is visible but not crash-durable until its parent directory is
# synced. Surface a failure instead of claiming the helper was installed
# durably; the complete visible binary is left for inspection/retry.
sync_path "$INSTALL_DIR"

echo
echo "Installed: $INSTALL_TARGET"
echo "Smoke test: echo '{\"cmd\":\"probe\"}' | \"$INSTALL_TARGET\""
echo "Point Python at it (if not on PATH): export MORDRED_TPMKEY_HELPER=\"$INSTALL_TARGET\""
