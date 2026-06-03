#!/usr/bin/env bash
# Build and install the mordred-hermes-tpmkey helper.
#
# Linux TPM 2.0 counterpart to native/sekey-helper/build.sh. Run on a Linux
# host with a Rust toolchain (cargo). Phase 2b additionally needs libtss2-dev
# (the tss-esapi backend); until it is wired the helper builds on any host and
# answers every command with the neutral UNAVAILABLE reason.
#
# Idempotent: re-running rebuilds and re-installs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALL_DIR="${MORDRED_TPMKEY_INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="mordred-hermes-tpmkey"

echo "==> cargo build --release"
cargo build --release

BUILT_BIN="target/release/$BINARY_NAME"
if [[ ! -f "$BUILT_BIN" ]]; then
    echo "ERROR: built binary not found at $BUILT_BIN" >&2
    exit 1
fi

echo "==> Installing to $INSTALL_DIR/$BINARY_NAME"
mkdir -p "$INSTALL_DIR"
cp -f "$BUILT_BIN" "$INSTALL_DIR/$BINARY_NAME"

echo
echo "Installed: $INSTALL_DIR/$BINARY_NAME"
echo "Smoke test: echo '{\"cmd\":\"probe\"}' | \"$INSTALL_DIR/$BINARY_NAME\""
echo "Point Python at it (if not on PATH): export MORDRED_TPMKEY_HELPER=\"$INSTALL_DIR/$BINARY_NAME\""
