#!/usr/bin/env bash
# Build, ad-hoc codesign, and install the mordred-hermes-sekey helper.
#
# The CryptoKit file-store design (SecureEnclave.P256 + dataRepresentation)
# does not touch the Keychain, so it needs NO keychain-access-groups
# entitlement, NO provisioning profile, and NO Developer ID identity — an
# ad-hoc signature (`codesign -s -`) is enough for Secure Enclave access.
#
# Run on a Mac with the Xcode toolchain and a Secure Enclave (Apple Silicon
# or T2). Idempotent: re-running rebuilds and re-installs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INSTALL_DIR="${MORDRED_SEKEY_INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="mordred-hermes-sekey"

# Resolve output directory before building (--show-bin-path exits immediately).
BIN_DIR="$(swift build -c release --show-bin-path)"

echo "==> swift build -c release"
swift build -c release

BUILT_BIN="$BIN_DIR/$BINARY_NAME"
if [[ ! -f "$BUILT_BIN" ]]; then
    echo "ERROR: built binary not found at $BUILT_BIN" >&2
    exit 1
fi

echo "==> codesign (ad-hoc)"
# Ad-hoc signature is sufficient: no entitlement, no profile, no .app needed
# because the helper persists keys as SecureEnclave dataRepresentation blobs
# in plain files rather than in the Keychain.
codesign --force --sign - "$BUILT_BIN"

echo "==> Installing to $INSTALL_DIR/$BINARY_NAME"
mkdir -p "$INSTALL_DIR"
cp -f "$BUILT_BIN" "$INSTALL_DIR/$BINARY_NAME"

echo "==> Verifying signature"
codesign -dvv "$INSTALL_DIR/$BINARY_NAME" 2>&1 | sed 's/^/    /'

echo
echo "Installed: $INSTALL_DIR/$BINARY_NAME"
echo "Smoke test: echo '{\"cmd\":\"probe\"}' | \"$INSTALL_DIR/$BINARY_NAME\""
echo "Point Python at it (if not on PATH): export MORDRED_SEKEY_HELPER=\"$INSTALL_DIR/$BINARY_NAME\""
