#!/usr/bin/env bash
# Build, codesign, and install the mordred-hermes-sekey Secure Enclave helper.
#
# Run on a developer Mac with the Xcode toolchain and the Developer ID
# Application signing identity in the login Keychain. Codesigning may trigger
# a Keychain authorization prompt the first time.
#
# Idempotent: re-running rebuilds and re-installs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SIGN_IDENTITY="${MORDRED_SEKEY_SIGN_IDENTITY:-Developer ID Application: Kazuki Kasahara (FW4R7Z9YKH)}"
TEAM_ID="FW4R7Z9YKH"
INSTALL_DIR="${MORDRED_SEKEY_INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="mordred-hermes-sekey"

echo "==> Verifying signing identity is present"
if ! security find-identity -v -p codesigning | grep -q "$TEAM_ID"; then
    echo "ERROR: no codesigning identity for team $TEAM_ID found in the Keychain." >&2
    echo "       Install the 'Developer ID Application' certificate first." >&2
    exit 1
fi

echo "==> swift build -c release"
swift build -c release

BUILT_BIN="$(swift build -c release --show-bin-path)/$BINARY_NAME"
if [[ ! -f "$BUILT_BIN" ]]; then
    echo "ERROR: built binary not found at $BUILT_BIN" >&2
    exit 1
fi

echo "==> codesign (hardened runtime, no entitlements)"
# No keychain-access-groups entitlement: a Developer ID binary that requests
# it without a provisioning profile is SIGKILLed by AMFI. SE keys persist in
# the legacy Keychain without it.
codesign --force --options runtime \
    --sign "$SIGN_IDENTITY" \
    --timestamp \
    "$BUILT_BIN"

echo "==> Installing to $INSTALL_DIR/$BINARY_NAME"
mkdir -p "$INSTALL_DIR"
cp -f "$BUILT_BIN" "$INSTALL_DIR/$BINARY_NAME"

echo "==> Verifying signature and entitlements"
codesign -dvvv --entitlements - "$INSTALL_DIR/$BINARY_NAME" 2>&1 | sed 's/^/    /'

echo
echo "Installed: $INSTALL_DIR/$BINARY_NAME"
echo "Smoke test: echo '{\"cmd\":\"probe\"}' | \"$INSTALL_DIR/$BINARY_NAME\""
echo "Point Python at it (if not on PATH): export MORDRED_SEKEY_HELPER=\"$INSTALL_DIR/$BINARY_NAME\""
