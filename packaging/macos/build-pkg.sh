#!/bin/bash
# Build Mordred.pkg: the Mac installer that runs scripts/install-standalone.sh for the
# logged-in user (see postinstall). Usage: packaging/macos/build-pkg.sh [OUTPUT.pkg]
#
# The package is unsigned unless MORDRED_PKG_SIGN names a "Developer ID Installer"
# identity; an unsigned package needs "Open Anyway" in System Settings > Privacy & Security.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd -P)"
root="$(cd "$here/../.." && pwd -P)"
out="${1:-$root/dist/Mordred.pkg}"
version="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$root/src/mordred_hermes/__about__.py")"
[[ -n "$version" ]] || { echo "build-pkg: cannot read the version" >&2; exit 1; }

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
payload="$stage/root/Library/Application Support/Mordred/installer/source"
mkdir -p "$payload" "$stage/scripts" "$stage/packages"
# What the installer builds from: the tracked and new files, without tests and docs.
(cd "$root" && git ls-files -co --exclude-standard | grep -v -e '^tests/' -e '^docs/' | rsync -a --files-from=- ./ "$payload/")
cp "$here/postinstall" "$stage/scripts/postinstall"
chmod 755 "$stage/scripts/postinstall"

pkgbuild --quiet --root "$stage/root" --scripts "$stage/scripts" --identifier com.mordred.installer \
  --version "$version" --install-location / "$stage/packages/Mordred-core.pkg"
sed "s/__VERSION__/$version/" "$here/distribution.xml" >"$stage/distribution.xml"
mkdir -p "$(dirname "$out")"
sign=()
if [[ -n "${MORDRED_PKG_SIGN:-}" ]]; then
  sign=(--sign "$MORDRED_PKG_SIGN")
fi
productbuild --quiet --distribution "$stage/distribution.xml" --package-path "$stage/packages" \
  --resources "$here/resources" ${sign[@]+"${sign[@]}"} "$out"
echo "$out ($version)"
