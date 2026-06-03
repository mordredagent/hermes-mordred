"""Subprocess ``_SecKeyOps`` backed by the ad-hoc-signed ``mordred-hermes-sekey`` CLI.

An unsigned / ad-hoc-signed Python interpreter cannot carry the
``keychain-access-groups`` entitlement, so persisting Secure Enclave keys
*in the Keychain* fails with ``errSecMissingEntitlement`` (-34018). The fix
is a small helper binary that Python shells out to: it uses CryptoKit
``SecureEnclave.P256`` and stores the key's ``dataRepresentation`` as a file
(never the Keychain), so no entitlement, provisioning profile, or paid
Developer account is needed — an ad-hoc ``codesign --sign -`` is enough.

This module is the Python half: it locates the helper
(:func:`_find_helper`), drives the JSON-over-stdio protocol
(:func:`_run_helper`), and exposes :class:`_HelperSecKeyOps`, which satisfies
the :class:`mordred_hermes.keyvault._seckey_backend._SecKeyOps` Protocol.

The boundary is identical to the pyobjc ops: every method returns plain
``bytes`` / ``None`` or raises
:class:`mordred_hermes.keyvault._seckey_backend._OpsError` carrying the raw
``OSStatus`` + domain. That lets :class:`_SecKeyBackend`'s existing
error-translation logic (``_translate_error``, ``errSec*`` branches) run
unchanged regardless of whether the SE op went through pyobjc or the helper.

The Swift source and wire protocol live in
``mordred-hermes/native/sekey-helper/`` (see its README).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ._seckey_backend import _OPS_REASONS, _OpsError

# Helper executable name (as installed by native/sekey-helper/build.sh).
_HELPER_NAME = "mordred-hermes-sekey"

# Linux TPM 2.0 helper executable name (native/tpmkey-helper/build.sh). It
# speaks the identical JSON-over-stdio protocol as the Secure-Enclave helper,
# so :class:`_HelperSecKeyOps` drives either one unchanged.
_TPM_HELPER_NAME = "mordred-hermes-tpmkey"

# Wall-clock budget for a single helper invocation. Generous because the
# ``ecdh`` command blocks on the Touch ID / passcode system prompt — the user
# must physically approve it. A missing helper or a hung op fails fast enough
# for callers either way.
_TIMEOUT_SECONDS = 120.0


def _find_named_helper(env_var: str, name: str) -> str | None:
    """Locate a helper binary by env override, then ``~/.local/bin``, then PATH.

    The resolution order is identical for every backend helper (Secure
    Enclave, TPM, …) — only the env-var name and binary name differ:

    1. ``env_var`` — an explicit absolute path. When set it is
       authoritative: a missing target yields ``None`` (we do NOT silently
       fall through to the default search, so a typo surfaces as "no helper"
       rather than picking up a different binary).
    2. ``~/.local/bin/<name>`` — the default install location.
    3. ``<name>`` on ``PATH``.
    """
    env = os.environ.get(env_var)
    if env:
        path = Path(env).expanduser()
        return str(path) if path.is_file() else None

    local = Path.home() / ".local" / "bin" / name
    if local.is_file():
        return str(local)

    return shutil.which(name)


def find_sekey_helper() -> str | None:
    """Locate the macOS Secure-Enclave helper (``mordred-hermes-sekey``)."""
    return _find_named_helper("MORDRED_SEKEY_HELPER", _HELPER_NAME)


def find_tpmkey_helper() -> str | None:
    """Locate the Linux TPM 2.0 helper (``mordred-hermes-tpmkey``)."""
    return _find_named_helper("MORDRED_TPMKEY_HELPER", _TPM_HELPER_NAME)


# Back-compat alias: the original Secure-Enclave-only locator. Production
# callers (``_default_ops``, ``probe_capability``) and tests still reference
# ``_find_helper`` / monkeypatch it, so it remains exactly
# ``find_sekey_helper``.
def _find_helper() -> str | None:
    """Deprecated alias for :func:`find_sekey_helper` (back-compat)."""
    return find_sekey_helper()


def _locate_helper_source() -> Path | None:
    """Locate the ``sekey-helper`` Swift source tree (``build.sh`` + sources).

    ``hermes mordred keyvault enable-se`` builds the helper from source, so it
    must find the source directory before invoking ``build.sh``. Resolution:

    1. **Source checkout** — walk up from this module to a ``native/sekey-helper``
       directory containing ``build.sh`` (editable install / repo clone).
    2. **Installed wheel** — a ``_native/sekey-helper`` copy shipped inside the
       package (added to the wheel separately; see packaging).

    Returns the directory :class:`~pathlib.Path`, or ``None`` when neither is
    present (e.g. a wheel install without the bundled sources).
    """
    marker = "build.sh"
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "native" / "sekey-helper"
        if (candidate / marker).is_file():
            return candidate
    # Installed-wheel fallback: a package-data copy under the package root.
    try:
        from importlib.resources import files

        packaged = files("mordred_hermes").joinpath("_native", "sekey-helper")
        if packaged.joinpath(marker).is_file():
            return Path(str(packaged))
    except (ModuleNotFoundError, TypeError, OSError):
        pass
    return None


def _is_tpmkey_source(candidate: Path) -> bool:
    """True when ``candidate`` is a genuine ``mordred-hermes-tpmkey`` crate.

    ``enable_tpm`` *executes* the ``build.sh`` that :func:`_locate_tpmkey_source`
    resolves to, so matching on ``build.sh`` alone would let a writable ancestor
    (e.g. ``/tmp/native/tpmkey-helper/build.sh``) hijack the build. Require the
    Cargo manifest with the expected package name and the Rust entry point too,
    so a bare planted ``build.sh`` is rejected.
    """
    manifest = candidate / "Cargo.toml"
    if not ((candidate / "build.sh").is_file() and manifest.is_file() and (candidate / "src" / "main.rs").is_file()):
        return False
    try:
        return f'name = "{_TPM_HELPER_NAME}"' in manifest.read_text(encoding="utf-8")
    except OSError:
        return False


def _locate_tpmkey_source() -> Path | None:
    """Locate the ``tpmkey-helper`` Rust source tree (``build.sh`` + Cargo crate).

    Mirror of :func:`_locate_helper_source` for the Linux TPM 2.0 helper
    (``native/tpmkey-helper``). ``hermes mordred keyvault enable-tpm`` builds it
    from source, so it must find the directory before invoking ``build.sh``.
    Resolution: a ``native/tpmkey-helper`` source checkout, then a bundled
    ``_native/tpmkey-helper`` wheel copy. Each candidate is validated by
    :func:`_is_tpmkey_source` so a decoy ``build.sh`` cannot hijack the build.
    """
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "native" / "tpmkey-helper"
        if _is_tpmkey_source(candidate):
            return candidate
    try:
        from importlib.resources import files

        packaged = Path(str(files("mordred_hermes").joinpath("_native", "tpmkey-helper")))
        if _is_tpmkey_source(packaged):
            return packaged
    except (ModuleNotFoundError, TypeError, OSError):
        pass
    return None


def _normalize_reason(value: Any) -> str | None:
    """Validate a helper-supplied ``reason`` against the neutral taxonomy.

    Returns the value only when it is a recognised member of
    :data:`mordred_hermes.keyvault._seckey_backend._OPS_REASONS`
    (``NOT_FOUND`` / ``EXISTS`` / ``UNAVAILABLE`` / ``AUTH_DENIED``);
    anything else — including ``None`` or an unknown future reason —
    becomes ``None`` so dispatch falls back to the numeric status. This
    keeps an older client forward-compatible: a helper may add reasons
    without breaking it (it just loses the neutral shortcut).
    """
    return value if isinstance(value, str) and value in _OPS_REASONS else None


def _run_helper(binary: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Invoke the helper once with ``payload`` on stdin, return parsed stdout.

    Raises:
        _OpsError: On spawn failure, timeout, a non-JSON response, a JSON
            ``{"error": {...}}`` object (carrying the helper's raw
            ``status``/``domain``), or a non-zero exit without an error
            object. ``domain="helper"`` (with ``status=-1``) marks failures
            originating in this bridge rather than in Security.framework, so
            ``_translate_error`` maps them to the conservative
            ``auth_failed`` default.
    """
    try:
        proc = subprocess.run(
            [binary],
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            timeout=_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise _OpsError(-1, "helper", f"helper timed out after {_TIMEOUT_SECONDS}s") from exc
    except OSError as exc:
        raise _OpsError(-1, "helper", f"failed to spawn helper {binary!r}: {exc}") from exc

    try:
        response = json.loads(proc.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        snippet = proc.stdout[:200]
        raise _OpsError(-1, "helper", f"helper returned non-JSON (exit {proc.returncode}): {snippet!r}") from exc

    if not isinstance(response, dict):
        raise _OpsError(-1, "helper", f"helper returned non-object JSON: {response!r}")

    error = response.get("error")
    if isinstance(error, dict):
        raise _OpsError(
            int(error.get("status", -1)),
            str(error.get("domain", "helper")),
            str(error.get("message", "")),
            reason=_normalize_reason(error.get("reason")),
        )

    if proc.returncode != 0:
        raise _OpsError(-1, "helper", f"helper exited {proc.returncode} without an error object")

    return response


def _hex_field(response: dict[str, Any], key: str) -> bytes:
    """Decode a hex-encoded field from a success response.

    A trusted helper always returns the documented field, but a malformed
    value must still surface as :class:`_OpsError` (not a raw
    ``KeyError``/``ValueError``) so the ops boundary contract holds: every
    failure is an ``_OpsError``.
    """
    try:
        return bytes.fromhex(response[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise _OpsError(-1, "helper", f"helper response missing or invalid {key!r}") from exc


class _HelperSecKeyOps:
    """``_SecKeyOps`` implementation that delegates to the signed CLI.

    One method call == one helper process invocation (the protocol is
    request/response per process). Tags and peer public keys cross the
    boundary as hex; the cleartext ``key_id`` never does (the tag is a
    SHA-256 prefix derived in :mod:`_seckey_backend`).
    """

    def __init__(self, binary: str) -> None:
        self._binary = binary

    def create_keypair(self, tag: bytes, label: str, *, unattended: bool = False) -> bytes:
        response = _run_helper(
            self._binary,
            {"cmd": "generate", "tag_hex": tag.hex(), "label": label, "unattended": unattended},
        )
        return _hex_field(response, "public_key_hex")

    def copy_public_key(self, tag: bytes) -> bytes:
        response = _run_helper(self._binary, {"cmd": "public_key", "tag_hex": tag.hex()})
        return _hex_field(response, "public_key_hex")

    def delete_key(self, tag: bytes) -> None:
        # The helper treats errSecItemNotFound as success, so this is idempotent.
        _run_helper(self._binary, {"cmd": "delete", "tag_hex": tag.hex()})

    def key_exchange(self, tag: bytes, peer_pub: bytes) -> bytes:
        response = _run_helper(
            self._binary,
            {"cmd": "ecdh", "tag_hex": tag.hex(), "peer_pub_hex": peer_pub.hex()},
        )
        return _hex_field(response, "shared_hex")

    def probe(self) -> None:
        _run_helper(self._binary, {"cmd": "probe"})
