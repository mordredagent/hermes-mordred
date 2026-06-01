"""Subprocess ``_SecKeyOps`` backed by the signed ``mordred-hermes-sekey`` CLI.

An unsigned / ad-hoc-signed Python interpreter cannot carry the
``keychain-access-groups`` entitlement, so persisting Secure Enclave keys
fails with ``errSecMissingEntitlement`` (-34018). The fix is a separately
Developer-ID-signed helper binary (with a bundle ID + entitlement) that
Python shells out to — the same architecture the 1Password CLI uses.

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

from ._seckey_backend import _OpsError

# Helper executable name (as installed by native/sekey-helper/build.sh).
_HELPER_NAME = "mordred-hermes-sekey"

# Wall-clock budget for a single helper invocation. Generous because the
# ``ecdh`` command blocks on the Touch ID / passcode system prompt — the user
# must physically approve it. A missing helper or a hung op fails fast enough
# for callers either way.
_TIMEOUT_SECONDS = 120.0


def _find_helper() -> str | None:
    """Locate the signed helper binary, or ``None`` if unavailable.

    Resolution order:

    1. ``MORDRED_SEKEY_HELPER`` — an explicit absolute path. When set it is
       authoritative: a missing target yields ``None`` (we do NOT silently
       fall through to the default search, so a typo surfaces as "no helper"
       rather than picking up a different binary).
    2. ``~/.local/bin/mordred-hermes-sekey`` — the default install location.
    3. ``mordred-hermes-sekey`` on ``PATH``.
    """
    env = os.environ.get("MORDRED_SEKEY_HELPER")
    if env:
        path = Path(env).expanduser()
        return str(path) if path.is_file() else None

    local = Path.home() / ".local" / "bin" / _HELPER_NAME
    if local.is_file():
        return str(local)

    return shutil.which(_HELPER_NAME)


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
