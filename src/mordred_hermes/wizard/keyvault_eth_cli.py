"""``hermes-mordred keyvault eth {new,derive,address}`` — Ethereum key CLI.

A dedicated CLI surface over :mod:`mordred_hermes.keyvault.ethereum`:

- ``new``     — :func:`~mordred_hermes.keyvault.ethereum.generate_ethereum_key`:
  generate a fresh random secp256k1 key, store it SE/TPM-encrypted, and print
  the EIP-55 address + the opaque ``envelope_id`` handle.
- ``derive``  — :func:`~mordred_hermes.keyvault.ethereum.derive_ethereum_key`:
  derive a deterministic BIP-44 account (``m/44'/60'/account'/change/index``)
  from the seed stored at ``keyvault init`` (``bip39.seed.v1``). When the
  keyvault holds exactly one seed it is auto-discovered; ``--seed-envelope-id``
  selects one explicitly when several are present.
- ``address`` — :func:`~mordred_hermes.keyvault.ethereum.get_ethereum_address`:
  read back the address for a previously stored key.

The raw private key never leaves the keyvault — every command returns only the
checksum address and the envelope handle, never the 32-byte scalar.

Mirrors :mod:`mordred_hermes.wizard.keyvault_native_cli`: small business
functions (``eth_new`` / ``eth_derive`` / ``eth_address``) plus thin
``cli_*`` argparse adapters wired in :mod:`cli`. Heavy imports (``eth-keys``
via the ethereum module, the production Secure-Enclave backend) stay
function-local so this module imports on any platform and without the
optional ``ethereum`` extra installed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TYPE_CHECKING

from ..keyvault._exceptions import WrapError
from . import _term
from ._defaults import resolve_backend
from ._keyvault_init import _stderr_audit_sink

if TYPE_CHECKING:
    from ..keyvault.wrap import AuditSink, NativeBackend

__all__ = [
    "cli_eth_address",
    "cli_eth_derive",
    "cli_eth_new",
    "eth_address",
    "eth_derive",
    "eth_new",
]

#: Errors that map to a legible "rc 1" rather than a traceback: a missing
#: optional extra (``eth-keys``), a missing/corrupt envelope (``OSError``),
#: a malformed ``envelope_id`` (``ValueError``), or a Secure-Enclave failure
#: (``WrapError``). Anything else is a real bug and propagates.
_EXPECTED_ERRORS = (ImportError, OSError, ValueError, WrapError)


def _resolve_sink(audit_sink: AuditSink | None) -> AuditSink:
    """Return ``audit_sink`` or the default stderr sink."""
    return audit_sink if audit_sink is not None else _stderr_audit_sink


def _list_seed_envelope_ids(key_id: str, home: Path | None) -> list[str]:
    """Stored HD seed ``envelope_id``s — delegates to the ethereum layer.

    The on-disk ciphertext layout is owned by
    :func:`mordred_hermes.keyvault.ethereum.list_seed_envelope_ids`; the
    wizard does not reconstruct the path formula itself.
    """
    from ..keyvault.ethereum import list_seed_envelope_ids

    return list_seed_envelope_ids(key_id, home=home)


def _resolve_seed_envelope_id(key_id: str, seed_envelope_id: str | None, home: Path | None) -> str | None:
    """Resolve the seed envelope to derive from, or ``None`` on an error.

    An explicit ``seed_envelope_id`` is returned as-is. Otherwise the single
    stored seed is auto-discovered; zero or several stored seeds emit an
    actionable error and return ``None`` (the caller maps that to rc 1).
    """
    if seed_envelope_id is not None:
        return seed_envelope_id

    found = _list_seed_envelope_ids(key_id, home)
    if not found:
        _term.emit_error(
            f"No HD seed stored for key {key_id!r}. Run `hermes-mordred keyvault init` "
            "to create one (it stores the seed for HD derivation), or store an imported "
            "seed first."
        )
        return None
    if len(found) > 1:
        _term.emit_error(
            f"Multiple HD seeds stored for key {key_id!r}. Pass --seed-envelope-id <id> "
            "to choose which one to derive from."
        )
        return None
    return found[0]


def _emit(payload: dict[str, object], lines: list[str], *, as_json: bool) -> None:
    """Print ``payload`` as JSON, or ``lines`` as human-readable text."""
    if as_json:
        print(json.dumps(payload))
    else:
        for line in lines:
            print(line)


# -----------------------------------------------------------------------------
# Business functions.
# -----------------------------------------------------------------------------


def eth_new(
    *,
    key_id: str = "default",
    as_json: bool = False,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink | None = None,
    home: Path | None = None,
) -> int:
    """Generate a random secp256k1 Ethereum key; print address + envelope id.

    Returns 0 on success; 1 if the ``ethereum`` extra is missing or the
    Secure Enclave fails. The private key is stored encrypted and never
    printed.
    """
    backend = resolve_backend(backend)
    sink = _resolve_sink(audit_sink)
    try:
        from ..keyvault.ethereum import generate_ethereum_key

        envelope_id, address = generate_ethereum_key(key_id, backend=backend, audit_sink=sink, home=home)
    except _EXPECTED_ERRORS as exc:
        _term.emit_error(f"Could not create Ethereum key: {exc}")
        return 1

    _emit(
        {"key_id": key_id, "envelope_id": envelope_id, "address": address},
        ["Ethereum key created.", f"  address:     {address}", f"  envelope_id: {envelope_id}"],
        as_json=as_json,
    )
    return 0


def eth_derive(
    *,
    index: int,
    account: int = 0,
    change: int = 0,
    seed_envelope_id: str | None = None,
    key_id: str = "default",
    as_json: bool = False,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink | None = None,
    home: Path | None = None,
) -> int:
    """Derive a BIP-44 Ethereum account from the stored HD seed.

    Resolves the seed envelope (auto-discovered when unique; otherwise via
    ``seed_envelope_id``), derives ``m/44'/60'/account'/change/index``, and
    prints the address + path. Decryption of the seed triggers Enclave
    authorization (Touch ID / passcode) unless the wrapping key is
    unattended. Returns 0 on success; 1 on a resolution or Enclave error.

    The optional BIP-39 passphrase ("25th word") is not exposed at this CLI
    surface — derivation always uses an empty passphrase. A seed that was
    protected by a 25th word must be derived through the Python API
    (:func:`mordred_hermes.keyvault.ethereum.derive_ethereum_key`).
    """
    backend = resolve_backend(backend)
    sink = _resolve_sink(audit_sink)

    resolved = _resolve_seed_envelope_id(key_id, seed_envelope_id, home)
    if resolved is None:
        return 1

    try:
        from ..keyvault.ethereum import derive_ethereum_key

        address, path = derive_ethereum_key(
            key_id,
            resolved,
            index,
            backend=backend,
            audit_sink=sink,
            home=home,
            account=account,
            change=change,
        )
    except _EXPECTED_ERRORS as exc:
        _term.emit_error(f"Could not derive Ethereum account: {exc}")
        return 1

    _emit(
        {
            "key_id": key_id,
            "address": address,
            "path": path,
            "index": index,
            "account": account,
            "change": change,
        },
        [f"  address: {address}", f"  path:    {path}"],
        as_json=as_json,
    )
    return 0


def eth_address(
    envelope_id: str,
    *,
    key_id: str = "default",
    as_json: bool = False,
    backend: NativeBackend | None = None,
    audit_sink: AuditSink | None = None,
    home: Path | None = None,
) -> int:
    """Read back the EIP-55 address for a stored Ethereum key envelope.

    Decryption triggers Enclave authorization (Touch ID / passcode). Returns
    0 on success; 1 for an unknown/malformed envelope or an Enclave error.
    """
    backend = resolve_backend(backend)
    sink = _resolve_sink(audit_sink)
    try:
        from ..keyvault.ethereum import get_ethereum_address

        address = get_ethereum_address(key_id, envelope_id, backend=backend, audit_sink=sink, home=home)
    except _EXPECTED_ERRORS as exc:
        _term.emit_error(f"Could not read Ethereum address: {exc}")
        return 1

    _emit(
        {"key_id": key_id, "envelope_id": envelope_id, "address": address},
        [f"  address: {address}"],
        as_json=as_json,
    )
    return 0


# -----------------------------------------------------------------------------
# CLI adapters wired in cli.py.
# -----------------------------------------------------------------------------


def cli_eth_new(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault eth new [--key-id ID] [--json]``."""
    return eth_new(key_id=args.key_id, as_json=bool(getattr(args, "json", False)))


def cli_eth_derive(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault eth derive --index N [...]``."""
    return eth_derive(
        key_id=args.key_id,
        index=args.index,
        account=args.account,
        change=args.change,
        seed_envelope_id=args.seed_envelope_id,
        as_json=bool(getattr(args, "json", False)),
    )


def cli_eth_address(args: argparse.Namespace) -> int:
    """argparse handler for ``keyvault eth address --envelope-id ID [--json]``."""
    return eth_address(args.envelope_id, key_id=args.key_id, as_json=bool(getattr(args, "json", False)))


# -----------------------------------------------------------------------------
# Subparser registration (called from cli._add_keyvault).
# -----------------------------------------------------------------------------


def add_eth_subparsers(ksub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``eth {new,derive,address}`` under the ``keyvault`` subparsers.

    Lives here rather than inlined in :func:`cli._add_keyvault` so that
    builder stays within the PLR0915 statement budget and ``cli.py`` keeps
    well under its size convention. ``func`` is wired directly to the
    ``cli_eth_*`` adapters (this module is already loaded to register them).
    """
    p_eth = ksub.add_parser("eth", help="Create / derive Ethereum keys (secp256k1)")
    esub = p_eth.add_subparsers(dest="eth_command", required=True, metavar="COMMAND")

    p_new = esub.add_parser("new", help="Generate a new random Ethereum key")
    p_new.add_argument("--key-id", default="default", help="Keyvault key id (default: default)")
    p_new.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p_new.set_defaults(func=cli_eth_new)

    p_derive = esub.add_parser(
        "derive",
        help="Derive a BIP-44 HD account from the stored seed",
        description=(
            "Derive m/44'/60'/account'/change/index from the stored seed. The "
            'BIP-39 passphrase ("25th word") is not supported here — derivation '
            "always uses an empty passphrase."
        ),
    )
    p_derive.add_argument("--index", type=int, default=0, help="BIP-44 address index (default: 0)")
    p_derive.add_argument("--account", type=int, default=0, help="BIP-44 account level (default: 0)")
    p_derive.add_argument("--change", type=int, default=0, help="BIP-44 change level (default: 0)")
    p_derive.add_argument(
        "--seed-envelope-id",
        default=None,
        help="Explicit seed envelope id (required only if several seeds are stored)",
    )
    p_derive.add_argument("--key-id", default="default", help="Keyvault key id (default: default)")
    p_derive.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p_derive.set_defaults(func=cli_eth_derive)

    p_addr = esub.add_parser("address", help="Show the address for a stored Ethereum key")
    p_addr.add_argument("--envelope-id", required=True, help="Envelope id from `keyvault eth new`")
    p_addr.add_argument("--key-id", default="default", help="Keyvault key id (default: default)")
    p_addr.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p_addr.set_defaults(func=cli_eth_address)
