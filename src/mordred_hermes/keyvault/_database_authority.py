"""Native root memory source, with no SQL dependency or ambient-key fallback.

Callers supply the already resolved database ROOT. Explicit profile-child paths
are rejected rather than interpreting that child's independent memory key as the
root source. Observation reads public metadata/ciphertext only. POSIX enrollment
is the sole writer of the stable source-generation binding.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import secrets
import sys
from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from .._database_contracts import DatabaseRefused, NativeSnapshot, RootIdentity
from .._database_lifecycle import ExclusiveLease
from .._private_fs import PrivateFSError, open_private_directory
from . import wrap

if TYPE_CHECKING:
    from ._windows_custody import WindowsCustodySession

_BINDING = "db-key-source.json"
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


@contextlib.contextmanager
def _refusal() -> Iterator[None]:
    # Custody has several independent exception taxonomies. Do not expose native
    # selectors, filesystem contents or parsed secrets through this boundary.
    try:
        yield
    except DatabaseRefused:
        raise
    except Exception as exc:
        raise DatabaseRefused("native database source is unavailable or invalid") from exc


def _root(root: Path) -> tuple[Path, RootIdentity]:
    absolute = root.absolute()
    # Root resolution belongs above this API. Reject both lexical and resolved
    # child spelling; never silently select a child's independent custody.
    if absolute.parent.name.casefold() == "profiles":
        raise DatabaseRefused("database source requires the resolved root home")
    if absolute != absolute.resolve(strict=True):
        raise DatabaseRefused("database source requires a canonical physical root")
    if sys.platform == "win32":
        from .._database_locking_windows import identify_root
    elif sys.platform in {"linux", "darwin"}:
        from .._database_locking_posix import identify_root
    else:
        raise DatabaseRefused("native database source platform is unsupported")
    return absolute, identify_root(absolute)


def _digest(identity: RootIdentity, provider: str, metadata: dict[str, object], wrapped: bytes) -> str:
    public = {
        "version": 1,
        "root": asdict(identity),
        "provider": provider,
        "authority": metadata,
        "wrapped_sha256": hashlib.sha256(wrapped).hexdigest(),
    }
    return hashlib.sha256(_json(public)).hexdigest()


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DatabaseRefused("duplicate database source metadata field")
        result[key] = value
    return result


def _binding(raw: bytes, identity: RootIdentity, provider: str, digest: str) -> NativeSnapshot:
    data = json.loads(raw, object_pairs_hook=_pairs)
    if (
        not raw.endswith(b"\n")
        or not isinstance(data, dict)
        or set(data) != {"version", "root", "provider", "generation", "record_sha256"}
        or type(data["version"]) is not int
        or data["version"] != 1
        or not isinstance(data["root"], dict)
        or type(data["root"].get("volume")) is not int
        or data["root"] != asdict(identity)
        or data["provider"] != provider
        or not isinstance(data["generation"], str)
        or _HEX32.fullmatch(data["generation"]) is None
        or data["record_sha256"] != digest
    ):
        raise DatabaseRefused("database source binding changed or is malformed")
    return NativeSnapshot(identity, "tpm" if provider == "tpm" else "secure-enclave", data["generation"], digest)


def _posix_record(root: Path, identity: RootIdentity) -> tuple[Literal["tpm", "secure-enclave"], str]:
    if sys.platform == "linux":
        from ._memory_key import memory_key_id

        key_id = memory_key_id(root)
        with open_private_directory(root / "mordred") as directory:
            wrapped = directory.read_bytes("memory-key.wrapped", max_bytes=wrap.HEADER_LEN)
        wrap._parse_header(wrapped, key_id)
        return "tpm", _digest(identity, "tpm", {"key_id": key_id, "role": "memory"}, wrapped)

    # Do not read a Keychain anchor on the metadata hot path. Only the stable
    # device-wrapping header contributes, never the manifest's update counter,
    # unrelated files, or .env ciphertext. Fresh load authenticates the pinned
    # manifest and its .env through open_vault before any value is returned.
    from . import manifest
    from ._identity import vault_identity

    vault_root = root / "mordred" / "vault"
    with open_private_directory(vault_root) as directory:
        generations = []
        for name in directory.list_names(max_entries=4096):
            matched = re.fullmatch(r"manifest\.([0-9]+)\.mvmf", name)
            if matched is not None:
                generations.append((int(matched[1]), name))
        if not generations:
            raise DatabaseRefused("database source vault has no device header")
        _, name = max(generations)
        current = manifest.parse_unverified(directory.read_bytes(name, max_bytes=8 * 1024 * 1024))
    key_id = vault_identity(vault_root)
    if current.key_id != key_id or ".env" not in current.files:
        raise DatabaseRefused("database source vault has no root memory source")
    wrap._parse_header(current.wmk, key_id)
    return "secure-enclave", _digest(identity, "secure-enclave", {"key_id": key_id, "role": "memory"}, current.wmk)


def _observe_posix(root: Path, identity: RootIdentity) -> NativeSnapshot:
    provider, digest = _posix_record(root, identity)
    with open_private_directory(root / "mordred") as directory:
        raw = directory.read_bytes(_BINDING, max_bytes=4096)
    result = _binding(raw, identity, provider, digest)
    if _root(root)[1] != identity:
        raise DatabaseRefused("database source root changed")
    return result


def _observe_windows(session: WindowsCustodySession, identity: RootIdentity) -> NativeSnapshot:
    lease, wrapped = session.memory_source_record()
    if lease.role != "memory" or _HEX64.fullmatch(lease.generation) is None:
        raise DatabaseRefused("database source memory generation is invalid")
    wrap._parse_header(wrapped, lease.native_key_id)
    metadata: dict[str, object] = {
        "profile_nonce": lease.profile_nonce,
        "role": lease.role,
        "generation": lease.generation,
        "epoch": lease.epoch,
        "key_id": lease.key_id,
        "native_key_id": lease.native_key_id,
        "public_sha256": lease.public_sha256,
    }
    session.check()
    return NativeSnapshot(identity, "cng", lease.generation, _digest(identity, "cng", metadata, wrapped))


def observe_database_source(*, root: Path) -> NativeSnapshot:
    """Read existing checked authority metadata with zero native key operations."""
    with _refusal():
        root, identity = _root(root)
        if sys.platform == "win32":
            from ._windows_custody import windows_custody_session

            with windows_custody_session(root) as session:
                result = _observe_windows(session, identity)
                if _root(root)[1] != identity:
                    raise DatabaseRefused("database source root changed")
                return result
        return _observe_posix(root, identity)


def _load_posix(root: Path, identity: RootIdentity, digest: str) -> bytes:
    if sys.platform == "linux":
        from ._memory_key import load_linux_memory_key

        return load_linux_memory_key(home=root)
    import io

    from dotenv import dotenv_values

    from . import vault
    from ._identity import resolve_store, vault_identity
    from ._seckey_backend import _SecKeyBackend
    from .memory_crypto import decode_key

    vault_root = root / "mordred" / "vault"
    key_id = vault_identity(vault_root)
    # Disable software Keychain fallback while retaining both native SE
    # namespaces so an existing macOS vault keeps its hardware authority.
    backend = _SecKeyBackend(sw_ops=None)
    with vault.open_vault(
        vault_root, key_id=key_id, backend=backend, store=resolve_store(None), anchor_label=key_id
    ) as opened:
        if _digest(identity, "secure-enclave", {"key_id": key_id, "role": "memory"}, opened._wmk) != digest:
            raise DatabaseRefused("observed vault device header is not the authenticated authority")
        plaintext = opened.read_file(".env")
    values = dotenv_values(stream=io.StringIO(plaintext.decode("utf-8")), interpolate=False)
    value = values.get("HERMES_MEMORY_KEY")
    if not value:
        raise DatabaseRefused("root vault memory key is absent")
    return decode_key(value)


def _key(material: bytes) -> bytes:
    if not isinstance(material, bytes) or len(material) != 32:
        raise DatabaseRefused("native database source must resolve exactly 32 bytes")
    return material


def load_database_source(*, root: Path, expected: NativeSnapshot) -> bytes:
    """Resolve fresh native custody only after matching the expected metadata."""
    with _refusal():
        root, identity = _root(root)
        if sys.platform == "win32":
            from ._windows_custody import windows_custody_session

            with windows_custody_session(root) as session:
                if _observe_windows(session, identity) != expected:
                    raise DatabaseRefused("database source changed before native resolution")
                material = _key(session.load_memory_key())
                if _observe_windows(session, identity) != expected or _root(root)[1] != identity:
                    raise DatabaseRefused("database source changed during native resolution")
                return material
        if _observe_posix(root, identity) != expected:
            raise DatabaseRefused("database source changed before native resolution")
        material = _key(_load_posix(root, identity, expected.record_sha256))
        if _observe_posix(root, identity) != expected:
            raise DatabaseRefused("database source changed during native resolution")
        return material


def enroll_database_source(*, root: Path, lease: ExclusiveLease) -> NativeSnapshot:
    """Authenticate existing native custody under preceding exclusive authority."""
    with _refusal():
        root, identity = _root(root)
        if type(lease) is not ExclusiveLease:
            raise DatabaseRefused("a preceding exclusive database lease is required")
        lease.assert_held(root)
        if sys.platform == "win32":
            expected = observe_database_source(root=root)
            _key(load_database_source(root=root, expected=expected))
            lease.assert_held(root)
            return expected
        provider, digest = _posix_record(root, identity)
        with open_private_directory(root / "mordred") as directory:
            try:
                raw = directory.read_bytes(_BINDING, max_bytes=4096)
            except PrivateFSError as exc:
                if exc.reason != "missing":
                    raise
                raw = None
        existing = None if raw is None else _binding(raw, identity, provider, digest)
        _key(_load_posix(root, identity, digest))
        if _posix_record(root, identity) != (provider, digest):
            raise DatabaseRefused("database source changed during enrollment")
        lease.assert_held(root)
        if existing is not None:
            if _observe_posix(root, identity) != existing:
                raise DatabaseRefused("database source binding changed during enrollment")
            return existing
        result = NativeSnapshot(identity, provider, secrets.token_hex(16), digest)
        data = {
            "version": 1,
            "root": asdict(identity),
            "provider": provider,
            "generation": result.generation,
            "record_sha256": digest,
        }
        with open_private_directory(root / "mordred") as directory, directory.transaction() as tx:
            lease.assert_held(root)
            tx.create_bytes(_BINDING, _json(data))
        if _observe_posix(root, identity) != result:
            raise DatabaseRefused("database source changed during enrollment publication")
        return result
