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
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from .._database_contracts import DatabaseRefused, NativeSnapshot, RootIdentity, decode_database_source_binding
from .._database_lifecycle import ExclusiveLease
from .._private_fs import PrivateFSError, open_private_directory
from .._private_fs._types import validate_leaf
from . import wrap

if TYPE_CHECKING:
    from ._windows_custody import WindowsCustodySession

_BINDING = "db-key-source.json"
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
    domain = resolve_database_domain(root)
    if domain.home != domain.root:
        raise DatabaseRefused("database source requires the resolved root home")
    return domain.root, domain.identities[0]


@dataclass(frozen=True)
class CheckedDatabaseDomain:
    """Physical identity observations; no key material or authority assertions."""

    home: Path
    root: Path
    identities: tuple[RootIdentity, ...]


def _identify_database_home(path: Path) -> RootIdentity:
    if sys.platform == "win32":
        from .._database_locking_windows import identify_root
    elif sys.platform in {"linux", "darwin"}:
        from .._database_locking_posix import identify_root
    else:
        raise DatabaseRefused("database domain platform is unsupported")
    return identify_root(path)


def _database_domain_paths(home: Path) -> tuple[Path, ...]:
    if home.name.casefold() == "profiles":
        raise DatabaseRefused("profile container is not a database home")
    if home.parent.name.casefold() != "profiles":
        return (home,)
    if home.parent.name != "profiles":
        raise DatabaseRefused("ambiguous profile container spelling")
    validate_leaf(home.name)
    if home.name.endswith((" ", ".")) or "~" in home.name:
        raise DatabaseRefused("ambiguous profile home component")
    root = home.parent.parent
    if any(part.casefold() == "profiles" for part in root.parts):
        raise DatabaseRefused("ambiguous nested profile domain")
    return root, home.parent, home


def resolve_database_domain(home: Path) -> CheckedDatabaseDomain:
    """Resolve an existing physical home or checked root/profiles/name domain.

    A profile's physical ownership does not establish historical key independence.
    All callers therefore guard its actual root until authenticated adoption.
    """
    with _refusal():
        if ".." in home.parts:
            raise DatabaseRefused("database home contains a parent alias")
        absolute = home.absolute()
        if absolute != absolute.resolve(strict=True):
            raise DatabaseRefused("database home must use its canonical physical path")
        paths = _database_domain_paths(absolute)
        root = paths[0]
        before = tuple(_identify_database_home(path) for path in paths)
        if root != absolute:
            binding = absolute / "mordred" / _BINDING
            # Presence, including an unsafe link, is enough to refuse a child's
            # attempt to publish root authority. Do not parse it as an exemption.
            try:
                binding.lstat()
            except FileNotFoundError:
                pass
            else:
                raise DatabaseRefused("profile child cannot own a root database source binding")
        after = tuple(_identify_database_home(path) for path in paths)
        if after != before or absolute != absolute.resolve(strict=True):
            raise DatabaseRefused("database home relationship changed")
        return CheckedDatabaseDomain(absolute, root, before)


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


def _binding(raw: bytes, identity: RootIdentity, provider: str, digest: str) -> NativeSnapshot:
    result = decode_database_source_binding(raw)
    if result.root != identity or result.provider != provider or result.record_sha256 != digest:
        raise DatabaseRefused("database source binding changed or is malformed")
    return result


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
    from . import vault
    from ._identity import resolve_store, vault_identity
    from ._memory_env import effective_memory_key
    from ._seckey_backend import _SecKeyBackend

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
    material = effective_memory_key(plaintext)
    if material is None:
        raise DatabaseRefused("root vault memory key is absent")
    return material


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


def retire_database_source(*, root: Path, expected: NativeSnapshot, lease: ExclusiveLease) -> None:
    """Retire only the observed POSIX binding after a fresh all-generation guard.

    The caller owns native custody and retains the preceding database lease
    through its subsequent native operation. This takes only the checked-file
    metadata transaction; it never acquires database or native custody locks.
    Successful retirement is not silently undone if that later operation fails.
    """
    from .._database_inventory import assert_mutation_safe

    with _refusal():
        root, identity = _root(root)
        if type(lease) is not ExclusiveLease:
            raise DatabaseRefused("a preceding exclusive database lease is required")
        ExclusiveLease.assert_held(lease, root)
        if identity.platform == "win32":
            raise DatabaseRefused("Windows has no independent database source binding")
        if _observe_posix(root, identity) != expected:
            raise DatabaseRefused("database source changed before retirement")
        with open_private_directory(root / "mordred") as directory:
            observed = directory.stat(_BINDING)
            raw = directory.read_bytes(_BINDING, max_bytes=4096)
            if directory.stat(_BINDING) != observed or decode_database_source_binding(raw) != expected:
                raise DatabaseRefused("database source binding changed before retirement")
            assert_mutation_safe(root, None, lease)
            if _observe_posix(root, identity) != expected:
                raise DatabaseRefused("database source changed during retirement")
            with directory.transaction() as tx:
                ExclusiveLease.assert_held(lease, root)
                if tx.stat(_BINDING) != observed or tx.read_bytes(_BINDING, max_bytes=4096) != raw:
                    raise DatabaseRefused("database source binding changed during retirement")
                tx.delete_file(_BINDING, expected_identity=observed.identity)


def _load_historical_database_source(*, root: Path, lease: ExclusiveLease) -> tuple[str, bytes]:
    """Authenticate existing POSIX custody without inventing/publishing a binding.

    Used only by offline legacy adoption before exhaustive ciphertext proof.
    Enrollment later repeats native authentication before assigning generation.
    """
    with _refusal():
        if type(lease) is not ExclusiveLease:
            raise DatabaseRefused("a preceding exclusive database lease is required")
        ExclusiveLease.assert_held(lease, root)
        root, identity = _root(root)
        if sys.platform not in {"darwin", "linux"}:
            raise DatabaseRefused("historical database source is unsupported")
        provider, digest = _posix_record(root, identity)
        material = _key(_load_posix(root, identity, digest))
        if _posix_record(root, identity) != (provider, digest) or _root(root)[1] != identity:
            raise DatabaseRefused("historical database source changed during authentication")
        ExclusiveLease.assert_held(lease, root)
        return digest, material
