"""Checked, canonical database marker v2; legacy intent is never authority."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal, cast

from .._database_contracts import DatabaseRefused, NativeSnapshot, RootIdentity
from .._database_lifecycle import ExclusiveLease
from .._private_fs import PrivateFSError, open_private_directory
from ..keyvault._database_authority import resolve_database_domain

_NAME = "db-encryption.marker"
_LIMIT = 4096


@dataclass(frozen=True)
class Marker:
    snapshot: NativeSnapshot


@dataclass(frozen=True)
class LegacyMarker:
    raw: bytes


def _json(snapshot: NativeSnapshot) -> bytes:
    return (
        json.dumps(
            {"version": 2, "format": "mordred-sqlcipher-v1", **asdict(snapshot)},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DatabaseRefused("duplicate database marker field")
        result[key] = value
    return result


def _object(value: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise DatabaseRefused("invalid database marker fields")
    return cast(dict[str, object], value)


def _hex(value: object, size: int) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{" + str(size) + "}", value) is None:
        raise DatabaseRefused("invalid database marker hexadecimal field")
    return value


def _decimal(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is None or int(value) >= 1 << 64:
        raise DatabaseRefused("invalid database marker POSIX identity")
    return value


def _root_fields(
    root: dict[str, object], value: object
) -> tuple[Literal["linux", "darwin", "win32"], Literal["tpm", "secure-enclave", "cng"], int, str, str]:
    volume = root["volume"]
    if type(volume) is not int or not 0 <= volume < 1 << 64:
        raise DatabaseRefused("invalid database marker volume")
    platform: Literal["linux", "darwin", "win32"]
    provider: Literal["tpm", "secure-enclave", "cng"]
    if root["platform"] == "linux" and value == "tpm":
        platform, provider = "linux", "tpm"
    elif root["platform"] == "darwin" and value == "secure-enclave":
        platform, provider = "darwin", "secure-enclave"
    elif root["platform"] == "win32" and value == "cng":
        platform, provider = "win32", "cng"
    else:
        raise DatabaseRefused("unsupported database marker platform/provider")
    if platform == "win32":
        file_id = _hex(root["file_id"], 32)
        owner = root["owner"]
        if not isinstance(owner, str) or re.fullmatch(r"[0-9a-f]{24,136}", owner) is None or len(owner) % 2:
            raise DatabaseRefused("invalid database marker SID")
        sid = bytes.fromhex(owner)
        if sid[0] != 1 or not 1 <= sid[1] <= 15 or len(sid) != 8 + 4 * sid[1]:
            raise DatabaseRefused("invalid database marker SID")
    else:
        file_id, owner = _decimal(root["file_id"]), _decimal(root["owner"])
    return platform, provider, volume, file_id, owner


def _decode(raw: bytes) -> Marker | LegacyMarker:
    if raw == b"1\n":
        return LegacyMarker(raw)
    if not 0 < len(raw) <= _LIMIT or not raw.endswith(b"\n"):
        raise DatabaseRefused("invalid database marker size or terminator")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise DatabaseRefused("malformed database marker") from None
    record = _object(value, {"version", "format", "root", "provider", "generation", "record_sha256"})
    if type(record["version"]) is not int or record["version"] != 2:
        raise DatabaseRefused("unsupported database marker version")
    if record["format"] != "mordred-sqlcipher-v1":
        raise DatabaseRefused("unsupported database marker format")
    root = _object(record["root"], {"platform", "volume", "file_id", "owner"})
    platform, provider, volume, file_id, owner = _root_fields(root, record["provider"])
    snapshot = NativeSnapshot(
        RootIdentity(platform, volume, file_id, owner),
        provider,
        _hex(record["generation"], 64 if platform == "win32" else 32),
        _hex(record["record_sha256"], 64),
    )
    if raw != _json(snapshot):
        raise DatabaseRefused("noncanonical database marker")
    return Marker(snapshot)


def _identity(root: Path) -> RootIdentity:
    domain = resolve_database_domain(root)
    if domain.home != domain.root:
        raise DatabaseRefused("database marker requires the resolved root home")
    return domain.identities[0]


def read_marker(root: Path) -> Marker | LegacyMarker | None:
    """Read existing private marker bytes; absent intent creates nothing."""
    identity = _identity(root)
    try:
        with open_private_directory(root / "mordred") as directory:
            try:
                raw = directory.read_bytes(_NAME, max_bytes=_LIMIT)
            except PrivateFSError as exc:
                if exc.reason != "missing":
                    raise
                raw = None
    except PrivateFSError as exc:
        if exc.reason != "missing":
            raise DatabaseRefused("database marker cannot be read safely") from None
        raw = None
    result = None if raw is None else _decode(raw)
    if _identity(root) != identity or (isinstance(result, Marker) and result.snapshot.root != identity):
        raise DatabaseRefused("database marker root identity changed")
    return result


def write_marker(root: Path, snapshot: NativeSnapshot, *, lease: ExclusiveLease) -> None:
    """Publish v2 under actual root EX proof; never adopt or change generation."""
    if type(lease) is not ExclusiveLease:
        raise DatabaseRefused("a preceding exclusive database lease is required")
    ExclusiveLease.assert_held(lease, root)
    if _identity(root) != snapshot.root:
        raise DatabaseRefused("database marker snapshot belongs to another root")
    data = _json(snapshot)
    if _decode(data) != Marker(snapshot):
        raise DatabaseRefused("invalid database marker snapshot")
    try:
        with open_private_directory(root / "mordred") as directory, directory.transaction() as tx:
            ExclusiveLease.assert_held(lease, root)
            try:
                previous = tx.read_bytes(_NAME, max_bytes=_LIMIT)
            except PrivateFSError as exc:
                if exc.reason != "missing":
                    raise
                previous = None
            if previous is not None:
                if _decode(previous) != Marker(snapshot):
                    raise DatabaseRefused("database marker cannot change authority in place")
            else:
                tx.create_bytes(_NAME, data)
            ExclusiveLease.assert_held(lease, root)
    except PrivateFSError:
        raise DatabaseRefused("database marker cannot be published safely") from None


def _adopt_marker(root: Path, snapshot: NativeSnapshot, *, lease: ExclusiveLease) -> None:
    """Publish only after migration's complete authenticated legacy journal."""
    from ._migrate import JOURNAL_SUBPATH, _read_json

    if type(lease) is not ExclusiveLease:
        raise DatabaseRefused("a preceding exclusive database lease is required")
    ExclusiveLease.assert_held(lease, root)
    journal = _read_json(root, JOURNAL_SUBPATH[-1])
    if journal.get("direction") != "adopt" or journal.get("snapshot") != asdict(snapshot):
        raise DatabaseRefused("legacy marker requires the authenticated adoption journal")
    if _identity(root) != snapshot.root:
        raise DatabaseRefused("legacy adoption root changed")
    with open_private_directory(root / "mordred") as directory, directory.transaction() as tx:
        previous = _decode(tx.read_bytes(_NAME, max_bytes=_LIMIT))
        if previous not in (LegacyMarker(b"1\n"), Marker(snapshot)):
            raise DatabaseRefused("legacy marker changed before adoption")
        ExclusiveLease.assert_held(lease, root)
        tx.replace_bytes(_NAME, _json(snapshot))
