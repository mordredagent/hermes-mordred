"""Inert root-domain types must be usable below native custody and SQL."""

from __future__ import annotations

import dataclasses
import subprocess
import sys
from pathlib import Path

import pytest


def test_database_contracts_are_frozen() -> None:
    from mordred_hermes._database_contracts import Dependency, Inventory, NativeSnapshot, RootIdentity

    root = RootIdentity("linux", 1, "2", "1000")
    source = NativeSnapshot(root, "tpm", "a" * 32, "b" * 64)
    entry = Dependency(Path("/synthetic/state.db"), "database", None)
    result = Inventory((entry,), True)
    for value, name in ((root, "owner"), (source, "generation"), (entry, "generation"), (result, "complete")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(value, name, None)
    assert result.entries[0].generation is None


def test_contract_imports_do_not_load_sql_or_native_custody() -> None:
    child = r"""
import importlib.abc
import sys
class Forbidden(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == x or fullname.startswith(x + '.') for x in
               ('sqlite3', 'sqlcipher3', 'mordred_hermes.dbcrypt', 'mordred_hermes.keyvault')):
            raise AssertionError('SQL/custody import below contract: ' + fullname)
sys.meta_path.insert(0, Forbidden())
import mordred_hermes._database_contracts
import mordred_hermes._database_inventory
import mordred_hermes._database_lifecycle
"""
    result = subprocess.run([sys.executable, "-c", child], text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


def source_binding(**updates):
    import json

    value = {
        "version": 1,
        "root": {"platform": "linux", "volume": 1, "file_id": "2", "owner": "1000"},
        "provider": "tpm",
        "generation": "a" * 32,
        "record_sha256": "b" * 64,
    }
    value.update(updates)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def test_source_binding_decoder_is_pure_and_returns_posix_snapshot():
    from mordred_hermes._database_contracts import NativeSnapshot, RootIdentity, decode_database_source_binding

    assert decode_database_source_binding(source_binding()) == NativeSnapshot(
        RootIdentity("linux", 1, "2", "1000"), "tpm", "a" * 32, "b" * 64
    )
    assert (
        decode_database_source_binding(
            source_binding(
                root={"platform": "darwin", "volume": 3, "file_id": "4", "owner": "501"}, provider="secure-enclave"
            )
        ).provider
        == "secure-enclave"
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"version": True},
        {"version": 2},
        {"extra": 1},
        {"provider": "cng"},
        {"provider": "secure-enclave"},
        {"generation": "A" * 32},
        {"generation": "a" * 64},
        {"record_sha256": "B" * 64},
        {"root": {"platform": "linux", "volume": 1.0, "file_id": "2", "owner": "1000"}},
        {"root": {"platform": "linux", "volume": -1, "file_id": "2", "owner": "1000"}},
        {"root": {"platform": "linux", "volume": 1, "file_id": "02", "owner": "1000"}},
        {"root": {"platform": "linux", "volume": 1, "file_id": "2", "owner": "+1000"}},
        {"root": {"platform": "linux", "volume": 1, "file_id": "2", "owner": "01000"}},
        {"root": {"platform": "win32", "volume": 1, "file_id": "0" * 32, "owner": "0101"}},
    ],
)
def test_source_binding_decoder_refuses_noncanonical_fields(updates):
    from mordred_hermes._database_contracts import DatabaseRefused, decode_database_source_binding

    with pytest.raises(DatabaseRefused):
        decode_database_source_binding(source_binding(**updates))


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"{}\n",
        b"x" * 4097,
        b"\xff\n",
        b'{"version":1,"version":1}\n',
        source_binding()[:-1],
        source_binding().decode().encode("utf-16"),
    ],
)
def test_source_binding_decoder_refuses_malformed_or_unbounded_data(data):
    from mordred_hermes._database_contracts import DatabaseRefused, decode_database_source_binding

    with pytest.raises(DatabaseRefused):
        decode_database_source_binding(data)
