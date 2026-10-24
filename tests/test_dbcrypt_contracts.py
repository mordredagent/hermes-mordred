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
