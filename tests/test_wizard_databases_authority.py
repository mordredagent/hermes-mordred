"""Legacy offline callers cannot consume runtime-native authority keys."""

from __future__ import annotations

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.dbcrypt._key import KeyProvider
from tests.test_dbcrypt_authority import native_root as native_root


@pytest.mark.parametrize("command", ["encrypt", "decrypt"])
@pytest.mark.parametrize("dry_run", [False, True])
def test_native_offline_commands_refuse_before_key_or_mutation(native_root, monkeypatch, capsys, command, dry_run):
    from mordred_hermes.wizard import databases_cli

    root, backend, _, _ = native_root
    (root / "state.db").write_bytes(b"retained database bytes")
    (root / "mordred/db-encryption.pending").write_bytes(b"retained pending bytes")
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    monkeypatch.setattr(databases_cli, "_preflight", lambda: None)

    def forbidden(self):
        pytest.fail("legacy offline command consumed a runtime-native bare key")

    monkeypatch.setattr(KeyProvider, "__call__", forbidden)
    operation = getattr(databases_cli, "databases_" + command)
    assert operation(home=root, dry_run=dry_run) == 1
    assert "offline" in capsys.readouterr().err.lower()
    assert backend.calls == []
    assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == before


def test_legacy_arm_cannot_downgrade_native_marker(native_root):
    from mordred_hermes import dbcrypt

    root, backend, _, _ = native_root
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    with pytest.raises(DatabaseRefused):
        dbcrypt.arm(root)
    assert backend.calls == []
    assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == before
