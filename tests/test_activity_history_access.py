"""History reads use guarded SQL authority without secondary raw database probes."""

from __future__ import annotations

import sqlite3

import pytest

from mordred_hermes.activity import _history_access
from mordred_hermes.activity._gate import ActivityRefused, open_store
from tests._activity_protection import native_root as native_root
from tests._activity_protection import protected_runtime as protected_runtime


def test_history_reads_reuse_guarded_runtime_without_raw_probe(protected_runtime, monkeypatch):
    home, provider, backend = protected_runtime
    open_store(home)
    from mordred_hermes.dbcrypt import _monitor

    def forbidden(*args, **kwargs):
        raise AssertionError("raw DB probe")

    monkeypatch.setattr(_monitor, "is_plaintext", forbidden)
    calls = list(backend.calls)
    assert _history_access.reader(home).status().counts["activity_events"] == 0
    assert backend.calls == calls
    provider.close()
    with pytest.raises(ActivityRefused):
        _history_access.reader(home)


def test_history_guarded_admission_rejects_plaintext(protected_runtime):
    home, _, _ = protected_runtime
    path = home / "plugin-data/mordred/mordred.db"
    path.parent.mkdir(mode=0o700, parents=True)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE activity_meta(key, value)")
    conn.commit()
    conn.close()
    with pytest.raises(ActivityRefused):
        _history_access.reader(home)


def test_existing_history_store_never_retargets_replaced_provider(protected_runtime, monkeypatch):
    from mordred_hermes import dbcrypt
    from mordred_hermes.dbcrypt._key import KeyProvider

    home, provider, _ = protected_runtime
    open_store(home)
    reader = _history_access.reader(home)
    provider.close()
    fresh = KeyProvider(home=home)
    monkeypatch.setattr(dbcrypt, "_PROVIDER", fresh)
    try:
        with pytest.raises(ActivityRefused):
            reader.status()
        assert fresh.current_authority is None
    finally:
        fresh.close()
