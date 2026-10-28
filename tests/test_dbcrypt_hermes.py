"""Qualification against the installed Hermes SessionDB, not a local replica."""

from __future__ import annotations

import importlib.util

import pytest
import sqlcipher3.dbapi2 as sc

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.dbcrypt._authority import Authority
from mordred_hermes.dbcrypt._shim import wrong_key_errors
from tests.test_dbcrypt_authority import native_root as _native_root

native_root = _native_root


def installed_hermes(monkeypatch, module):
    spec = importlib.util.find_spec("hermes_state")
    assert spec and spec.origin and "site-packages" in spec.origin
    qualified = importlib.util.spec_from_file_location("_task6_real_hermes_state", spec.origin)
    assert qualified and qualified.loader
    real = importlib.util.module_from_spec(qualified)
    qualified.loader.exec_module(real)
    monkeypatch.setattr(real, "sqlite3", module)
    return real


@pytest.mark.parametrize("profile", ["", "profiles/work"])
def test_real_sessiondb_fts_japanese(native_root, monkeypatch, profile):
    from mordred_hermes.dbcrypt._shim import build_module

    root = native_root[0]
    home = root / profile
    path = home / "state.db"
    for iteration in range(2):
        authority = Authority.acquire(home)
        try:
            hermes = installed_hermes(monkeypatch, build_module(authority=authority))
            db = hermes.SessionDB(path)
            try:
                if iteration == 0:
                    db.create_session("japanese-test", source="cli")
                    message_id = db.append_message("japanese-test", "user", "今日は東京で日本語を勉強します")
                assert db.get_messages("japanese-test")[0]["content"] == "今日は東京で日本語を勉強します"
                if not hasattr(db, "_fts_enabled"):
                    pytest.skip("the installed Hermes SessionDB predates FTS/trigram message search")
                assert db._fts_enabled and db._trigram_available
                hits = db.search_messages("日本語")
                assert len(hits) == 1
                assert hits[0]["session_id"] == "japanese-test"
                assert hits[0]["id"] == message_id
                assert hits[0]["context"] == [{"role": "user", "content": "今日は東京で日本語を勉強します"}]
            finally:
                db.close()
        finally:
            authority.close()
    authority = Authority.acquire(home)
    try:
        hermes = installed_hermes(monkeypatch, build_module(authority=authority))
        readonly = hermes.SessionDB(path, read_only=True)
        try:
            assert readonly.get_messages("japanese-test")[0]["content"] == "今日は東京で日本語を勉強します"
        finally:
            readonly.close()
    finally:
        authority.close()
    keyless = sc.connect(str(path))
    try:
        with pytest.raises(wrong_key_errors(sc)):
            keyless.execute("SELECT content FROM messages").fetchall()
    finally:
        keyless.close()


def test_unsupported_session_schema_refused_without_repair(native_root, monkeypatch):
    from mordred_hermes.dbcrypt._connection import open_protected
    from mordred_hermes.dbcrypt._shim import build_module

    authority = Authority.acquire(native_root[0])
    path = native_root[0] / "state.db"
    try:
        conn = open_protected(path, authority=authority)
        conn.execute("CREATE TABLE schema_version(version INTEGER)")
        conn.execute("INSERT INTO schema_version VALUES (999999)")
        conn.commit()
        conn.close()
        before = path.stat().st_ino, path.read_bytes()
        hermes = installed_hermes(monkeypatch, build_module(authority=authority))
        with pytest.raises(DatabaseRefused):
            hermes.SessionDB(path)
        assert (path.stat().st_ino, path.read_bytes()) == before
    finally:
        authority.close()
