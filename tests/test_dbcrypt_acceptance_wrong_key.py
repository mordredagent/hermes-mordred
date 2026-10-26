"""Collector wrong-key reads follow the existing SQLCipher error contract."""

from __future__ import annotations

import contextlib
import runpy
from pathlib import Path

import pytest
import sqlcipher3.dbapi2 as driver

from mordred_hermes._database_contracts import DatabaseRefused


@pytest.fixture
def collector():
    return runpy.run_path(str(Path(__file__).with_name("_dbcrypt_acceptance_native.py")))


@pytest.fixture
def software_key(monkeypatch, tmp_path):
    from mordred_hermes import _database_lifecycle
    from mordred_hermes.keyvault import _memory_key

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(_database_lifecycle, "acquire_runtime", lambda _root: contextlib.nullcontext())
    monkeypatch.setattr(_memory_key, "resolve_memory_key", lambda **_kwargs: b"p" * 32)


class ReadProbe:
    def __init__(self, failure, where):
        self.failure = failure
        self.where = where
        self.queries = []
        self.closed = False

    def execute(self, sql):
        self.queries.append(sql)
        if sql == "SELECT count(*) FROM messages" and self.where == "execute" and self.failure is not None:
            raise self.failure
        return self

    def fetchone(self):
        if self.where == "fetchone" and self.failure is not None:
            raise self.failure
        return (1,)

    def close(self):
        self.closed = True


def failure_for(case):
    return {
        "database": driver.DatabaseError("wrong-key fixture"),
        "unicode": UnicodeDecodeError("utf-8", b"\xff", 0, 1, "wrong-key fixture"),
        "memory": MemoryError("wrong-key fixture"),
        "success": None,
        "unrelated": ValueError("unrelated fixture"),
        "authority": DatabaseRefused("authority fixture"),
    }[case]


@pytest.mark.parametrize("where", ["execute", "fetchone"])
@pytest.mark.parametrize("case", ["database", "unicode", "memory", "success", "unrelated", "authority"])
def test_wrong_profile_read_contract(collector, software_key, monkeypatch, tmp_path, case, where):
    failure = failure_for(case)
    probe = ReadProbe(failure, where)
    monkeypatch.setattr(driver, "connect", lambda _path: probe)
    if case in {"database", "unicode", "memory"}:
        collector["_wrong_profile_key"](tmp_path)
    elif case == "success":
        with pytest.raises(AssertionError, match="independent profile memory key decrypted Root database"):
            collector["_wrong_profile_key"](tmp_path)
    else:
        with pytest.raises(type(failure)) as caught:
            collector["_wrong_profile_key"](tmp_path)
        assert caught.value is failure
    assert probe.closed
    assert probe.queries[-1] == "SELECT count(*) FROM messages"
    assert len(probe.queries) == 4  # Three genuine apply_key pragmas precede the read.


@pytest.mark.parametrize("where", ["execute", "fetchone"])
@pytest.mark.parametrize("case", ["database", "unicode", "memory", "success", "unrelated", "authority"])
def test_shared_ciphertext_read_contract(collector, case, where):
    failure = failure_for(case)
    probe = ReadProbe(failure, where)
    read = collector["_require_ciphertext_read_refused"]
    message = "keyless/wrong-key ciphertext read succeeded"
    if case in {"database", "unicode", "memory"}:
        read(probe, message)
    elif case == "success":
        with pytest.raises(AssertionError, match=message):
            read(probe, message)
    else:
        with pytest.raises(type(failure)) as caught:
            read(probe, message)
        assert caught.value is failure
    assert probe.queries == ["SELECT count(*) FROM messages"]
    assert not probe.closed  # The calling lifecycle owns cleanup.


@pytest.mark.parametrize("case", ["database", "unicode", "memory"])
def test_key_application_failure_is_not_a_refused_read(collector, software_key, monkeypatch, tmp_path, case):
    from mordred_hermes.dbcrypt import _shim

    failure = failure_for(case)
    probe = ReadProbe(None, "execute")
    monkeypatch.setattr(driver, "connect", lambda _path: probe)

    def refuse_key(_connection, _key):
        raise failure

    monkeypatch.setattr(_shim, "apply_key", refuse_key)
    with pytest.raises(type(failure)) as caught:
        collector["_wrong_profile_key"](tmp_path)
    assert caught.value is failure
    assert probe.closed
    assert probe.queries == []
