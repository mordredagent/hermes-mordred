"""Canonical/borrowed Windows coordination participates in custody ordering."""

import pytest

from mordred_hermes import _config_io as cio
from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import _database_mutation as mutation
from tests.test_config_io import fs as fs
from tests.test_config_io_custody import loan_fs as loan_fs


def test_borrowed_canonical_callbacks_refuse_without_acquiring(loan_fs, monkeypatch):
    _, paths = loan_fs
    paths.home.mkdir(mode=0o700)
    monkeypatch.setattr(mutation, "acquire_exclusive", lambda *a, **kw: pytest.fail("reverse acquisition"))
    with cio.canonical_session(paths, scope="policy") as canonical:
        with (
            canonical.borrow_mordred_transaction(),
            pytest.raises(DatabaseRefused),
            mutation.database_key_mutation(root=paths.home, generation=None),
        ):
            pytest.fail("borrowed canonical omitted")
        with (
            cio.canonical_session(paths, scope="home"),
            pytest.raises(DatabaseRefused),
            mutation.database_key_mutation(root=paths.home, generation=None),
        ):
            pytest.fail("nested canonical omitted")


def test_preceding_lease_can_be_borrowed_with_canonical_session(loan_fs, monkeypatch):
    _, paths = loan_fs
    paths.home.mkdir(mode=0o700)
    with mutation.database_key_mutation(root=paths.home, generation=None) as outer:
        monkeypatch.setattr(mutation, "acquire_exclusive", lambda *a, **kw: pytest.fail("nested OS acquisition"))
        with (
            cio.canonical_session(paths, scope="policy") as canonical,
            canonical.borrow_mordred_transaction(),
            mutation.database_key_mutation(root=paths.home, generation=None) as inner,
        ):
            assert inner is outer


def test_canonical_intent_is_visible_before_mutex_acquisition(fs, monkeypatch):
    _, paths = fs
    paths.home.mkdir(mode=0o700)
    observed = []

    class Mutex:
        def acquire(self, **kwargs):
            with pytest.raises(DatabaseRefused), mutation.database_key_mutation(root=paths.home, generation=None):
                pytest.fail("canonical mutex callback acquired database")
            observed.append("refused")
            return True

        def release(self):
            pass

    monkeypatch.setattr(cio, "_lock", Mutex())
    monkeypatch.setattr(mutation, "acquire_exclusive", lambda *a, **kw: pytest.fail("reverse acquisition"))
    with cio.canonical_session(paths, scope="home"):
        pass
    assert observed == ["refused"]
