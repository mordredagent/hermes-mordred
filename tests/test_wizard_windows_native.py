"""Native NTFS wizard routing for Windows custody (C6).

Real confidential/private admission, binary SID and physical home identity,
and the real ``win32`` platform decision (nothing patches ``_platform``).
Injected seams: the CNG backend, C4 helper presence, C4 structural runtime
admission and the gateway inventory. Host-skipped off Windows; selected by
the scoped Windows CI job. The real installed-runtime proof is covered by the
gated live recipe (``tests/test_wizard_windows_memory_live.py``).
"""

from __future__ import annotations

import os

import pytest

from mordred_hermes._private_fs import open_private_directory
from mordred_hermes.keyvault import _memory_storage as storage
from mordred_hermes.keyvault import _seckey_helper, _windows_processes
from mordred_hermes.keyvault import _windows_custody as custody
from mordred_hermes.wizard import _vault_lifecycle, encryption_cli, keyvault_windows_cli, memory_cli
from tests._keyvault_fakes import FakeBackend
from tests.test_private_fs_confidential_windows import descriptor
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual NTFS wizard custody routing")


@pytest.fixture
def native(shared_home, monkeypatch):
    home = shared_home
    backend = FakeBackend()
    helper = str(home.parent / "bin" / "mordred-hermes-winkey.exe")
    monkeypatch.setattr(_seckey_helper, "find_winkey_helper", lambda: helper)
    monkeypatch.setattr(storage, "windows_memory_runtime_admitted", lambda executable=None: True)
    monkeypatch.setattr(custody, "windows_backend", lambda: backend)
    monkeypatch.setattr(
        _windows_processes,
        "inspect_windows_gateway_runtimes",
        lambda path, **kwargs: _windows_processes.GatewayInventory("known", (), ()),
    )
    return home, backend


def generated(backend) -> int:
    return sum(1 for call in backend.calls if call[0] == "generate")


def test_native_ceremony_through_a_case_alias_enrolls_once(native, capsys):
    home, backend = native
    parent = descriptor(home)
    alias = home.with_name(home.name.upper())
    assert keyvault_windows_cli.native_init(home=alias, roles=["memory", "audit"]) == 0
    assert keyvault_windows_cli.native_init(home=home, roles=["memory", "audit"]) == 0
    out = capsys.readouterr().out
    assert out.count("enrolled now") == 2 and out.count("already enrolled (unchanged)") == 2
    assert generated(backend) == 2
    assert not (home / "mordred" / "memory-vault.marker").exists()
    assert descriptor(home) == parent, "no ACL repair on the inherited home"


def test_native_status_is_load_only(native, monkeypatch):
    home, backend = native
    assert keyvault_windows_cli.native_init(home=home) == 0
    calls = list(backend.calls)

    def forbidden():
        raise AssertionError("status constructed a native backend")

    monkeypatch.setattr(custody, "windows_backend", forbidden)
    statuses = encryption_cli.collect_status(
        home=home.with_name(home.name.upper()), root=home / "mordred" / "vault", platform="win32", workspace=None
    )  # type: ignore[arg-type]
    memory = next(item for item in statuses if item.target == "memory")
    assert "memory custody enrolled (inert)" in memory.detail
    assert backend.calls == calls


def test_native_copied_home_refuses_the_ceremony(native, capsys):
    home, backend = native
    assert keyvault_windows_cli.native_init(home=home) == 0
    copied = home.parent / "copied wizard home"
    with open_private_directory(copied, create=True):
        pass
    with open_private_directory(copied / "mordred", create=True) as directory, directory.transaction() as tx:
        for name in ("windows-custody.json", "memory-key.wrapped"):
            tx.create_bytes(name, (home / "mordred" / name).read_bytes())
    calls = list(backend.calls)
    assert keyvault_windows_cli.native_init(home=copied) == 1
    assert "(custody-broken)" in capsys.readouterr().err
    assert backend.calls == calls


def test_native_purge_refuses_an_enabled_profile_without_native_calls(native, capsys):
    home, backend = native
    assert keyvault_windows_cli.native_init(home=home) == 0
    calls = list(backend.calls)
    assert memory_cli.purge(home=home, root=home / "mordred" / "vault") == 1
    assert "memory has not been explicitly disabled" in capsys.readouterr().err
    assert backend.calls == calls


def test_native_vault_init_refuses_before_backend(native, monkeypatch, capsys):
    home, _ = native

    def reached(*args, **kwargs):
        raise AssertionError("a vault backend/store was resolved on Windows")

    monkeypatch.setattr(_vault_lifecycle, "resolve_backend", reached)
    monkeypatch.setattr(_vault_lifecycle, "resolve_store", reached)
    assert _vault_lifecycle.init(root=home / "mordred" / "vault") == 1
    assert "file_vault is excluded on Windows" in capsys.readouterr().err
