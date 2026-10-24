"""Caller integration uses genuine database exclusion and authenticated vaults."""

# ruff: noqa: F811 - imported pytest fixtures are resolved by parameter name

import pytest

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault._database_mutation import database_key_mutation
from mordred_hermes.wizard import _vault_entries, _vault_lifecycle, uninstall_cli, vault_memory_key
from mordred_hermes.wizard._flow_session import FlowSession
from tests._keyvault_fakes import FakeAnchorStore, FakeBackend, FixedPassphrasePromptIO
from tests.test_keyvault_vault_database_guard import ENV, durable, enrolled_source, source  # noqa: F401


def test_memory_key_caller_brokers_once_and_reuses_flow(source):
    _home, opened, backend, store, ops = source
    with FlowSession() as flow:
        flow.keep_vault(opened._root, opened)
        before = len([c for c in ops.calls if c[0] == "ecdh"])
        assert (
            vault_memory_key.ensure_memory_key(root=opened._root, backend=backend, store=store, flow_session=flow)[0]
            == 0
        )
        assert (
            vault_memory_key.ensure_memory_key(root=opened._root, backend=backend, store=store, flow_session=flow)[0]
            == 0
        )
        assert len([c for c in ops.calls if c[0] == "ecdh"]) == before


def test_enroll_key_caller_passes_preceding_lease(source):
    _, opened, backend, store, _ = source
    with FlowSession() as flow:
        flow.keep_vault(opened._root, opened)
        rc, _, result = _vault_entries._enroll_one(
            root=opened._root,
            name=".env",
            plaintext=ENV,
            backend=backend,
            store=store,
            read_back=True,
            flow_session=flow,
        )
        assert rc == 0
        assert result == ENV


def test_init_caller_refuses_before_native_generation(tmp_path):
    (tmp_path / "mordred").mkdir(mode=0o700)
    (tmp_path / "state.db").write_bytes(b"retained")
    backend, store = FakeBackend(), FakeAnchorStore()
    assert (
        _vault_lifecycle.init(
            root=tmp_path / "mordred/vault",
            backend=backend,
            store=store,
            prompt_io=FixedPassphrasePromptIO("synthetic"),
        )
        == 1
    )
    assert not backend.calls
    assert not (tmp_path / "mordred/vault").exists()


def test_native_teardown_uses_real_owner_and_retains_files_on_refusal(source, monkeypatch):
    home, opened, backend, store, _ops = source
    ctx = uninstall_cli.UninstallContext(
        home=home, user_home=home, vault_root=opened._root, backend=backend, store=store
    )
    with FlowSession() as flow:
        flow.keep_vault(opened._root, opened)
        with database_key_mutation(root=home, generation=None) as lease:
            before = durable(home)

            def refuse(*args, **kwargs):
                raise DatabaseRefused("native refused")

            monkeypatch.setattr(backend, "delete_enclave_key", refuse)
            with pytest.raises(DatabaseRefused):
                uninstall_cli._delete_vault_keys(ctx, flow, lease)
            assert durable(home) == before
            assert not any(c[0] == "delete" for c in store.calls)


def test_native_teardown_reuses_authenticated_handle(source):
    home, opened, backend, store, ops = source
    ctx = uninstall_cli.UninstallContext(
        home=home, user_home=home, vault_root=opened._root, backend=backend, store=store
    )
    with FlowSession() as flow:
        flow.keep_vault(opened._root, opened)
        with database_key_mutation(root=home, generation=None) as lease:
            uninstall_cli._delete_vault_keys(ctx, flow, lease)
    assert len([c for c in ops.calls if c[0] == "delete"]) == 1
    assert any(c[0] == "delete" for c in store.calls)


def test_memory_purge_authenticates_once_before_source_change(source):
    from mordred_hermes.wizard import memory_cli

    home, opened, backend, store, ops = source
    with database_key_mutation(root=home, generation=None) as lease:
        opened.enroll_file(".env", ENV, database_lease=lease)
    from mordred_hermes.keyvault.memory_crypto import seal

    (home / "memories").mkdir()
    (home / "memories/MEMORY.md").write_bytes(seal(b"notes", key=b"a" * 32, name="MEMORY.md"))
    before = len([c for c in ops.calls if c[0] == "ecdh"])
    assert memory_cli.purge(home=home, root=opened._root, backend=backend, store=store) == 0
    assert len([c for c in ops.calls if c[0] == "ecdh"]) - before == 1


@pytest.mark.parametrize("dependency", ["state.db", "mordred/db-key-source.json.tmp", "backups/state.db.bak"])
def test_env_purge_dependency_refuses_before_plaintext_or_marker_writes(source, dependency):
    from mordred_hermes.wizard import env_decrypt_cli

    home, opened, backend, store, _ = source
    with database_key_mutation(root=home, generation=None) as lease:
        opened.enroll_file(".env", ENV, database_lease=lease)
    path = home / dependency
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(b"retained dependency")
    before = durable(home)
    assert env_decrypt_cli.purge(home=home, root=opened._root, backend=backend, store=store) == 1
    assert durable(home) == before


def test_same_decoded_key_update_and_idempotent_memory_caller_need_no_lease(source):
    import base64

    home, opened, backend, store, _ = source
    with database_key_mutation(root=home, generation=None) as lease:
        opened.enroll_file(".env", ENV, database_lease=lease)
    (home / "state.db").write_bytes(b"retained dependency")
    plaintext = b"HERMES_MEMORY_KEY=base64:" + base64.urlsafe_b64encode(b"a" * 32) + b"\nAPI_KEY=new\n"
    with FlowSession() as flow:
        flow.keep_vault(opened._root, opened)
        assert (
            _vault_entries._enroll_one(
                root=opened._root,
                name=".env",
                plaintext=plaintext,
                backend=backend,
                store=store,
                read_back=True,
                flow_session=flow,
            )[0]
            == 0
        )
        assert (
            vault_memory_key.ensure_memory_key(root=opened._root, backend=backend, store=store, flow_session=flow)[0]
            == 0
        )


def test_enroll_callback_under_held_custody_cannot_broker_reverse_order(source):
    home, opened, backend, store, _ = source
    before = durable(home)
    with FlowSession() as flow:
        flow.keep_vault(opened._root, opened)
        with opened._custody_scope():
            assert (
                _vault_entries._enroll_one(
                    root=opened._root,
                    name=".env",
                    plaintext=ENV,
                    backend=backend,
                    store=store,
                    read_back=True,
                    flow_session=flow,
                )[0]
                == 1
            )
    assert durable(home) == before


def test_source_only_binding_retires_under_authenticated_native_teardown(enrolled_source):
    home, opened, backend, store, ops, _, _ = enrolled_source
    binding = home / "mordred/db-key-source.json"
    assert binding.exists()
    ctx = uninstall_cli.UninstallContext(
        home=home, user_home=home, vault_root=opened._root, backend=backend, store=store
    )
    with FlowSession() as flow:
        flow.keep_vault(opened._root, opened)
        with database_key_mutation(root=home, generation=None) as lease:
            uninstall_cli._delete_vault_keys(ctx, flow, lease)
    assert not binding.exists()
    assert not opened._root.exists()
    assert any(c[0] == "delete" for c in ops.calls)
    assert any(c[0] == "delete" for c in store.calls)


@pytest.mark.parametrize("canonical", [False, True])
def test_init_caller_preserves_retained_ciphertext_before_native_generation(tmp_path, canonical):
    root = tmp_path / "mordred/vault" if canonical else tmp_path / "custom"
    root.mkdir(parents=True, mode=0o700)
    (root / "blobs").mkdir(mode=0o700)
    (root / "blobs/orphan.blob").write_bytes(b"retained ciphertext")
    backend, store = FakeBackend(), FakeAnchorStore()
    assert (
        _vault_lifecycle.init(root=root, backend=backend, store=store, prompt_io=FixedPassphrasePromptIO("synthetic"))
        == 1
    )
    assert not backend.calls
    assert (root / "blobs/orphan.blob").read_bytes() == b"retained ciphertext"


def test_default_native_teardown_resolves_backend_once_before_open(source, monkeypatch):
    from mordred_hermes.keyvault import _identity
    from mordred_hermes.wizard import _vault_open

    home, opened, backend, store, _ = source
    calls = []

    def resolve(_backend):
        calls.append("resolve")
        return backend if len(calls) == 1 else FakeBackend()

    monkeypatch.setattr(_identity, "resolve_backend", resolve)
    monkeypatch.setattr(_vault_open, "resolve_backend", lambda value: value if value is not None else resolve(value))
    ctx = uninstall_cli.UninstallContext(home=home, user_home=home, vault_root=opened._root, store=store)
    with FlowSession() as flow, database_key_mutation(root=home, generation=None) as lease:
        uninstall_cli._delete_vault_keys(ctx, flow, lease)
    assert calls == ["resolve"]


def test_recovery_caller_checks_dependencies_before_native_or_source_writes(source):
    home, opened, backend, store, ops = source
    (home / "state.db").write_bytes(b"retained dependency")
    before, calls = durable(home), list(ops.calls)
    assert (
        _vault_lifecycle.recover(
            root=opened._root, backend=backend, store=store, prompt_io=FixedPassphrasePromptIO("synthetic")
        )
        == 1
    )
    assert durable(home) == before
    assert ops.calls == calls


def test_env_purge_unverified_vault_refuses_even_with_existing_plaintext(source):
    from mordred_hermes.wizard import env_decrypt_cli

    home, opened, _, store, _ = source
    (home / ".env").write_bytes(b"EXISTING=1\n")
    before = durable(home)
    assert env_decrypt_cli.purge(home=home, root=opened._root, backend=FakeBackend(), store=store) == 1
    assert durable(home) == before


def test_explicit_reseal_source_change_reports_refusal_and_preserves_plaintext(source):
    from mordred_hermes.wizard import env_decrypt_cli

    home, opened, backend, store, _ = source
    with database_key_mutation(root=home, generation=None) as lease:
        opened.enroll_file(".env", ENV, database_lease=lease)
    plaintext = b"HERMES_MEMORY_KEY=hex:" + (b"b" * 32).hex().encode() + b"\n"
    (home / ".env").write_bytes(plaintext)
    before = durable(home)
    assert env_decrypt_cli.reseal(home=home, root=opened._root, backend=backend, store=store) == 1
    assert durable(home) == before
    assert opened.read_file(".env") == ENV
