"""Excluded Windows keyvault capabilities refuse before any state mutation (C5e).

Every guarded public entry point must raise ``KeyvaultUnsupportedOnWindows``
before ``_storage``, anchor/backend resolution, lock acquisition, native key
use or plaintext capture/deletion. Fault injectors fail the test if any of
those paths is reached. Retained excluded artifacts are preserved and reported.
"""

import inspect
import sys
import types
from pathlib import Path

import pytest

from mordred_hermes._private_fs import PrivateFSError, open_private_directory
from mordred_hermes.keyvault import (
    _anchor_keychain,
    _config_bootstrap,
    _env_reseal,
    _env_write_guard,
    _identity,
    _runtime_env,
    _storage,
    anchor,
    api,
    vault,
    vault_master,
    wrap,
)
from tests._keyvault_fakes import FakeAnchorStore, FakeBackend
from tests.test_windows_custody import fs  # noqa: F401


def capability_module():
    from mordred_hermes.keyvault import _windows_capability

    return _windows_capability


class Reached(AssertionError):
    pass


_TRIPWIRES = [
    (vault, "_ensure_dir"),
    (vault, "_ensure_lock"),
    (vault, "keyvault_lock"),
    (vault, "atomic_write"),
    (vault, "safe_read"),
    (vault, "_load_pinned_unverified"),
    (vault, "_load_latest_unverified"),
    (vault, "_read_recovery_blob"),
    (vault, "_load_recovery_matched_unverified"),
    (vault, "open_master_key"),
    (vault, "artifacts_present"),
    (vault_master, "seal"),
    (vault_master, "open_passphrase"),
    (vault_master, "reseal_onto_device"),
    (vault_master, "rewrap_from_device"),
    (vault_master, "rewrap_from_passphrase"),
    (anchor, "write_anchor"),
    (anchor, "verify_pinned"),
    (_identity, "resolve_backend"),
    (_identity, "resolve_store"),
    (_identity, "resolve_backend_store"),
    (_anchor_keychain, "default_anchor_store"),
    (_runtime_env, "resolve_backend_store"),
    (_runtime_env, "_env_optout_marker_path"),
    (_config_bootstrap, "resolve_backend_store"),
    (_config_bootstrap, "_marker_path"),
    (_config_bootstrap, "capture_plaintext"),
    (_config_bootstrap, "publish_plaintext_no_replace"),
    (_config_bootstrap, "read_regular_plaintext"),
    (_config_bootstrap, "discard_capture"),
    (_env_reseal, "resolve_backend"),
    (_env_reseal, "resolve_store"),
    (_env_reseal, "capture_plaintext"),
    (_env_reseal, "discard_capture"),
    (_env_reseal, "_env_enrolled"),
    (_env_reseal, "_env_optout_marker_path"),
    (wrap, "wrap_dek"),
    (wrap, "unwrap_dek"),
]


@pytest.fixture
def windows(monkeypatch):
    cap = capability_module()
    monkeypatch.setattr(cap, "_platform", lambda: "win32")
    return cap


@pytest.fixture
def tripwires(monkeypatch):
    reached = []

    def install(module, name):
        def tripwire(*args, **kwargs):
            reached.append(f"{module.__name__}.{name}")
            raise Reached(f"{module.__name__}.{name}")

        monkeypatch.setattr(module, name, tripwire)

    for module, name in _TRIPWIRES:
        install(module, name)
    for name, value in vars(_storage).items():
        if inspect.isfunction(value) and value.__module__ == _storage.__name__:
            install(_storage, name)
    return reached


@pytest.fixture
def retained(tmp_path):
    """A profile holding retained excluded artifacts and live plaintext."""
    home = tmp_path / "retained-home"
    with open_private_directory(home, create=True):
        pass
    mordred = home / "mordred"
    with open_private_directory(mordred, create=True) as directory, directory.transaction() as tx:
        tx.create_bytes("config-vault.marker", b"1\n")
        tx.create_bytes("env-vault.optout", b"1\n")
    with open_private_directory(mordred / "vault", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes("manifest.0.mvmf", b"retained manifest")
        tx.create_bytes("recovery.mrkv", b"retained recovery")
    # The generic secret store (_storage layout) is not ported to Windows.
    with open_private_directory(mordred / "keyvault", create=True) as directory, directory.transaction() as tx:
        tx.create_bytes("meta.json", b'{"version":1,"keys":{}}')
    (home / ".env").write_bytes(b"API_KEY=plaintext\n")
    (home / "config.yaml").write_bytes(b"model: local\n")
    return home


def snapshot(home: Path) -> dict[str, bytes | None]:
    paths = [
        home / ".env",
        home / "config.yaml",
        home / "mordred" / "config-vault.marker",
        home / "mordred" / "env-vault.optout",
        home / "mordred" / "vault" / "manifest.0.mvmf",
        home / "mordred" / "vault" / "recovery.mrkv",
        home / "mordred" / "keyvault" / "meta.json",
    ]
    state: dict[str, bytes | None] = {str(path): path.read_bytes() if path.exists() else None for path in paths}
    state["vault-names"] = "\n".join(sorted(p.name for p in (home / "mordred" / "vault").iterdir())).encode()
    state["store-names"] = "\n".join(sorted(p.name for p in (home / "mordred" / "keyvault").iterdir())).encode()
    state["mordred-names"] = "\n".join(sorted(p.name for p in (home / "mordred").iterdir())).encode()
    return state


def _sink(entry):
    raise Reached("audit sink")


def _open_vault_object():
    # Mutation methods must refuse before reading any instance state.
    return object.__new__(vault.OpenVault)


def _calls(home: Path, backend: FakeBackend, store: FakeAnchorStore):
    root = home / "mordred" / "vault"
    return [
        (
            "file_vault",
            "init_vault",
            lambda: vault.init_vault(root, key_id="k", passphrase="p", backend=backend, store=store, anchor_label="k"),
        ),
        (
            "file_vault",
            "open_vault",
            lambda: vault.open_vault(root, key_id="k", backend=backend, store=store, anchor_label="k"),
        ),
        ("file_vault", "enroll_file", lambda: vault.OpenVault.enroll_file(_open_vault_object(), ".env", b"x")),
        ("file_vault", "unenroll_file", lambda: vault.OpenVault.unenroll_file(_open_vault_object(), ".env")),
        ("recovery", "recover_vault", lambda: vault.recover_vault(root, "p")),
        (
            "recovery",
            "recover_to_device",
            lambda: vault.recover_to_device(root, "p", backend=backend, store=store, key_id="k", anchor_label="k"),
        ),
        (
            "recovery",
            "change_passphrase",
            lambda: vault.change_passphrase(
                root, new_passphrase="n", key_id="k", backend=backend, store=store, anchor_label="k"
            ),
        ),
        (
            "env_config_workspace_seals",
            "inject_vault_env",
            lambda: _runtime_env.inject_vault_env(root=root, environ={}),
        ),
        (
            "env_config_workspace_seals",
            "materialize_config",
            lambda: _config_bootstrap.materialize_config(root=root, home=home),
        ),
        (
            "env_config_workspace_seals",
            "reseal_config",
            lambda: _config_bootstrap.reseal_config(root=root, home=home),
        ),
        ("env_config_workspace_seals", "reseal_env", lambda: _env_reseal.reseal_env(home=home, root=root)),
        (
            "recovery",
            "export_backup",
            lambda: api.export_backup("k", "p", backend=backend, audit_sink=_sink, home=home),
        ),
        (
            "recovery",
            "import_backup",
            lambda: api.import_backup(
                b"blob", "p", seed_phrase="s", pow_bytes=b"x", backend=backend, audit_sink=_sink, home=home
            ),
        ),
        (
            "secret_store",
            "generate",
            lambda: api.generate("seed", "p", b"pow", b"d" * 32, backend=backend, audit_sink=_sink, home=home),
        ),
        (
            "secret_store",
            "confirm_generate",
            lambda: api.confirm_generate(object(), b"d" * 32, backend=backend, audit_sink=_sink, home=home),
        ),
        (
            "secret_store",
            "encrypt",
            lambda: api.encrypt("k", b"secret", "purpose", backend=backend, audit_sink=_sink, home=home),
        ),
        (
            "secret_store",
            "decrypt",
            lambda: api.decrypt("k", "envelope", "purpose", backend=backend, audit_sink=_sink, home=home),
        ),
    ]


_NAMES = [operation for _, operation, _ in _calls(Path("unused"), FakeBackend(), FakeAnchorStore())]


def _reason(capability):
    return "not-ported-on-windows" if capability == "secret_store" else "excluded-on-windows"


@pytest.fixture
def no_mkdir(monkeypatch):
    import os

    def mkdir(*args, **kwargs):
        raise Reached("mkdir")

    monkeypatch.setattr(os, "mkdir", mkdir)
    monkeypatch.setattr(os, "makedirs", mkdir)
    monkeypatch.setattr(Path, "mkdir", mkdir)


@pytest.mark.parametrize("operation", _NAMES)
def test_excluded_entry_points_refuse_before_any_mutation(windows, tripwires, retained, no_mkdir, operation):
    backend, store = FakeBackend(), FakeAnchorStore()
    capability, call = next((cap, fn) for cap, name, fn in _calls(retained, backend, store) if name == operation)
    before = snapshot(retained)
    with pytest.raises(windows.KeyvaultUnsupportedOnWindows) as refused:
        call()
    error = refused.value
    assert isinstance(error, vault.VaultError)
    assert (error.capability, error.operation, error.reason) == (capability, operation, _reason(capability))
    assert "preserved" in str(error)
    assert tripwires == []
    assert backend.calls == []
    assert store.calls == []
    assert snapshot(retained) == before


def test_entry_points_keep_existing_behavior_off_windows(monkeypatch, tripwires, retained):
    cap = capability_module()
    for platform in ("darwin", "linux"):
        monkeypatch.setattr(cap, "_platform", lambda platform=platform: platform)
        assert cap.refuse_excluded_on_windows("file_vault", "open_vault") is None
        # The POSIX path proceeds into its existing implementation (and so
        # reaches the first fault injector), never a Windows refusal.
        with pytest.raises(Reached):
            vault.open_vault(
                retained / "mordred" / "vault",
                key_id="k",
                backend=FakeBackend(),
                store=FakeAnchorStore(),
                anchor_label="k",
            )


def test_startup_and_session_hooks_stay_inert_on_windows(monkeypatch, tripwires, retained):
    monkeypatch.setattr(sys, "platform", "win32")
    before = snapshot(retained)

    def writer(*args, **kwargs):
        return None

    host = types.SimpleNamespace(save_env_value=writer)
    assert _runtime_env.install_vault_env_decrypt(environ={}) == 0
    assert _config_bootstrap.install_config_decrypt(home=retained) == 0
    assert _env_write_guard.install_env_write_guard(config_module=host) is False
    assert host.save_env_value is writer
    assert _env_write_guard.reseal_stray_env_if_present(home=retained) is False
    assert tripwires == []
    assert snapshot(retained) == before


def test_low_level_crypto_and_injected_backends_remain_usable(windows):
    from mordred_hermes.keyvault.memory_crypto import seal, unseal

    backend = FakeBackend()
    backend.generate_enclave_key("k")
    dek, memory_key = b"D" * 32, b"K" * 32
    blob = wrap.wrap_dek(dek, "k", backend=backend)
    roundtrip = wrap.unwrap_dek(blob, "k", backend=backend, audit_sink=lambda entry: None) == dek
    assert roundtrip, "injected-backend MRKW roundtrip failed"
    sealed = unseal(seal(b"memory", key=memory_key, name="MEMORY.md"), key=memory_key, name="MEMORY.md")
    assert sealed == b"memory"


def test_retained_artifacts_are_reported_as_preserved(fs, windows, retained):  # noqa: F811
    before = snapshot(retained)
    reports = windows.excluded_artifacts(retained)
    mordred = retained / "mordred"
    assert reports == (
        windows.ExcludedArtifactReport("config_seal_marker", mordred / "config-vault.marker"),
        windows.ExcludedArtifactReport("env_seal_optout", mordred / "env-vault.optout"),
        windows.ExcludedArtifactReport("file_vault", mordred / "vault"),
    )
    assert all(report.present for report in reports)
    assert snapshot(retained) == before


def test_excluded_artifacts_absent_profile_reports_nothing_without_creating(fs, windows):  # noqa: F811
    _, _, home, _ = fs
    assert windows.excluded_artifacts(home) == ()
    assert windows.excluded_artifacts(home.parent / "absent") == ()
    assert not (home / "mordred").exists()
    assert not (home.parent / "absent").exists()


def test_excluded_artifact_inspection_failure_is_not_empty(fs, windows, retained, monkeypatch):  # noqa: F811
    from mordred_hermes import _config_io as cio

    def unsafe(path):
        raise PrivateFSError("unsafe", "ancestor_identity")

    monkeypatch.setattr(cio, "open_optional_confidential_directory", unsafe)
    with pytest.raises(PrivateFSError) as refused:
        windows.excluded_artifacts(retained)
    assert refused.value.reason == "unsafe"


def test_secret_store_layout_and_lifecycle_primitives_refuse_before_any_creation(
    windows, tmp_path, monkeypatch, no_mkdir
):
    reached = []
    for name in ("ensure_lock_file", "_advisory_file_lock", "_ensure_layout_locked", "_check_dir_mode"):

        def tripwire(*args, name=name, **kwargs):
            reached.append(name)
            raise Reached(name)

        monkeypatch.setattr(_storage, name, tripwire)
    root = tmp_path / "fresh-home" / "mordred" / "keyvault"
    for operation, call in (
        ("ensure_layout", lambda: _storage.ensure_layout(root)),
        ("keyvault_lifecycle_lock", lambda: _storage.keyvault_lifecycle_lock(root).__enter__()),
        ("keyvault_lock", lambda: _storage.keyvault_lock(root).__enter__()),
    ):
        with pytest.raises(windows.KeyvaultUnsupportedOnWindows) as refused:
            call()
        assert (refused.value.capability, refused.value.reason) == ("secret_store", "not-ported-on-windows")
        assert refused.value.operation in (operation, "keyvault_lifecycle_lock")
    assert reached == []
    assert not (tmp_path / "fresh-home").exists()


def test_secret_store_reset_refuses_before_lock_journal_or_native_deletion(
    windows, retained, monkeypatch, no_mkdir, capsys
):
    import shutil

    from mordred_hermes.keyvault import _memory_key
    from mordred_hermes.wizard.keyvault_cli import reset_keyvault

    def tripwire(*args, **kwargs):
        raise Reached("reset mutation")

    for name in ("ensure_lock_file", "write_reset_journal", "clear_reset_journal", "keyvault_lifecycle_lock"):
        monkeypatch.setattr(_storage, name, tripwire)
    monkeypatch.setattr(_memory_key, "memory_key_lock", tripwire)
    monkeypatch.setattr(shutil, "rmtree", tripwire)
    backend = FakeBackend()
    before = snapshot(retained)
    # The wizard refuses first (C6) with the classified reason, before the Linux
    # memory-key lock or the keyvault lifecycle lock -- never a traceback.
    assert reset_keyvault(home=retained, backend=backend, assume_yes=True) == 1
    err = capsys.readouterr().err
    assert "keyvault reset: secret_store is not yet ported to Windows" in err and "(not-ported-on-windows)" in err
    assert backend.calls == []
    assert snapshot(retained) == before


def test_secret_store_layout_unchanged_off_windows(monkeypatch, tmp_path):
    cap = capability_module()
    monkeypatch.setattr(cap, "_platform", lambda: "linux")
    root = tmp_path / "posix-home" / "mordred" / "keyvault"
    if sys.platform == "win32":
        pytest.skip("POSIX keyvault layout modes")
    _storage.ensure_layout(root)
    assert (root / "meta.json").is_file()


def test_guards_stay_importable_without_the_keyvault_crypto_stack(tmp_path):
    import subprocess

    script = (
        "import sys\n"
        "for name in ('argon2', 'blake3', 'cryptography'):\n"
        "    sys.modules[name] = None\n"
        "from pathlib import Path\n"
        "from mordred_hermes.keyvault import _env_reseal, _storage, _windows_capability\n"
        "home = Path(sys.argv[1])\n"
        "if sys.platform != 'win32':\n"
        "    (home / '.env').write_text('A=1\\n')\n"
        "    assert _env_reseal.reseal_env(home=home, root=home / 'mordred' / 'vault') == 0\n"
        "    root = home / 'mordred' / 'keyvault'\n"
        "    root.mkdir(mode=0o700, parents=True)\n"
        "    with _storage.keyvault_read_lock(root) as present:\n"
        "        assert present is True\n"
        "assert issubclass(_windows_capability.KeyvaultUnsupportedOnWindows, Exception)\n"
        "print('ok')\n"
    )
    home = tmp_path / "minimal-home"
    home.mkdir()
    result = subprocess.run(
        [sys.executable, "-c", script, str(home)], capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == "ok"
