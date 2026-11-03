"""Tests for the runtime env transparent-decrypt shim (design note §8.2 item 3).

``_runtime_env.inject_vault_env`` opens the at-rest vault on the **hot path**
(device key — Secure Enclave or its software fallback, no passphrase) and
injects the enrolled ``.env`` into a target environ mapping, so an unattended
Hermes process (telegram / gateway / cron) reads secrets from the vault instead
of plaintext on disk.

The vault is built with the shared software fakes (:class:`FakeBackend` does a
real P-256 ECDH; :class:`FakeAnchorStore` is an in-memory keychain), so the
whole init → enroll → hot-path-open → read path runs for real on any platform.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _identity, _memory_key_holder, _runtime_env, anchor, manifest, vault
from mordred_hermes.keyvault._anchor_keychain import KeychainAnchorError
from mordred_hermes.keyvault._database_mutation import database_key_mutation
from mordred_hermes.keyvault._memory_key import resolve_memory_key
from mordred_hermes.keyvault._memory_key_holder import evict_ambient_memory_key, memory_key_value
from mordred_hermes.wizard import vault_cli
from tests._upstream_canary import import_target

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

_PASSPHRASE = "correct horse battery staple"
_KEY_NAME = "HERMES_MEMORY_KEY"
_VAULT_KEY = base64.urlsafe_b64encode(b"\x11" * 32).decode("ascii")
_STALE_KEY = base64.urlsafe_b64encode(b"\x22" * 32).decode("ascii")


class _ReadRaisesStore(FakeAnchorStore):
    """AnchorStore whose ``read`` raises a Keychain I/O error (not item-not-found)."""

    def read(self, label: str) -> bytes | None:
        raise KeychainAnchorError(-25308, "keychain locked")


def _init_vault_with_env(
    root: Path,
    backend: FakeBackend,
    store: FakeAnchorStore,
    env_bytes: bytes | None,
    *,
    database_lease: Any = None,
) -> None:
    """Materialize a real vault at ``root`` and (optionally) enroll ``.env``."""
    key_id = anchor_label = _identity.vault_identity(root)
    backend.generate_enclave_key(key_id)
    opened = vault.init_vault(
        root,
        key_id=key_id,
        passphrase=_PASSPHRASE,
        backend=backend,
        store=store,
        anchor_label=anchor_label,
        database_lease=database_lease,
    )
    try:
        if env_bytes is not None:
            opened.enroll_file(".env", env_bytes, database_lease=database_lease)
    finally:
        opened.close()


def _memory_key_vault(home: Path) -> tuple[Path, FakeBackend, FakeAnchorStore]:
    """A real vault under ``home`` whose ``.env`` holds the memory key and ``FOO``."""
    from mordred_hermes.wizard._vault_lifecycle import _initialization_lease

    root = home / "mordred/vault"
    backend, store = FakeBackend(), FakeAnchorStore()
    with _initialization_lease(root) as lease:
        _init_vault_with_env(root, backend, store, None, database_lease=lease)
    key_id = anchor_label = _identity.vault_identity(root)
    with (
        database_key_mutation(root=home, generation=None) as lease,
        vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened,
    ):
        opened.enroll_file(".env", f"{_KEY_NAME}={_VAULT_KEY}\nFOO=bar\n".encode(), database_lease=lease)
    return root, backend, store


@pytest.fixture
def _audit_sink(monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.keyvault import kek, vault_master

    audit: list[object] = []
    monkeypatch.setattr(kek, "_noop_audit", audit.append)
    monkeypatch.setattr(vault_master, "_noop_audit", audit.append)


@pytest.fixture
def _fresh_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """``install_vault_env_decrypt()`` on simulated macOS, with fakes and no vault.

    No real Keychain item or Secure Enclave key is touched. ``FOO`` is recorded as
    absent so a test's injection into ``os.environ`` is undone afterwards.
    """
    monkeypatch.setattr(_runtime_env.sys, "platform", "darwin")
    monkeypatch.setattr(_runtime_env, "_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(_runtime_env, "default_vault_root", lambda: tmp_path / "mordred/vault")
    monkeypatch.setattr(_runtime_env, "resolve_backend_store", lambda _b, _s: (FakeBackend(), FakeAnchorStore()))
    monkeypatch.setattr(_runtime_env, "_INJECTED_INTO_OS_ENVIRON", False)
    monkeypatch.delenv("FOO", raising=False)
    return tmp_path


class TestVaultIdentity:
    """The runtime shim must open the SAME vault that ``init`` / ``migrate`` created."""

    def test_identity_matches_vault_cli(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_identity, "_hermes_home", lambda: tmp_path)
        monkeypatch.setattr(vault_cli, "_hermes_home", lambda: tmp_path)
        root = _identity.default_vault_root()
        assert root == vault_cli._resolve_root(None) == tmp_path / "mordred" / "vault"
        assert _identity.vault_identity(root) == vault_cli._vault_identity(root)


class TestInjectVaultEnv:
    def test_injects_decrypted_env_vars(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, b"ANTHROPIC_API_KEY=sk-secret\nFOO=bar\nBAZ=${FOO}/x\n")
        environ = {"FOO": "stale", "KEEP": "me"}

        n = _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert n == 3
        assert environ == {
            "ANTHROPIC_API_KEY": "sk-secret",
            "FOO": "bar",  # vault overrides stale values
            "KEEP": "me",
            "BAZ": "${FOO}/x",  # secret values are never interpolated
        }

    def test_no_vault_is_noop(self, tmp_path: Path) -> None:
        environ = {"X": "1"}
        n = _runtime_env.inject_vault_env(
            root=tmp_path / "v", environ=environ, backend=FakeBackend(), store=FakeAnchorStore()
        )
        assert n == 0
        assert environ == {"X": "1"}

    def test_missing_env_name_is_noop(self, tmp_path: Path) -> None:
        """A vault with no enrolled .env injects nothing — not an error."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, None)  # init only, no .env enrolled
        environ = {"X": "1"}
        n = _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert n == 0
        assert environ == {"X": "1"}

    def test_keychain_read_error_fails_closed(self, tmp_path: Path) -> None:
        """A Keychain failure while probing the anchor must propagate, never silently no-op."""
        environ: dict[str, str] = {}
        with pytest.raises(anchor.AnchorError):
            _runtime_env.inject_vault_env(
                root=tmp_path / "v", environ=environ, backend=FakeBackend(), store=_ReadRaisesStore()
            )
        assert environ == {}

    def test_tampered_manifest_fails_closed(self, tmp_path: Path) -> None:
        """A present-but-tampered vault must fail closed (raise), never inject stale/empty."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, b"FOO=bar\n")  # generation 1
        mpath = root / "manifest.1.mvmf"
        raw = bytearray(mpath.read_bytes())
        raw[-1] ^= 0x01  # flip a trailing (MAC) bit
        mpath.write_bytes(bytes(raw))

        environ: dict[str, str] = {}
        with pytest.raises((manifest.ManifestError, vault.VaultError, anchor.AnchorError)):
            _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert environ == {}

    def test_anchor_absent_with_disk_artifacts_fails_closed(self, tmp_path: Path) -> None:
        """Manifests on disk but the device anchor gone → fail closed.

        Silently no-oping would let an anchor-delete downgrade the process to
        whatever plaintext remains (e.g. an un-shredded ``.env``).
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, b"FOO=bar\n")
        store.delete(_identity.vault_identity(root))  # drop the anchor, keep manifests
        assert list(root.glob("manifest.*.mvmf"))  # vault artifacts remain on disk

        environ: dict[str, str] = {}
        with pytest.raises(vault.VaultError):
            _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert environ == {}

    def test_non_utf8_payload_fails_closed(self, tmp_path: Path) -> None:
        """A non-UTF-8 enrolled ``.env`` raises a domain VaultError, not a raw decode error."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, None)
        # Construct a legacy authenticated invalid source directly: new source
        # mutations now reject this before publication, while runtime must still
        # fail closed for already-existing invalid vault contents.
        import hashlib

        from mordred_hermes.keyvault import anchor, file_container, manifest

        selector = _identity.vault_identity(root)
        with vault.open_vault(root, key_id=selector, backend=backend, store=store, anchor_label=selector) as opened:
            blob = file_container.encode(
                opened._master, b"\xff\xfe\x00not utf-8", key_id=selector, wmk=opened._wmk, name=".env"
            )
            digest = hashlib.sha256(blob).hexdigest()
            vault.atomic_write(root / "blobs" / f"{digest}.blob", blob)
            legacy = manifest.VaultManifest(key_id=selector, wmk=opened._wmk, files={".env": digest}, generation=1)
            vault.atomic_write(root / "manifest.1.mvmf", manifest.encode(legacy, opened._master))
            anchor.write_anchor(store, selector, wmk=opened._wmk, generation=1)
        environ: dict[str, str] = {}
        with pytest.raises(vault.VaultError):
            _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert environ == {}

    def test_blob_corruption_fails_closed(self, tmp_path: Path) -> None:
        """A corrupted blob fails its content-address / AEAD check on read — fail closed."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_vault_with_env(root, backend, store, b"FOO=bar\n")
        blobs = list((root / "blobs").glob("*.blob"))
        assert blobs
        raw = bytearray(blobs[0].read_bytes())
        raw[-1] ^= 0x01
        blobs[0].write_bytes(bytes(raw))

        environ: dict[str, str] = {}
        with pytest.raises(vault.VaultError):
            _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert environ == {}


class TestInstallVaultEnvDecrypt:
    def test_noop_off_darwin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_runtime_env.sys, "platform", "linux")
        called = False

        def _spy(**_: object) -> int:
            nonlocal called
            called = True
            return 0

        monkeypatch.setattr(_runtime_env, "inject_vault_env", _spy)
        assert _runtime_env.install_vault_env_decrypt(environ={}) == 0
        assert called is False  # the device-key path is never touched off macOS

    def test_delegates_on_darwin(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(_runtime_env.sys, "platform", "darwin")
        # Isolate from the real ~/.hermes: the opt-out marker check reads
        # `_hermes_home()`, so without this a developer who has run
        # `encryption disable env` (marker present) would see this short-circuit.
        monkeypatch.setattr(_runtime_env, "_hermes_home", lambda: tmp_path)
        monkeypatch.setattr(_runtime_env, "default_vault_root", lambda: tmp_path / "v")
        seen: dict[str, object] = {}

        def _spy(*, root: Path, environ: dict[str, str], **_: object) -> int:
            seen["root"] = root
            seen["environ"] = environ
            return 3

        monkeypatch.setattr(_runtime_env, "inject_vault_env", _spy)
        env: dict[str, str] = {}
        assert _runtime_env.install_vault_env_decrypt(environ=env) == 3
        assert seen["root"] == tmp_path / "v"
        assert seen["environ"] is env


class TestRegister:
    """The mordred_keyvault plugin entry point installs the shim at discovery."""

    def test_register_installs_env_decrypt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import keyvault

        class FakeCtx:
            def register_hook(self, _name: str, _callback: object) -> None:
                pass

        called = False

        def _spy(**_: object) -> int:
            nonlocal called
            called = True
            return 0

        monkeypatch.setattr(_runtime_env, "install_vault_env_decrypt", _spy)
        keyvault.register(FakeCtx())
        assert called is True


class _RecordingCtx:
    def __init__(self, *, reject: str | None = None) -> None:
        self.hooks: list[tuple[str, Any]] = []
        self._reject = reject

    def register_hook(self, name: str, callback: Any) -> None:
        if name == self._reject:
            raise RuntimeError("host rejected hook")
        self.hooks.append((name, callback))


def _register_keyvault(monkeypatch: pytest.MonkeyPatch, ctx: _RecordingCtx) -> None:
    from mordred_hermes import keyvault
    from mordred_hermes.keyvault import _memory_hook

    monkeypatch.setattr(_runtime_env, "install_vault_env_decrypt", lambda **_: 0)
    monkeypatch.setattr(_memory_hook, "install_memory_hook", lambda **_: False)
    monkeypatch.setattr(keyvault, "_install_journey_guard", lambda: None)
    keyvault.register(ctx)


@pytest.mark.usefixtures("_audit_sink")
class TestMemoryKeyNeverObservable:
    """The memory key stays out of ``os.environ``, whatever re-populates it."""

    def test_memory_key_withheld_from_environ(self, tmp_path: Path) -> None:
        root, backend, store = _memory_key_vault(tmp_path)
        environ: dict[str, str] = {}
        assert _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store) == 2
        assert environ == {"FOO": "bar"}
        assert _memory_key_holder.get_value() == _VAULT_KEY

    def test_vault_key_evicts_stale_environ_key(self, tmp_path: Path) -> None:
        root, backend, store = _memory_key_vault(tmp_path)
        environ = {_KEY_NAME: _STALE_KEY}
        _memory_key_holder.set_value(_STALE_KEY)
        _runtime_env.inject_vault_env(root=root, environ=environ, backend=backend, store=store)
        assert _KEY_NAME not in environ
        assert _memory_key_holder.get_value() == _VAULT_KEY

    @pytest.mark.usefixtures("_fresh_install")
    def test_ambient_key_quarantined_without_vault(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_KEY_NAME, _STALE_KEY)
        assert _runtime_env.install_vault_env_decrypt() == 0
        assert _KEY_NAME not in os.environ
        assert _memory_key_holder.get_value() == _STALE_KEY
        assert memory_key_value(os.environ) == _STALE_KEY

    def test_evict_removes_reloaded_key_when_holder_full(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _memory_key_holder.set_value(_VAULT_KEY)
        monkeypatch.setenv(_KEY_NAME, _STALE_KEY)
        evict_ambient_memory_key()
        assert _KEY_NAME not in os.environ
        assert _memory_key_holder.get_value() == _VAULT_KEY

    def test_empty_ambient_value_is_removed_but_not_adopted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_KEY_NAME, "")
        evict_ambient_memory_key()
        assert _KEY_NAME not in os.environ
        assert _memory_key_holder.get_value() is None

    def test_evict_is_a_noop_on_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setenv(_KEY_NAME, _STALE_KEY)
        evict_ambient_memory_key()
        assert os.environ[_KEY_NAME] == _STALE_KEY
        assert _memory_key_holder.get_value() is None

    def test_explicit_mapping_keeps_dict_semantics(self) -> None:
        _memory_key_holder.set_value(_VAULT_KEY)
        assert memory_key_value({}) is None
        assert memory_key_value({_KEY_NAME: _STALE_KEY}) == _STALE_KEY
        assert memory_key_value(dict(os.environ)) is None
        assert memory_key_value(os.environ) == _VAULT_KEY

    @pytest.mark.usefixtures("_fresh_install")
    def test_repeat_install_still_evicts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert _runtime_env.install_vault_env_decrypt() == 0
        assert _runtime_env._INJECTED_INTO_OS_ENVIRON is True
        monkeypatch.setenv(_KEY_NAME, _STALE_KEY)
        assert _runtime_env.install_vault_env_decrypt() == 0
        assert _KEY_NAME not in os.environ

    def test_optout_still_evicts(self, _fresh_install: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        marker = _runtime_env._env_optout_marker_path(_fresh_install)
        marker.parent.mkdir(parents=True)
        marker.touch()
        monkeypatch.setenv(_KEY_NAME, _STALE_KEY)
        assert _runtime_env.install_vault_env_decrypt() == 0
        assert _KEY_NAME not in os.environ
        assert _memory_key_holder.get_value() == _STALE_KEY

    @pytest.mark.usefixtures("_fresh_install")
    def test_linux_install_evicts_unmanaged_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv(_KEY_NAME, _STALE_KEY)
        assert _runtime_env.install_vault_env_decrypt() == 0
        assert _KEY_NAME not in os.environ
        assert _memory_key_holder.get_value() == _STALE_KEY

    def test_maintenance_process_leaves_environ_alone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.dbcrypt import _cli

        monkeypatch.setattr(_cli, "maintenance_process", lambda: True)
        monkeypatch.setenv(_KEY_NAME, _STALE_KEY)
        assert _runtime_env.install_vault_env_decrypt() == 0
        assert os.environ[_KEY_NAME] == _STALE_KEY

    def test_pre_tool_call_hook_evicts_reloaded_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _RecordingCtx()
        _register_keyvault(monkeypatch, ctx)
        from mordred_hermes import keyvault

        callbacks = [callback for name, callback in ctx.hooks if name == "pre_tool_call"]
        assert callbacks == [keyvault._on_pre_tool_call_evict]
        _memory_key_holder.set_value(_VAULT_KEY)
        monkeypatch.setenv(_KEY_NAME, _STALE_KEY)
        assert callbacks[0](tool_name="terminal", args={"command": "env"}, session_id="s") is None
        assert _KEY_NAME not in os.environ
        assert _memory_key_holder.get_value() == _VAULT_KEY

    def test_pre_tool_call_rejection_does_not_break_startup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _RecordingCtx(reject="pre_tool_call")
        _register_keyvault(monkeypatch, ctx)
        assert {name for name, _callback in ctx.hooks} >= {"on_session_start", "on_session_end"}

    def test_session_boundary_evicts_even_if_reseal_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes import keyvault
        from mordred_hermes.keyvault import _env_write_guard

        def _boom() -> None:
            raise RuntimeError("reseal failed")

        monkeypatch.setattr(_env_write_guard, "reseal_stray_env_if_present", _boom)
        monkeypatch.setenv(_KEY_NAME, _STALE_KEY)
        keyvault._on_session_reseal(session_id="s")
        assert _KEY_NAME not in os.environ

    def test_hermes_make_run_env_cannot_observe_memory_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        local = import_target("tools.environments.local")
        root, backend, store = _memory_key_vault(tmp_path)
        monkeypatch.delenv("FOO", raising=False)
        _runtime_env.inject_vault_env(root=root, environ=os.environ, backend=backend, store=store)
        for child_env in (local._make_run_env({}), local._sanitize_subprocess_env(dict(os.environ))):
            assert _KEY_NAME not in child_env
            assert _VAULT_KEY not in child_env.values()
            assert child_env["FOO"] == "bar"  # the seam still reflects os.environ
        key = resolve_memory_key(home=tmp_path, platform="darwin", environ=os.environ)
        assert key is not None
        assert len(key) == 32

    def test_child_process_does_not_inherit_memory_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        root, backend, store = _memory_key_vault(tmp_path)
        monkeypatch.delenv("FOO", raising=False)
        _runtime_env.inject_vault_env(root=root, environ=os.environ, backend=backend, store=store)
        probe = "import os; print(os.environ.get('FOO'), os.environ.get('HERMES_MEMORY_KEY'))"
        result = subprocess.run([sys.executable, "-I", "-c", probe], capture_output=True, text=True, check=True)
        assert result.stdout.split() == ["bar", "None"]

    @pytest.mark.usefixtures("_fresh_install")
    def test_install_refuses_when_key_observable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(_KEY_NAME, raising=False)

        def _leaky(*, environ: dict[str, str], **_: object) -> int:
            environ[_KEY_NAME] = _VAULT_KEY
            return 1

        monkeypatch.setattr(_runtime_env, "inject_vault_env", _leaky)
        with pytest.raises(vault.VaultError) as raised:
            _runtime_env.install_vault_env_decrypt()
        assert _VAULT_KEY not in str(raised.value)
        assert _runtime_env._INJECTED_INTO_OS_ENVIRON is False
