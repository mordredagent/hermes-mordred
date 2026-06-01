"""Tests for ``hermes mordred vault ...`` — the at-rest vault CLI.

Design note: ``mordred-docs/mordred/SECRETS_ENV_ENCRYPTION.ja.md`` §8.2.

These cover the **cold-path** surface — commands that open a vault through
:func:`mordred_hermes.keyvault.vault.recover_vault` (passphrase recovery
sidecar), which needs neither the Secure-Enclave ``NativeBackend`` nor the
device-bound anchor store. They therefore run on any platform and against a
vault copied to another machine.

The vault under test is built with the shared software fakes
(:class:`FakeBackend` does a real P-256 ECDH; :class:`FakeAnchorStore` is an
in-memory keychain), so the whole init → enroll → recover path runs for real
on CI; only the hardware Enclave and the real Keychain are stubbed.
"""

from __future__ import annotations

import argparse
import base64
from pathlib import Path

import pytest

from mordred_hermes.keyvault import kek, manifest, vault
from mordred_hermes.keyvault._anchor_keychain import KeychainAnchorError
from mordred_hermes.keyvault._exceptions import WrapError
from mordred_hermes.wizard import vault_cli

from ._keyvault_fakes import FakeAnchorStore, FakeBackend


class _ReadRaisesStore(FakeAnchorStore):
    """AnchorStore whose ``read`` raises a Keychain I/O error (not item-not-found).

    Models a transient real-Keychain failure (e.g. errSecInteractionNotAllowed)
    so the CLI's fail-closed handling can be exercised cross-platform.
    """

    def read(self, label: str) -> bytes | None:
        raise KeychainAnchorError(-25308, "keychain locked")


class _GenerateRaisesBackend(FakeBackend):
    """Backend whose wrapping-key generation fails with a non-duplicate WrapError."""

    def generate_enclave_key(self, key_id: str, *, unattended: bool | None = None) -> bytes:
        raise WrapError("simulated device key store failure")


_KEY_ID = "vault-cli-test-key"
_LABEL = "mordred.vault.cli.test"
_PASSPHRASE = "correct horse battery staple"


class _PromptIO:
    """Minimal scripted :class:`~mordred_hermes.wizard.configure.PromptIO`.

    ``password`` gives a single fixed answer to every ``ask_password`` call;
    ``passwords`` gives a queue popped in order (``init`` asks for the
    passphrase twice). ``ask_text`` is unused here but present for the protocol.
    """

    def __init__(self, *, password: str = "", passwords: list[str] | None = None) -> None:
        self._password = password
        self._passwords = list(passwords) if passwords is not None else None

    def ask_text(self, label: str, default: str = "") -> str:
        return default

    def ask_password(self, label: str, default: str = "") -> str:
        if self._passwords is not None:
            return self._passwords.pop(0)
        return self._password


def _build_vault(root: Path, *, files: dict[str, bytes] | None = None) -> None:
    """Materialize a real vault at ``root`` sealed under ``_PASSPHRASE``.

    Uses the software fakes for init/enroll (the hot path) so the on-disk
    ``recovery.mrkv`` + ``manifest.<gen>`` the cold path reads back are
    genuine. The returned vault is closed; callers open it via the CLI.
    """
    backend = FakeBackend()
    backend.generate_enclave_key(_KEY_ID)
    store = FakeAnchorStore()
    opened = vault.init_vault(
        root, key_id=_KEY_ID, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=_LABEL
    )
    try:
        for name, plaintext in (files or {}).items():
            opened.enroll_file(name, plaintext)
    finally:
        opened.close()


class TestInit:
    def test_creates_a_recoverable_vault(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        backend = FakeBackend()
        store = FakeAnchorStore()
        rc = vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            backend=backend,
            store=store,
        )
        assert rc == 0
        # A real, cold-path-recoverable vault now exists at the root.
        opened = vault.recover_vault(tmp_path, _PASSPHRASE)
        try:
            assert opened.generation == 0
            assert opened.list_files() == []
        finally:
            opened.close()

    def test_passphrase_mismatch_writes_nothing(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=["alpha", "beta"]),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        assert rc == 1
        assert "match" in capsys.readouterr().err.lower()
        with pytest.raises(vault.VaultError):  # nothing was written
            vault.recover_vault(tmp_path, "alpha")

    def test_empty_passphrase_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=["", ""]),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        assert rc == 1
        assert "empty" in capsys.readouterr().err.lower()

    def test_reinit_existing_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        backend = FakeBackend()
        store = FakeAnchorStore()
        first = vault_cli.init(
            root=tmp_path, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
        )
        assert first == 0
        # Same root + same device store: the second init must refuse, not clobber.
        rc = vault_cli.init(
            root=tmp_path, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
        )
        assert rc == 1
        assert "already" in capsys.readouterr().err.lower()

    def test_success_message_points_at_recovery_passphrase(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        out = capsys.readouterr().out.lower()
        assert "vault" in out
        assert "passphrase" in out or "recovery" in out

    def test_cli_init_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def _spy(*, root: Path, prompt_io: object = None, backend: object = None, store: object = None) -> int:
            seen["root"] = root
            return 0

        monkeypatch.setattr(vault_cli, "init", _spy)
        rc = vault_cli.cli_init(argparse.Namespace(root=str(tmp_path)))
        assert rc == 0
        assert seen["root"] == tmp_path


class TestAdd:
    def _init(self, root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
        assert (
            vault_cli.init(
                root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
            )
            == 0
        )

    def test_enrolls_file_readable_via_cold_path(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "secret.env"
        src.write_bytes(b"ANTHROPIC_API_KEY=sk-secret\n")

        rc = vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store)
        assert rc == 0
        # Readable back through the independent cold path.
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"ANTHROPIC_API_KEY=sk-secret\n"
        finally:
            opened.close()

    def test_round_trips_through_cat(self, tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "c.yaml"
        src.write_bytes(b"a: 1\n")
        assert vault_cli.add(root=root, name="config.yaml", source=src, backend=backend, store=store) == 0
        capsysbinary.readouterr()  # drop add's stdout

        rc = vault_cli.cat(root=root, name="config.yaml", prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 0
        assert capsysbinary.readouterr().out == b"a: 1\n"

    def test_add_to_uninitialised_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        src = tmp_path / "x"
        src.write_bytes(b"v")
        rc = vault_cli.add(root=tmp_path / "v", name=".env", source=src, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_missing_source_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        rc = vault_cli.add(root=root, name=".env", source=tmp_path / "nope", backend=backend, store=store)
        assert rc == 1
        assert "nope" in capsys.readouterr().err

    def test_overwrite_supersedes(self, tmp_path: Path) -> None:
        """M-4: enrolling an existing name supersedes it (new generation)."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src1, src2 = tmp_path / "a", tmp_path / "b"
        src1.write_bytes(b"one")
        src2.write_bytes(b"two")
        assert vault_cli.add(root=root, name=".env", source=src1, backend=backend, store=store) == 0
        assert vault_cli.add(root=root, name=".env", source=src2, backend=backend, store=store) == 0
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"two"
            assert opened.generation == 2  # init=gen0, add=gen1, overwrite=gen2
        finally:
            opened.close()

    def test_cli_add_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def _spy(*, root: Path, name: str, source: Path, backend: object = None, store: object = None) -> int:
            seen.update(root=root, name=name, source=source)
            return 0

        monkeypatch.setattr(vault_cli, "add", _spy)
        rc = vault_cli.cli_add(argparse.Namespace(root=str(tmp_path), name=".env", source=str(tmp_path / "s")))
        assert rc == 0
        assert seen["root"] == tmp_path
        assert seen["name"] == ".env"
        assert seen["source"] == tmp_path / "s"


class TestStatus:
    def test_reports_generation_and_files(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _build_vault(tmp_path, files={".env": b"K=v\n", "config.yaml": b"a: 1\n"})
        rc = vault_cli.status(root=tmp_path, prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 0
        out = capsys.readouterr().out
        assert ".env" in out
        assert "config.yaml" in out
        assert "generation: 2" in out

    def test_empty_vault_reports_zero(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _build_vault(tmp_path)
        rc = vault_cli.status(root=tmp_path, prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 0
        out = capsys.readouterr().out
        assert "generation: 0" in out
        assert "files: 0" in out

    def test_status_does_not_leak_plaintext(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """``status`` lists enrolled names but never decrypts file contents."""
        secret = b"ANTHROPIC_API_KEY=sk-do-not-print"
        _build_vault(tmp_path, files={".env": secret})
        vault_cli.status(root=tmp_path, prompt_io=_PromptIO(password=_PASSPHRASE))
        captured = capsys.readouterr()
        assert secret.decode() not in captured.out
        assert secret.decode() not in captured.err

    def test_read_only_notice(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A cold-path open is read-only; the operator is told so."""
        _build_vault(tmp_path, files={".env": b"K=v\n"})
        vault_cli.status(root=tmp_path, prompt_io=_PromptIO(password=_PASSPHRASE))
        assert "read-only" in capsys.readouterr().out.lower()

    def test_wrong_passphrase_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _build_vault(tmp_path, files={".env": b"K=v\n"})
        rc = vault_cli.status(root=tmp_path, prompt_io=_PromptIO(password="not the passphrase"))
        assert rc == 1
        assert "passphrase" in capsys.readouterr().err.lower()

    def test_escapes_control_chars_in_names(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """L-1: a crafted enrolled name must not emit raw terminal control codes."""
        _build_vault(tmp_path, files={".env\x1b[31mX": b"v"})
        rc = vault_cli.status(root=tmp_path, prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 0
        out = capsys.readouterr().out
        assert "\x1b" not in out  # raw ESC must never reach the terminal

    def test_not_a_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        # An empty directory has no manifest — recover_vault raises VaultError.
        rc = vault_cli.status(root=tmp_path, prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_cli_status_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """``cli_status(args)`` resolves ``--root`` and delegates to :func:`status`."""
        seen: dict[str, object] = {}

        def _spy(*, root: Path, prompt_io: object = None) -> int:
            seen["root"] = root
            return 0

        monkeypatch.setattr(vault_cli, "status", _spy)
        rc = vault_cli.cli_status(argparse.Namespace(root=str(tmp_path)))
        assert rc == 0
        assert seen["root"] == tmp_path

    def test_tampered_manifest_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A manifest-body edit (no master) passes the recovery-digest check on
        the untouched wmk but fails the MAC — status fails closed (rc 1)."""
        _build_vault(tmp_path, files={".env": b"value"})
        mpath = tmp_path / "manifest.1.mvmf"
        body, _, b64tag = mpath.read_bytes().partition(b"\n")
        raw = bytearray(base64.b64decode(b64tag))
        raw[-1] ^= 0x01  # flip a MAC-tag bit
        mpath.write_bytes(body + b"\n" + base64.b64encode(bytes(raw)))

        rc = vault_cli.status(root=tmp_path, prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 1
        assert "manifest" in capsys.readouterr().err.lower()

    def test_wmk_substitution_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A swapped-wmk manifest is rejected by the sidecar's SHA-256(wmk)
        recovery digest before any decrypt — status fails closed (rc 1)."""
        backend = FakeBackend()
        backend.generate_enclave_key(_KEY_ID)
        store = FakeAnchorStore()
        opened = vault.init_vault(
            tmp_path, key_id=_KEY_ID, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=_LABEL
        )
        opened.enroll_file(".env", b"value")  # generation 1
        opened.close()

        wmk_evil = kek.seal_master_key(_KEY_ID, backend=backend)
        master_evil = kek.open_master_key(wmk_evil, _KEY_ID, backend=backend)
        forged = manifest.encode(
            manifest.VaultManifest(key_id=_KEY_ID, wmk=wmk_evil, files={}, generation=1), master_evil
        )
        (tmp_path / "manifest.1.mvmf").write_bytes(forged)

        rc = vault_cli.status(root=tmp_path, prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 1
        assert "tampering" in capsys.readouterr().err.lower()


class TestCat:
    def test_prints_decrypted_bytes(self, tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]) -> None:
        _build_vault(tmp_path, files={".env": b"ANTHROPIC_API_KEY=sk-secret\n"})
        rc = vault_cli.cat(root=tmp_path, name=".env", prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 0
        # Raw bytes, byte-exact — no trailing newline added, binary-safe.
        assert capsysbinary.readouterr().out == b"ANTHROPIC_API_KEY=sk-secret\n"

    def test_binary_content_is_byte_exact(self, tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]) -> None:
        blob = bytes(range(256))
        _build_vault(tmp_path, files={"key.bin": blob})
        rc = vault_cli.cat(root=tmp_path, name="key.bin", prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 0
        assert capsysbinary.readouterr().out == blob

    def test_unknown_name_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _build_vault(tmp_path, files={".env": b"K=v\n"})
        rc = vault_cli.cat(root=tmp_path, name="nope.txt", prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 1
        assert "nope.txt" in capsys.readouterr().err

    def test_wrong_passphrase_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _build_vault(tmp_path, files={".env": b"K=v\n"})
        rc = vault_cli.cat(root=tmp_path, name=".env", prompt_io=_PromptIO(password="wrong"))
        assert rc == 1
        assert "passphrase" in capsys.readouterr().err.lower()

    def test_not_a_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.cat(root=tmp_path, name=".env", prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_cli_cat_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """``cli_cat(args)`` resolves ``--root`` + ``name`` and delegates to :func:`cat`."""
        seen: dict[str, object] = {}

        def _spy(*, root: Path, name: str, prompt_io: object = None) -> int:
            seen["root"] = root
            seen["name"] = name
            return 0

        monkeypatch.setattr(vault_cli, "cat", _spy)
        rc = vault_cli.cli_cat(argparse.Namespace(root=str(tmp_path), name=".env"))
        assert rc == 0
        assert seen["root"] == tmp_path
        assert seen["name"] == ".env"


class TestResolveRoot:
    def test_explicit_root_used_verbatim(self) -> None:
        assert vault_cli._resolve_root("/some/where/vault") == Path("/some/where/vault")

    def test_default_root_under_hermes_home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(vault_cli, "_hermes_home", lambda: tmp_path)
        assert vault_cli._resolve_root(None) == tmp_path / "mordred" / "vault"

    # H-2: a relative or non-normalized root must resolve to a stable absolute
    # path, so `init` and a later `add` derive the SAME vault identity regardless
    # of how the operator spells --root (else a second init clobbers the vault).
    def test_relative_root_is_resolved_absolute(self) -> None:
        assert vault_cli._resolve_root("relative/vault").is_absolute()

    def test_equivalent_spellings_resolve_equal(self, tmp_path: Path) -> None:
        direct = vault_cli._resolve_root(str(tmp_path / "vault"))
        via_dotdot = vault_cli._resolve_root(str(tmp_path / "sub" / ".." / "vault"))
        assert direct == via_dotdot


class TestFailClosed:
    """Review H-1: every failure path returns rc 1, never an uncaught traceback."""

    def test_init_keychain_error_in_reinit_guard(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            backend=FakeBackend(),
            store=_ReadRaisesStore(),
        )
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_init_wraperror_generating_key(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            backend=_GenerateRaisesBackend(),
            store=FakeAnchorStore(),
        )
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_add_keychain_error_opening(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        assert (
            vault_cli.init(
                root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
            )
            == 0
        )
        src = tmp_path / "s"
        src.write_bytes(b"v")
        rc = vault_cli.add(root=root, name=".env", source=src, backend=backend, store=_ReadRaisesStore())
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_cold_path_corrupt_recovery_sidecar(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _build_vault(tmp_path, files={".env": b"v"})
        rec = tmp_path / "recovery.mrkv"
        raw = bytearray(rec.read_bytes())
        raw[:4] = b"XXXX"  # corrupt the MRKV magic -> backup.BackupCorrupt
        rec.write_bytes(raw)
        rc = vault_cli.status(root=tmp_path, prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""
