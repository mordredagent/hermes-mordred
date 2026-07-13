"""Tests for ``hermes mordred vault ...`` — the at-rest vault CLI.

Design note: ``docs/dev/SECRETS_ENV_ENCRYPTION.md`` §8.2.

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
from mordred_hermes.keyvault._storage import KeyvaultPermissionError
from mordred_hermes.wizard import vault_cli, vault_memory_key
from mordred_hermes.wizard._prompt_io import _RefusingPromptIO

from ._keyvault_fakes import FakeAnchorStore, FakeBackend, FixedPassphrasePromptIO


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


class _FailOnNthEnrollStore(FakeAnchorStore):
    """AnchorStore that fails its ``arm``-th write after :meth:`arm` is called.

    The anchor write is ``enroll_file``'s commit point, so failing the Nth
    write simulates a device-anchor failure partway through a multi-file
    ``migrate`` (after earlier files have already committed).
    """

    def __init__(self, *, fail_on: int) -> None:
        super().__init__()
        self._armed = False
        self._writes = 0
        self._fail_on = fail_on

    def arm(self) -> None:
        self._armed = True
        self._writes = 0

    def write(self, label: str, value: bytes) -> None:
        if self._armed:
            self._writes += 1
            if self._writes == self._fail_on:
                raise KeychainAnchorError(-25308, "simulated anchor-commit failure mid-migrate")
        super().write(label, value)


class _ReadOSErrorVault:
    """Stub :class:`OpenVault` whose ``.env`` read raises an ``OSError``.

    Models ``_storage.KeyvaultPermissionError`` (an ``OSError`` subclass) from a
    bad-mode / symlink / I/O failure during ``read_file`` so ``set_memory_key``'s
    fail-closed handling of that path can be exercised cross-platform.
    """

    def list_files(self) -> list[str]:
        return [".env"]

    def read_file(self, name: str) -> bytes:
        raise KeyvaultPermissionError(13, "permission denied")

    def close(self) -> None:
        pass

    def __enter__(self) -> _ReadOSErrorVault:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


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

    def test_output_teaches_the_two_key_model(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Newcomers conflate the device key with the recovery passphrase. The
        creation output must state the two-key model so the mental model lands at
        the moment of creation, not buried in docs."""
        vault_cli.init(
            root=tmp_path,
            prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        out = capsys.readouterr().out.lower()
        # both opening paths are named
        assert "two ways" in out
        assert "this device" in out
        # the passphrase is framed as the backup, not the everyday key
        assert "day to day" in out
        assert "lost" in out

    def test_cli_init_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def _spy(*, root: Path, prompt_io: object = None, backend: object = None, store: object = None) -> int:
            seen["root"] = root
            return 0

        monkeypatch.setattr(vault_cli, "init", _spy)
        rc = vault_cli.cli_init(argparse.Namespace(root=str(tmp_path)))
        assert rc == 0
        assert seen["root"] == tmp_path


class TestEnsureInitialised:
    """`ensure_initialised` — the create-the-vault-on-first-`encryption enable` path."""

    def test_noop_when_vault_already_exists(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        assert (
            vault_cli.init(
                root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
            )
            == 0
        )
        # An existing vault is left untouched and never re-prompts: an empty
        # password queue would IndexError if `init` were (wrongly) re-entered.
        rc = vault_cli.ensure_initialised(root=root, prompt_io=_PromptIO(passwords=[]), backend=backend, store=store)
        assert rc == 0

    def test_creates_vault_when_missing(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        rc = vault_cli.ensure_initialised(
            root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
        )
        assert rc == 0
        vault.recover_vault(root, _PASSPHRASE).close()  # a real cold-path-recoverable vault now exists

    def test_prompts_only_once_across_repeated_calls(self, tmp_path: Path) -> None:
        """`encryption enable all` fans out over targets — the vault must be created
        (and the passphrase asked) on the first call only; a second call with the
        same store is a silent no-op that never re-prompts."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        prompt = FixedPassphrasePromptIO(_PASSPHRASE)
        assert vault_cli.ensure_initialised(root=root, prompt_io=prompt, backend=backend, store=store) == 0
        assert vault_cli.ensure_initialised(root=root, prompt_io=prompt, backend=backend, store=store) == 0
        # 2 = the first call's confirm-twice; the second call must not prompt again.
        assert prompt.password_calls == 2

    def test_empty_passphrase_returns_1_and_writes_nothing(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        rc = vault_cli.ensure_initialised(
            root=root, prompt_io=_PromptIO(passwords=["", ""]), backend=FakeBackend(), store=FakeAnchorStore()
        )
        assert rc == 1
        with pytest.raises(vault.VaultError):  # nothing was written
            vault.recover_vault(root, "")

    def test_fail_closed_when_anchor_read_errors(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A transient Keychain read failure must not be read as 'no vault' and
        clobber a possibly-existing one — ensure returns 1 and creates nothing."""
        rc = vault_cli.ensure_initialised(
            root=tmp_path / "v",
            prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]),
            backend=FakeBackend(),
            store=_ReadRaisesStore(),
        )
        assert rc == 1
        assert "determine vault state" in capsys.readouterr().err.lower()


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

    def test_succeeds_with_no_prompt_io_at_all(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """The default call shape (no ``prompt_io``, exactly how ``cli_status``
        invokes it) succeeds — there is nothing to prompt for."""
        _build_vault(tmp_path, files={".env": b"K=v\n"})
        rc = vault_cli.status(root=tmp_path)
        assert rc == 0
        assert "generation: 1" in capsys.readouterr().out

    def test_never_prompts_even_with_a_refusing_prompt_io(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``status`` must never prompt: a ``prompt_io`` that raises
        :class:`NonInteractiveAbort` on its very first call (the
        ``--non-interactive`` guard) still lets ``status`` succeed, proving it
        is never called at all."""
        _build_vault(tmp_path, files={".env": b"K=v\n"})
        rc = vault_cli.status(root=tmp_path, prompt_io=_RefusingPromptIO())
        assert rc == 0
        assert "generation: 1" in capsys.readouterr().out

    def test_json_succeeds_with_a_refusing_prompt_io(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """The ``--json`` shape is equally non-prompting — Phase 5 (UX review
        2026-06-11) added ``--json`` for scripting, but a non-interactive run
        used to abort via ``NonInteractiveAbort`` on the passphrase prompt every
        time, making it unusable in automation. It no longer prompts at all."""
        import json

        _build_vault(tmp_path, files={".env": b"K=v\n", "config.yaml": b"a: 1\n"})
        rc = vault_cli.status(root=tmp_path, prompt_io=_RefusingPromptIO(), as_json=True)
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        assert body["generation"] == 2
        assert sorted(body["files"]) == [".env", "config.yaml"]
        assert body["read_only"] is True
        assert body["authenticated"] is False

    def test_escapes_control_chars_in_names(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """L-1: a crafted enrolled name must not emit raw terminal control codes."""
        _build_vault(tmp_path, files={".env\x1b[31mX": b"v"})
        rc = vault_cli.status(root=tmp_path, prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 0
        out = capsys.readouterr().out
        assert "\x1b" not in out  # raw ESC must never reach the terminal

    def test_not_a_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        # An empty directory has no manifest.*.mvmf — nothing to parse. A
        # _RefusingPromptIO proves this fails closed WITHOUT ever prompting.
        rc = vault_cli.status(root=tmp_path, prompt_io=_RefusingPromptIO())
        assert rc == 1
        assert "no vault" in capsys.readouterr().err.lower()

    def test_deeply_nested_manifest_reports_error_not_traceback(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Code review 2026-07-13: the manifest is parsed unauthenticated, so a
        crafted body must produce the friendly rc-1 error — json.loads raises
        RecursionError (not a ManifestError) on deeply-nested arrays."""
        depth = 100_000
        (tmp_path / "manifest.0.mvmf").write_bytes(b"[" * depth + b"]" * depth + b"\ndGFn")
        rc = vault_cli.status(root=tmp_path, prompt_io=_RefusingPromptIO())
        assert rc == 1
        assert "cannot read vault manifest" in capsys.readouterr().err

    def test_oversized_manifest_reports_error_not_oom(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A multi-GB decoy manifest must be refused by the size cap, not
        slurped into memory; real manifests are a few KBs."""
        from mordred_hermes.wizard import _vault_entries

        cap = _vault_entries._MAX_MANIFEST_BYTES
        (tmp_path / "manifest.0.mvmf").write_bytes(b"x" * (cap + 2))
        rc = vault_cli.status(root=tmp_path, prompt_io=_RefusingPromptIO())
        assert rc == 1
        assert "implausibly large" in capsys.readouterr().err

    def test_cli_status_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """``cli_status(args)`` resolves ``--root`` and delegates to :func:`status`."""
        seen: dict[str, object] = {}

        def _spy(*, root: Path, prompt_io: object = None, as_json: bool = False) -> int:
            seen["root"] = root
            seen["as_json"] = as_json
            return 0

        monkeypatch.setattr(vault_cli, "status", _spy)
        rc = vault_cli.cli_status(argparse.Namespace(root=str(tmp_path)))
        assert rc == 0
        assert seen["root"] == tmp_path
        assert seen["as_json"] is False

    def test_tampered_manifest_tag_is_not_detected(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """``status`` now reads the manifest body UNAUTHENTICATED (no master key
        is ever unwrapped — see its docstring), so it has nothing to check a MAC
        tag against. A tampered tag (the body itself is untouched here) is
        therefore invisible to it: rc 0, the still-correct body contents. Only a
        command that actually opens the vault (``cat``) would catch this; the
        JSON ``"authenticated": false`` field is the caller-visible flag for the
        trade."""
        _build_vault(tmp_path, files={".env": b"value"})
        mpath = tmp_path / "manifest.1.mvmf"
        body, _, b64tag = mpath.read_bytes().partition(b"\n")
        raw = bytearray(base64.b64decode(b64tag))
        raw[-1] ^= 0x01  # flip a MAC-tag bit
        mpath.write_bytes(body + b"\n" + base64.b64encode(bytes(raw)))

        rc = vault_cli.status(root=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert "generation: 1" in out
        assert ".env" in out

    def test_wmk_substitution_is_not_detected(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A swapped-``wmk`` manifest would previously be rejected by the
        sidecar's SHA-256(wmk) recovery digest — but ``status`` no longer opens
        the vault (so it never reads the sidecar), so a structurally-valid
        forged manifest parses fine and its forged contents are reported as-is:
        rc 0, the forged empty file list. Detecting a substitution like this
        again requires a command that actually opens the vault."""
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

        rc = vault_cli.status(root=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert "generation: 1" in out
        assert "files: 0" in out


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
        # _resolve_root delegates to _identity.resolve_root, so the default-root
        # home seam now lives in _identity (not vault_cli).
        monkeypatch.setattr(vault_cli._identity, "_hermes_home", lambda: tmp_path)
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
        """``cat`` still opens the cold path (unlike ``status``, which no longer
        touches the recovery sidecar at all — see the test below) — a corrupt
        sidecar fails closed."""
        _build_vault(tmp_path, files={".env": b"v"})
        rec = tmp_path / "recovery.mrkv"
        raw = bytearray(rec.read_bytes())
        raw[:4] = b"XXXX"  # corrupt the MRKV magic -> backup.BackupCorrupt
        rec.write_bytes(raw)
        rc = vault_cli.cat(root=tmp_path, name=".env", prompt_io=_PromptIO(password=_PASSPHRASE))
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_status_ignores_corrupt_recovery_sidecar(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """``status`` reads only the manifest, never the recovery sidecar, so a
        sidecar corruption that fails ``cat`` (above) does not affect it."""
        _build_vault(tmp_path, files={".env": b"v"})
        rec = tmp_path / "recovery.mrkv"
        raw = bytearray(rec.read_bytes())
        raw[:4] = b"XXXX"
        rec.write_bytes(raw)
        rc = vault_cli.status(root=tmp_path, prompt_io=_RefusingPromptIO())
        assert rc == 0


class TestMigrate:
    """``vault migrate`` — batch-import existing plaintext files (design §8.2).

    A batch :func:`add`: one hot-path open, each source enrolled under its
    basename, **read-all-then-enroll-all** so a single bad path or a duplicate
    basename aborts before anything is committed (no half-migrated vault).
    """

    def _init(self, root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
        assert (
            vault_cli.init(
                root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
            )
            == 0
        )

    def test_enrolls_each_source_under_basename(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        plain = tmp_path / "plain"
        plain.mkdir()
        (plain / ".env").write_bytes(b"ANTHROPIC_API_KEY=sk-secret\n")
        (plain / "config.yaml").write_bytes(b"a: 1\n")

        rc = vault_cli.migrate(root=root, sources=[plain / ".env", plain / "config.yaml"], backend=backend, store=store)
        assert rc == 0
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"ANTHROPIC_API_KEY=sk-secret\n"
            assert opened.read_file("config.yaml") == b"a: 1\n"
            assert opened.generation == 2  # init=gen0, then +1 per enrolled file
        finally:
            opened.close()

    def test_missing_source_aborts_before_any_enroll(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Read-all-first: one unreadable path commits NOTHING (no partial migrate)."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        good = tmp_path / ".env"
        good.write_bytes(b"K=v\n")

        rc = vault_cli.migrate(root=root, sources=[good, tmp_path / "nope.yaml"], backend=backend, store=store)
        assert rc == 1
        assert "nope.yaml" in capsys.readouterr().err
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.list_files() == []  # nothing committed — aborted before the first enroll
            assert opened.generation == 0
        finally:
            opened.close()

    def test_duplicate_basename_refused(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Two sources mapping to the same enrolled name is ambiguous: fail-closed, nothing enrolled."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        (a / ".env").write_bytes(b"one")
        (b / ".env").write_bytes(b"two")

        rc = vault_cli.migrate(root=root, sources=[a / ".env", b / ".env"], backend=backend, store=store)
        assert rc == 1
        assert ".env" in capsys.readouterr().err
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.list_files() == []
        finally:
            opened.close()

    def test_empty_sources_is_noop(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        rc = vault_cli.migrate(root=root, sources=[], backend=backend, store=store)
        assert rc == 0
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.generation == 0  # untouched — short-circuits before opening
        finally:
            opened.close()

    def test_migrate_to_uninitialised_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        src = tmp_path / ".env"
        src.write_bytes(b"K=v\n")
        rc = vault_cli.migrate(root=tmp_path / "v", sources=[src], backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        assert "init" in capsys.readouterr().err.lower()

    def test_keychain_error_opening_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / ".env"
        src.write_bytes(b"K=v\n")
        rc = vault_cli.migrate(root=root, sources=[src], backend=backend, store=_ReadRaisesStore())
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_does_not_remove_plaintext_source(self, tmp_path: Path) -> None:
        """Like ``add``, migrate never deletes the plaintext — the operator owns shredding."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / ".env"
        src.write_bytes(b"K=v\n")
        assert vault_cli.migrate(root=root, sources=[src], backend=backend, store=store) == 0
        assert src.exists()
        assert src.read_bytes() == b"K=v\n"

    def test_overwrite_supersedes(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / ".env"
        src.write_bytes(b"old")
        assert vault_cli.migrate(root=root, sources=[src], backend=backend, store=store) == 0
        src.write_bytes(b"new")
        assert vault_cli.migrate(root=root, sources=[src], backend=backend, store=store) == 0
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"new"
            assert opened.generation == 2
        finally:
            opened.close()

    def test_cli_migrate_uses_explicit_sources(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def _spy(*, root: Path, sources: list[Path], backend: object = None, store: object = None) -> int:
            seen["root"] = root
            seen["sources"] = sources
            return 0

        monkeypatch.setattr(vault_cli, "migrate", _spy)
        rc = vault_cli.cli_migrate(
            argparse.Namespace(root=str(tmp_path), source=[str(tmp_path / ".env"), str(tmp_path / "config.yaml")])
        )
        assert rc == 0
        assert seen["root"] == tmp_path
        assert seen["sources"] == [tmp_path / ".env", tmp_path / "config.yaml"]

    def test_cli_migrate_discovers_default_hermes_set(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """No explicit sources -> import ``.env`` + ``config.yaml`` under the Hermes home."""
        home = tmp_path / "home"
        home.mkdir()
        (home / ".env").write_bytes(b"K=v\n")
        (home / "config.yaml").write_bytes(b"a: 1\n")
        monkeypatch.setattr(vault_cli, "_hermes_home", lambda: home)
        seen: dict[str, object] = {}

        def _spy(*, root: Path, sources: list[Path], backend: object = None, store: object = None) -> int:
            seen["sources"] = sources
            return 0

        monkeypatch.setattr(vault_cli, "migrate", _spy)
        rc = vault_cli.cli_migrate(argparse.Namespace(root=str(tmp_path / "v"), source=[]))
        assert rc == 0
        # Discovery order is fixed (.env before config.yaml), so assert the list directly.
        assert seen["sources"] == [home / ".env", home / "config.yaml"]

    def test_cli_migrate_skips_absent_default_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Only existing default files are migrated (``.env`` present, ``config.yaml`` absent)."""
        home = tmp_path / "home"
        home.mkdir()
        (home / ".env").write_bytes(b"K=v\n")
        monkeypatch.setattr(vault_cli, "_hermes_home", lambda: home)
        seen: dict[str, object] = {}

        def _spy(*, root: Path, sources: list[Path], backend: object = None, store: object = None) -> int:
            seen["sources"] = sources
            return 0

        monkeypatch.setattr(vault_cli, "migrate", _spy)
        rc = vault_cli.cli_migrate(argparse.Namespace(root=str(tmp_path / "v"), source=[]))
        assert rc == 0
        assert seen["sources"] == [home / ".env"]

    def test_cli_migrate_no_sources_found_returns_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        home = tmp_path / "home"
        home.mkdir()  # neither .env nor config.yaml present
        monkeypatch.setattr(vault_cli, "_hermes_home", lambda: home)

        def _never(**_: object) -> int:
            raise AssertionError("migrate must not run when discovery finds nothing")

        monkeypatch.setattr(vault_cli, "migrate", _never)
        rc = vault_cli.cli_migrate(argparse.Namespace(root=str(tmp_path / "v"), source=[]))
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_partial_failure_reports_failed_file_and_count(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A device error on the 2nd enroll fails closed, names the failed file,
        and reports how many committed before it (the only path that exercises
        the enrolled-index attribution)."""
        root = tmp_path / "v"
        backend = FakeBackend()
        store = _FailOnNthEnrollStore(fail_on=2)  # open() only reads; 1st/2nd writes are the two enrolls
        self._init(root, backend, store)
        first, second = tmp_path / ".env", tmp_path / "config.yaml"
        first.write_bytes(b"first")
        second.write_bytes(b"second")

        store.arm()
        rc = vault_cli.migrate(root=root, sources=[first, second], backend=backend, store=store)
        assert rc == 1
        err = capsys.readouterr().err
        assert "config.yaml" in err  # the file whose commit failed
        assert "1 of 2 already enrolled" in err  # the first file committed before the failure
        # The first file did commit (each enroll is its own crash-safe generation).
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"first"
        finally:
            opened.close()

    def test_directory_source_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A directory passed as a source is unreadable (IsADirectoryError -> OSError) -> fail-closed."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        a_dir = tmp_path / "adir"
        a_dir.mkdir()
        rc = vault_cli.migrate(root=root, sources=[a_dir], backend=backend, store=store)
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""


class TestSetMemoryKey:
    """``vault set-memory-key`` — enroll/rotate ``HERMES_MEMORY_KEY`` in the vault ``.env``.

    The key lets Hermes encrypt ``~/.hermes/memories/*.md`` (upstream
    AES-256-GCM); storing it in the vault ``.env`` means the device key protects
    it at rest and the runtime shim injects it into the environment at startup.
    """

    @pytest.fixture(autouse=True)
    def _isolate_ambient_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """No ambient HERMES_MEMORY_KEY by default, so tests exercise the fresh-key path.

        Clears the env var and points the Hermes home at an empty dir (no plaintext
        .env to adopt). The adoption tests override these.
        """
        monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
        empty_home = tmp_path / "ambient_home"
        empty_home.mkdir()
        monkeypatch.setattr(vault_memory_key, "_hermes_home", lambda: empty_home)

    def _init(self, root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
        assert (
            vault_cli.init(
                root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
            )
            == 0
        )

    def _env_text(self, root: Path) -> str:
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            return opened.read_file(".env").decode("utf-8")
        finally:
            opened.close()

    def _generation(self, root: Path) -> int:
        opened = vault.recover_vault(root, _PASSPHRASE)
        try:
            return opened.generation
        finally:
            opened.close()

    def _key_value(self, root: Path) -> str:
        for line in self._env_text(root).splitlines():
            if line.startswith("HERMES_MEMORY_KEY="):
                return line.split("=", 1)[1]
        raise AssertionError("HERMES_MEMORY_KEY not enrolled")

    @staticmethod
    def _decodes_to_32_bytes(value: str) -> bool:
        padding = "=" * (-len(value) % 4)
        return len(base64.urlsafe_b64decode(value + padding)) == 32

    def test_adds_key_to_empty_vault(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._decodes_to_32_bytes(self._key_value(root))  # a valid AES-256 key

    def test_preserves_existing_env_lines(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        src.write_bytes(b"ANTHROPIC_API_KEY=sk-secret\nFOO=bar\n")
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        text = self._env_text(root)
        assert "ANTHROPIC_API_KEY=sk-secret" in text
        assert "FOO=bar" in text
        assert "HERMES_MEMORY_KEY=" in text

    def test_idempotent_when_already_set(self, tmp_path: Path) -> None:
        """A second call without ``--rotate`` is a no-op: same key, no new generation."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        first_value = self._key_value(root)
        gen = self._generation(root)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._key_value(root) == first_value  # unchanged
        assert self._generation(root) == gen  # no needless re-enroll

    def test_rotate_replaces_key(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        first_value = self._key_value(root)
        assert vault_memory_key.set_memory_key(root=root, rotate=True, backend=backend, store=store) == 0
        text = self._env_text(root)
        assert self._key_value(root) != first_value  # rotated
        assert text.count("HERMES_MEMORY_KEY=") == 1  # replaced in place, not duplicated

    def test_does_not_print_secret(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        captured = capsys.readouterr()
        value = self._key_value(root)
        assert value not in captured.out
        assert value not in captured.err

    def test_prints_config_hint(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        out = capsys.readouterr().out.lower()
        assert "config.yaml" in out
        assert "encryption" in out  # tells the operator how to turn it on

    def test_uninitialised_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_memory_key.set_memory_key(root=tmp_path / "v", backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_keychain_error_opening_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        rc = vault_memory_key.set_memory_key(root=root, backend=backend, store=_ReadRaisesStore())
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_non_utf8_existing_env_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A non-UTF-8 enrolled ``.env`` cannot be merged as text — fail closed, enroll nothing."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        src.write_bytes(b"\xff\xfe not utf-8")
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0
        gen = self._generation(root)
        rc = vault_memory_key.set_memory_key(root=root, backend=backend, store=store)
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""
        assert self._generation(root) == gen  # nothing enrolled

    def test_rotate_collapses_duplicate_keys(self, tmp_path: Path) -> None:
        """Review P2: ``--rotate`` must leave exactly one key — dotenv keeps the *last*,
        so a stale later duplicate would silently win over the rotated value."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        src.write_bytes(b"HERMES_MEMORY_KEY=aaa\nHERMES_MEMORY_KEY=bbb\nFOO=bar\n")
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0

        assert vault_memory_key.set_memory_key(root=root, rotate=True, backend=backend, store=store) == 0
        text = self._env_text(root)
        assert text.count("HERMES_MEMORY_KEY=") == 1  # both duplicates collapsed to one
        assert "FOO=bar" in text  # unrelated entry preserved
        assert self._key_value(root) not in {"aaa", "bbb"}  # a fresh value, not a stale duplicate
        assert self._decodes_to_32_bytes(self._key_value(root))

    def test_rotate_warns_about_orphaned_memories(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Review P1: rotating orphans memories encrypted under the old key — warn loudly."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        capsys.readouterr()  # drop the initial store output (no warning expected there)

        assert vault_memory_key.set_memory_key(root=root, rotate=True, backend=backend, store=store) == 0
        err = capsys.readouterr().err.lower()
        assert "warning" in err
        assert "memor" in err  # names the agent-memory files at risk

    def test_first_store_does_not_warn(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """The orphaned-memory warning is rotation-only; a first store must not emit it."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert "warning" not in capsys.readouterr().err.lower()

    def test_read_oserror_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Review P2: a read I/O error (KeyvaultPermissionError) fails closed, not a traceback."""

        def _fake_open(*args: object, **kwargs: object) -> _ReadOSErrorVault:
            return _ReadOSErrorVault()

        monkeypatch.setattr(vault, "open_vault", _fake_open)
        rc = vault_memory_key.set_memory_key(root=tmp_path / "v", backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_invalid_existing_key_is_replaced_without_rotate(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Re-review P2: a present-but-unusable key is not treated as 'already set'.

        An empty / wrong-length `HERMES_MEMORY_KEY` would make `memory.encryption`
        fail at startup, so it must be replaced even without `--rotate` — and
        without the rotation warning, since it never encrypted anything.
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        src.write_bytes(b"HERMES_MEMORY_KEY=\nFOO=bar\n")  # empty value → not 32 bytes
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0

        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._decodes_to_32_bytes(self._key_value(root))  # now a usable key
        assert "FOO=bar" in self._env_text(root)
        assert "warning" not in capsys.readouterr().err.lower()  # nothing was orphaned

    def test_short_existing_key_is_replaced(self, tmp_path: Path) -> None:
        """A too-short value decodes to ≠32 bytes → invalid → replaced, not kept."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        src.write_bytes(b"HERMES_MEMORY_KEY=abc\n")
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._key_value(root) != "abc"
        assert self._decodes_to_32_bytes(self._key_value(root))

    def test_refuses_when_effective_key_invalid_but_valid_exists(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Re-review P1/P2: a valid key shadowed by a later invalid duplicate is ambiguous.

        dotenv last-wins makes the *effective* key the invalid one, yet an earlier
        valid key may have encrypted memories. Refuse (rc 1) rather than guess or
        regenerate — and leave the .env untouched so nothing is lost.
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        valid = base64.urlsafe_b64encode(b"\x22" * 32).decode("ascii")
        src = tmp_path / "s"
        src.write_bytes(f"HERMES_MEMORY_KEY={valid}\nHERMES_MEMORY_KEY=oops\nFOO=bar\n".encode())
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0
        gen = self._generation(root)

        rc = vault_memory_key.set_memory_key(root=root, backend=backend, store=store)
        assert rc == 1
        assert "rotate" in capsys.readouterr().err.lower()  # guidance points at --rotate
        assert self._env_text(root).count("HERMES_MEMORY_KEY=") == 2  # .env untouched
        assert self._generation(root) == gen  # nothing enrolled — no data loss

    def test_quoted_valid_key_is_recognized(self, tmp_path: Path) -> None:
        """Re-review P2: a dotenv-quoted valid key (``"base64:..."``) is recognized, not replaced."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        raw = base64.urlsafe_b64encode(b"\x33" * 32).decode("ascii")
        src = tmp_path / "s"
        src.write_bytes(f'HERMES_MEMORY_KEY="base64:{raw}"\n'.encode())
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0
        gen = self._generation(root)

        # Recognized as already set (the runtime's dotenv parse strips quotes) → no-op.
        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._generation(root) == gen  # untouched, not regenerated

    def test_bare_key_line_does_not_shadow_written_key(self, tmp_path: Path) -> None:
        """Re-review P2: a bare ``HERMES_MEMORY_KEY`` (dotenv → None) must be removed on write.

        Otherwise it stays as the last entry and shadows the written key, so the
        runtime shim's dotenv parse sees None and injects nothing.
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        # invalid assignment then a bare line → dotenv effective value is None.
        src.write_bytes(b"HERMES_MEMORY_KEY=bad\nHERMES_MEMORY_KEY\nFOO=bar\n")
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0

        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        text = self._env_text(root)
        assert "FOO=bar" in text  # unrelated entry preserved
        # The effective value the runtime would inject is now a usable 32-byte key,
        # not None — i.e. the bare shadow was removed, not left behind.
        assert vault_memory_key._is_valid_memory_key(vault_memory_key._effective_memory_key(text))

    def test_bare_key_with_trailing_comment_does_not_shadow(self, tmp_path: Path) -> None:
        """Re-review P2: ``HERMES_MEMORY_KEY # comment`` is a dotenv bare entry (None) too.

        Delegating removal to dotenv's parser drops it like any other binding, so
        it can't be left behind to shadow the written key.
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        src = tmp_path / "s"
        src.write_bytes(b"HERMES_MEMORY_KEY=bad\nHERMES_MEMORY_KEY # disabled\nFOO=bar\n")
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0

        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        text = self._env_text(root)
        assert "FOO=bar" in text
        # the effective value the runtime would inject is now a usable 32-byte key
        assert vault_memory_key._is_valid_memory_key(vault_memory_key._effective_memory_key(text))

    def test_refuses_valid_key_with_trailing_comment_shadowed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A valid key with a trailing comment, shadowed by a later invalid one, is detected.

        dotenv strips the comment, so the earlier line *is* a valid key — the
        ambiguity must be surfaced (refuse), not lost by regenerating.
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        valid = base64.urlsafe_b64encode(b"\x44" * 32).decode("ascii")
        src = tmp_path / "s"
        src.write_bytes(f"HERMES_MEMORY_KEY={valid} # my key\nHERMES_MEMORY_KEY=bad\n".encode())
        assert vault_cli.add(root=root, name=".env", source=src, backend=backend, store=store) == 0
        gen = self._generation(root)

        rc = vault_memory_key.set_memory_key(root=root, backend=backend, store=store)
        assert rc == 1
        assert "rotate" in capsys.readouterr().err.lower()
        assert self._generation(root) == gen  # .env untouched — no data loss

    def test_adopts_env_var_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Re-review P1: a valid HERMES_MEMORY_KEY in the live env is ADOPTED, not replaced.

        A fresh key would override the user's existing one at startup and orphan
        memories already encrypted under it.
        """
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        existing = base64.urlsafe_b64encode(b"\x55" * 32).decode("ascii")
        monkeypatch.setenv("HERMES_MEMORY_KEY", existing)

        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._key_value(root) == existing  # adopted the env key, not regenerated

    def test_adopts_plaintext_home_env_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A valid key in the plaintext home .env (not yet migrated) is adopted."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        home = tmp_path / "real_home"
        home.mkdir()
        existing = base64.urlsafe_b64encode(b"\x66" * 32).decode("ascii")
        (home / ".env").write_text(f"HERMES_MEMORY_KEY={existing}\n", encoding="utf-8")
        monkeypatch.delenv("HERMES_MEMORY_KEY", raising=False)
        monkeypatch.setattr(vault_memory_key, "_hermes_home", lambda: home)

        assert vault_memory_key.set_memory_key(root=root, backend=backend, store=store) == 0
        assert self._key_value(root) == existing  # adopted from the plaintext .env

    def test_rotate_mints_fresh_even_with_ambient_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--rotate ignores the ambient key, mints fresh, and warns about orphaning."""
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        self._init(root, backend, store)
        ambient = base64.urlsafe_b64encode(b"\x77" * 32).decode("ascii")
        monkeypatch.setenv("HERMES_MEMORY_KEY", ambient)

        assert vault_memory_key.set_memory_key(root=root, rotate=True, backend=backend, store=store) == 0
        assert self._key_value(root) != ambient  # a fresh key, not the ambient one
        assert "warning" in capsys.readouterr().err.lower()  # rotating away a usable key warns

    def test_cli_set_memory_key_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def _spy(*, root: Path, rotate: bool = False, backend: object = None, store: object = None) -> int:
            seen["root"] = root
            seen["rotate"] = rotate
            return 0

        monkeypatch.setattr(vault_memory_key, "set_memory_key", _spy)
        rc = vault_memory_key.cli_set_memory_key(argparse.Namespace(root=str(tmp_path), rotate=True))
        assert rc == 0
        assert seen["root"] == tmp_path
        assert seen["rotate"] is True


class TestOpenHotPath:
    """``_open_hot_path_or_report`` — the shared hot-path open used by add /
    migrate / set_memory_key. Returns the opened vault (caller closes it), or
    prints a fail-closed reason to stderr and returns ``None``.
    """

    def test_returns_opened_vault_when_initialised(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        assert (
            vault_cli.init(
                root=root, prompt_io=_PromptIO(passwords=[_PASSPHRASE, _PASSPHRASE]), backend=backend, store=store
            )
            == 0
        )
        opened = vault_cli._open_hot_path_or_report(root, backend=backend, store=store)
        assert opened is not None
        try:
            assert opened.generation == 0  # freshly initialised, nothing enrolled
        finally:
            opened.close()

    def test_uninitialised_returns_none_and_points_at_init(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        opened = vault_cli._open_hot_path_or_report(tmp_path / "v", backend=FakeBackend(), store=FakeAnchorStore())
        assert opened is None
        assert "init" in capsys.readouterr().err.lower()  # guidance: run `vault init` first

    def test_keychain_error_returns_none(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        opened = vault_cli._open_hot_path_or_report(tmp_path / "v", backend=FakeBackend(), store=_ReadRaisesStore())
        assert opened is None
        assert capsys.readouterr().err.strip() != ""


class TestStatusJson:
    """Phase 5 (UX review 2026-06-11): read commands need --json for scripting."""

    def test_status_json_reports_generation_and_files(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        import json

        _build_vault(tmp_path, files={".env": b"K=v\n", "config.yaml": b"a: 1\n"})
        rc = vault_cli.status(root=tmp_path, prompt_io=_PromptIO(password=_PASSPHRASE), as_json=True)
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        assert body["generation"] == 2
        assert sorted(body["files"]) == [".env", "config.yaml"]
        assert body["read_only"] is True

    def test_status_json_flag_is_wired(self) -> None:
        from mordred_hermes.wizard import cli

        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        ns = parser.parse_args(["vault", "status", "--json"])
        assert ns.json is True


_NEW_PASSPHRASE = "a brand new passphrase 2026"


def _build_at_cli_identity(
    root: Path, backend: FakeBackend, store: FakeAnchorStore, *, files: dict[str, bytes] | None = None
) -> None:
    """Build a real vault whose identity matches what the CLI derives from ``root``.

    ``vault_cli.change_passphrase`` derives key_id/anchor_label via
    ``_vault_identity(root)``; the fixed-id ``_build_vault`` helper would not
    match, so the device-key path needs this root-derived build (same ``backend``
    + ``store`` instances must be reused so the wrapping key and anchor persist).
    """
    ident = vault_cli._vault_identity(root)
    backend.generate_enclave_key(ident)
    opened = vault.init_vault(
        root, key_id=ident, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=ident
    )
    try:
        for name, plaintext in (files or {}).items():
            opened.enroll_file(name, plaintext)
    finally:
        opened.close()


class TestChangePassphrase:
    """`vault change-passphrase` — rotate the recovery passphrase, master unchanged."""

    def test_device_path_rotates_keeps_files_and_invalidates_old(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from cryptography.exceptions import InvalidTag

        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store, files={".env": b"SECRET=1\n"})

        rc = vault_cli.change_passphrase(
            root=root,
            prompt_io=_PromptIO(passwords=[_NEW_PASSPHRASE, _NEW_PASSPHRASE]),
            backend=backend,
            store=store,
        )
        assert rc == 0

        # The new passphrase opens the vault and the enrolled file is intact —
        # proof the master (and every blob) is unchanged, only the sidecar.
        opened = vault.recover_vault(root, _NEW_PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"SECRET=1\n"
        finally:
            opened.close()

        # The old passphrase no longer opens it.
        with pytest.raises(InvalidTag):
            vault.recover_vault(root, _PASSPHRASE)

    def test_cold_path_rotation_with_old_passphrase(self, tmp_path: Path) -> None:
        from cryptography.exceptions import InvalidTag

        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store, files={".env": b"A=1\n"})
        ident = vault_cli._vault_identity(root)

        # Cold path: authorized by the current passphrase, device key unused.
        vault.change_passphrase(
            root,
            new_passphrase=_NEW_PASSPHRASE,
            old_passphrase=_PASSPHRASE,
            key_id=ident,
            anchor_label=ident,
        )
        opened = vault.recover_vault(root, _NEW_PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"A=1\n"
        finally:
            opened.close()
        with pytest.raises(InvalidTag):
            vault.recover_vault(root, _PASSPHRASE)

    def test_cold_path_wrong_old_passphrase_raises_and_keeps_sidecar(self, tmp_path: Path) -> None:
        from cryptography.exceptions import InvalidTag

        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store)
        ident = vault_cli._vault_identity(root)
        with pytest.raises(InvalidTag):
            vault.change_passphrase(
                root,
                new_passphrase=_NEW_PASSPHRASE,
                old_passphrase="the wrong current passphrase",
                key_id=ident,
                anchor_label=ident,
            )
        # The sidecar was not rewritten: the original passphrase still opens it.
        vault.recover_vault(root, _PASSPHRASE).close()

    def test_cli_falls_back_to_old_passphrase_when_device_unavailable(self, tmp_path: Path) -> None:
        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store, files={".env": b"Z=9\n"})

        # A store whose read raises makes the device path fail, forcing the CLI
        # fallback; the prompt then supplies the new passphrase twice, then the current one.
        rc = vault_cli.change_passphrase(
            root=root,
            prompt_io=_PromptIO(passwords=[_NEW_PASSPHRASE, _NEW_PASSPHRASE, _PASSPHRASE]),
            backend=backend,
            store=_ReadRaisesStore(),
        )
        assert rc == 0
        opened = vault.recover_vault(root, _NEW_PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"Z=9\n"
        finally:
            opened.close()

    def test_cli_empty_new_passphrase_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store)
        rc = vault_cli.change_passphrase(
            root=root, prompt_io=_PromptIO(passwords=["", ""]), backend=backend, store=store
        )
        assert rc == 1
        assert "empty" in capsys.readouterr().err.lower()
        vault.recover_vault(root, _PASSPHRASE).close()  # original passphrase still valid

    def test_cli_mismatch_new_passphrase_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store)
        rc = vault_cli.change_passphrase(
            root=root, prompt_io=_PromptIO(passwords=["alpha", "beta"]), backend=backend, store=store
        )
        assert rc == 1
        assert "match" in capsys.readouterr().err.lower()
        vault.recover_vault(root, _PASSPHRASE).close()

    def test_cli_no_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.change_passphrase(
            root=tmp_path / "nope",
            prompt_io=_PromptIO(passwords=[_NEW_PASSPHRASE, _NEW_PASSPHRASE]),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        assert rc == 1
        assert "no vault" in capsys.readouterr().err.lower()

    def test_subcommands_are_wired_under_vault_and_encryption(self) -> None:
        from mordred_hermes.wizard import cli

        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        for argv in (["vault", "change-passphrase"], ["encryption", "change-passphrase"]):
            ns = parser.parse_args(argv)
            assert ns.func.__name__ == "_handle_vault_change_passphrase"

    def test_device_key_open_unaffected_and_generation_unchanged(self, tmp_path: Path) -> None:
        """The headline claim: rotation re-wraps only the recovery sidecar, so the
        everyday device-key (hot path) open still works, the file is intact, and no
        new generation is written (nothing is re-encrypted)."""
        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store, files={".env": b"K=v\n"})
        ident = vault_cli._vault_identity(root)

        before = vault.open_vault(root, key_id=ident, backend=backend, store=store, anchor_label=ident)
        try:
            gen_before = before.generation
        finally:
            before.close()

        rc = vault_cli.change_passphrase(
            root=root,
            prompt_io=_PromptIO(passwords=[_NEW_PASSPHRASE, _NEW_PASSPHRASE]),
            backend=backend,
            store=store,
        )
        assert rc == 0

        after = vault.open_vault(root, key_id=ident, backend=backend, store=store, anchor_label=ident)
        try:
            assert after.generation == gen_before  # no re-encrypt, no generation bump
            assert after.read_file(".env") == b"K=v\n"
        finally:
            after.close()

    def test_rotation_survives_missing_lock_file(self, tmp_path: Path) -> None:
        """`keyvault_lock` opens .lock without O_CREAT; a vault whose dotfile was
        dropped (backup that skipped it, manual cleanup) must still rotate —
        `change_passphrase` re-materializes the lock like the other write paths."""
        backend, store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, backend, store, files={".env": b"K=v\n"})
        (root / ".lock").unlink()  # simulate a vault restored without the dotfile

        rc = vault_cli.change_passphrase(
            root=root,
            prompt_io=_PromptIO(passwords=[_NEW_PASSPHRASE, _NEW_PASSPHRASE]),
            backend=backend,
            store=store,
        )
        assert rc == 0
        opened = vault.recover_vault(root, _NEW_PASSPHRASE)
        try:
            assert opened.read_file(".env") == b"K=v\n"
        finally:
            opened.close()


class TestRecover:
    """`vault recover` — cold-open via passphrase AND re-key onto THIS device.

    Models migrating a vault dir to a new machine: it is built at the CLI
    identity with one backend+store (the 'old machine'), then ``recover`` runs
    with a FRESH backend+store (the 'new machine' — no wrapping key, no anchor).
    A successful recover restores the writable device hot path on the new host.
    """

    def test_happy_path_restores_hot_path(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        old_backend, old_store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, old_backend, old_store, files={".env": b"SECRET=1\n"})

        # The new machine: nothing provisioned yet.
        new_backend, new_store = FakeBackend(), FakeAnchorStore()
        rc = vault_cli.recover(
            root=root,
            prompt_io=_PromptIO(password=_PASSPHRASE),
            backend=new_backend,
            store=new_store,
        )
        assert rc == 0
        assert "re-keyed" in capsys.readouterr().out.lower()

        # The hot path is restored: a plain device-key open (new backend + the
        # freshly flipped anchor) works and can enroll a new file.
        ident = vault_cli._vault_identity(root)
        opened = vault.open_vault(root, key_id=ident, backend=new_backend, store=new_store, anchor_label=ident)
        try:
            assert opened.read_file(".env") == b"SECRET=1\n"
            opened.enroll_file("config.yaml", b"a: 1\n")  # commit works → no longer read-only
            assert opened.read_file("config.yaml") == b"a: 1\n"
        finally:
            opened.close()

    def test_wrong_passphrase_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        old_backend, old_store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, old_backend, old_store, files={".env": b"SECRET=1\n"})

        new_backend, new_store = FakeBackend(), FakeAnchorStore()
        rc = vault_cli.recover(
            root=root,
            prompt_io=_PromptIO(password="not the passphrase"),
            backend=new_backend,
            store=new_store,
        )
        assert rc == 1
        assert "passphrase" in capsys.readouterr().err.lower()
        # No anchor was flipped on the new machine — nothing committed.
        assert new_store.read(vault_cli._vault_identity(root)) is None

    def test_no_vault_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = vault_cli.recover(
            root=tmp_path / "empty",
            prompt_io=_PromptIO(password=_PASSPHRASE),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_tampered_manifest_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A manifest-body edit fails the MAC under the recovered master → fail closed."""
        old_backend, old_store = FakeBackend(), FakeAnchorStore()
        root = tmp_path / "vault"
        _build_at_cli_identity(root, old_backend, old_store, files={".env": b"value"})
        mpath = root / "manifest.1.mvmf"
        body, _, b64tag = mpath.read_bytes().partition(b"\n")
        raw = bytearray(base64.b64decode(b64tag))
        raw[-1] ^= 0x01
        mpath.write_bytes(body + b"\n" + base64.b64encode(bytes(raw)))

        rc = vault_cli.recover(
            root=root,
            prompt_io=_PromptIO(password=_PASSPHRASE),
            backend=FakeBackend(),
            store=FakeAnchorStore(),
        )
        assert rc == 1
        assert capsys.readouterr().err.strip() != ""

    def test_cli_recover_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def _spy(*, root: Path, prompt_io: object = None, backend: object = None, store: object = None) -> int:
            seen["root"] = root
            return 0

        monkeypatch.setattr(vault_cli, "recover", _spy)
        rc = vault_cli.cli_recover(argparse.Namespace(root=str(tmp_path)))
        assert rc == 0
        assert seen["root"] == tmp_path


class TestErrorColour:
    """Vault errors route through ``_term.emit_error``: red ``error:`` on a tty, plain off it.

    Mirrors the network-CLI reproducer (PR #159). Uses the no-prompt
    ``migrate``-to-uninitialised-vault path so the assertion needs no passphrase
    PromptIO — the failing open prints its reason via ``_term`` either way.
    """

    def test_open_error_is_red_when_forced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        src = tmp_path / ".env"
        src.write_bytes(b"K=v\n")
        rc = vault_cli.migrate(root=tmp_path / "v", sources=[src], backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        err = capsys.readouterr().err
        assert "\033[31m" in err  # red `error:` label
        assert "init" in err.lower()

    def test_open_error_plain_and_prefixed_off_tty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Off a tty the output is plain, now carrying the shared `error:` prefix.
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        src = tmp_path / ".env"
        src.write_bytes(b"K=v\n")
        rc = vault_cli.migrate(root=tmp_path / "v", sources=[src], backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 1
        err = capsys.readouterr().err
        assert err.startswith("error: no vault at")
        assert "\033" not in err
