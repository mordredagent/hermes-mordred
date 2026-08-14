"""Portable Keyvault export CLI and end-to-end recovery tests.

Every test uses a temporary Hermes home and the software P-256 fake backend;
the real home, macOS Keychain, Secure Enclave, and TPM helper are never opened.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _bip39, _storage, api, backup, ethereum
from mordred_hermes.keyvault import pow as keyvault_pow
from mordred_hermes.wizard import keyvault_cli, keyvault_export_cli
from mordred_hermes.wizard.cli import _setup_subparser, main
from tests._keyvault_fakes import FakeBackend

SEED = _bip39.entropy_to_mnemonic(bytes(range(32)))
OTHER_VALID_SEED = _bip39.entropy_to_mnemonic(bytes(reversed(range(32))))
PASSPHRASE = "correct horse battery staple"
RANDOM_ETHEREUM_KEY = bytes(range(1, 33))


class RecordingPromptIO:
    """Queue-backed PromptIO test double that records masked vs visible input."""

    def __init__(self, passwords: list[str]) -> None:
        self._passwords = list(passwords)
        self.calls: list[tuple[str, str]] = []

    def ask_choice(self, label: str, choices: object, default: str) -> str:
        self.calls.append(("choice", label))
        return default

    def ask_text(self, label: str, default: str = "") -> str:
        self.calls.append(("text", label))
        return default

    def ask_bool(self, label: str, default: bool) -> bool:
        self.calls.append(("bool", label))
        return default

    def ask_password(self, label: str, default: str = "") -> str:
        del default
        self.calls.append(("password", label))
        return self._passwords.pop(0)


@pytest.fixture(autouse=True)
def _fast_pow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep real deterministic PoW coverage while making CLI tests fast."""

    monkeypatch.setattr(keyvault_pow, "POW_DIFFICULTY_BITS", 4)


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make accidental default-home resolution harmless as well as explicit calls."""

    home = tmp_path / "hermes-home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def _sink(entries: list[dict[str, Any]]) -> Any:
    def append(entry: dict[str, Any]) -> None:
        entries.append(dict(entry))

    return append


def _initialize_source(
    home: Path,
    backend: FakeBackend,
    *,
    store_seed: bool,
    add_ethereum_key: bool = False,
) -> tuple[str, str | None, list[dict[str, Any]]]:
    """Create the API-equivalent of a completed normal or paper-only init."""

    entries: list[dict[str, Any]] = []
    sink = _sink(entries)
    normalized_seed = api._normalize_seed_phrase(SEED)
    pow_bytes = keyvault_pow.compute_pow(
        normalized_seed,
        difficulty_bits=keyvault_pow.POW_DIFFICULTY_BITS,
    )
    _handle, digest = api.prepare_generate(SEED, PASSPHRASE, pow_bytes)
    generated = api.generate(
        SEED,
        PASSPHRASE,
        pow_bytes,
        digest,
        backend=backend,
        audit_sink=sink,
        home=home,
    )
    if store_seed:
        ethereum.store_seed_phrase(
            generated.key_id,
            SEED,
            backend=backend,
            audit_sink=sink,
            home=home,
        )
    ethereum_envelope: str | None = None
    if add_ethereum_key:
        ethereum_envelope = api.encrypt(
            generated.key_id,
            RANDOM_ETHEREUM_KEY,
            "ethereum.key.v1",
            backend=backend,
            audit_sink=sink,
            home=home,
        )
    entries.clear()
    return generated.key_id, ethereum_envelope, entries


def _export(
    *,
    home: Path,
    backend: FakeBackend,
    output: Path,
    prompts: RecordingPromptIO,
    entries: list[dict[str, Any]] | None = None,
) -> int:
    audit_entries = entries if entries is not None else []
    return keyvault_export_cli.export_keyvault_backup(
        output_path=output,
        home=home,
        backend=backend,
        prompt_io=prompts,
        audit_sink=_sink(audit_entries),
    )


def _assert_fresh_destination(home: Path, backend: FakeBackend) -> None:
    root = _storage.resolve_keyvault_dir(home)
    if root.exists():
        assert _storage.load_meta(root)["keys"] == {}
    assert backend._keys == {}


def _file_snapshot(root: Path) -> dict[Path, bytes]:
    """Return managed file contents so export's read-only source contract is testable."""

    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}


class TestPortableExport:
    def test_initialized_keyvault_exports_parseable_mode_0600_blob(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _key_id, _ethereum_envelope, entries = _initialize_source(
            isolated_home,
            backend,
            store_seed=True,
        )
        output = tmp_path / "keyvault-backup.mrkv"
        prompts = RecordingPromptIO([PASSPHRASE])
        source_before = _file_snapshot(isolated_home)
        native_keys_before = dict(backend._keys)

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=prompts,
                entries=entries,
            )
            == 0
        )

        blob = output.read_bytes()
        assert backup.parse_header(blob).version == backup.VERSION
        assert blob.startswith(b"MRKV")
        assert os.stat(output, follow_symlinks=False).st_mode & 0o777 == 0o600
        assert prompts.calls == [("password", "Keyvault init passphrase")]
        assert any(entry.get("reason") == "keyvault.backup_exported" for entry in entries)
        assert _file_snapshot(isolated_home) == source_before
        assert backend._keys == native_keys_before
        out = capsys.readouterr().out
        assert "snapshot" in out.lower()
        assert "keyvault eth new" in out

    def test_stored_seed_rejects_wrong_init_passphrase_without_output(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "wrong-passphrase.mrkv"
        wrong_passphrase = "a secret but incorrect passphrase"

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([wrong_passphrase]),
            )
            == 1
        )

        captured = capsys.readouterr()
        rendered = captured.out + captured.err
        assert "does not match" in rendered
        assert wrong_passphrase not in rendered
        assert PASSPHRASE not in rendered
        assert not (output.exists() or output.is_symlink())

    def test_existing_file_is_never_overwritten_or_prompted_for(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "existing.mrkv"
        output.write_bytes(b"keep-me")
        prompts = RecordingPromptIO([])

        assert _export(home=isolated_home, backend=backend, output=output, prompts=prompts) == 1

        assert output.read_bytes() == b"keep-me"
        assert prompts.calls == []
        assert "overwrite" in capsys.readouterr().err.lower()

    def test_existing_directory_is_never_replaced(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "backup.mrkv"
        output.mkdir()

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([]),
            )
            == 1
        )

        assert output.is_dir()
        assert "directory" in capsys.readouterr().err.lower()

    def test_missing_output_parent_fails_before_prompt(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        prompts = RecordingPromptIO([])
        output = tmp_path / "missing-parent" / "backup.mrkv"

        assert _export(home=isolated_home, backend=backend, output=output, prompts=prompts) == 1

        assert prompts.calls == []
        assert "does not exist" in capsys.readouterr().err.lower()
        assert not output.exists()

    def test_symlink_output_parent_is_rejected_before_prompt(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        real_parent = tmp_path / "real-parent"
        real_parent.mkdir()
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        prompts = RecordingPromptIO([])
        output = linked_parent / "backup.mrkv"

        assert _export(home=isolated_home, backend=backend, output=output, prompts=prompts) == 1

        assert prompts.calls == []
        assert "real directory" in capsys.readouterr().err.lower()
        assert not (real_parent / "backup.mrkv").exists()

    def test_symlink_is_rejected_without_touching_its_target(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        target = tmp_path / "target"
        target.write_bytes(b"target-stays")
        output = tmp_path / "backup.mrkv"
        output.symlink_to(target)
        prompts = RecordingPromptIO([])

        assert _export(home=isolated_home, backend=backend, output=output, prompts=prompts) == 1

        assert output.is_symlink()
        assert target.read_bytes() == b"target-stays"
        assert prompts.calls == []
        assert "symbolic link" in capsys.readouterr().err.lower()

    def test_paper_only_export_masks_seed_and_recomputes_pow(
        self,
        isolated_home: Path,
        tmp_path: Path,
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=False)
        output = tmp_path / "paper-only.mrkv"
        prompts = RecordingPromptIO([PASSPHRASE, SEED])

        assert _export(home=isolated_home, backend=backend, output=output, prompts=prompts) == 0

        assert output.read_bytes().startswith(b"MRKV")
        assert prompts.calls == [
            ("password", "Keyvault init passphrase"),
            ("password", "24-word Seed Phrase (paper-only Keyvault)"),
        ]
        assert not any(kind == "text" for kind, _label in prompts.calls)

    def test_paper_only_invalid_seed_is_rejected_without_output(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=False)
        output = tmp_path / "invalid-paper.mrkv"
        invalid_seed = "not a valid seed phrase"

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE, invalid_seed]),
            )
            == 1
        )

        captured = capsys.readouterr()
        rendered = captured.out + captured.err
        assert "valid 24-word BIP39" in rendered
        assert invalid_seed not in rendered
        assert PASSPHRASE not in rendered
        assert not output.exists()

    def test_empty_passphrase_is_rejected_without_output(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "empty-passphrase.mrkv"

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([""]),
            )
            == 1
        )

        assert "must not be empty" in capsys.readouterr().err.lower()
        assert not output.exists()

    def test_uninitialized_keyvault_is_actionable_and_does_not_prompt(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        prompts = RecordingPromptIO([])
        output = tmp_path / "uninitialized.mrkv"

        assert _export(home=isolated_home, backend=FakeBackend(), output=output, prompts=prompts) == 1

        assert prompts.calls == []
        assert "keyvault init" in capsys.readouterr().err.lower()
        assert not output.exists()

    def test_output_write_failure_leaves_no_final_file(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "unwritten.mrkv"

        def fail_write(path: Path, data: bytes) -> bool:
            del path, data
            raise OSError("simulated full disk")

        monkeypatch.setattr(keyvault_export_cli._plaintext_capture, "publish_plaintext_no_replace", fail_write)

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 1
        )

        assert not (output.exists() or output.is_symlink())
        assert "written safely" in capsys.readouterr().err.lower()

    def test_output_that_appears_during_export_wins_without_replacement(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "raced.mrkv"

        def lose_publication_race(path: Path, data: bytes) -> bool:
            del path, data
            output.write_bytes(b"other-writer")
            return False

        monkeypatch.setattr(
            keyvault_export_cli._plaintext_capture,
            "publish_plaintext_no_replace",
            lose_publication_race,
        )

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 1
        )

        assert output.read_bytes() == b"other-writer"
        assert "appeared during export" in capsys.readouterr().err.lower()


class TestExportRecovery:
    def test_export_then_recover_restores_hd_seed_and_random_ethereum_key(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        source_backend = FakeBackend()
        key_id, ethereum_envelope, _entries = _initialize_source(
            isolated_home,
            source_backend,
            store_seed=True,
            add_ethereum_key=True,
        )
        assert ethereum_envelope is not None
        output = tmp_path / "portable.mrkv"
        assert (
            _export(
                home=isolated_home,
                backend=source_backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 0
        )

        destination = tmp_path / "fresh-hermes-home"
        destination_backend = FakeBackend()
        assert (
            keyvault_cli.recover(
                blob_path=output,
                home=destination,
                backend=destination_backend,
                prompt_io=RecordingPromptIO([SEED, PASSPHRASE]),
                audit_sink=_sink([]),
            )
            == 0
        )

        assert ethereum.list_seed_envelope_ids(key_id, home=destination)
        restored = api.decrypt(
            key_id,
            ethereum_envelope,
            "ethereum.key.v1",
            backend=destination_backend,
            audit_sink=_sink([]),
            home=destination,
        )
        assert restored == RANDOM_ETHEREUM_KEY
        assert "recovered" in capsys.readouterr().out.lower()

    def test_paper_only_export_recovers_into_fresh_keyvault(
        self,
        isolated_home: Path,
        tmp_path: Path,
    ) -> None:
        source_backend = FakeBackend()
        key_id, ethereum_envelope, _entries = _initialize_source(
            isolated_home,
            source_backend,
            store_seed=False,
            add_ethereum_key=True,
        )
        assert ethereum_envelope is not None
        output = tmp_path / "paper.mrkv"
        assert (
            _export(
                home=isolated_home,
                backend=source_backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE, SEED]),
            )
            == 0
        )

        destination = tmp_path / "paper-destination"
        destination_backend = FakeBackend()
        assert (
            keyvault_cli.recover(
                blob_path=output,
                home=destination,
                backend=destination_backend,
                prompt_io=RecordingPromptIO([SEED, PASSPHRASE]),
                audit_sink=_sink([]),
            )
            == 0
        )
        assert (
            api.decrypt(
                key_id,
                ethereum_envelope,
                "ethereum.key.v1",
                backend=destination_backend,
                audit_sink=_sink([]),
                home=destination,
            )
            == RANDOM_ETHEREUM_KEY
        )

    def test_wrong_passphrase_is_fail_closed_without_partial_destination(
        self,
        isolated_home: Path,
        tmp_path: Path,
    ) -> None:
        source_backend = FakeBackend()
        _initialize_source(isolated_home, source_backend, store_seed=True, add_ethereum_key=True)
        output = tmp_path / "portable.mrkv"
        assert (
            _export(
                home=isolated_home,
                backend=source_backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 0
        )

        destination = tmp_path / "wrong-passphrase-destination"
        destination_backend = FakeBackend()
        assert (
            keyvault_cli.recover(
                blob_path=output,
                home=destination,
                backend=destination_backend,
                prompt_io=RecordingPromptIO([SEED, "wrong passphrase"]),
                audit_sink=_sink([]),
            )
            == 1
        )
        _assert_fresh_destination(destination, destination_backend)

    def test_wrong_valid_seed_is_fail_closed_without_partial_destination(
        self,
        isolated_home: Path,
        tmp_path: Path,
    ) -> None:
        source_backend = FakeBackend()
        _initialize_source(isolated_home, source_backend, store_seed=True, add_ethereum_key=True)
        output = tmp_path / "portable.mrkv"
        assert (
            _export(
                home=isolated_home,
                backend=source_backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 0
        )

        destination = tmp_path / "wrong-seed-destination"
        destination_backend = FakeBackend()
        assert (
            keyvault_cli.recover(
                blob_path=output,
                home=destination,
                backend=destination_backend,
                prompt_io=RecordingPromptIO([OTHER_VALID_SEED, PASSPHRASE]),
                audit_sink=_sink([]),
            )
            == 1
        )
        _assert_fresh_destination(destination, destination_backend)

    def test_tampered_blob_is_fail_closed_without_partial_destination(
        self,
        isolated_home: Path,
        tmp_path: Path,
    ) -> None:
        source_backend = FakeBackend()
        _initialize_source(isolated_home, source_backend, store_seed=True, add_ethereum_key=True)
        output = tmp_path / "portable.mrkv"
        assert (
            _export(
                home=isolated_home,
                backend=source_backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 0
        )
        tampered = bytearray(output.read_bytes())
        tampered[-1] ^= 1
        output.write_bytes(tampered)
        output.chmod(0o600)

        destination = tmp_path / "tampered-destination"
        destination_backend = FakeBackend()
        assert (
            keyvault_cli.recover(
                blob_path=output,
                home=destination,
                backend=destination_backend,
                prompt_io=RecordingPromptIO([SEED, PASSPHRASE, ""]),
                audit_sink=_sink([]),
            )
            == 1
        )
        _assert_fresh_destination(destination, destination_backend)


class TestExportParserAndSecrecy:
    def test_help_lists_export(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["keyvault", "--help"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "export" in out
        assert "--output" not in out  # option is shown by `keyvault export --help`

        with pytest.raises(SystemExit) as export_exc:
            main(["keyvault", "export", "--help"])
        assert export_exc.value.code == 0
        export_help = capsys.readouterr().out
        assert "--output" in export_help
        assert "0600" in export_help

    def test_standalone_and_host_use_the_same_export_parser_surface(self, tmp_path: Path) -> None:
        standalone = argparse.ArgumentParser(prog="hermes-mordred")
        _setup_subparser(standalone, required=False)
        standalone_ns = standalone.parse_args(["keyvault", "export", "--output", str(tmp_path / "a.mrkv")])

        host = argparse.ArgumentParser(prog="hermes")
        host_sub = host.add_subparsers(dest="command", required=True)
        mordred = host_sub.add_parser("mordred")
        _setup_subparser(mordred)
        host_ns = host.parse_args(["mordred", "keyvault", "export", "--output", str(tmp_path / "a.mrkv")])

        assert standalone_ns.keyvault_command == host_ns.keyvault_command == "export"
        assert standalone_ns.output == host_ns.output
        assert standalone_ns.func is host_ns.func

    def test_cli_adapter_passes_output_path_without_subprocess(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seen: list[Path] = []

        def fake_export(*, output_path: Path) -> int:
            seen.append(output_path)
            return 0

        monkeypatch.setattr(keyvault_export_cli, "export_keyvault_backup", fake_export)
        output = tmp_path / "adapter.mrkv"

        assert keyvault_export_cli.cli_export(argparse.Namespace(output=str(output))) == 0
        assert seen == [output]

    def test_secrets_and_blob_never_reach_output_or_audit(
        self,
        isolated_home: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True, add_ethereum_key=True)
        entries: list[dict[str, Any]] = []
        output = tmp_path / "redacted.mrkv"

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
                entries=entries,
            )
            == 0
        )

        blob = output.read_bytes()
        captured = capsys.readouterr()
        rendered = captured.out + captured.err + repr(entries)
        assert PASSPHRASE not in rendered
        assert SEED not in rendered
        assert blob.hex() not in rendered
        assert repr(blob) not in rendered
        assert all("passphrase" not in repr(entry).lower() for entry in entries)
        assert all("seed" not in repr(entry).lower() for entry in entries)

    def test_unexpected_secret_bearing_exception_is_redacted(
        self,
        isolated_home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        backend = FakeBackend()
        _initialize_source(isolated_home, backend, store_seed=True)
        output = tmp_path / "never-created.mrkv"
        blob_marker = "MRKV-secret-body-marker"

        def explode(*args: object, **kwargs: object) -> bytes:
            del args, kwargs
            raise RuntimeError(f"{PASSPHRASE} {SEED} {blob_marker}")

        monkeypatch.setattr(api, "export_backup", explode)

        assert (
            _export(
                home=isolated_home,
                backend=backend,
                output=output,
                prompts=RecordingPromptIO([PASSPHRASE]),
            )
            == 1
        )

        captured = capsys.readouterr()
        rendered = captured.out + captured.err
        assert PASSPHRASE not in rendered
        assert SEED not in rendered
        assert blob_marker not in rendered
        assert "failed safely" in rendered.lower()
        assert not (output.exists() or output.is_symlink())
