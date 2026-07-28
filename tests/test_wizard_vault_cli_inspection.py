"""Vault CLI status, cat, root-resolution, and JSON-output tests."""

from __future__ import annotations

import argparse
import base64
from pathlib import Path

import pytest

from mordred_hermes.keyvault import kek, manifest, vault
from mordred_hermes.wizard import vault_cli
from mordred_hermes.wizard._prompt_io import _RefusingPromptIO

from ._keyvault_fakes import FakeAnchorStore, FakeBackend
from ._wizard_vault_cli_helpers import _KEY_ID, _LABEL, _PASSPHRASE, _build_vault, _PromptIO


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
