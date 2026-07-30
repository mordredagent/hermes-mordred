"""``hermes mordred keyvault {enable-se,enable-tpm}`` — native-helper build CLI.

v2-OS2 follow-up (b): the commands that build the platform hardware-helper
binaries from source (``enable-se`` / ``enable-tpm``) are extracted out of
``keyvault_cli`` into their own module so ``keyvault_cli`` drops back under the
800-LOC guideline. This first section pins the post-split module surface; the
behavioural coverage (the migrated ``TestEnableSE`` / ``TestEnableTPM`` …
classes) is added with the move.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

# ``keyvault_cli`` is imported only for the negative-contract assertions (the
# native-build commands must NO LONGER live there); ``keyvault_native_cli`` is
# the module under test.
from mordred_hermes.wizard import keyvault_cli, keyvault_native_cli

#: Public command + argparse-adapter surface that must live in the new module.
_PUBLIC = ("enable_se", "cli_enable_se", "enable_tpm", "cli_enable_tpm")
#: Build seams (unit-test hooks) that move with the commands.
_SEAMS = (
    "_se_platform_reason",
    "_missing_build_tools",
    "_locate_sekey_source",
    "_run_sekey_build",
    "_verify_sekey_helper",
    "_tpm_platform_reason",
    "_missing_tpm_build_tools",
    "_locate_tpmkey_source",
    "_run_tpmkey_build",
    "_verify_tpmkey_helper",
)


@pytest.mark.parametrize("name", _PUBLIC + _SEAMS)
def test_native_cli_exposes_command(name: str) -> None:
    assert hasattr(keyvault_native_cli, name), f"keyvault_native_cli must expose {name}"


@pytest.mark.parametrize("name", _PUBLIC + _SEAMS)
def test_keyvault_cli_no_longer_exposes_native_command(name: str) -> None:
    # Clean split: the native-build commands are GONE from keyvault_cli.
    assert not hasattr(keyvault_cli, name), f"keyvault_cli must not still expose {name}"


def test_public_commands_in_native_all() -> None:
    for name in _PUBLIC:
        assert name in keyvault_native_cli.__all__


class TestEnableSE:
    """``hermes mordred keyvault enable-se`` — build + install the SE helper.

    The command orchestrates platform/toolchain guards → locate source →
    build+sign+install → verify. Each step is a module-level seam so these
    behavioural tests run with no Swift toolchain and no Secure Enclave.
    """

    def _patch_all_ok(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
        calls: dict[str, Any] = {"build": 0, "verify": 0}
        monkeypatch.setattr(keyvault_native_cli, "_se_platform_reason", lambda: None, raising=False)
        monkeypatch.setattr(keyvault_native_cli, "_missing_build_tools", lambda: [], raising=False)
        monkeypatch.setattr(
            keyvault_native_cli, "_locate_sekey_source", lambda: tmp_path / "sekey-helper", raising=False
        )

        def _build(src: Path, *, install_dir: Path | None, unattended: bool | None) -> tuple[int, str]:
            calls["build"] += 1
            calls["build_args"] = (src, install_dir, unattended)
            return 0, "Installed: ~/.local/bin/mordred-hermes-sekey"

        def _verify(*, install_dir: Path | None = None) -> bool:
            calls["verify"] += 1
            calls["verify_install_dir"] = install_dir
            return True

        monkeypatch.setattr(keyvault_native_cli, "_run_sekey_build", _build, raising=False)
        monkeypatch.setattr(keyvault_native_cli, "_verify_sekey_helper", _verify, raising=False)
        return calls

    def test_happy_path_builds_verifies_returns_0(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        calls = self._patch_all_ok(monkeypatch, tmp_path)
        rc = keyvault_native_cli.enable_se(home=tmp_path)
        assert rc == 0
        assert calls["build"] == 1 and calls["verify"] == 1
        # No --install-dir given → verify must be probed with install_dir=None.
        assert calls["verify_install_dir"] is None
        out = capsys.readouterr().out
        assert "mordred-hermes-sekey" in out
        assert "later fresh key creation" in out
        assert "now active for the keyvault" not in out

    def test_unattended_is_rejected_as_an_installer_noop(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(
            keyvault_native_cli,
            "_run_sekey_build",
            lambda *a, **k: pytest.fail("build must not run for a rejected --unattended flag"),
        )

        rc = keyvault_native_cli.enable_se(home=tmp_path, unattended=True)

        assert rc == 1
        err = capsys.readouterr().err
        assert "cannot be applied while installing" in err
        assert "MORDRED_SEKEY_UNATTENDED=1" in err

    def test_existing_key_allows_install_without_claiming_hardware_promotion(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mordred_hermes.keyvault import _storage

        calls = self._patch_all_ok(monkeypatch, tmp_path)
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta = _storage.load_meta(root)
        meta["keys"]["0" * 32] = {"key_id": "default", "created_at": "2026-01-01T00:00:00Z"}
        _storage.save_meta(root, meta)

        rc = keyvault_native_cli.enable_se(home=tmp_path)

        captured = capsys.readouterr()
        assert rc == 0
        assert calls["build"] == 1 and calls["verify"] == 1
        assert captured.err == ""
        assert "remain in their current backend namespace" in captured.out
        assert "now active for the keyvault" not in captured.out
        assert _storage.load_meta(root) == meta

    @pytest.mark.parametrize("residue_kind", ["commit", "ciphertext", "backend_store"])
    def test_existing_artifacts_do_not_block_helper_refresh_or_get_modified(
        self,
        residue_kind: str,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from mordred_hermes.keyvault import _storage

        calls = self._patch_all_ok(monkeypatch, tmp_path)
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        if residue_kind == "commit":
            artifact = root / "digests" / "orphan.commit"
            expected = b"x" * 32
            _storage.atomic_write(artifact, expected)
        elif residue_kind == "ciphertext":
            purpose_dir = root / "ciphertexts" / ("a" * 32) / ("b" * 32)
            purpose_dir.mkdir(parents=True)
            artifact = purpose_dir / "orphan.gcm"
            expected = b"orphan"
            artifact.write_bytes(expected)
        else:
            store_dir = root / "sekey"
            store_dir.mkdir()
            artifact = store_dir / "orphan.bin"
            expected = b"opaque-key-blob"
            artifact.write_bytes(expected)

        rc = keyvault_native_cli.enable_se(home=tmp_path)

        assert rc == 0
        assert calls["build"] == 1 and calls["verify"] == 1
        assert artifact.read_bytes() == expected
        assert capsys.readouterr().err == ""

    def test_unsupported_platform_returns_1_without_building(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(
            keyvault_native_cli,
            "_se_platform_reason",
            lambda: "Secure Enclave requires macOS on Apple Silicon",
            raising=False,
        )
        monkeypatch.setattr(
            keyvault_native_cli,
            "_run_sekey_build",
            lambda *a, **k: pytest.fail("build ran on unsupported platform"),
            raising=False,
        )
        rc = keyvault_native_cli.enable_se(home=tmp_path)
        assert rc == 1
        assert "macOS" in capsys.readouterr().err

    def test_missing_toolchain_returns_1_with_actionable_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(keyvault_native_cli, "_missing_build_tools", lambda: ["swift", "codesign"], raising=False)
        monkeypatch.setattr(
            keyvault_native_cli,
            "_run_sekey_build",
            lambda *a, **k: pytest.fail("build ran without toolchain"),
            raising=False,
        )
        rc = keyvault_native_cli.enable_se(home=tmp_path)
        assert rc == 1
        assert "swift" in capsys.readouterr().err

    def test_missing_source_returns_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(keyvault_native_cli, "_locate_sekey_source", lambda: None, raising=False)
        monkeypatch.setattr(
            keyvault_native_cli,
            "_run_sekey_build",
            lambda *a, **k: pytest.fail("build ran without source"),
            raising=False,
        )
        rc = keyvault_native_cli.enable_se(home=tmp_path)
        assert rc == 1

    def test_build_failure_returns_1_and_surfaces_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(
            keyvault_native_cli, "_run_sekey_build", lambda *a, **k: (1, "swift build error: boom"), raising=False
        )
        rc = keyvault_native_cli.enable_se(home=tmp_path)
        assert rc == 1
        assert "boom" in capsys.readouterr().err

    def test_verify_failure_returns_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(keyvault_native_cli, "_verify_sekey_helper", lambda **_k: False, raising=False)
        rc = keyvault_native_cli.enable_se(home=tmp_path)
        assert rc == 1

    def test_install_dir_threaded_to_build_and_verify(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # enable-se parity with codex MEDIUM-1: --install-dir must reach BOTH the
        # build (env) and the verify (where to look for the installed binary), so
        # a custom not-on-PATH install dir does not yield a false verify failure.
        calls = self._patch_all_ok(monkeypatch, tmp_path)
        install_dir = tmp_path / "bin"
        rc = keyvault_native_cli.enable_se(install_dir=install_dir, home=tmp_path)
        assert rc == 0
        assert calls["build_args"][1] == install_dir
        assert calls["verify_install_dir"] == install_dir

    def test_prints_progress_notice_before_build(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """UX: the build can take minutes with capture_output=True (no live
        output), so the operator must see a notice before it starts, not sit
        looking at a blank terminal."""
        self._patch_all_ok(monkeypatch, tmp_path)
        rc = keyvault_native_cli.enable_se(home=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert "Building" in out
        assert "Secure Enclave" in out
        assert "minutes" in out

    def test_no_progress_notice_when_platform_guard_refuses(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The notice must only print once the build is actually about to run,
        not before an early guard refusal."""
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(
            keyvault_native_cli,
            "_se_platform_reason",
            lambda: "Secure Enclave requires macOS on Apple Silicon",
            raising=False,
        )
        rc = keyvault_native_cli.enable_se(home=tmp_path)
        assert rc == 1
        assert "Building" not in capsys.readouterr().out


class TestEnableSESeams:
    """Direct coverage tests for the enable-se seams (mocked at the stdlib edge)."""

    def test_platform_reason_none_on_darwin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        assert keyvault_native_cli._se_platform_reason() is None

    def test_platform_reason_set_off_darwin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("platform.system", lambda: "Linux")
        reason = keyvault_native_cli._se_platform_reason()
        assert reason is not None and "macOS" in reason

    def test_missing_build_tools_reports_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda name: None if name == "swift" else "/usr/bin/" + name)
        assert keyvault_native_cli._missing_build_tools() == ["swift"]

    def test_missing_build_tools_empty_when_all_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
        assert keyvault_native_cli._missing_build_tools() == []

    def test_locate_sekey_source_delegates(self) -> None:
        # In a source checkout this resolves the native/sekey-helper tree.
        src = keyvault_native_cli._locate_sekey_source()
        assert src is not None
        assert (src / "build.sh").is_file()

    def test_run_sekey_build_forwards_env_and_returns_output(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        seen: dict[str, Any] = {}
        monkeypatch.delenv("MORDRED_SEKEY_UNATTENDED", raising=False)

        class _CP:
            returncode = 0
            stdout = "ok-out"
            stderr = ""

        def _fake_run(cmd: list[str], **kwargs: Any) -> Any:
            seen["cmd"] = cmd
            seen["env"] = kwargs["env"]
            return _CP()

        monkeypatch.setattr("subprocess.run", _fake_run)
        rc, out = keyvault_native_cli._run_sekey_build(tmp_path, install_dir=tmp_path / "bin", unattended=True)
        assert rc == 0 and "ok-out" in out
        assert seen["env"]["MORDRED_SEKEY_INSTALL_DIR"] == str(tmp_path / "bin")
        assert "MORDRED_SEKEY_UNATTENDED" not in seen["env"]
        assert seen["cmd"][0] == "bash"

    def test_run_sekey_build_oserror_returns_1(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        def _boom(*a: Any, **k: Any) -> Any:
            raise OSError("no bash")

        monkeypatch.setattr("subprocess.run", _boom)
        rc, out = keyvault_native_cli._run_sekey_build(tmp_path, install_dir=None, unattended=None)
        assert rc == 1 and "no bash" in out

    def test_verify_sekey_helper_false_when_no_binary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper._find_helper", lambda: None)
        assert keyvault_native_cli._verify_sekey_helper() is False

    def test_verify_sekey_helper_true_on_probe_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper._find_helper", lambda: "/fake/helper")

        class _Ops:
            def __init__(self, binary: str) -> None:
                pass

            def probe(self) -> None:
                return None

        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper._HelperSecKeyOps", _Ops)
        assert keyvault_native_cli._verify_sekey_helper() is True

    def test_verify_sekey_helper_false_on_probe_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper._find_helper", lambda: "/fake/helper")

        class _Ops:
            def __init__(self, binary: str) -> None:
                pass

            def probe(self) -> None:
                raise RuntimeError("boom")

        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper._HelperSecKeyOps", _Ops)
        assert keyvault_native_cli._verify_sekey_helper() is False

    def test_verify_sekey_helper_prefers_install_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # enable-se parity with codex MEDIUM-1: when --install-dir is given, verify
        # must probe the binary THERE, not only env / ~/.local/bin / PATH via
        # _find_helper.
        binary = tmp_path / "mordred-hermes-sekey"
        binary.write_text("#!/bin/sh\n")
        monkeypatch.setattr(
            "mordred_hermes.keyvault._seckey_helper._find_helper",
            lambda: pytest.fail("must not fall back to _find_helper when install_dir has the binary"),
        )
        seen: dict[str, str] = {}

        class _Ops:
            def __init__(self, b: str) -> None:
                seen["binary"] = b

            def probe(self) -> None:
                return None

        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper._HelperSecKeyOps", _Ops)
        assert keyvault_native_cli._verify_sekey_helper(install_dir=tmp_path) is True
        assert seen["binary"] == str(binary)

    def test_verify_sekey_helper_falls_back_when_install_dir_binary_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # install_dir given but the binary is not there yet (e.g. a silent build
        # failure) → fall back to _find_helper, which here finds nothing.
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper._find_helper", lambda: None)
        assert keyvault_native_cli._verify_sekey_helper(install_dir=empty_dir) is False


class TestEnableTPM:
    """``hermes mordred keyvault enable-tpm`` — build + install the TPM helper.

    v2-OS2 Phase 2c. The Linux counterpart to ``enable-se``: it builds the
    ``mordred-hermes-tpmkey`` Rust helper (``native/tpmkey-helper``) and verifies
    it. Same orchestration shape (platform/toolchain guards → locate source →
    build → verify) with each step a module-level seam, so these behavioural
    tests run with no Rust toolchain and no TPM. The TPM is Tier 2
    (machine-bound), so there is **no** ``--unattended`` per-use gate.
    """

    def _patch_all_ok(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
        calls: dict[str, Any] = {"build": 0, "verify": 0}
        monkeypatch.setattr(keyvault_native_cli, "_tpm_platform_reason", lambda: None, raising=False)
        monkeypatch.setattr(keyvault_native_cli, "_missing_tpm_build_tools", lambda: [], raising=False)
        monkeypatch.setattr(
            keyvault_native_cli, "_locate_tpmkey_source", lambda: tmp_path / "tpmkey-helper", raising=False
        )

        def _build(src: Path, *, install_dir: Path | None) -> tuple[int, str]:
            calls["build"] += 1
            calls["build_args"] = (src, install_dir)
            return 0, "Installed: ~/.local/bin/mordred-hermes-tpmkey"

        def _verify(*, install_dir: Path | None = None) -> bool:
            calls["verify"] += 1
            calls["verify_install_dir"] = install_dir
            return True

        monkeypatch.setattr(keyvault_native_cli, "_run_tpmkey_build", _build, raising=False)
        monkeypatch.setattr(keyvault_native_cli, "_verify_tpmkey_helper", _verify, raising=False)
        return calls

    def test_happy_path_builds_verifies_returns_0(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        calls = self._patch_all_ok(monkeypatch, tmp_path)
        rc = keyvault_native_cli.enable_tpm(home=tmp_path)
        assert rc == 0
        assert calls["build"] == 1 and calls["verify"] == 1
        out = capsys.readouterr().out
        assert "mordred-hermes-tpmkey" in out
        assert "hardware probe succeeded" in out
        assert "now active for the keyvault" not in out

    def test_unsupported_platform_returns_1_without_building(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(
            keyvault_native_cli, "_tpm_platform_reason", lambda: "TPM 2.0 keyvault requires Linux", raising=False
        )
        monkeypatch.setattr(
            keyvault_native_cli,
            "_run_tpmkey_build",
            lambda *a, **k: pytest.fail("build ran on unsupported platform"),
            raising=False,
        )
        rc = keyvault_native_cli.enable_tpm(home=tmp_path)
        assert rc == 1
        assert "Linux" in capsys.readouterr().err

    def test_missing_toolchain_returns_1_with_actionable_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(keyvault_native_cli, "_missing_tpm_build_tools", lambda: ["cargo"], raising=False)
        monkeypatch.setattr(
            keyvault_native_cli,
            "_run_tpmkey_build",
            lambda *a, **k: pytest.fail("build ran without toolchain"),
            raising=False,
        )
        rc = keyvault_native_cli.enable_tpm(home=tmp_path)
        assert rc == 1
        assert "cargo" in capsys.readouterr().err

    def test_missing_source_returns_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(keyvault_native_cli, "_locate_tpmkey_source", lambda: None, raising=False)
        monkeypatch.setattr(
            keyvault_native_cli,
            "_run_tpmkey_build",
            lambda *a, **k: pytest.fail("build ran without source"),
            raising=False,
        )
        rc = keyvault_native_cli.enable_tpm(home=tmp_path)
        assert rc == 1

    def test_build_failure_returns_1_and_surfaces_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(
            keyvault_native_cli, "_run_tpmkey_build", lambda *a, **k: (1, "cargo build error: boom"), raising=False
        )
        rc = keyvault_native_cli.enable_tpm(home=tmp_path)
        assert rc == 1
        assert "boom" in capsys.readouterr().err

    def test_verify_failure_returns_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(keyvault_native_cli, "_verify_tpmkey_helper", lambda **_k: False, raising=False)
        rc = keyvault_native_cli.enable_tpm(home=tmp_path)
        assert rc == 1

    def test_verify_failure_message_is_honest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # codex HIGH + MEDIUM-2: on Linux there is no software fallback (Phase 1
        # fail-closed), so the failure message must be honest — not the
        # copied-from-enable-se "keeps using the software fallback" claim.
        # UX review 2026-06-11: the Phase 2b TPM backend has LANDED (#114), so
        # the message must no longer call the failure "expected" pending Phase
        # 2b — it must point at real TPM troubleshooting instead.
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(keyvault_native_cli, "_verify_tpmkey_helper", lambda **_k: False, raising=False)
        keyvault_native_cli.enable_tpm(home=tmp_path)
        err = capsys.readouterr().err
        assert "keep using the software fallback" not in err
        assert "fails closed" in err
        assert "Phase 2b" not in err
        assert "/dev/tpmrm0" in err
        assert "hermes-mordred keyvault enable-tpm" in err

    def test_install_dir_threaded_to_build_and_verify(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # codex MEDIUM-1: --install-dir must reach BOTH the build (env) and the
        # verify (where to look for the installed binary).
        calls = self._patch_all_ok(monkeypatch, tmp_path)
        install_dir = tmp_path / "bin"
        rc = keyvault_native_cli.enable_tpm(install_dir=install_dir, home=tmp_path)
        assert rc == 0
        assert calls["build_args"][1] == install_dir
        assert calls["verify_install_dir"] == install_dir

    def test_prints_progress_notice_before_build(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """UX: the build can take minutes with capture_output=True (no live
        output), so the operator must see a notice before it starts, not sit
        looking at a blank terminal."""
        self._patch_all_ok(monkeypatch, tmp_path)
        rc = keyvault_native_cli.enable_tpm(home=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert "Building" in out
        assert "TPM" in out
        assert "minutes" in out

    def test_no_progress_notice_when_platform_guard_refuses(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The notice must only print once the build is actually about to run,
        not before an early guard refusal."""
        self._patch_all_ok(monkeypatch, tmp_path)
        monkeypatch.setattr(
            keyvault_native_cli, "_tpm_platform_reason", lambda: "TPM 2.0 keyvault requires Linux", raising=False
        )
        rc = keyvault_native_cli.enable_tpm(home=tmp_path)
        assert rc == 1
        assert "Building" not in capsys.readouterr().out


class TestEnableTPMSeams:
    """Direct coverage tests for the enable-tpm seams (mocked at the stdlib edge)."""

    def test_platform_reason_none_on_linux(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("platform.system", lambda: "Linux")
        assert keyvault_native_cli._tpm_platform_reason() is None

    def test_platform_reason_set_off_linux(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        reason = keyvault_native_cli._tpm_platform_reason()
        assert reason is not None and "Linux" in reason

    def test_missing_tpm_build_tools_reports_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda name: None if name == "cargo" else "/usr/bin/" + name)
        assert keyvault_native_cli._missing_tpm_build_tools() == ["cargo"]

    def test_missing_tpm_build_tools_empty_when_all_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
        assert keyvault_native_cli._missing_tpm_build_tools() == []

    def test_locate_tpmkey_source_delegates(self) -> None:
        # In a source checkout this resolves the native/tpmkey-helper tree.
        src = keyvault_native_cli._locate_tpmkey_source()
        assert src is not None
        assert (src / "build.sh").is_file()
        assert (src / "Cargo.toml").is_file()

    def test_run_tpmkey_build_forwards_env_and_returns_output(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        seen: dict[str, Any] = {}

        class _CP:
            returncode = 0
            stdout = "ok-out"
            stderr = ""

        def _fake_run(cmd: list[str], **kwargs: Any) -> Any:
            seen["cmd"] = cmd
            seen["env"] = kwargs["env"]
            return _CP()

        monkeypatch.setattr("subprocess.run", _fake_run)
        rc, out = keyvault_native_cli._run_tpmkey_build(tmp_path, install_dir=tmp_path / "bin")
        assert rc == 0 and "ok-out" in out
        assert seen["env"]["MORDRED_TPMKEY_INSTALL_DIR"] == str(tmp_path / "bin")
        # Tier 2 has no per-use gate, so the TPM build never sets an unattended flag.
        assert "MORDRED_TPMKEY_UNATTENDED" not in seen["env"]
        assert seen["cmd"][0] == "bash"

    def test_run_tpmkey_build_oserror_returns_1(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        def _boom(*a: Any, **k: Any) -> Any:
            raise OSError("no bash")

        monkeypatch.setattr("subprocess.run", _boom)
        rc, out = keyvault_native_cli._run_tpmkey_build(tmp_path, install_dir=None)
        assert rc == 1 and "no bash" in out

    def test_verify_tpmkey_helper_false_when_no_binary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper.find_tpmkey_helper", lambda: None)
        assert keyvault_native_cli._verify_tpmkey_helper() is False

    def test_verify_tpmkey_helper_true_on_probe_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper.find_tpmkey_helper", lambda: "/fake/helper")

        class _Ops:
            def __init__(self, binary: str) -> None:
                pass

            def probe(self) -> None:
                return None

        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper._HelperSecKeyOps", _Ops)
        assert keyvault_native_cli._verify_tpmkey_helper() is True

    def test_verify_tpmkey_helper_false_on_probe_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper.find_tpmkey_helper", lambda: "/fake/helper")

        class _Ops:
            def __init__(self, binary: str) -> None:
                pass

            def probe(self) -> None:
                raise RuntimeError("boom")

        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper._HelperSecKeyOps", _Ops)
        assert keyvault_native_cli._verify_tpmkey_helper() is False

    def test_verify_tpmkey_helper_prefers_install_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # codex MEDIUM-1: when --install-dir is given, verify must probe the
        # binary THERE, not only env / ~/.local/bin / PATH via find_tpmkey_helper.
        binary = tmp_path / "mordred-hermes-tpmkey"
        binary.write_text("#!/bin/sh\n")
        monkeypatch.setattr(
            "mordred_hermes.keyvault._seckey_helper.find_tpmkey_helper",
            lambda: pytest.fail("must not fall back to find_tpmkey_helper when install_dir has the binary"),
        )
        seen: dict[str, str] = {}

        class _Ops:
            def __init__(self, b: str) -> None:
                seen["binary"] = b

            def probe(self) -> None:
                return None

        monkeypatch.setattr("mordred_hermes.keyvault._seckey_helper._HelperSecKeyOps", _Ops)
        assert keyvault_native_cli._verify_tpmkey_helper(install_dir=tmp_path) is True
        assert seen["binary"] == str(binary)


class TestErrorColour:
    """enable-se errors route through ``_term.emit_error``: red ``error:`` on a tty, plain off it.

    Mirrors the network / vault / keyvault reproducers (PR #159 / #164 / #165).
    These commands used to write a manual ``error:`` prefix; emit_error re-adds
    it, so plain output stays byte-identical while a tty now gets colour.
    """

    def test_enable_se_error_is_red_when_forced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        monkeypatch.setattr(
            keyvault_native_cli, "_se_platform_reason", lambda: "Secure Enclave requires macOS on Apple Silicon"
        )
        rc = keyvault_native_cli.enable_se(home=tmp_path)
        assert rc == 1
        err = capsys.readouterr().err
        assert "\033[31m" in err  # red `error:` label
        assert "Secure Enclave requires macOS" in err

    def test_enable_se_error_plain_and_prefixed_off_tty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Off a tty the output is plain, carrying the shared `error:` prefix that
        # emit_error supplies in place of the old hand-written one.
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setattr(
            keyvault_native_cli, "_se_platform_reason", lambda: "Secure Enclave requires macOS on Apple Silicon"
        )
        rc = keyvault_native_cli.enable_se(home=tmp_path)
        assert rc == 1
        err = capsys.readouterr().err
        assert err.startswith("error: Secure Enclave requires macOS")
        assert "\033" not in err
