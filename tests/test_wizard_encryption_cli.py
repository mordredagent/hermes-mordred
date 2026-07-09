"""Tests for ``hermes mordred encryption`` — the unified at-rest toggle surface.

Phase 0: the namespace skeleton + a **side-effect-free** ``status`` that reports
the state of all four targets (``env`` / ``config`` / ``memory`` / ``workspace``)
without ever opening the vault cold path (no passphrase prompt) or probing the
device key store. Enrollment is read from the plaintext manifest body
(:func:`mordred_hermes.keyvault.manifest.parse_unverified`); the config opt-in is
the marker file; memory is the ``config.yaml`` flag; the workspace is on-disk
artifact + mountpoint detection.

``active`` is the *effective* state on this OS: the runtime decrypt shims are
macOS-only (see :mod:`mordred_hermes.keyvault._runtime_env`), so an enrolled
target is reported inactive off ``darwin`` rather than implying protection that
is not actually wired.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _identity, vault
from mordred_hermes.keyvault._config_bootstrap import _marker_path
from mordred_hermes.wizard import encryption_cli

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

_PASSPHRASE = "correct horse battery staple"


# --- shared vault helpers (mirror test_wizard_config_decrypt_cli) -------------
def _init_empty_vault(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    key_id = anchor_label = _identity.vault_identity(root)
    backend.generate_enclave_key(key_id)
    vault.init_vault(
        root, key_id=key_id, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=anchor_label
    ).close()


def _enroll(root: Path, name: str, data: bytes, backend: FakeBackend, store: FakeAnchorStore) -> None:
    key_id = anchor_label = _identity.vault_identity(root)
    with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
        opened.enroll_file(name, data)


# -----------------------------------------------------------------------------
# _enrolled_names — side-effect-free enrollment read (no device key, no cold path)
# -----------------------------------------------------------------------------
class TestEnrolledNames:
    def test_empty_for_missing_vault(self, tmp_path: Path) -> None:
        assert encryption_cli._enrolled_names(tmp_path / "nope") == set()

    def test_lists_enrolled_names_without_keys(self, tmp_path: Path) -> None:
        root = tmp_path / "v"
        backend, store = FakeBackend(), FakeAnchorStore()
        _init_empty_vault(root, backend, store)
        _enroll(root, ".env", b"A=1\n", backend, store)

        # No backend / store / passphrase passed — purely reads the plaintext manifest body.
        assert ".env" in encryption_cli._enrolled_names(root)

    def test_degrades_without_crypto_stack_in_subprocess(self) -> None:
        """Minimal install (no ``[keyvault]`` extra): the lazy keyvault import
        raises ``ModuleNotFoundError`` for argon2 — ``_enrolled_names`` must
        degrade to the empty set (its never-raise contract) and the whole
        ``status`` overview must still exit 0, not abort with the install hint.

        Found in the 2026-07-09 CLI sweep: ``hermes-mordred status`` exited 1
        with the keyvault hint instead of printing policy / network state.

        Runs in a subprocess: blocking the crypto imports in-process would race
        the copies other tests have already imported (mirrors
        ``test_audit_cli.TestMinimalInstallImport``).
        """
        import subprocess
        import sys
        import textwrap

        script = textwrap.dedent(
            """
            import argparse, os, sys, tempfile
            from pathlib import Path

            class _Blocker:
                BLOCKED = ("cryptography", "blake3", "argon2")
                def find_spec(self, name, path=None, target=None):
                    if name.split(".")[0] in self.BLOCKED:
                        raise ModuleNotFoundError(f"No module named {name!r} (blocked by test)", name=name)
                    return None

            sys.meta_path.insert(0, _Blocker())
            os.environ["HERMES_HOME"] = tempfile.mkdtemp()

            from mordred_hermes.wizard import encryption_cli
            assert encryption_cli._enrolled_names(Path("/nonexistent/vault")) == set()

            from mordred_hermes.wizard._cli_parsers import _handle_status
            rc = _handle_status(argparse.Namespace(json=False))
            assert rc == 0, f"status must degrade cleanly, got rc={rc}"
            print("OK")
            """
        )
        proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60, check=False)
        assert proc.returncode == 0, f"status crashed without crypto stack:\n{proc.stderr}"
        assert "OK" in proc.stdout


# -----------------------------------------------------------------------------
# Per-target detectors — configured / active / detail
# -----------------------------------------------------------------------------
class TestEnvStatus:
    def test_not_enrolled(self, tmp_path: Path) -> None:
        st = encryption_cli.env_status(root=tmp_path / "v", home=tmp_path / "home", platform="darwin")
        assert st.target == "env"
        assert st.configured is False
        assert st.active is False

    def test_enrolled_active_on_macos(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        st = encryption_cli.env_status(root=tmp_path / "v", home=tmp_path / "home", platform="darwin")
        assert st.configured is True
        assert st.active is True

    def test_enrolled_inactive_off_macos(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        st = encryption_cli.env_status(root=tmp_path / "v", home=tmp_path / "home", platform="linux")
        assert st.configured is True
        assert st.active is False  # enrolled but the runtime shim is a no-op off darwin

    def test_enrolled_but_opted_out_is_inactive(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        marker = encryption_cli._env_optout_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("opt-out\n", encoding="utf-8")
        st = encryption_cli.env_status(root=tmp_path / "v", home=home, platform="darwin")
        assert st.configured is True  # still enrolled
        assert st.active is False  # but injection is suppressed by the opt-out marker
        assert "disabled" in st.detail.lower()

    def test_plaintext_present_while_active_is_drift(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A plaintext .env on disk while sealed (active, no opt-out, macOS) is drift:
        a host write slipped a partial plaintext past the seal — surface it loudly."""
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        home.mkdir()
        (home / ".env").write_text("FOO=bar\n", encoding="utf-8")
        st = encryption_cli.env_status(root=tmp_path / "v", home=home, platform="darwin")
        assert st.active is True
        assert st.drift is True
        assert encryption_cli.status_mark(st) == "exposed"
        assert "plaintext" in st.detail.lower()
        assert st.to_dict()["drift"] is True

    def test_plaintext_off_macos_is_not_drift(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Off macOS the plaintext is kept intentionally (inactive), so it is not drift."""
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        home.mkdir()
        (home / ".env").write_text("FOO=bar\n", encoding="utf-8")
        st = encryption_cli.env_status(root=tmp_path / "v", home=home, platform="linux")
        assert st.drift is False
        assert encryption_cli.status_mark(st) != "exposed"

    def test_no_plaintext_while_active_is_clean(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sealed with no plaintext on disk is the healthy state — `on`, not `exposed`."""
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        home.mkdir()
        st = encryption_cli.env_status(root=tmp_path / "v", home=home, platform="darwin")
        assert st.drift is False
        assert encryption_cli.status_mark(st) == "on"

    def test_stray_reseal_temp_is_drift(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A reseal temp stranded by a crash is a plaintext at rest the plain ".env"
        check would miss — env_status must still flag it as exposed."""
        monkeypatch.setattr(encryption_cli, "_enrolled_names", lambda _root: {".env"})
        home = tmp_path / "home"
        home.mkdir()
        (home / ".env.reseal.tmp").write_text("FOO=bar\n", encoding="utf-8")  # only the temp, no .env
        st = encryption_cli.env_status(root=tmp_path / "v", home=home, platform="darwin")
        assert st.drift is True
        assert encryption_cli.status_mark(st) == "exposed"
        assert st.to_dict()["drift"] is True


class TestConfigStatus:
    def test_marker_absent(self, tmp_path: Path) -> None:
        st = encryption_cli.config_status(home=tmp_path, platform="darwin")
        assert st.target == "config"
        assert st.configured is False

    def test_marker_present_with_hook_active_on_macos(self, tmp_path: Path) -> None:
        marker = _marker_path(tmp_path)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("vault-managed\n", encoding="utf-8")
        st = encryption_cli.config_status(home=tmp_path, platform="darwin", hook_installed=True)
        assert st.configured is True
        assert st.active is True
        assert "hook installed" in st.detail

    def test_marker_present_no_hook_inactive_on_macos(self, tmp_path: Path) -> None:
        # Marker set but the decrypt .pth hook absent: nothing reseals, so the
        # plaintext stays on disk — configured but NOT active, and the detail says so.
        marker = _marker_path(tmp_path)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("vault-managed\n", encoding="utf-8")
        st = encryption_cli.config_status(home=tmp_path, platform="darwin", hook_installed=False)
        assert st.configured is True
        assert st.active is False
        assert "NOT installed" in st.detail

    def test_marker_present_inactive_off_macos(self, tmp_path: Path) -> None:
        marker = _marker_path(tmp_path)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("vault-managed\n", encoding="utf-8")
        st = encryption_cli.config_status(home=tmp_path, platform="linux")
        assert st.configured is True
        assert st.active is False


class TestMemoryStatus:
    def test_flag_false_or_absent(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text("model: x\n", encoding="utf-8")
        st = encryption_cli.memory_status(home=tmp_path, platform="darwin")
        assert st.target == "memory"
        assert st.configured is False

    def test_flag_true_active_on_macos(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text("memory:\n  encryption:\n    enabled: true\n", encoding="utf-8")
        st = encryption_cli.memory_status(home=tmp_path, platform="darwin")
        assert st.configured is True
        assert st.active is True

    def test_flag_true_inactive_off_macos(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text("memory:\n  encryption:\n    enabled: true\n", encoding="utf-8")
        st = encryption_cli.memory_status(home=tmp_path, platform="linux")
        assert st.configured is True
        assert st.active is False

    def test_missing_config_is_not_configured(self, tmp_path: Path) -> None:
        st = encryption_cli.memory_status(home=tmp_path, platform="darwin")
        assert st.configured is False


class TestWorkspaceStatus:
    def test_no_artifacts(self, tmp_path: Path) -> None:
        st = encryption_cli.workspace_status(
            image=tmp_path / "img.sparsebundle",
            blob=tmp_path / "passphrase.wrapped",
            mount=tmp_path / "mnt",
            platform="darwin",
            on_path=lambda _name: False,
        )
        assert st.target == "workspace"
        assert st.configured is False

    def test_image_and_blob_present_is_configured(self, tmp_path: Path) -> None:
        image = tmp_path / "img.sparsebundle"
        blob = tmp_path / "passphrase.wrapped"
        image.mkdir()  # sparsebundle is a directory bundle
        blob.write_bytes(b"wrapped")
        st = encryption_cli.workspace_status(
            image=image,
            blob=blob,
            mount=tmp_path / "mnt",
            platform="darwin",
            on_path=lambda _name: True,
        )
        assert st.configured is True
        assert st.active is True

    def test_macos_only_off_darwin(self, tmp_path: Path) -> None:
        image = tmp_path / "img.sparsebundle"
        blob = tmp_path / "passphrase.wrapped"
        image.mkdir()
        blob.write_bytes(b"wrapped")
        st = encryption_cli.workspace_status(
            image=image,
            blob=blob,
            mount=tmp_path / "mnt",
            platform="linux",
            on_path=lambda _name: True,
        )
        assert st.active is False
        assert "macos" in st.detail.lower()


# -----------------------------------------------------------------------------
# Aggregation + rendering
# -----------------------------------------------------------------------------
class TestRender:
    def test_collect_returns_all_four_targets(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        statuses = encryption_cli.collect_status(
            home=home,
            root=tmp_path / "v",
            platform="darwin",
            workspace=encryption_cli.WorkspacePaths(
                image=tmp_path / "img.sparsebundle",
                blob=tmp_path / "passphrase.wrapped",
                mount=tmp_path / "mnt",
            ),
            on_path=lambda _name: False,
        )
        assert [s.target for s in statuses] == list(encryption_cli.TARGETS)

    def test_render_json_is_machine_readable(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        statuses = encryption_cli.collect_status(
            home=home,
            root=tmp_path / "v",
            platform="darwin",
            workspace=encryption_cli.WorkspacePaths(
                image=tmp_path / "img.sparsebundle",
                blob=tmp_path / "passphrase.wrapped",
                mount=tmp_path / "mnt",
            ),
            on_path=lambda _name: False,
        )
        payload = json.loads(encryption_cli.render_json(statuses))
        assert {row["target"] for row in payload} == set(encryption_cli.TARGETS)
        for row in payload:
            assert set(row) >= {"target", "configured", "active", "detail"}

    def test_render_text_lists_every_target(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        statuses = encryption_cli.collect_status(
            home=home,
            root=tmp_path / "v",
            platform="linux",
            workspace=encryption_cli.WorkspacePaths(
                image=tmp_path / "img.sparsebundle",
                blob=tmp_path / "passphrase.wrapped",
                mount=tmp_path / "mnt",
            ),
            on_path=lambda _name: False,
        )
        text = encryption_cli.render_text(statuses)
        for target in encryption_cli.TARGETS:
            assert target in text

    def test_status_mark_reflects_active_not_just_configured(self) -> None:
        on = encryption_cli.TargetStatus("env", configured=True, active=True, detail="active")
        paused = encryption_cli.TargetStatus("env", configured=True, active=False, detail="disabled")
        off = encryption_cli.TargetStatus("env", configured=False, active=False, detail="not enrolled")
        assert encryption_cli.status_mark(on) == "on"
        # configured but not active -> 'paused', NOT 'on' (the misleading old behavior)
        assert encryption_cli.status_mark(paused) == "paused"
        assert encryption_cli.status_mark(off) == "off"

    def test_render_text_marks_disabled_target_paused_with_legend(self) -> None:
        statuses = [
            encryption_cli.TargetStatus("env", configured=True, active=False, detail="disabled"),
            encryption_cli.TargetStatus("config", configured=False, active=False, detail="not vault-managed"),
        ]
        text = encryption_cli.render_text(statuses)
        assert "[paused]" in text  # the disabled-but-enrolled target reads paused
        assert "legend:" in text  # legend explains 'paused' whenever it appears

    def test_render_text_unchanged_when_nothing_paused(self) -> None:
        # No paused row -> marks stay width 3 (on/off) and no legend, so existing
        # docs/tests that show `[on ]` / `[off]` keep rendering identically.
        statuses = [
            encryption_cli.TargetStatus("env", configured=True, active=True, detail="active"),
            encryption_cli.TargetStatus("config", configured=False, active=False, detail="not vault-managed"),
        ]
        text = encryption_cli.render_text(statuses)
        assert "[on ]" in text
        assert "[off]" in text
        assert "legend:" not in text

    def test_workspace_mark_is_sealed_when_set_up_and_unmounted(self) -> None:
        # The workspace is encrypted at rest whenever it is set up and sealed,
        # so `disable` (= seal) must NOT read as the others' `on`/`off`.
        sealed = encryption_cli.TargetStatus(
            "workspace", configured=True, active=True, detail="sealed at rest", mounted=False
        )
        assert encryption_cli.status_mark(sealed) == "sealed"

    def test_workspace_mark_is_open_when_mounted(self) -> None:
        mounted = encryption_cli.TargetStatus(
            "workspace", configured=True, active=True, detail="unlocked & mounted", mounted=True
        )
        assert encryption_cli.status_mark(mounted) == "open"

    def test_workspace_mark_is_off_when_not_set_up_or_off_os(self) -> None:
        not_set_up = encryption_cli.TargetStatus("workspace", configured=False, active=False, detail="not installed")
        off_os = encryption_cli.TargetStatus("workspace", configured=True, active=False, detail="macOS only")
        assert encryption_cli.status_mark(not_set_up) == "off"
        assert encryption_cli.status_mark(off_os) == "off"

    def test_render_text_explains_workspace_marks_below(self) -> None:
        # The exact shape of `encryption disable all`: env paused, workspace
        # sealed. The sealed workspace must read `[sealed]`, not the others'
        # `on`, and the explanation line must be rendered below.
        statuses = [
            encryption_cli.TargetStatus("env", configured=True, active=False, detail="disabled"),
            encryption_cli.TargetStatus(
                "workspace", configured=True, active=True, detail="sealed at rest", mounted=False
            ),
        ]
        text = encryption_cli.render_text(statuses)
        assert "[sealed]" in text  # sealed, not the misleading `on`
        assert "workspace:" in text  # the explanation line is rendered below
        assert encryption_cli.WORKSPACE_LEGEND_BODY in text

    def test_to_dict_serializes_mounted_only_for_workspace(self) -> None:
        # `mounted` is a workspace-only rendering hint: it appears in JSON for an
        # active workspace (so consumers can tell sealed from open) and is absent
        # for the core targets and for an off workspace (where it is `None`).
        env = encryption_cli.TargetStatus("env", configured=True, active=True, detail="active")
        assert "mounted" not in env.to_dict()

        sealed = encryption_cli.TargetStatus(
            "workspace", configured=True, active=True, detail="sealed at rest", mounted=False
        )
        assert sealed.to_dict()["mounted"] is False

        off = encryption_cli.TargetStatus("workspace", configured=False, active=False, detail="not installed")
        assert "mounted" not in off.to_dict()


# -----------------------------------------------------------------------------
# Colour — opt-in styling; plain output stays byte-identical (above tests assert it)
# -----------------------------------------------------------------------------
class TestColor:
    def test_style_mark_colours_by_state(self) -> None:
        assert "\033[32m" in encryption_cli.style_mark("on", "on", enabled=True)  # green
        assert "\033[32m" in encryption_cli.style_mark("sealed", "sealed", enabled=True)  # green
        assert "\033[33m" in encryption_cli.style_mark("paused", "paused", enabled=True)  # yellow
        assert "\033[36m" in encryption_cli.style_mark("open", "open", enabled=True)  # cyan
        assert "\033[2m" in encryption_cli.style_mark("off", "off", enabled=True)  # dim

    def test_style_mark_plain_when_disabled(self) -> None:
        # The padded cell passes through unchanged so column alignment is preserved.
        assert encryption_cli.style_mark("on", "on ", enabled=False) == "on "

    def test_style_mark_unknown_word_passes_through(self) -> None:
        assert encryption_cli.style_mark("mystery", "mystery", enabled=True) == "mystery"

    def test_render_text_default_has_no_ansi(self) -> None:
        statuses = [
            encryption_cli.TargetStatus("env", configured=True, active=True, detail="active"),
            encryption_cli.TargetStatus("config", configured=True, active=False, detail="disabled"),
        ]
        assert "\033" not in encryption_cli.render_text(statuses)

    def test_render_text_color_emits_ansi_and_keeps_words(self) -> None:
        statuses = [
            encryption_cli.TargetStatus("env", configured=True, active=True, detail="active"),
            encryption_cli.TargetStatus("config", configured=True, active=False, detail="disabled"),
        ]
        text = encryption_cli.render_text(statuses, color=True)
        assert "\033[" in text  # styled
        assert "\033[1m" in text  # heading is bold
        assert "on" in text and "paused" in text  # mark words still present

    def _run_status(self, tmp_path: Path) -> int:
        return encryption_cli.status(
            home=tmp_path,
            root=tmp_path / "v",
            platform="linux",
            workspace=encryption_cli.WorkspacePaths(
                image=tmp_path / "img.sparsebundle",
                blob=tmp_path / "pp.wrapped",
                mount=tmp_path / "mnt",
            ),
            on_path=lambda _name: False,
        )

    def test_status_wiring_no_ansi_when_not_a_tty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The capsys stdout is not a tty, so the live should_color gate in status()
        # must yield plain text — guards the `encryption status` colour wiring.
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert self._run_status(tmp_path) == 0
        assert "\033" not in capsys.readouterr().out

    def test_status_wiring_colours_when_forced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # FORCE_COLOR drives colour through the same wiring even off a tty.
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        assert self._run_status(tmp_path) == 0
        assert "\033[" in capsys.readouterr().out


# -----------------------------------------------------------------------------
# CLI wiring — `encryption status` parses and runs end to end (non-prompting)
# -----------------------------------------------------------------------------
class TestCliWiring:
    def test_status_command_runs_and_returns_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from mordred_hermes.wizard import cli

        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(encryption_cli, "_hermes_home", lambda: home)
        monkeypatch.setattr(
            encryption_cli,
            "_default_workspace_paths",
            lambda: encryption_cli.WorkspacePaths(
                image=tmp_path / "img.sparsebundle",
                blob=tmp_path / "passphrase.wrapped",
                mount=tmp_path / "mnt",
            ),
        )

        rc = cli.main(["encryption", "status", "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert {row["target"] for row in payload} == set(encryption_cli.TARGETS)


# -----------------------------------------------------------------------------
# CLI dispatch — enable / disable / purge route to the right per-target engine
# -----------------------------------------------------------------------------
class TestCliDispatch:
    def _patch_home(self, monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
        monkeypatch.setattr(encryption_cli, "_hermes_home", lambda: home)

    def test_enable_env_dispatches(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli, env_decrypt_cli

        self._patch_home(monkeypatch, tmp_path / "home")
        seen: dict[str, object] = {}

        def _spy(*, home: Path, root: Path, platform: str, **_: object) -> int:
            seen.update(home=home, root=root, platform=platform)
            return 0

        monkeypatch.setattr(env_decrypt_cli, "enable", _spy)
        assert cli.main(["encryption", "enable", "env"]) == 0
        assert seen["home"] == tmp_path / "home"

    def test_disable_config_dispatches(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli, config_decrypt_cli

        self._patch_home(monkeypatch, tmp_path / "home")
        called = {"n": 0}

        def _spy(**_: object) -> int:
            called["n"] += 1
            return 0

        monkeypatch.setattr(config_decrypt_cli, "disable", _spy)
        assert cli.main(["encryption", "disable", "config"]) == 0
        assert called["n"] == 1

    def test_purge_requires_yes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli, memory_cli

        self._patch_home(monkeypatch, tmp_path / "home")
        called = {"n": 0}
        monkeypatch.setattr(memory_cli, "purge", lambda **_: called.__setitem__("n", called["n"] + 1) or 0)

        # without --yes: refuse (non-zero) and never touch the engine
        assert cli.main(["encryption", "purge", "memory"]) != 0
        assert called["n"] == 0

    def test_purge_with_yes_dispatches(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli, memory_cli

        self._patch_home(monkeypatch, tmp_path / "home")
        called = {"n": 0}
        monkeypatch.setattr(memory_cli, "purge", lambda **_: called.__setitem__("n", called["n"] + 1) or 0)

        assert cli.main(["encryption", "purge", "memory", "--yes"]) == 0
        assert called["n"] == 1


# -----------------------------------------------------------------------------
# `all` pseudo-target — best-effort fan-out over every target, workspace gated.
# -----------------------------------------------------------------------------
class TestCliDispatchAll:
    def _patch_home(self, monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
        monkeypatch.setattr(encryption_cli, "_hermes_home", lambda: home)

    def _spy_engines(
        self,
        monkeypatch: pytest.MonkeyPatch,
        verb: str,
        *,
        rc_for: dict[str, int] | None = None,
    ) -> dict[str, int]:
        """Replace every per-target engine ``verb`` with a counting spy.

        Returns a dict mapping target -> call count (a target absent from the
        dict was never invoked). ``rc_for`` overrides the exit code a given
        target's spy returns (default 0). The spies are silent so stdout
        assertions see only the ``all`` summary block.
        """
        from mordred_hermes.wizard import config_decrypt_cli, env_decrypt_cli, memory_cli, workspace_cli

        rc_for = rc_for or {}
        calls: dict[str, int] = {}

        def make(name: str) -> object:
            def _spy(*_a: object, **_k: object) -> int:
                calls[name] = calls.get(name, 0) + 1
                return rc_for.get(name, 0)

            return _spy

        monkeypatch.setattr(env_decrypt_cli, verb, make("env"))
        monkeypatch.setattr(config_decrypt_cli, verb, make("config"))
        monkeypatch.setattr(memory_cli, verb, make("memory"))
        # workspace dispatch goes through the cli_<verb> wrappers, not <verb>.
        monkeypatch.setattr(workspace_cli, f"cli_{verb}", make("workspace"))
        return calls

    def test_enable_all_runs_core_and_workspace_on_macos(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_home(monkeypatch, tmp_path / "home")
        calls = self._spy_engines(monkeypatch, "enable")
        rc = encryption_cli._dispatch_all("enable", platform="darwin", on_path=lambda _n: True)
        assert rc == 0
        assert calls == {"env": 1, "config": 1, "memory": 1, "workspace": 1}

    def test_enable_all_skips_workspace_off_macos(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_home(monkeypatch, tmp_path / "home")
        calls = self._spy_engines(monkeypatch, "enable")
        rc = encryption_cli._dispatch_all("enable", platform="linux", on_path=lambda _n: True)
        assert rc == 0
        assert calls == {"env": 1, "config": 1, "memory": 1}  # workspace skipped, not failed

    def test_enable_all_skips_workspace_when_tooling_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_home(monkeypatch, tmp_path / "home")
        calls = self._spy_engines(monkeypatch, "enable")
        rc = encryption_cli._dispatch_all("enable", platform="darwin", on_path=lambda _n: False)
        assert rc == 0
        assert "workspace" not in calls
        assert calls["env"] == 1

    def test_all_continues_past_failure_and_reports_nonzero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_home(monkeypatch, tmp_path / "home")
        calls = self._spy_engines(monkeypatch, "enable", rc_for={"memory": 1})
        rc = encryption_cli._dispatch_all("enable", platform="linux", on_path=lambda _n: True)
        assert rc == 1  # a target failed
        assert calls == {"env": 1, "config": 1, "memory": 1}  # every core target still attempted

    def test_enable_all_prints_contiguous_summary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_home(monkeypatch, tmp_path / "home")
        self._spy_engines(monkeypatch, "enable")  # silent spies → output is only the summary
        encryption_cli._dispatch_all("enable", platform="linux", on_path=lambda _n: True)
        lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
        # Header + one line per target + a trailing, indented totals line — together.
        assert "encryption enable all:" in lines
        assert any("workspace" in ln and "skipped" in ln for ln in lines)
        assert "  3 ok, 0 failed, 1 skipped" in lines  # indented roll-up (not the old prefixed form)

    def test_enable_all_via_cli_accepts_all_choice(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli

        self._patch_home(monkeypatch, tmp_path / "home")
        calls = self._spy_engines(monkeypatch, "enable")
        monkeypatch.setattr(encryption_cli, "_workspace_eligible", lambda *_a, **_k: (False, "test"))
        assert cli.main(["encryption", "enable", "all"]) == 0
        assert calls == {"env": 1, "config": 1, "memory": 1}

    def test_purge_all_requires_yes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli

        self._patch_home(monkeypatch, tmp_path / "home")
        calls = self._spy_engines(monkeypatch, "purge")
        monkeypatch.setattr(encryption_cli, "_workspace_eligible", lambda *_a, **_k: (False, "test"))
        assert cli.main(["encryption", "purge", "all"]) != 0  # gate refuses
        assert calls == {}  # never reached the engines

    def test_purge_all_with_yes_dispatches(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import cli

        self._patch_home(monkeypatch, tmp_path / "home")
        calls = self._spy_engines(monkeypatch, "purge")
        monkeypatch.setattr(encryption_cli, "_workspace_eligible", lambda *_a, **_k: (False, "test"))
        assert cli.main(["encryption", "purge", "all", "--yes"]) == 0
        assert calls == {"env": 1, "config": 1, "memory": 1}


# -----------------------------------------------------------------------------
# `_workspace_eligible` — the workspace gate for `all` (M1: direct unit coverage)
# -----------------------------------------------------------------------------
class TestWorkspaceEligible:
    def test_non_macos_never_eligible(self) -> None:
        ok, reason = encryption_cli._workspace_eligible("enable", platform="linux", on_path=lambda _n: True)
        assert ok is False
        assert "macOS" in reason

    def test_enable_eligible_with_tooling(self) -> None:
        ok, _ = encryption_cli._workspace_eligible("enable", platform="darwin", on_path=lambda _n: True)
        assert ok is True

    def test_enable_skipped_without_tooling(self) -> None:
        ok, reason = encryption_cli._workspace_eligible("enable", platform="darwin", on_path=lambda _n: False)
        assert ok is False
        assert "tooling" in reason

    def test_purge_eligible_when_volume_set_up(self, tmp_path: Path) -> None:
        image = tmp_path / "claude-private.sparsebundle"
        image.write_text("x")
        blob = tmp_path / "passphrase.wrapped"
        blob.write_text("y")
        ws = encryption_cli.WorkspacePaths(image=image, blob=blob, mount=tmp_path / "mnt")
        # on_path is irrelevant for purge — only on-disk artifacts decide eligibility.
        ok, _ = encryption_cli._workspace_eligible("purge", platform="darwin", on_path=lambda _n: False, workspace=ws)
        assert ok is True

    def test_purge_skipped_when_not_set_up(self, tmp_path: Path) -> None:
        ws = encryption_cli.WorkspacePaths(
            image=tmp_path / "absent.sparsebundle",
            blob=tmp_path / "absent.wrapped",
            mount=tmp_path / "mnt",
        )
        ok, reason = encryption_cli._workspace_eligible(
            "purge", platform="darwin", on_path=lambda _n: True, workspace=ws
        )
        assert ok is False
        assert "not set up" in reason


def test_all_core_targets_derived_from_targets() -> None:
    """L1: ``_ALL_CORE_TARGETS`` is the leading slice of ``TARGETS`` (no drift)."""
    assert encryption_cli.TARGETS[-1] == "workspace"
    assert encryption_cli._ALL_CORE_TARGETS == ("env", "config", "memory")
    assert encryption_cli.TARGETS[:-1] == encryption_cli._ALL_CORE_TARGETS
