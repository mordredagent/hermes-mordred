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


class TestConfigStatus:
    def test_marker_absent(self, tmp_path: Path) -> None:
        st = encryption_cli.config_status(home=tmp_path, platform="darwin")
        assert st.target == "config"
        assert st.configured is False

    def test_marker_present_active_on_macos(self, tmp_path: Path) -> None:
        marker = _marker_path(tmp_path)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("vault-managed\n", encoding="utf-8")
        st = encryption_cli.config_status(home=tmp_path, platform="darwin")
        assert st.configured is True
        assert st.active is True

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
