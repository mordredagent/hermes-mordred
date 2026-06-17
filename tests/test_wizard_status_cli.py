"""Tests for ``hermes-mordred status`` — the at-a-glance dashboard.

UX review 2026-06-11: Mordred state was scattered over five read commands
(``network status`` / ``encryption status`` / ``vault status`` /
``keyvault list`` / ``policy show``) with no way to see "how am I
protected right now?" in one screen. ``status`` aggregates policy mode,
network path, keyvault, and the four encryption targets.

Like ``encryption status`` (whose side-effect-free design this reuses),
``status`` must never prompt, never open the vault cold path, and never
touch the Secure Enclave — it reads on-disk artifacts only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _storage
from mordred_hermes.wizard import status_cli
from mordred_hermes.wizard.encryption_cli import WORKSPACE_LEGEND_BODY, TargetStatus, WorkspacePaths


def _key_id_hash(key_id: str) -> str:
    return hashlib.sha256(key_id.encode("utf-8")).hexdigest()[:16]


def _build_keyvault(home: Path, keys: dict[str, bytes]) -> Path:
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    meta = _storage.load_meta(root)
    for key_id, digest in keys.items():
        h = _key_id_hash(key_id)
        meta["keys"][h] = {"key_id": key_id, "created_at": "2026-06-11T00:00:00Z"}
        _storage.atomic_write(root / "digests" / f"{h}.commit", digest)
    _storage.save_meta(root, meta)
    return root


def _workspace(tmp_path: Path) -> WorkspacePaths:
    return WorkspacePaths(
        image=tmp_path / "ws" / "img.sparsebundle",
        blob=tmp_path / "ws" / "passphrase.wrapped",
        mount=tmp_path / "ws-mnt",
    )


def _collect(tmp_path: Path, **overrides: object) -> status_cli.StatusReport:
    kwargs: dict[str, object] = {
        "home": tmp_path,
        "root": _storage.resolve_keyvault_dir(tmp_path),
        "platform": "darwin",
        "workspace": _workspace(tmp_path),
        "on_path": lambda name: False,
        "helper_finder": lambda platform: None,
    }
    kwargs.update(overrides)
    return status_cli.collect(**kwargs)  # type: ignore[arg-type]


class TestPolicySection:
    def test_defaults_to_lenient_without_config(self, tmp_path: Path) -> None:
        report = _collect(tmp_path)
        assert report.policy_mode == "lenient"

    def test_reads_mode_from_config_yaml(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text(
            "plugins:\n  mordred_privacy_check:\n    policy: strict\n",
            encoding="utf-8",
        )
        report = _collect(tmp_path)
        assert report.policy_mode == "strict"


class TestNetworkSection:
    def test_defaults_to_clearnet_without_config(self, tmp_path: Path) -> None:
        report = _collect(tmp_path)
        assert report.network_configured_path == "clearnet"
        assert report.network_live is False

    def test_reads_configured_path(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text(
            "plugins:\n  mordred_network:\n    default_path: tor\n",
            encoding="utf-8",
        )
        report = _collect(tmp_path)
        assert report.network_configured_path == "tor"


class TestKeyvaultSection:
    def test_uninitialised_keyvault(self, tmp_path: Path) -> None:
        report = _collect(tmp_path)
        assert report.keyvault_initialized is False
        assert report.keyvault_key_count == 0

    def test_initialised_keyvault_counts_keys(self, tmp_path: Path) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32, "payments": b"\x02" * 32})
        report = _collect(tmp_path)
        assert report.keyvault_initialized is True
        assert report.keyvault_key_count == 2

    def test_corrupt_meta_reports_without_raising(self, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        root.mkdir(parents=True)
        meta = root / "meta.json"
        meta.write_text("{not json", encoding="utf-8")
        meta.chmod(0o600)  # pass the permission gate so the corrupt-body path is hit
        report = _collect(tmp_path)
        assert report.keyvault_initialized is False
        assert "corrupt" in report.keyvault_detail

    def test_unreadable_meta_reports_without_raising(self, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        root.mkdir(parents=True)
        meta = root / "meta.json"
        meta.write_text("{}", encoding="utf-8")
        meta.chmod(0o644)  # KeyvaultPermissionError: keyvault files must be 0o600
        report = _collect(tmp_path)
        assert report.keyvault_initialized is False
        assert "unreadable" in report.keyvault_detail

    def test_hardware_helper_reported(self, tmp_path: Path) -> None:
        report = _collect(tmp_path, helper_finder=lambda platform: "/usr/local/bin/helper")
        assert report.keyvault_helper_installed is True


class TestRendering:
    def test_text_includes_all_sections(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = status_cli.status(
            home=tmp_path,
            root=_storage.resolve_keyvault_dir(tmp_path),
            platform="darwin",
            workspace=_workspace(tmp_path),
            on_path=lambda name: False,
            helper_finder=lambda platform: None,
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "policy" in out
        assert "network" in out
        assert "keyvault" in out
        for target in ("env", "config", "memory", "workspace"):
            assert target in out

    def test_sealed_workspace_renders_sealed_with_explanation(self) -> None:
        # A sealed workspace must read `[sealed]` (not the others' `on`) and the
        # dashboard must print the workspace explanation line below the targets.
        report = status_cli.StatusReport(
            policy_mode="lenient",
            network_configured_path="clearnet",
            network_live=False,
            network_active_path=None,
            network_ready=None,
            keyvault_initialized=False,
            keyvault_key_count=0,
            keyvault_helper_installed=False,
            keyvault_detail="not initialised",
            encryption=[
                TargetStatus("env", configured=True, active=False, detail="disabled"),
                TargetStatus("workspace", configured=True, active=True, detail="sealed at rest", mounted=False),
            ],
        )
        text = status_cli.render_text(report)
        assert "[sealed]" in text
        assert WORKSPACE_LEGEND_BODY in text

    def test_json_is_machine_readable(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = status_cli.status(
            home=tmp_path,
            root=_storage.resolve_keyvault_dir(tmp_path),
            platform="darwin",
            workspace=_workspace(tmp_path),
            as_json=True,
            on_path=lambda name: False,
            helper_finder=lambda platform: None,
        )
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        assert body["policy"]["mode"] == "lenient"
        assert body["network"]["configured_path"] == "clearnet"
        assert body["keyvault"]["initialized"] is False
        assert len(body["encryption"]) == 4


class TestCliWiring:
    def test_status_command_is_wired(self) -> None:
        from mordred_hermes.wizard import cli

        parser = argparse.ArgumentParser(prog="hermes-mordred")
        cli._setup_subparser(parser)
        ns = parser.parse_args(["status", "--json"])
        assert ns.json is True
        assert callable(ns.func)


class TestNeverRaiseContract:
    """Code-review fix (2026-06-12): status must not raise even when the
    helper finder blows up (e.g. Path.home() RuntimeError in a container
    with no passwd entry for the uid)."""

    def test_raising_helper_finder_degrades_to_not_installed(self, tmp_path: Path) -> None:
        def _boom(platform: str) -> str | None:
            raise RuntimeError("no home directory")

        report = _collect(tmp_path, helper_finder=_boom)
        assert report.keyvault_helper_installed is False
