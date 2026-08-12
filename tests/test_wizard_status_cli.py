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
from dataclasses import replace
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _native_key_id, _storage
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

    def test_non_utf8_meta_reports_without_raising(self, tmp_path: Path) -> None:
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_bytes(b"\xffnot-utf8")

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

    def test_pending_reset_journal_is_reported_unavailable(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        with _storage.keyvault_lifecycle_lock(root):
            _storage.write_reset_journal(root, b"pending reset")

        report = _collect(tmp_path)
        assert report.keyvault_initialized is False
        assert report.keyvault_key_count == 0
        assert "reset" in report.keyvault_detail

    def test_pending_native_key_is_unavailable_even_with_committed_rows(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        meta = _storage.load_meta(root)
        meta[_native_key_id.PENDING_NATIVE_KEY_FIELD] = {
            "key_id": "interrupted",
            _native_key_id.NATIVE_KEY_ID_FIELD: _native_key_id.scoped_native_key_id(root, "interrupted"),
        }
        _storage.save_meta(root, meta)

        report = _collect(tmp_path)

        assert report.keyvault_initialized is False
        assert report.keyvault_key_count == 0
        assert "provisioning" in report.keyvault_detail

    def _audit_record(self, root: Path) -> dict[str, str]:
        from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID

        return {
            "key_id": AUDIT_LOG_KEY_ID,
            _native_key_id.NATIVE_KEY_ID_FIELD: _native_key_id.scoped_native_key_id(root, AUDIT_LOG_KEY_ID),
        }

    def test_stranded_pending_audit_key_is_reported_not_silently_plaintext(self, tmp_path: Path) -> None:
        """The worst case must not read as a healthy vault.

        Provisioning refuses to adopt a native audit key of unproven durability,
        so a pending-without-committed profile keeps a plaintext audit log on
        every retry. Reporting only "1 key" hid that permanently.
        """
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        meta = _storage.load_meta(root)
        meta[_native_key_id.PENDING_AUDIT_KEY_FIELD] = self._audit_record(root)
        _storage.save_meta(root, meta)

        report = _collect(tmp_path)

        assert report.keyvault_initialized is True
        assert "INCOMPLETE" in report.keyvault_detail
        assert "plaintext" in report.keyvault_detail
        # Machine consumers need it too, not just the rendered dashboard.
        assert "INCOMPLETE" in json.dumps(report.to_dict())

    def test_committed_audit_key_reports_encrypted(self, tmp_path: Path) -> None:
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        meta = _storage.load_meta(root)
        meta[_native_key_id.AUDIT_KEY_FIELD] = self._audit_record(root)
        _storage.save_meta(root, meta)

        report = _collect(tmp_path)

        assert report.keyvault_initialized is True
        assert "audit log encrypted" in report.keyvault_detail

    def test_absent_audit_key_reports_plaintext(self, tmp_path: Path) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        report = _collect(tmp_path)
        assert "audit log plaintext" in report.keyvault_detail

    def test_hardware_helper_reported(self, tmp_path: Path) -> None:
        report = _collect(tmp_path, helper_finder=lambda platform: "/usr/local/bin/helper")
        assert report.keyvault_helper_installed is True

    def _mral_header_bytes(self) -> bytes:
        """Build a real MRAL header line from the format's own constants.

        Mirrors ``EncryptedWriter._active``'s header shape rather than a
        copy-pasted literal, so this stays honest if the wire format changes.
        """
        from mordred_hermes.keyvault.log_encryption import FORMAT_VERSION, MAGIC

        header = {
            "fmt": MAGIC.decode("ascii"),
            "ver": FORMAT_VERSION,
            "key_id": "audit-log",
            "wdek": "aGVsbG8=",
        }
        return (json.dumps(header, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")

    def _audit_log_path(self, home: Path) -> Path:
        path = home / "mordred" / "audit.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def test_legacy_row_with_encrypted_log_reports_encrypted_legacy_key(self, tmp_path: Path) -> None:
        # A legacy row (no NATIVE_KEY_ID_FIELD) is exactly what
        # ``_build_keyvault`` produces — this is the a9-predating shape
        # ``privacy_check.audit._select_audit_native_key`` resolves to the
        # legacy global audit key for, silently, with no manifest trace.
        _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        self._audit_log_path(tmp_path).write_bytes(self._mral_header_bytes())

        report = _collect(tmp_path)

        assert report.keyvault_initialized is True
        assert "; audit log encrypted (legacy key)" in report.keyvault_detail

    def test_legacy_row_with_plaintext_ndjson_log_reports_plaintext(self, tmp_path: Path) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        entry = json.dumps({"ts": "2026-06-11T00:00:00.000Z", "event": "test"}) + "\n"
        self._audit_log_path(tmp_path).write_text(entry, encoding="utf-8")

        report = _collect(tmp_path)

        assert report.keyvault_initialized is True
        # endswith, not `in`: the scoped-profile verdict also starts with
        # "; audit log plaintext", so only the exact tail pins this branch.
        assert report.keyvault_detail.endswith("; audit log plaintext")

    def test_legacy_row_with_absent_log_reports_plaintext(self, tmp_path: Path) -> None:
        # No audit.log file at all — the common case for a fresh legacy
        # profile that hasn't written any entries yet.
        _build_keyvault(tmp_path, {"default": b"\x01" * 32})

        report = _collect(tmp_path)

        assert report.keyvault_initialized is True
        # endswith, not `in`: the scoped-profile verdict also starts with
        # "; audit log plaintext", so only the exact tail pins this branch.
        assert report.keyvault_detail.endswith("; audit log plaintext")

    def test_legacy_row_with_garbage_log_does_not_raise_and_reports_plaintext(self, tmp_path: Path) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        self._audit_log_path(tmp_path).write_bytes(b"\xff\xfe\x00garbage-not-json-or-utf8\x01\x02")

        report = _collect(tmp_path)

        assert report.keyvault_initialized is True
        # endswith, not `in`: the scoped-profile verdict also starts with
        # "; audit log plaintext", so only the exact tail pins this branch.
        assert report.keyvault_detail.endswith("; audit log plaintext")

    def test_scoped_row_without_audit_fields_still_reports_no_wrapping_key(self, tmp_path: Path) -> None:
        """Regression guard: a scoped (non-legacy) profile must NOT fall into
        the legacy file-probing branch just because it has no audit record."""
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        meta = _storage.load_meta(root)
        key_id = "default"
        h = _key_id_hash(key_id)
        meta["keys"][h] = {
            "key_id": key_id,
            "created_at": "2026-06-11T00:00:00Z",
            _native_key_id.NATIVE_KEY_ID_FIELD: _native_key_id.scoped_native_key_id(root, key_id),
        }
        _storage.atomic_write(root / "digests" / f"{h}.commit", b"\x01" * 32)
        _storage.save_meta(root, meta)
        # Even an MRAL-encrypted log on disk must not flip a scoped profile's
        # verdict — only the legacy branch reads the file at all.
        self._audit_log_path(tmp_path).write_bytes(self._mral_header_bytes())

        report = _collect(tmp_path)

        assert report.keyvault_initialized is True
        assert report.keyvault_detail.endswith("; audit log plaintext (no audit wrapping key)")


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

    def test_status_wiring_no_ansi_when_not_a_tty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # capsys' stdout is not a tty, so the live should_color gate must yield
        # plain text — guards the dashboard colour wiring.
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        rc = status_cli.status(
            home=tmp_path,
            root=_storage.resolve_keyvault_dir(tmp_path),
            platform="darwin",
            workspace=_workspace(tmp_path),
            on_path=lambda name: False,
            helper_finder=lambda platform: None,
        )
        assert rc == 0
        assert "\033" not in capsys.readouterr().out

    def test_status_wiring_colours_when_forced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # FORCE_COLOR drives colour through the same wiring even off a tty.
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        rc = status_cli.status(
            home=tmp_path,
            root=_storage.resolve_keyvault_dir(tmp_path),
            platform="darwin",
            workspace=_workspace(tmp_path),
            on_path=lambda name: False,
            helper_finder=lambda platform: None,
        )
        assert rc == 0
        assert "\033[" in capsys.readouterr().out

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

    def _sample_report(self) -> status_cli.StatusReport:
        return status_cli.StatusReport(
            policy_mode="strict",
            network_configured_path="tor",
            network_live=True,
            network_active_path="tor",
            network_ready=True,
            keyvault_initialized=True,
            keyvault_key_count=2,
            keyvault_helper_installed=True,
            keyvault_detail="2 keys",
            encryption=[
                TargetStatus("env", configured=True, active=True, detail="active"),
                TargetStatus("config", configured=True, active=False, detail="disabled"),
            ],
        )

    def test_render_text_default_has_no_ansi(self) -> None:
        assert "\033" not in status_cli.render_text(self._sample_report())

    @pytest.mark.parametrize(
        ("mode", "detail"),
        [
            ("strict", "blocks on policy violations"),
            ("lenient", "warns and audits; continues"),
            ("off", "guards disabled"),
        ],
    )
    def test_policy_mode_has_short_explanation(self, mode: str, detail: str) -> None:
        report = replace(self._sample_report(), policy_mode=mode)
        assert f"policy mode : {mode} ({detail})" in status_cli.render_text(report)

    def test_render_text_color_emits_ansi(self) -> None:
        text = status_cli.render_text(self._sample_report(), color=True)
        assert "\033[" in text  # styled
        assert "\033[1m" in text  # the dashboard heading is bold

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
