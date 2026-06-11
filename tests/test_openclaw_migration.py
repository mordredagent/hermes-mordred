"""Phase E tests -- Story 1.5 OpenClaw migration (H5 conflict resolution).

H5 row policy table (PATHS.md §OpenClaw migration L286):

| OpenClaw path | New path | Conflict policy |
|---|---|---|
| audit.log | append-by-timestamp-window; marker last | --audit-merge=skip|append-all|abort |
| keyvault/ | never overwrite | abort if dest exists |
| credentials/ | never overwrite | abort if dest exists |
| openclaw.json plugins | upsert via PolicyWriter | --policy-conflict=keep-existing|overwrite|abort |

Idempotency marker: `~/.hermes/mordred/.audit-migrated-from-openclaw`
holds an ISO-8601 UTC timestamp; presence skips audit migration on
re-runs (use --reset to force).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.wizard import openclaw_migration, upgrade
from mordred_hermes.wizard.policy_writer import PolicyWriter


def _writer(tmp_path: Path) -> PolicyWriter:
    return PolicyWriter(
        config_path=tmp_path / "hermes" / "config.yaml",
        policy_json_path=tmp_path / "hermes" / "mordred" / "policy.json",
        mordred_dir=tmp_path / "hermes" / "mordred",
    )


def _seed_openclaw(
    base: Path,
    *,
    audit_lines: list[str] | None = None,
    policy: dict[str, Any] | None = None,
    keyvault: bool = False,
    credentials: bool = False,
    openclaw_json: dict[str, Any] | None = None,
) -> None:
    """Create a synthetic ~/.openclaw/mordred/ tree under ``base``.

    ``base`` is the OpenClaw root (e.g. ``tmp_path / "openclaw" / "mordred"``).
    The sibling ``openclaw.json`` lives at ``base.parent / "openclaw.json"``.
    """
    base.mkdir(parents=True, exist_ok=True)
    if audit_lines:
        (base / "audit.log").write_text("\n".join(audit_lines) + "\n", encoding="utf-8")
    if policy is not None:
        (base / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
    if keyvault:
        (base / "keyvault").mkdir(exist_ok=True)
        (base / "keyvault" / "key1.bin").write_bytes(b"opaque-keyvault-bytes")
    if credentials:
        (base / "credentials").mkdir(exist_ok=True)
        (base / "credentials" / "network.json").write_bytes(b'{"x": 1}')
    if openclaw_json is not None:
        (base.parent / "openclaw.json").write_text(json.dumps(openclaw_json), encoding="utf-8")


# -----------------------------------------------------------------------------
# detect() -- presence flags only, no migration
# -----------------------------------------------------------------------------


class TestDetect:
    def test_all_absent(self, tmp_path: Path) -> None:
        state = openclaw_migration.detect(tmp_path / "openclaw" / "mordred")
        assert state.has_audit is False
        assert state.has_policy_json is False
        assert state.has_keyvault is False
        assert state.has_credentials is False
        assert state.has_openclaw_json is False

    def test_all_present(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-01T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
            policy={"policy": "strict"},
            keyvault=True,
            credentials=True,
            openclaw_json={"plugins": {"entries": {}}},
        )
        state = openclaw_migration.detect(base)
        assert state.has_audit is True
        assert state.has_policy_json is True
        assert state.has_keyvault is True
        assert state.has_credentials is True
        assert state.has_openclaw_json is True


# -----------------------------------------------------------------------------
# migrate() -- top-level dispatch returns Story1_5Action
# -----------------------------------------------------------------------------


class TestMigrateNoOp:
    def test_returns_noop_when_base_missing(self, tmp_path: Path) -> None:
        result = openclaw_migration.migrate(
            openclaw_base=tmp_path / "no-such-base",
            policy_writer=_writer(tmp_path),
            options=upgrade.UpgradeOptions(),
        )
        assert result == "noop"


# -----------------------------------------------------------------------------
# Audit log migration (H5: append-by-timestamp-window + marker file)
# -----------------------------------------------------------------------------


class TestAuditMigration:
    def test_safe_append_when_no_existing_audit(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=[
                '{"ts":"2026-05-01T00:00:00.000Z","event":"pre_install","decision":"allow","skill_id":"a"}',
                '{"ts":"2026-05-02T00:00:00.000Z","event":"pre_install","decision":"allow","skill_id":"b"}',
            ],
        )
        w = _writer(tmp_path)
        result = openclaw_migration.migrate(
            openclaw_base=base,
            policy_writer=w,
            options=upgrade.UpgradeOptions(),
        )
        assert result == "migrated"
        # Hermes audit.log exists with both lines
        hermes_audit = tmp_path / "hermes" / "mordred" / "audit.log"
        assert hermes_audit.exists()
        lines = [line for line in hermes_audit.read_text(encoding="utf-8").splitlines() if line]
        assert len(lines) == 2
        assert "skill_id" in lines[0]

    def test_marker_written_after_successful_migration(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-01T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(
            openclaw_base=base,
            policy_writer=w,
            options=upgrade.UpgradeOptions(),
        )
        marker = tmp_path / "hermes" / "mordred" / ".audit-migrated-from-openclaw"
        assert marker.exists()
        content = marker.read_text(encoding="utf-8").strip()
        assert content.endswith("Z")
        assert "T" in content

    def test_marker_skips_re_migration(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-01T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        hermes_audit = tmp_path / "hermes" / "mordred" / "audit.log"
        lines_after_first = hermes_audit.read_text(encoding="utf-8")

        result = openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        assert result == "skipped-marker"
        assert hermes_audit.read_text(encoding="utf-8") == lines_after_first

    def test_reset_overrides_marker(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-01T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        result = openclaw_migration.migrate(
            openclaw_base=base,
            policy_writer=w,
            options=upgrade.UpgradeOptions(reset=True, audit_merge="append-all"),
        )
        assert result == "migrated"
        hermes_audit = tmp_path / "hermes" / "mordred" / "audit.log"
        lines = [line for line in hermes_audit.read_text(encoding="utf-8").splitlines() if line]
        assert len(lines) == 2

    def test_overlap_aborts_without_audit_merge_flag(self, tmp_path: Path) -> None:
        """Existing Hermes audit overlaps OpenClaw audit -> needs explicit policy."""
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-05T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
        )
        hermes_audit = tmp_path / "hermes" / "mordred" / "audit.log"
        hermes_audit.parent.mkdir(parents=True, exist_ok=True)
        hermes_audit.write_text(
            '{"ts":"2026-05-04T00:00:00.000Z","event":"pre_install","decision":"allow"}\n',
            encoding="utf-8",
        )
        w = _writer(tmp_path)
        with pytest.raises(SystemExit, match=r"audit-merge"):
            openclaw_migration.migrate(
                openclaw_base=base,
                policy_writer=w,
                options=upgrade.UpgradeOptions(),
            )

    def test_overlap_skip_does_not_append(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            audit_lines=['{"ts":"2026-05-05T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
        )
        hermes_audit = tmp_path / "hermes" / "mordred" / "audit.log"
        hermes_audit.parent.mkdir(parents=True, exist_ok=True)
        original = '{"ts":"2026-05-04T00:00:00.000Z","event":"pre_install","decision":"allow"}\n'
        hermes_audit.write_text(original, encoding="utf-8")
        w = _writer(tmp_path)
        openclaw_migration.migrate(
            openclaw_base=base,
            policy_writer=w,
            options=upgrade.UpgradeOptions(audit_merge="skip"),
        )
        assert hermes_audit.read_text(encoding="utf-8") == original


# -----------------------------------------------------------------------------
# Keyvault / credentials -- never overwrite
# -----------------------------------------------------------------------------


class TestKeyvaultCredentialsNeverOverwrite:
    def test_keyvault_copied_when_dest_absent(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(base, keyvault=True)
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        dest_keyvault = tmp_path / "hermes" / "mordred" / "keyvault"
        assert dest_keyvault.is_dir()
        assert (dest_keyvault / "key1.bin").read_bytes() == b"opaque-keyvault-bytes"

    def test_keyvault_collision_aborts(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(base, keyvault=True)
        hermes_kv = tmp_path / "hermes" / "mordred" / "keyvault"
        hermes_kv.mkdir(parents=True)
        (hermes_kv / "existing.bin").write_bytes(b"do-not-touch")
        w = _writer(tmp_path)
        with pytest.raises(SystemExit, match=r"keyvault"):
            openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        assert (hermes_kv / "existing.bin").read_bytes() == b"do-not-touch"

    def test_credentials_collision_aborts(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(base, credentials=True)
        hermes_creds = tmp_path / "hermes" / "mordred" / "credentials"
        hermes_creds.mkdir(parents=True)
        (hermes_creds / "x.json").write_bytes(b"{}")
        w = _writer(tmp_path)
        with pytest.raises(SystemExit, match=r"credentials"):
            openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())

    def test_keyvault_idempotent_when_already_migrated(self, tmp_path: Path) -> None:
        """Codex P1-B: second `upgrade` after a successful first run must not abort.

        First run copies keyvault. Second run sees dest exists with identical
        content -- treat as already migrated and skip (NOT abort).
        """
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(base, keyvault=True)
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        # Second run -- must not crash even though dest now exists
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        # Existing dest content unchanged
        dest_keyvault = tmp_path / "hermes" / "mordred" / "keyvault"
        assert (dest_keyvault / "key1.bin").read_bytes() == b"opaque-keyvault-bytes"

    def test_keyvault_content_collision_still_aborts(self, tmp_path: Path) -> None:
        """Idempotency must NOT swallow real data conflicts -- different content
        at dest still aborts (data-loss protection per PATHS.md H5)."""
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(base, keyvault=True)
        # Pre-existing Hermes keyvault with DIFFERENT content
        hermes_kv = tmp_path / "hermes" / "mordred" / "keyvault"
        hermes_kv.mkdir(parents=True)
        (hermes_kv / "key1.bin").write_bytes(b"different-content")
        w = _writer(tmp_path)
        with pytest.raises(SystemExit, match=r"keyvault"):
            openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        # Existing data must remain untouched
        assert (hermes_kv / "key1.bin").read_bytes() == b"different-content"

    def test_partial_failure_retry_after_audit_overlap(self, tmp_path: Path) -> None:
        """Codex P1-B (sub-case): keyvault copies, then audit step aborts on
        overlap -- a retry with --audit-merge=skip must succeed, not crash on
        the now-existing keyvault dest."""
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            keyvault=True,
            audit_lines=['{"ts":"2026-05-05T00:00:00.000Z","event":"pre_install","decision":"allow"}'],
        )
        # Pre-seed Hermes audit with overlapping ts (forces overlap abort)
        hermes_audit = tmp_path / "hermes" / "mordred" / "audit.log"
        hermes_audit.parent.mkdir(parents=True, exist_ok=True)
        hermes_audit.write_text(
            '{"ts":"2026-05-04T00:00:00.000Z","event":"pre_install","decision":"allow"}\n',
            encoding="utf-8",
        )
        w = _writer(tmp_path)

        # First run: keyvault copies, audit aborts (overlap, no merge flag)
        with pytest.raises(SystemExit, match=r"audit-merge"):
            openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())

        # Retry with --audit-merge=skip: must NOT crash on already-copied keyvault
        result = openclaw_migration.migrate(
            openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions(audit_merge="skip")
        )
        assert result == "migrated"


# -----------------------------------------------------------------------------
# Codex P1-A + P2 -- conflict resolver applies to OpenClaw snapshot too;
# policy.json mirror must be emitted when policy is migrated.
# -----------------------------------------------------------------------------


class TestCodexFindings:
    def test_openclaw_policy_respects_policy_conflict_keep_existing(self, tmp_path: Path) -> None:
        """Codex P1-A: --policy-conflict=keep-existing must protect the
        existing Hermes section even from OpenClaw migration overwrites."""
        # Pre-seed Hermes config with strict
        config = tmp_path / "hermes" / "config.yaml"
        config.parent.mkdir(parents=True)
        config.write_text(
            "plugins:\n  mordred_privacy_check:\n    policy: strict\n"
            "    allow_cloud_llm: false\n    cloud_provider_allowlist: []\n",
            encoding="utf-8",
        )
        # OpenClaw wants to migrate "off"
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            openclaw_json={
                "plugins": {
                    "entries": {
                        "mordred-privacy-check": {
                            "id": "mordred-privacy-check",
                            "config": {"policy": "off", "allow_cloud_llm": False, "cloud_provider_allowlist": []},
                        }
                    }
                }
            },
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(
            openclaw_base=base,
            policy_writer=w,
            options=upgrade.UpgradeOptions(policy_conflict="keep-existing"),
        )
        # Existing strict policy preserved
        assert "policy: strict" in config.read_text(encoding="utf-8")

    def test_openclaw_policy_respects_policy_conflict_abort(self, tmp_path: Path) -> None:
        """Codex P1-A: --policy-conflict=abort must SystemExit on OpenClaw policy mismatch."""
        config = tmp_path / "hermes" / "config.yaml"
        config.parent.mkdir(parents=True)
        config.write_text(
            "plugins:\n  mordred_privacy_check:\n    policy: strict\n"
            "    allow_cloud_llm: false\n    cloud_provider_allowlist: []\n",
            encoding="utf-8",
        )
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            openclaw_json={
                "plugins": {
                    "entries": {
                        "mordred-privacy-check": {
                            "id": "mordred-privacy-check",
                            "config": {"policy": "off"},
                        }
                    }
                }
            },
        )
        w = _writer(tmp_path)
        with pytest.raises(SystemExit, match=r"policy-conflict"):
            openclaw_migration.migrate(
                openclaw_base=base,
                policy_writer=w,
                options=upgrade.UpgradeOptions(policy_conflict="abort"),
            )

    def test_openclaw_policy_emits_policy_json_mirror(self, tmp_path: Path) -> None:
        """Codex P2: policy.json mirror must be written when OpenClaw policy migrates."""
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            openclaw_json={
                "plugins": {
                    "entries": {
                        "mordred-privacy-check": {
                            "id": "mordred-privacy-check",
                            "config": {
                                "policy": "strict",
                                "allow_cloud_llm": True,
                                "cloud_provider_allowlist": ["anthropic"],
                            },
                        }
                    }
                }
            },
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        policy_json = tmp_path / "hermes" / "mordred" / "policy.json"
        assert policy_json.exists(), "policy.json mirror must be emitted by OpenClaw migration"
        import json as _json

        body = _json.loads(policy_json.read_text(encoding="utf-8"))
        assert body["policy"] == "strict"
        assert body["allow_cloud_llm"] is True
        assert body["cloud_provider_allowlist"] == ["anthropic"]


# -----------------------------------------------------------------------------
# openclaw.json policy block -- transform + upsert via PolicyWriter
# -----------------------------------------------------------------------------


class TestPolicyTransform:
    def test_transforms_openclaw_policy_into_config_yaml(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            openclaw_json={
                "plugins": {
                    "entries": {
                        "mordred-privacy-check": {
                            "id": "mordred-privacy-check",
                            "config": {
                                "policy": "strict",
                                "allow_cloud_llm": True,
                                "cloud_provider_allowlist": ["anthropic"],
                            },
                        }
                    }
                }
            },
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        ytext = (tmp_path / "hermes" / "config.yaml").read_text(encoding="utf-8")
        assert "policy: strict" in ytext
        assert "anthropic" in ytext
        assert "allow_cloud_llm: true" in ytext.lower()

    def test_string_false_allow_cloud_llm_migrates_to_false(self, tmp_path: Path) -> None:
        """M2 (security review 2026-06-11): a foreign OpenClaw config holding
        ``"allow_cloud_llm": "false"`` (string) must not truthy-coerce to an
        enabled cloud-LLM grant in the migrated config.yaml."""
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(
            base,
            openclaw_json={
                "plugins": {
                    "entries": {
                        "mordred-privacy-check": {
                            "id": "mordred-privacy-check",
                            "config": {
                                "policy": "strict",
                                "allow_cloud_llm": "false",
                            },
                        }
                    }
                }
            },
        )
        w = _writer(tmp_path)
        openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        ytext = (tmp_path / "hermes" / "config.yaml").read_text(encoding="utf-8")
        assert "allow_cloud_llm: false" in ytext.lower()

    def test_missing_openclaw_policy_section_is_handled(self, tmp_path: Path) -> None:
        base = tmp_path / "openclaw" / "mordred"
        _seed_openclaw(base, openclaw_json={"plugins": {"entries": {}}})
        w = _writer(tmp_path)
        result = openclaw_migration.migrate(openclaw_base=base, policy_writer=w, options=upgrade.UpgradeOptions())
        assert result == "migrated"
