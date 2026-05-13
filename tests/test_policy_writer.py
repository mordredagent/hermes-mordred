"""Phase B tests -- ruamel.yaml round-trip preservation + policy.json mirror.

Snapshot strategy: comments / anchors / key-order are checked in inline
inside this file (deliberately weird YAML to stress ruamel round-trip).
After :class:`PolicyWriter` rewrites, the result is asserted via simple
substring checks -- a real diff is easier to debug than a pickle blob.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from mordred_hermes.wizard.policy_writer import (
    MORDRED_PLUGIN_NAMES,
    PolicySnapshot,
    PolicyWriter,
)


def _writer(tmp_path: Path) -> PolicyWriter:
    return PolicyWriter(
        config_path=tmp_path / "config.yaml",
        policy_json_path=tmp_path / "mordred" / "policy.json",
        mordred_dir=tmp_path / "mordred",
    )


class TestEmitPolicyJson:
    def test_writes_snapshot_with_0600_mode(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.emit_policy_json(PolicySnapshot(policy="lenient"))
        path = tmp_path / "mordred" / "policy.json"
        assert path.exists()
        body = json.loads(path.read_text(encoding="utf-8"))
        # Phase 2 fields (local_llm_endpoint / local_llm_model_id /
        # cloud_attempt_action) land here with defaults so llm_guard can
        # read them without needing wizard rerun. See POLICY.md §Phase 2.
        assert body == {
            "policy": "lenient",
            "allow_cloud_llm": False,
            "cloud_provider_allowlist": [],
            "audit_log_path": None,
            "local_llm_endpoint": "http://localhost:1234/v1",
            "local_llm_model_id": "",
            "cloud_attempt_action": "always-block",
        }
        st_mode = stat.S_IMODE(os.stat(path).st_mode)
        assert st_mode == 0o600, f"expected 0o600, got 0o{st_mode:o}"

    def test_field_order_preserved(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        snap = PolicySnapshot(
            policy="strict",
            allow_cloud_llm=True,
            cloud_provider_allowlist=("anthropic", "openai"),
        )
        w.emit_policy_json(snap)
        text = (tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8")
        assert (
            text.index('"policy"')
            < text.index('"allow_cloud_llm"')
            < text.index('"cloud_provider_allowlist"')
            < text.index('"audit_log_path"')
            < text.index('"local_llm_endpoint"')
            < text.index('"local_llm_model_id"')
            < text.index('"cloud_attempt_action"')
        )

    def test_idempotent(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        snap = PolicySnapshot(policy="off")
        w.emit_policy_json(snap)
        path = tmp_path / "mordred" / "policy.json"
        first_mtime = path.stat().st_mtime_ns
        w.emit_policy_json(snap)
        assert path.stat().st_mtime_ns == first_mtime, "no-op write must not touch mtime"


class TestPolicySnapshotPhase2Fields:
    """Phase 2 fields persisted into policy.json (Codex M3, moved from PR2).

    The fields are kw-only with defaults so existing positional callers
    (``PolicySnapshot(policy="strict")``) keep working. They are read by
    ``mordred_llm_guard`` (Phase 2 PR2 enforce + local_adapter) — wizard
    is the sole writer.
    """

    def test_custom_values_round_trip(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        snap = PolicySnapshot(
            policy="strict",
            local_llm_endpoint="http://127.0.0.1:11434/v1",
            local_llm_model_id="llama3.1:70b",
            cloud_attempt_action="prompt-once",
        )
        w.emit_policy_json(snap)
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body["local_llm_endpoint"] == "http://127.0.0.1:11434/v1"
        assert body["local_llm_model_id"] == "llama3.1:70b"
        assert body["cloud_attempt_action"] == "prompt-once"

    def test_snapshot_is_frozen(self) -> None:
        """Defensive copy guarantee — llm_guard reads, never mutates."""
        snap = PolicySnapshot(policy="strict")
        with pytest.raises((AttributeError, TypeError)):
            snap.local_llm_endpoint = "http://evil.example.com"  # type: ignore[misc]

    def test_config_yaml_section_omits_phase2_fields(self) -> None:
        """``plugins.mordred_privacy_check`` config body must NOT carry llm_guard fields.

        privacy_check reads its own section from config.yaml (see
        ``privacy_check/_runtime.py:_load_state``). Polluting that section
        with Phase 2 fields would cross plugin boundaries — they belong in
        ``plugins.mordred_llm_guard`` (added in PR2) instead, or in
        ``policy.json`` (the cross-plugin mirror) here.
        """
        snap = PolicySnapshot(
            policy="strict",
            local_llm_endpoint="http://localhost:1234/v1",
            local_llm_model_id="qwen2.5",
            cloud_attempt_action="always-block",
        )
        section = snap.to_config_yaml_section()
        assert "local_llm_endpoint" not in section
        assert "local_llm_model_id" not in section
        assert "cloud_attempt_action" not in section

    def test_back_compat_positional_construction(self) -> None:
        """Existing call-sites (``PolicySnapshot("strict")``) keep working.

        Phase 1 tests construct snapshots with positional + a small kw-only
        set; the Phase 2 extension must not reorder existing parameters.
        """
        snap = PolicySnapshot(policy="strict")
        # Defaults pinned so a wizard-less consumer can rely on them.
        assert snap.local_llm_endpoint == "http://localhost:1234/v1"
        assert snap.local_llm_model_id == ""
        assert snap.cloud_attempt_action == "always-block"

    def test_cloud_attempt_action_only_accepts_known_values(self) -> None:
        """No validation at the dataclass level — schema is documented but
        not enforced (matches Phase 1 pattern). This test just guards the
        Literal type hint so mypy --strict catches typos at compile time.

        The runtime test below ensures we did not silently widen the type.
        """
        from typing import get_type_hints

        from mordred_hermes.wizard.policy_writer import PolicySnapshot as Snap

        hints = get_type_hints(Snap)
        # ``Literal['always-block', 'prompt-once']`` -> __args__ exposes the values
        action_hint = hints["cloud_attempt_action"]
        args = getattr(action_hint, "__args__", ())
        assert set(args) == {"always-block", "prompt-once"}, args


class TestUpsertMordredSections:
    def test_creates_config_yaml_when_absent(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.upsert_mordred_sections(
            {
                "mordred_privacy_check": {
                    "policy": "lenient",
                    "allow_cloud_llm": False,
                    "cloud_provider_allowlist": [],
                }
            }
        )
        text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "mordred_privacy_check" in text
        assert "policy: lenient" in text
        for name in MORDRED_PLUGIN_NAMES:
            assert name in text

    def test_preserves_user_comments_and_anchors(self, tmp_path: Path) -> None:
        seed = """\
# Hermes user config (do not delete this comment)
profile: default  # inline comment

defaults: &defs
  retries: 3
  timeout: 30  # seconds

plugins:
  enabled:
    - my_other_plugin
    - mordred_privacy_check
  mordred_privacy_check:
    policy: strict
    allow_cloud_llm: false
    cloud_provider_allowlist: []

  my_other_plugin:
    <<: *defs
    custom: value
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.upsert_mordred_sections(
            {
                "mordred_privacy_check": {
                    "policy": "lenient",
                    "allow_cloud_llm": False,
                    "cloud_provider_allowlist": ["anthropic"],
                }
            }
        )

        result = config_path.read_text(encoding="utf-8")
        assert "# Hermes user config (do not delete this comment)" in result
        assert "# seconds" in result
        assert "&defs" in result
        assert "<<: *defs" in result
        assert "my_other_plugin:" in result
        assert "custom: value" in result
        assert "policy: lenient" in result
        assert "anthropic" in result
        for name in MORDRED_PLUGIN_NAMES:
            assert name in result

    def test_refuses_non_mordred_plugin_section(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        with pytest.raises(ValueError, match="refusing to touch 'random_plugin'"):
            w.upsert_mordred_sections({"random_plugin": {"key": "value"}})

    def test_does_not_duplicate_in_plugins_enabled(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        body = {"policy": "lenient", "allow_cloud_llm": False, "cloud_provider_allowlist": []}
        w.upsert_mordred_sections({"mordred_privacy_check": body})
        w.upsert_mordred_sections({"mordred_privacy_check": body})
        text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        for name in MORDRED_PLUGIN_NAMES:
            list_occurrences = sum(1 for line in text.splitlines() if line.strip() == f"- {name}")
            assert list_occurrences == 1, f"{name} listed {list_occurrences} times"

    def test_idempotent_when_state_unchanged(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        body = {"policy": "lenient", "allow_cloud_llm": False, "cloud_provider_allowlist": []}
        w.upsert_mordred_sections({"mordred_privacy_check": body})
        config_path = tmp_path / "config.yaml"
        first_mtime = config_path.stat().st_mtime_ns
        w.upsert_mordred_sections({"mordred_privacy_check": body})
        assert config_path.stat().st_mtime_ns == first_mtime

    def test_existing_plugins_enabled_extended_not_replaced(self, tmp_path: Path) -> None:
        seed = """\
plugins:
  enabled:
    - some_user_plugin
    - mordred_wizard
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.upsert_mordred_sections(
            {"mordred_privacy_check": {"policy": "off", "allow_cloud_llm": False, "cloud_provider_allowlist": []}}
        )
        result = config_path.read_text(encoding="utf-8")
        assert "some_user_plugin" in result, "non-Mordred entries must be preserved"
        for name in MORDRED_PLUGIN_NAMES:
            assert name in result


class TestWriteCompose:
    def test_writes_both_files(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict", allow_cloud_llm=True, cloud_provider_allowlist=("anthropic",)))
        json_path = tmp_path / "mordred" / "policy.json"
        yaml_path = tmp_path / "config.yaml"
        assert json_path.exists()
        assert yaml_path.exists()
        body = json.loads(json_path.read_text(encoding="utf-8"))
        assert body["policy"] == "strict"
        assert body["allow_cloud_llm"] is True
        ytext = yaml_path.read_text(encoding="utf-8")
        assert "policy: strict" in ytext
        assert "anthropic" in ytext

    def test_no_lingering_tmp_files_on_success(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="lenient"))
        leftovers = sorted(p.name for p in tmp_path.rglob("*.tmp"))
        assert leftovers == [], f"unexpected .tmp leftovers: {leftovers}"
