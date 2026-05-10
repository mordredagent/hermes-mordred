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
        assert body == {
            "policy": "lenient",
            "allow_cloud_llm": False,
            "cloud_provider_allowlist": [],
            "audit_log_path": None,
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
        )

    def test_idempotent(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        snap = PolicySnapshot(policy="off")
        w.emit_policy_json(snap)
        path = tmp_path / "mordred" / "policy.json"
        first_mtime = path.stat().st_mtime_ns
        w.emit_policy_json(snap)
        assert path.stat().st_mtime_ns == first_mtime, "no-op write must not touch mtime"


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
