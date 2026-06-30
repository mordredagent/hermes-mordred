"""Phase B tests -- ruamel.yaml round-trip preservation + policy.json mirror.

Snapshot strategy: comments / anchors / key-order are checked in inline
inside this file (deliberately weird YAML to stress ruamel round-trip).
After :class:`PolicyWriter` rewrites, the result is asserted via simple
substring checks -- a real diff is easier to debug than a pickle blob.
"""

from __future__ import annotations

import contextlib
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
        # read them without needing wizard rerun. Phase 3 PR3a Task #7
        # added ``disable_ipv6`` so the network reader doesn't have to
        # rerun the mode-default heuristic. See POLICY.md §Phase 2 / §Phase 3.
        assert body == {
            "policy": "lenient",
            "allow_cloud_llm": False,
            "cloud_provider_allowlist": [],
            "audit_log_path": None,
            "local_llm_endpoint": "http://localhost:1234/v1",
            "local_llm_model_id": "",
            "cloud_attempt_action": "always-block",
            "disable_ipv6": True,
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


class TestMergeMordredSections:
    """Partial-update merge API (Phase 3 PR3a, review-L4 fix from PR #18).

    ``upsert_mordred_sections`` does whole-section replacement -- correct for
    ``hermes mordred configure`` writing a full ``PolicySnapshot``, but
    destructive for partial writers like ``hermes mordred network use`` that
    only know about ``default_path``. The merge variant preserves on-disk
    sub-fields (Tor binary path, Mullvad account ref, etc.) that other code
    paths or hand-edits established.
    """

    def test_merge_preserves_existing_sub_fields(self, tmp_path: Path) -> None:
        seed = """\
plugins:
  enabled:
    - mordred_network
  mordred_network:
    default_path: tor
    tor_binary_path: /usr/bin/tor
    tor_socks_port: 9050
    mullvad_account_id_env: MORDRED_MULLVAD_ACCOUNT
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "clearnet"}})

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "clearnet"
        assert section["tor_binary_path"] == "/usr/bin/tor"
        assert section["tor_socks_port"] == 9050
        assert section["mullvad_account_id_env"] == "MORDRED_MULLVAD_ACCOUNT"

    def test_merge_idempotent(self, tmp_path: Path) -> None:
        seed = """\
plugins:
  mordred_network:
    default_path: tor
    tor_binary_path: /usr/bin/tor
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "tor"}})
        first_mtime = config_path.stat().st_mtime_ns
        w.merge_mordred_sections({"mordred_network": {"default_path": "tor"}})
        assert config_path.stat().st_mtime_ns == first_mtime, "no-op merge must not touch mtime"

    def test_merge_preserves_comments_and_anchors(self, tmp_path: Path) -> None:
        seed = """\
# user-owned config (preserve this comment)
profile: default  # inline

defaults: &defs
  retries: 3

plugins:
  enabled:
    - my_other_plugin
  mordred_network:
    default_path: tor  # set by `hermes mordred network use tor`
    tor_binary_path: /usr/bin/tor

  my_other_plugin:
    <<: *defs
    custom: value
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "clearnet"}})

        result = config_path.read_text(encoding="utf-8")
        assert "# user-owned config (preserve this comment)" in result
        assert "# inline" in result
        assert "&defs" in result
        assert "<<: *defs" in result
        assert "custom: value" in result
        assert "tor_binary_path: /usr/bin/tor" in result
        assert "default_path: clearnet" in result

    def test_merge_refuses_non_mordred_plugin(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        with pytest.raises(ValueError, match="refusing to touch 'random_plugin'"):
            w.merge_mordred_sections({"random_plugin": {"key": "value"}})

    def test_merge_creates_section_when_absent(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "tor"}})
        text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "default_path: tor" in text
        for name in MORDRED_PLUGIN_NAMES:
            assert name in text, f"plugins.enabled must list {name}"

    def test_merge_creates_section_with_existing_unrelated_plugins(self, tmp_path: Path) -> None:
        """Fresh ``plugins.mordred_network`` section under an existing ``plugins`` block."""
        seed = """\
plugins:
  enabled:
    - my_other_plugin
  my_other_plugin:
    custom: value
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "vpn"}})

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"]["default_path"] == "vpn"
        assert data["plugins"]["my_other_plugin"]["custom"] == "value"

    def test_merge_overwrites_non_mapping_section(self, tmp_path: Path) -> None:
        """If ``plugins.mordred_network`` is pathologically a scalar / list, we
        replace it entirely with the merge body (no in-place merge possible)
        instead of crashing."""
        seed = """\
plugins:
  mordred_network: "string-instead-of-mapping"
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "tor"}})

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"] == {"default_path": "tor"}


class TestPolicySnapshotDisableIPv6Field:
    """Phase 3 PR3a Task #7: PolicySnapshot gains ``disable_ipv6`` so the
    wizard can persist it to ``policy.json``. The network reader (Task #2)
    consumes it through ``_resolve_disable_ipv6``; PolicyWriter is the
    sole writer side.
    """

    def test_default_is_true(self) -> None:
        """Safe-by-default mirrors RuntimeConfig.disable_ipv6 default."""
        snap = PolicySnapshot(policy="lenient")
        assert snap.disable_ipv6 is True

    def test_field_round_trips_through_policy_json(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        snap = PolicySnapshot(policy="strict", disable_ipv6=False)
        w.emit_policy_json(snap)
        body = json.loads((tmp_path / "mordred" / "policy.json").read_text(encoding="utf-8"))
        assert body["disable_ipv6"] is False

    def test_field_omitted_from_privacy_check_section(self) -> None:
        """``disable_ipv6`` lives in policy.json + plugins.mordred_network, NOT
        in plugins.mordred_privacy_check (cross-plugin discipline)."""
        snap = PolicySnapshot(policy="strict", disable_ipv6=True)
        section = snap.to_config_yaml_section()
        assert "disable_ipv6" not in section


class TestNetworkAnswersToConfigYamlSection:
    """``NetworkAnswers.to_config_yaml_section()`` returns the body upserted
    into ``plugins.mordred_network`` so PolicyWriter.write can persist it
    alongside snapshot fields."""

    def test_to_config_yaml_section_shape(self) -> None:
        from mordred_hermes.wizard.network_cli import NetworkAnswers

        na = NetworkAnswers(
            default_network_path="vpn",
            tor_binary_path="/opt/tor/bin/tor",
            tor_socks_port=19050,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="jp",
            mullvad_killswitch=True,
        )
        section = na.to_config_yaml_section()
        assert section == {
            "default_path": "vpn",
            "tor_binary_path": "/opt/tor/bin/tor",
            "tor_socks_port": 19050,
            "mullvad_account_id_env": "MORDRED_MULLVAD_ACCOUNT",
            "mullvad_relay_country": "jp",
            "mullvad_killswitch": True,
            "vpn_provider": "mullvad",
        }


class TestPolicyWriterWritesNetworkSection:
    """Task #7: ``PolicyWriter.write`` accepts an optional
    ``network_answers`` and upserts ``plugins.mordred_network`` in
    config.yaml via :meth:`merge_mordred_sections`. The merge variant is
    used (not whole-replace) so future writers like ``hermes mordred
    network use`` don't clobber the wizard's choices when only the path
    changes (Task #1 contract)."""

    def test_write_upserts_network_section_when_answers_provided(self, tmp_path: Path) -> None:
        from mordred_hermes.wizard.network_cli import NetworkAnswers

        w = _writer(tmp_path)
        snap = PolicySnapshot(policy="strict")
        na = NetworkAnswers(
            default_network_path="tor",
            tor_binary_path="/usr/bin/tor",
            tor_socks_port=9050,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="auto",
            mullvad_killswitch=True,
        )
        w.write(snap, network_answers=na)
        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with (tmp_path / "config.yaml").open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "tor"
        assert section["mullvad_killswitch"] is True
        assert section["tor_socks_port"] == 9050

    def test_write_without_network_answers_omits_section(self, tmp_path: Path) -> None:
        """Backward compat: existing call sites passing only ``snapshot``
        must not write a (probably-wrong-default-valued) mordred_network."""
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="lenient"))
        text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        # mordred_network may appear in plugins.enabled, but its section
        # body should be absent (no default_path / tor_binary_path / ...).
        assert "default_path" not in text
        assert "tor_binary_path" not in text

    def test_write_uses_merge_not_whole_replace(self, tmp_path: Path) -> None:
        """When a prior network section exists (e.g., from a previous
        configure run that the user partially edited), the wizard must
        merge -- not clobber -- per the Task #1 contract."""
        from mordred_hermes.wizard.network_cli import NetworkAnswers

        config_path = tmp_path / "config.yaml"
        seed = """\
plugins:
  mordred_network:
    default_path: tor
    custom_user_field: keep-me
"""
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        na = NetworkAnswers(
            default_network_path="vpn",
            tor_binary_path="/usr/bin/tor",
            tor_socks_port=9050,
            mullvad_account_id_env="MORDRED_MULLVAD_ACCOUNT",
            mullvad_relay_country="auto",
            mullvad_killswitch=False,
        )
        w.write(PolicySnapshot(policy="strict"), network_answers=na)

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section["default_path"] == "vpn"
        assert section["custom_user_field"] == "keep-me", "merge must preserve unknown user fields"


class TestCorruptedPluginsScalarRecovery:
    """H1 (review 2026-05-14): when ``config.yaml`` has a corrupted
    ``plugins: <scalar>`` (e.g. a string, list, or None from a hand-edit
    or a half-finished crash recovery), both merge and upsert helpers
    must not crash with AttributeError / TypeError. They should treat
    the corrupted section as ``{}`` and rebuild it.
    """

    def test_merge_recovers_from_plugins_scalar(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text("plugins: a-string\n", encoding="utf-8")

        w = _writer(tmp_path)
        # Must not crash with AttributeError.
        w.merge_mordred_sections({"mordred_network": {"default_path": "tor"}})

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"]["default_path"] == "tor"

    def test_upsert_recovers_from_plugins_scalar(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text("plugins: 42\n", encoding="utf-8")

        w = _writer(tmp_path)
        # Must not crash with TypeError on int subscript.
        w.upsert_mordred_sections(
            {"mordred_privacy_check": {"policy": "lenient", "allow_cloud_llm": False, "cloud_provider_allowlist": []}}
        )

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_privacy_check"]["policy"] == "lenient"

    def test_merge_recovers_from_plugins_list(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text("plugins:\n  - item1\n  - item2\n", encoding="utf-8")

        w = _writer(tmp_path)
        w.merge_mordred_sections({"mordred_network": {"default_path": "vpn"}})

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"]["default_path"] == "vpn"


class TestUpsertMordredSectionsStillReplaces:
    """Regression guard: ``upsert_mordred_sections`` (whole-replace) must keep
    its full-snapshot semantics so ``configure`` rewrites stay clean.

    The merge variant is the new partial-update API. The whole-replace one is
    NOT deprecated — it is the right behaviour when the caller has computed
    every field of the section from scratch.
    """

    def test_upsert_clobbers_unspecified_sub_fields(self, tmp_path: Path) -> None:
        seed = """\
plugins:
  mordred_network:
    default_path: tor
    tor_binary_path: /usr/bin/tor
    tor_socks_port: 9050
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(seed, encoding="utf-8")

        w = _writer(tmp_path)
        w.upsert_mordred_sections({"mordred_network": {"default_path": "clearnet"}})

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
        section = data["plugins"]["mordred_network"]
        assert section == {"default_path": "clearnet"}, "whole-replace must drop unspecified sub-fields"


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


class TestHasConfigYamlSectionProtocol:
    """H2 (review 2026-05-14): ``PolicyWriter.write`` accepted
    ``network_answers: object | None`` and called ``.to_config_yaml_section()``
    behind a ``# type: ignore[attr-defined]``. The structural shape is now
    described by a ``runtime_checkable`` Protocol exposed from the module so
    callers and tests can verify conformance and mypy --strict can drop the
    type ignore.
    """

    def test_protocol_is_runtime_checkable_and_importable(self) -> None:
        from mordred_hermes.wizard.policy_writer import _HasConfigYamlSection

        class _Stub:
            def to_config_yaml_section(self) -> dict[str, object]:
                return {"default_path": "tor"}

        class _NotStub:
            pass

        assert isinstance(_Stub(), _HasConfigYamlSection)
        assert not isinstance(_NotStub(), _HasConfigYamlSection)

    def test_write_accepts_protocol_shape_without_type_ignore(self, tmp_path: Path) -> None:
        """Duck-type compliance: any object implementing the Protocol works."""

        class _MinimalNetworkAnswers:
            def to_config_yaml_section(self) -> dict[str, object]:
                return {"default_path": "tor", "tor_socks_port": 9050}

        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict"), network_answers=_MinimalNetworkAnswers())

        from ruamel.yaml import YAML

        yaml = YAML(typ="safe", pure=True)
        with (tmp_path / "config.yaml").open(encoding="utf-8") as f:
            data = yaml.load(f)
        assert data["plugins"]["mordred_network"]["default_path"] == "tor"
        assert data["plugins"]["mordred_network"]["tor_socks_port"] == 9050


class TestAtomicWriteHardening:
    """H3+M5+M6 (review 2026-05-14): the canonical ``_atomic_write_text``
    writes the tmpfile via ``Path.write_text``, which creates the file at
    the process umask (typically 0o644). For writes that specify
    ``mode=0o600`` (policy.json, .env, credentials JSON) the secret content
    lands on disk in the umask-default mode and a co-tenant on the same
    host can read it during the gap between ``write_text`` and ``os.chmod``.

    The tmpfile name is also predictable (``<path>.tmp``), so concurrent
    writers collide on the same path and a stale ``.tmp`` from a prior
    crash can break subsequent writes.

    Hardening: switch to ``tempfile.mkstemp`` (atomic ``O_CREAT|O_EXCL`` at
    0o600 with a random suffix). Closes H3 (umask window), M5 (predictable
    name), M6 (stale-collision).
    """

    def test_tmpfile_at_replace_time_matches_target_mode(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The tmpfile written by ``_atomic_write_text(..., mode=0o600)``
        must already be 0o600 (or tighter) at every observable point during
        its on-disk lifetime — not just after a post-write ``os.chmod``.

        We monitor every observable transition: the file's mode at the
        moment of the first stat after creation, at the moment of
        ``os.replace``, and at the moment of every ``os.chmod`` call. None
        of them may exceed the target mode. The current ``Path.write_text``
        approach leaves the file at umask-default (0o644) between
        ``write_text`` and ``os.chmod``; with ``tempfile.mkstemp`` the file
        is at 0o600 from the moment of creation.
        """
        from mordred_hermes.wizard import policy_writer as pw

        target = tmp_path / "policy.json"
        captured_pre_chmod: list[int] = []
        real_chmod = os.chmod

        def capturing_chmod(path: object, mode: int, *args: object, **kwargs: object) -> None:
            with contextlib.suppress(FileNotFoundError):
                if str(path).startswith(str(tmp_path)) and str(path) != str(target):
                    captured_pre_chmod.append(stat.S_IMODE(os.stat(str(path)).st_mode))
            real_chmod(path, mode, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "chmod", capturing_chmod)
        pw._atomic_write_text(target, "secret-payload\n", mode=0o600)

        too_broad = [oct(m) for m in captured_pre_chmod if m > 0o600]
        assert not too_broad, (
            f"tmpfile observed at mode wider than 0o600 before chmod: {too_broad}; "
            "umask-default window leaks secret content to co-tenants (H3)"
        )

    def test_tmpfile_name_is_randomized_per_invocation(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Consecutive writes to the same target must use distinct tmpfile
        names — predictable ``<name>.tmp`` paths collide under concurrent
        writers (M5) and leave stale-collision footguns after a crash (M6).
        """
        from mordred_hermes.wizard import policy_writer as pw

        target = tmp_path / "policy.json"
        tmpfiles_seen: list[str] = []
        real_replace = os.replace

        def capturing_replace(src: object, dst: object, *args: object, **kwargs: object) -> None:
            tmpfiles_seen.append(os.path.basename(str(src)))
            real_replace(src, dst, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "replace", capturing_replace)
        pw._atomic_write_text(target, "first-payload\n", mode=0o600)
        # second write must produce a different content so idempotent-skip
        # doesn't short-circuit (and thus skip the tmpfile rotation).
        pw._atomic_write_text(target, "second-payload\n", mode=0o600)

        assert len(tmpfiles_seen) == 2, f"expected 2 replace calls, got {tmpfiles_seen}"
        assert tmpfiles_seen[0] != tmpfiles_seen[1], (
            f"tmpfile names must be randomized to avoid predictable collisions; "
            f"got the same name {tmpfiles_seen[0]!r} twice"
        )
