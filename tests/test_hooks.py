"""Tests for on_session_start + pre_tool_call hook handlers (Phase E)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from mordred_hermes.privacy_check import _runtime, hooks


def _audit_entries(log_path: Path) -> list[dict[str, object]]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line]


def _write_config(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def reset_runtime() -> Iterator[None]:
    _runtime.reset_state_for_tests()
    yield
    _runtime.reset_state_for_tests()


@pytest.fixture
def strict_config(tmp_path: Path) -> Path:
    return _write_config(
        tmp_path / "config.yaml",
        """\
plugins:
  mordred_privacy_check:
    policy: strict
""",
    )


@pytest.fixture
def lenient_config(tmp_path: Path) -> Path:
    return _write_config(
        tmp_path / "config.yaml",
        """\
plugins:
  mordred_privacy_check:
    policy: lenient
""",
    )


@pytest.fixture
def off_config(tmp_path: Path) -> Path:
    return _write_config(
        tmp_path / "config.yaml",
        """\
plugins:
  mordred_privacy_check:
    policy: off
""",
    )


class TestOnSessionStartNoSiblingsDisabled:
    def test_emits_no_origin_skill_marker_once(self, strict_config: Path, tmp_path: Path) -> None:
        audit = tmp_path / "audit.log"
        _runtime.ensure_state(config_path=strict_config, audit_path=audit)
        hooks.on_session_start(session_id="s1", model="m", platform="cli")
        # Second invocation must not duplicate the degraded marker
        hooks.on_session_start(session_id="s2", model="m", platform="cli")
        entries = _audit_entries(audit)
        no_origin = [e for e in entries if e.get("reason") == "mordred.degraded.no_origin_skill"]
        assert len(no_origin) == 1
        assert no_origin[0]["decision"] == "warn"
        assert no_origin[0]["event"] == "on_session_start"

    def test_does_not_poison_process(self, strict_config: Path, tmp_path: Path) -> None:
        _runtime.ensure_state(config_path=strict_config, audit_path=tmp_path / "audit.log")
        hooks.on_session_start()
        assert not _runtime.is_poisoned()


class TestOnSessionStartStrictAbort:
    def test_strict_with_disabled_sibling_raises_systemexit(self, tmp_path: Path) -> None:
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  disabled:
    - mordred_network
  mordred_privacy_check:
    policy: strict
""",
        )
        audit = tmp_path / "audit.log"
        _runtime.ensure_state(config_path=config, audit_path=audit)
        with pytest.raises(SystemExit):
            hooks.on_session_start()
        # Audit landed before SystemExit
        entries = _audit_entries(audit)
        block_entries = [e for e in entries if e.get("decision") == "block"]
        assert len(block_entries) == 1
        assert block_entries[0]["reason"] == "mordred.degraded.disable_unprotected"
        assert "mordred_network" in block_entries[0]["disabled_siblings"]
        # Process is poisoned
        assert _runtime.is_poisoned()

    def test_strict_with_enabled_allowlist_excluding_sibling_raises(self, tmp_path: Path) -> None:
        """Opt-in allowlist that excludes a sibling counts as 'disabled'."""
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  enabled:
    - mordred_privacy_check
    - mordred_network
    - mordred_llm_guard
    - mordred_keyvault
    # mordred_wizard intentionally absent
  mordred_privacy_check:
    policy: strict
""",
        )
        _runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        with pytest.raises(SystemExit):
            hooks.on_session_start()


class TestOnSessionStartLenientWithDisabled:
    def test_lenient_with_disabled_sibling_warns_and_continues(self, tmp_path: Path) -> None:
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  disabled:
    - mordred_network
  mordred_privacy_check:
    policy: lenient
""",
        )
        audit = tmp_path / "audit.log"
        _runtime.ensure_state(config_path=config, audit_path=audit)
        # Should NOT raise
        hooks.on_session_start()
        entries = _audit_entries(audit)
        warn_entries = [e for e in entries if e.get("reason") == "mordred.degraded.disable_unprotected"]
        assert len(warn_entries) == 1
        assert warn_entries[0]["decision"] == "warn"
        # And NOT poisoned
        assert not _runtime.is_poisoned()


class TestPreToolCallStrict:
    @pytest.mark.parametrize("blocked_tool", ["web_fetch", "web_search"])
    def test_blocks_default_blocklist_on_clearnet(self, strict_config: Path, tmp_path: Path, blocked_tool: str) -> None:
        audit = tmp_path / "audit.log"
        _runtime.ensure_state(config_path=strict_config, audit_path=audit)
        result = hooks.pre_tool_call(tool_name=blocked_tool, args={}, task_id="t", session_id="s", tool_call_id="c")
        assert result is not None
        assert result["action"] == "block"
        assert blocked_tool in result["message"]
        # Audit landed
        entries = _audit_entries(audit)
        blocks = [e for e in entries if e.get("event") == "pre_tool_call"]
        assert len(blocks) == 1
        assert blocks[0]["decision"] == "block"
        assert blocks[0]["reason"] == "policy.strict.clearnet"
        assert blocks[0]["tool_name"] == blocked_tool

    def test_allows_unlisted_tool(self, strict_config: Path, tmp_path: Path) -> None:
        audit = tmp_path / "audit.log"
        _runtime.ensure_state(config_path=strict_config, audit_path=audit)
        result = hooks.pre_tool_call(tool_name="read_file")
        assert result is None
        # No pre_tool_call entries for allows
        entries = _audit_entries(audit)
        assert all(e.get("event") != "pre_tool_call" for e in entries)


class TestPreToolCallLenientAndOff:
    def test_lenient_allows_blocklisted_tool(self, lenient_config: Path, tmp_path: Path) -> None:
        _runtime.ensure_state(config_path=lenient_config, audit_path=tmp_path / "audit.log")
        assert hooks.pre_tool_call(tool_name="web_fetch") is None

    def test_off_allows_blocklisted_tool(self, off_config: Path, tmp_path: Path) -> None:
        _runtime.ensure_state(config_path=off_config, audit_path=tmp_path / "audit.log")
        assert hooks.pre_tool_call(tool_name="web_fetch") is None


class TestPoisonDefenseInDepth:
    def test_poisoned_process_blocks_every_tool(self, strict_config: Path, tmp_path: Path) -> None:
        audit = tmp_path / "audit.log"
        _runtime.ensure_state(config_path=strict_config, audit_path=audit)
        _runtime.poison("synthetic poison reason for test")
        # Even tools NOT in the strict blocklist get blocked
        result = hooks.pre_tool_call(tool_name="read_file")
        assert result is not None
        assert result["action"] == "block"
        assert "synthetic poison" in result["message"]
        entries = _audit_entries(audit)
        blocks = [e for e in entries if e.get("event") == "pre_tool_call"]
        assert blocks[0]["reason"] == "mordred.degraded.disable_unprotected"


class TestKwargRobustness:
    def test_extra_kwargs_ignored(self, strict_config: Path, tmp_path: Path) -> None:
        """Hermes adds new payload fields without warning — handlers must tolerate."""
        _runtime.ensure_state(config_path=strict_config, audit_path=tmp_path / "audit.log")
        # Future-proof: pass an unexpected kwarg
        hooks.on_session_start(session_id="s", model="m", platform="cli", future_field=42)
        result = hooks.pre_tool_call(tool_name="read_file", args={}, future_field="x")
        assert result is None

    def test_missing_tool_name_treated_as_empty(self, strict_config: Path, tmp_path: Path) -> None:
        _runtime.ensure_state(config_path=strict_config, audit_path=tmp_path / "audit.log")
        # No tool_name in payload — must not crash
        result = hooks.pre_tool_call()
        # Empty tool_name is not in blocklist, so allow
        assert result is None


class TestPolicyDefaults:
    def test_missing_section_defaults_to_lenient(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path / "config.yaml", "plugins: {}\n")
        _runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        # Lenient mode allows web_fetch
        assert hooks.pre_tool_call(tool_name="web_fetch") is None

    def test_invalid_policy_value_fails_closed_to_strict(self, tmp_path: Path) -> None:
        # M1 port: an invalid mode in an EXISTING config reads as strict —
        # falling back to lenient let a corrupted value silently downgrade
        # enforcement.
        config = _write_config(
            tmp_path / "config.yaml",
            """\
plugins:
  mordred_privacy_check:
    policy: bogus
""",
        )
        _runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        result = hooks.pre_tool_call(tool_name="web_fetch")
        assert result is not None
        assert result["action"] == "block"

    def test_missing_config_file_defaults_to_lenient(self, tmp_path: Path) -> None:
        non_existent = tmp_path / "nope.yaml"
        _runtime.ensure_state(config_path=non_existent, audit_path=tmp_path / "audit.log")
        assert hooks.pre_tool_call(tool_name="web_fetch") is None


class TestAllowCloudLlmStrictBool:
    """M2 (security review 2026-06-11): allow_cloud_llm must be a real bool.

    ``bool(section.get(...))`` truthy-coerced YAML strings — a hand-edited
    ``allow_cloud_llm: "false"`` silently *granted* cloud-LLM permission.
    Only ``True`` (the bool) may enable it; anything else reads as False.
    """

    def _config(self, tmp_path: Path, raw: str) -> Path:
        return _write_config(
            tmp_path / "config.yaml",
            f"""\
plugins:
  mordred_privacy_check:
    policy: strict
    allow_cloud_llm: {raw}
""",
        )

    @pytest.mark.parametrize("raw", ['"false"', '"true"', '"yes"', "1"])
    def test_non_bool_values_never_enable(self, raw: str, tmp_path: Path) -> None:
        state = _runtime.ensure_state(
            config_path=self._config(tmp_path, raw),
            audit_path=tmp_path / "audit.log",
        )
        assert state.allow_cloud_llm is False

    def test_real_bool_true_enables(self, tmp_path: Path) -> None:
        state = _runtime.ensure_state(
            config_path=self._config(tmp_path, "true"),
            audit_path=tmp_path / "audit.log",
        )
        assert state.allow_cloud_llm is True
