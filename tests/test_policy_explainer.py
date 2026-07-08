"""Phase D tests -- policy show / explain / dry-run / reload.

Reuses the existing fixture skills under ``tests/fixtures/`` so the
matrix mirrors what install_wrapper enforces. Output is captured via
StringIO; nothing under ~/.hermes/ is touched.
"""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import pytest

from mordred_hermes.privacy_check import _runtime as privacy_runtime
from mordred_hermes.wizard import policy_explainer

FIXTURES = Path(__file__).parent / "fixtures"
CLEARNET = FIXTURES / "clearnet_skill"
TOR = FIXTURES / "tor_skill"
MISSING = FIXTURES / "missing_metadata_skill"


def _write_policy(tmp_path: Path, policy: str) -> Path:
    """Write policy.json -- for `show()` tests (the only consumer that reads it)."""
    p = tmp_path / "mordred" / "policy.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(
            {
                "policy": policy,
                "allow_cloud_llm": False,
                "cloud_provider_allowlist": [],
                "audit_log_path": None,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return p


def _write_config(tmp_path: Path, policy: str) -> Path:
    """Write config.yaml -- the source explain/dry-run actually read.

    Same shape privacy_check._runtime._load_state reads (plugins.mordred_privacy_check).
    """
    p = tmp_path / "config.yaml"
    p.write_text(
        f"plugins:\n  mordred_privacy_check:\n    policy: {policy}\n",
        encoding="utf-8",
    )
    return p


# -----------------------------------------------------------------------------
# show()
# -----------------------------------------------------------------------------


class TestShow:
    def test_returns_1_when_policy_json_absent(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = policy_explainer.show(policy_json_path=tmp_path / "missing.json")
        assert rc == 1
        err = capsys.readouterr().err
        assert "No Mordred policy configured" in err
        assert "configure" in err

    def test_prints_policy_json_to_stdout(self, tmp_path: Path) -> None:
        p = _write_policy(tmp_path, "strict")
        out = io.StringIO()
        rc = policy_explainer.show(policy_json_path=p, out=out)
        assert rc == 0
        body = json.loads(out.getvalue())
        assert body["policy"] == "strict"

    def test_returns_1_when_policy_json_malformed(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        p = tmp_path / "policy.json"
        p.write_text("{ this is not valid json", encoding="utf-8")
        rc = policy_explainer.show(policy_json_path=p)
        assert rc == 1
        assert "Failed to read" in capsys.readouterr().err


# -----------------------------------------------------------------------------
# explain() -- skill resolution + decision printing
# -----------------------------------------------------------------------------


class TestExplain:
    def test_returns_1_when_skill_not_found(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = policy_explainer.explain(
            "nonexistent",
            config_path=tmp_path / "config.yaml",
            skills_dirs=[tmp_path / "skills"],
        )
        assert rc == 1
        assert "not found" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "evil_id",
        [
            "../etc/passwd",
            "..",
            ".",
            "",
            "foo/bar",
            r"foo\bar",
            "\x00",
            "/etc/passwd",
            # Unicode look-alike separators that bypass naive `"/" in s` checks.
            "foo／bar",  # noqa: RUF001 -- U+FF0F FULLWIDTH SOLIDUS, intentionally ambiguous
            "foo∕bar",  # noqa: RUF001 -- U+2215 DIVISION SLASH, intentionally ambiguous
            "café",  # any non-ASCII
        ],
    )
    def test_traversal_attempts_rejected(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], evil_id: str
    ) -> None:
        """``skill_id`` must match the ASCII allowlist; traversal sequences fail closed."""
        rc = policy_explainer.explain(
            evil_id,
            config_path=_write_config(tmp_path, "lenient"),
            skills_dirs=[tmp_path / "skills"],
        )
        assert rc == 1
        assert "not found" in capsys.readouterr().err

    def test_symlink_pointing_outside_search_dir_is_ignored(self, tmp_path: Path) -> None:
        """A skill dir that's actually a symlink to outside the search root must miss."""
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "SKILL.md").write_text("---\nname: x\n---\n", encoding="utf-8")

        skills = tmp_path / "skills"
        skills.mkdir()
        (skills / "escape").symlink_to(outside, target_is_directory=True)

        rc = policy_explainer.explain(
            "escape",
            config_path=_write_config(tmp_path, "lenient"),
            skills_dirs=[skills],
        )
        assert rc == 1, "symlink escape must be rejected"

    def test_strict_clearnet_skill_blocks(self, tmp_path: Path) -> None:
        skills = tmp_path / "skills"
        (skills / "my-skill").mkdir(parents=True)
        (skills / "my-skill" / "SKILL.md").write_text(
            (CLEARNET / "SKILL.md").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        config = _write_config(tmp_path, "strict")
        out = io.StringIO()
        rc = policy_explainer.explain(
            "my-skill",
            config_path=config,
            skills_dirs=[skills],
            out=out,
        )
        text = out.getvalue()
        assert rc == 2
        assert "decision: block" in text
        assert "policy.strict.clearnet" in text
        assert "policy_mode: strict" in text

    def test_strict_tor_skill_allows(self, tmp_path: Path) -> None:
        skills = tmp_path / "skills"
        (skills / "tor-skill").mkdir(parents=True)
        (skills / "tor-skill" / "SKILL.md").write_text(
            (TOR / "SKILL.md").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        config = _write_config(tmp_path, "strict")
        out = io.StringIO()
        rc = policy_explainer.explain(
            "tor-skill",
            config_path=config,
            skills_dirs=[skills],
            out=out,
        )
        text = out.getvalue()
        assert rc == 0
        assert "decision: allow" in text


# -----------------------------------------------------------------------------
# dry_run() -- direct path-based eval
# -----------------------------------------------------------------------------


class TestDryRun:
    def test_returns_1_when_skill_md_missing(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = policy_explainer.dry_run(tmp_path / "no-such-skill")
        assert rc == 1
        assert "SKILL.md not found" in capsys.readouterr().err

    def test_strict_clearnet_blocks(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path, "strict")
        out = io.StringIO()
        rc = policy_explainer.dry_run(CLEARNET, config_path=config, out=out)
        text = out.getvalue()
        assert rc == 2
        assert "dry-run: block" in text
        assert "policy.strict.clearnet" in text

    def test_lenient_missing_metadata_warns(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path, "lenient")
        out = io.StringIO()
        rc = policy_explainer.dry_run(MISSING, config_path=config, out=out)
        text = out.getvalue()
        assert rc == 0
        assert "dry-run: warn" in text
        assert "policy.lenient.unknown_metadata_warning" in text

    def test_off_mode_always_allows(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path, "off")
        out = io.StringIO()
        rc = policy_explainer.dry_run(CLEARNET, config_path=config, out=out)
        assert rc == 0
        assert "dry-run: allow" in out.getvalue()

    def test_explicit_skill_md_path(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path, "strict")
        out = io.StringIO()
        rc = policy_explainer.dry_run(TOR / "SKILL.md", config_path=config, out=out)
        assert rc == 0
        assert "dry-run: allow" in out.getvalue()


# -----------------------------------------------------------------------------
# reload()
# -----------------------------------------------------------------------------


class TestReload:
    def test_clears_cached_state(self, tmp_path: Path) -> None:
        config = tmp_path / "config.yaml"
        config.write_text("plugins:\n  mordred_privacy_check:\n    policy: strict\n", encoding="utf-8")
        privacy_runtime.reset_state_for_tests()
        state_before = privacy_runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        assert state_before.policy_mode == "strict"

        config.write_text("plugins:\n  mordred_privacy_check:\n    policy: off\n", encoding="utf-8")
        out = io.StringIO()
        rc = policy_explainer.reload(out=out)
        assert rc == 0
        assert "reloaded" in out.getvalue().lower()

        state_after = privacy_runtime.ensure_state(config_path=config, audit_path=tmp_path / "audit.log")
        assert state_after.policy_mode == "off"

    def test_idempotent(self) -> None:
        privacy_runtime.reset_state_for_tests()
        rc1 = policy_explainer.reload(out=io.StringIO())
        rc2 = policy_explainer.reload(out=io.StringIO())
        assert rc1 == 0 and rc2 == 0

    def test_warns_when_process_is_poisoned(self, capsys: pytest.CaptureFixture[str]) -> None:
        """reload() does not clear the poison flag and must surface that to the user."""
        privacy_runtime.reset_state_for_tests()
        privacy_runtime.poison("synthetic poison for test")
        try:
            rc = policy_explainer.reload(out=io.StringIO())
            assert rc == 0
            err = capsys.readouterr().err
            assert "poisoned" in err.lower()
            assert "restart" in err.lower()
        finally:
            privacy_runtime.reset_state_for_tests()


# -----------------------------------------------------------------------------
# CLI handler adapters
# -----------------------------------------------------------------------------


class TestCliAdapters:
    def test_cli_show(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        p = _write_policy(tmp_path, "lenient")
        monkeypatch.setattr(policy_explainer, "DEFAULT_POLICY_JSON_PATH", p)
        rc = policy_explainer.cli_show(argparse.Namespace())
        assert rc == 0

    def test_cli_explain_unknown_skill(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(policy_explainer, "DEFAULT_HERMES_CONFIG_PATH", tmp_path / "config.yaml")
        monkeypatch.setattr(policy_explainer, "DEFAULT_SKILLS_DIRS", (tmp_path / "skills",))
        rc = policy_explainer.cli_explain(argparse.Namespace(skill_id="nope"))
        assert rc == 1

    def test_cli_dry_run_passes_through(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        config = _write_config(tmp_path, "off")
        monkeypatch.setattr(policy_explainer, "DEFAULT_HERMES_CONFIG_PATH", config)
        rc = policy_explainer.cli_dry_run(argparse.Namespace(skill_path=str(TOR)))
        assert rc == 0

    def test_cli_reload_returns_0(self) -> None:
        privacy_runtime.reset_state_for_tests()
        rc = policy_explainer.cli_reload(argparse.Namespace())
        assert rc == 0


# -----------------------------------------------------------------------------
# _resolve_policy_mode -- defaulting and bad-input handling
# -----------------------------------------------------------------------------


class TestResolvePolicyMode:
    """Mode resolution reads ~/.hermes/config.yaml -- the same source as the install hook."""

    def test_defaults_to_lenient_when_config_missing(self, tmp_path: Path) -> None:
        assert policy_explainer._resolve_policy_mode(tmp_path / "missing.yaml") == "lenient"

    def test_fails_closed_to_strict_on_invalid_yaml(self, tmp_path: Path) -> None:
        # M1 port: a config.yaml that EXISTS but cannot be parsed reads as
        # strict — collapsing it to lenient let a corrupted file silently
        # downgrade install-time enforcement.
        p = tmp_path / "config.yaml"
        p.write_text("plugins:\n  mordred_privacy_check:\n    policy: : :", encoding="utf-8")
        assert policy_explainer._resolve_policy_mode(p) == "strict"

    def test_fails_closed_to_strict_on_unreadable_config(self, tmp_path: Path) -> None:
        # Exists-but-unreadable (a directory raises IsADirectoryError on
        # open) must not be misread as "absent" -> lenient.
        a_dir = tmp_path / "config.yaml"
        a_dir.mkdir()
        assert policy_explainer._resolve_policy_mode(a_dir) == "strict"

    def test_fails_closed_to_strict_on_unknown_policy_value(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        p = tmp_path / "config.yaml"
        p.write_text("plugins:\n  mordred_privacy_check:\n    policy: wat\n", encoding="utf-8")
        import logging

        with caplog.at_level(logging.WARNING, logger="mordred.privacy_check"):
            assert policy_explainer._resolve_policy_mode(p) == "strict"
        assert any("invalid policy" in r.getMessage() for r in caplog.records)

    @pytest.mark.parametrize("mode", ["strict", "lenient", "off"])
    def test_passes_through_valid_modes(self, tmp_path: Path, mode: str) -> None:
        p = _write_config(tmp_path, mode)
        assert policy_explainer._resolve_policy_mode(p) == mode

    def test_drift_free_with_config_yaml_edit(self, tmp_path: Path) -> None:
        """Editing config.yaml directly is reflected without going through PolicyWriter.

        This is the regression test for Codex P2 -- previously _resolve_policy_mode
        read policy.json (a wizard-written mirror) and could drift.
        """
        config = tmp_path / "config.yaml"
        config.write_text("plugins:\n  mordred_privacy_check:\n    policy: lenient\n", encoding="utf-8")
        assert policy_explainer._resolve_policy_mode(config) == "lenient"

        # User edits config.yaml directly -- explainer must reflect it
        config.write_text("plugins:\n  mordred_privacy_check:\n    policy: strict\n", encoding="utf-8")
        assert policy_explainer._resolve_policy_mode(config) == "strict"


class TestGuidanceSpelling:
    """UX review 2026-06-11: guidance must name the working CLI spelling."""

    def test_missing_policy_points_at_working_configure_command(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = policy_explainer.show(policy_json_path=tmp_path / "absent" / "policy.json")
        assert rc == 1
        err = capsys.readouterr().err
        assert "hermes-mordred configure" in err

    def test_skill_not_found_lists_paths_without_python_repr(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = policy_explainer.explain(
            "no-such-skill",
            config_path=tmp_path / "config.yaml",
            skills_dirs=(tmp_path / "a", tmp_path / "b"),
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "['" not in err  # no Python list repr in user output
        assert str(tmp_path / "a") in err


class TestErrorColour:
    """Wizard tail-cluster errors route through ``_term.emit_error``: red ``error:`` on a tty, plain off it.

    Mirrors the network / vault / keyvault / native+audit reproducers
    (PR #159 / #164 / #165 / #166). Uses ``policy show`` against a missing
    policy.json — a no-setup error path representative of this PR's modules.
    """

    def test_show_error_is_red_when_forced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        rc = policy_explainer.show(policy_json_path=tmp_path / "missing.json")
        assert rc == 1
        err = capsys.readouterr().err
        assert "\033[31m" in err  # red `error:` label
        assert "No Mordred policy configured" in err

    def test_show_error_plain_and_prefixed_off_tty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        rc = policy_explainer.show(policy_json_path=tmp_path / "missing.json")
        assert rc == 1
        err = capsys.readouterr().err
        assert err.startswith("error: No Mordred policy configured")
        assert "\033" not in err
