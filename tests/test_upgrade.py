"""Phase E tests -- `hermes mordred upgrade` Story 1 (idempotent migration).

RED phase 1: dataclass shape + minimum dispatch -- proves the file
imports and exposes the documented surface. Story 1.5 OpenClaw tests
live in `test_openclaw_migration.py`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mordred_hermes.wizard import upgrade
from mordred_hermes.wizard.policy_writer import PolicySnapshot, PolicyWriter


def _writer(tmp_path: Path) -> PolicyWriter:
    return PolicyWriter(
        config_path=tmp_path / "config.yaml",
        policy_json_path=tmp_path / "mordred" / "policy.json",
        mordred_dir=tmp_path / "mordred",
    )


# -----------------------------------------------------------------------------
# UpgradeOptions dataclass
# -----------------------------------------------------------------------------


class TestUpgradeOptions:
    def test_defaults(self) -> None:
        opts = upgrade.UpgradeOptions()
        assert opts.reset is False
        assert opts.non_interactive is False
        assert opts.audit_merge is None
        assert opts.policy_conflict is None

    def test_frozen(self) -> None:
        opts = upgrade.UpgradeOptions()
        with pytest.raises((AttributeError, Exception)):
            opts.reset = True  # type: ignore[misc]

    def test_audit_merge_accepts_known_values(self) -> None:
        for v in ("skip", "append-all", "abort"):
            assert upgrade.UpgradeOptions(audit_merge=v).audit_merge == v

    def test_policy_conflict_accepts_known_values(self) -> None:
        for v in ("keep-existing", "overwrite", "abort"):
            assert upgrade.UpgradeOptions(policy_conflict=v).policy_conflict == v


# -----------------------------------------------------------------------------
# upgrade.run() -- Story 1 happy paths
# -----------------------------------------------------------------------------


class TestRunNoOp:
    """Re-running upgrade against an already-migrated config is a no-op."""

    def test_returns_noop_when_no_existing_state_and_no_openclaw(self, tmp_path: Path) -> None:
        """Empty target = no Hermes config + no OpenClaw = nothing to do."""
        w = _writer(tmp_path)
        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "noop"
        assert report.story1_5_action == "noop"
        assert (tmp_path / "config.yaml").exists() is False, "noop must not create files"

    def test_existing_matching_section_is_noop(self, tmp_path: Path) -> None:
        """If config.yaml already has the snapshot the wizard would write, no rewrite."""
        w = _writer(tmp_path)
        snap = PolicySnapshot(policy="lenient")
        # First write seeds disk
        w.write(snap)
        first_mtime = (tmp_path / "config.yaml").stat().st_mtime_ns

        # Run upgrade with the same target snapshot -- must not touch the file
        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            target_snapshot=snap,
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "noop"
        assert (tmp_path / "config.yaml").stat().st_mtime_ns == first_mtime


class TestRunStory1Apply:
    """Story 1: existing Hermes config but missing/different mordred section."""

    def test_writes_snapshot_when_section_absent(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        # Pre-existing config with no mordred section
        config = tmp_path / "config.yaml"
        config.write_text("profile: default\n", encoding="utf-8")

        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            target_snapshot=PolicySnapshot(policy="lenient"),
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "applied"
        text = config.read_text(encoding="utf-8")
        assert "mordred_privacy_check" in text
        assert "policy: lenient" in text
        # User's pre-existing profile key is preserved (round-trip)
        assert "profile: default" in text


class TestRunPolicyConflict:
    """When config.yaml has a different mordred section, --policy-conflict drives behaviour."""

    def test_keep_existing_does_not_overwrite(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        # Seed with strict
        w.write(PolicySnapshot(policy="strict"))

        report = upgrade.run(
            options=upgrade.UpgradeOptions(policy_conflict="keep-existing"),
            policy_writer=w,
            target_snapshot=PolicySnapshot(policy="lenient"),  # different
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "kept-existing"
        text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "policy: strict" in text  # not overwritten
        assert "policy: lenient" not in text

    def test_overwrite_replaces_section(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict"))

        report = upgrade.run(
            options=upgrade.UpgradeOptions(policy_conflict="overwrite"),
            policy_writer=w,
            target_snapshot=PolicySnapshot(policy="off"),
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "overwritten"
        text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
        assert "policy: off" in text

    def test_abort_raises_systemexit(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict"))

        with pytest.raises(SystemExit):
            upgrade.run(
                options=upgrade.UpgradeOptions(policy_conflict="abort"),
                policy_writer=w,
                target_snapshot=PolicySnapshot(policy="lenient"),
                openclaw_base=tmp_path / "no-openclaw-here",
            )

    def test_non_interactive_without_policy_conflict_aborts(self, tmp_path: Path) -> None:
        """--non-interactive without --policy-conflict must fail closed."""
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict"))

        with pytest.raises(SystemExit, match=r"policy-conflict"):
            upgrade.run(
                options=upgrade.UpgradeOptions(non_interactive=True),
                policy_writer=w,
                target_snapshot=PolicySnapshot(policy="lenient"),
                openclaw_base=tmp_path / "no-openclaw-here",
            )

    def test_reset_overrides_policy_conflict(self, tmp_path: Path) -> None:
        """--reset forces overwrite regardless of --policy-conflict."""
        w = _writer(tmp_path)
        w.write(PolicySnapshot(policy="strict"))

        report = upgrade.run(
            options=upgrade.UpgradeOptions(reset=True, policy_conflict="keep-existing"),
            policy_writer=w,
            target_snapshot=PolicySnapshot(policy="off"),
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert report.story1_action == "overwritten"
        assert "policy: off" in (tmp_path / "config.yaml").read_text(encoding="utf-8")


# -----------------------------------------------------------------------------
# Idempotency -- second run of the same upgrade is a no-op
# -----------------------------------------------------------------------------


class TestIdempotency:
    def test_second_run_is_noop_after_apply(self, tmp_path: Path) -> None:
        """Realistic: existing Hermes user runs `upgrade` to back-fill mordred,
        then re-runs -- second call must be a no-op (no rewrite, no mtime bump)."""
        w = _writer(tmp_path)
        # Pre-seed Hermes config (mordred section absent)
        (tmp_path / "config.yaml").write_text("profile: default\n", encoding="utf-8")
        snap = PolicySnapshot(policy="lenient")

        first = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            target_snapshot=snap,
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert first.story1_action == "applied"
        first_mtime = (tmp_path / "config.yaml").stat().st_mtime_ns

        second = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            target_snapshot=snap,
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert second.story1_action == "noop"
        assert (tmp_path / "config.yaml").stat().st_mtime_ns == first_mtime


# -----------------------------------------------------------------------------
# UpgradeReport shape
# -----------------------------------------------------------------------------


class TestReport:
    def test_report_has_story1_and_story1_5_fields(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        report = upgrade.run(
            options=upgrade.UpgradeOptions(),
            policy_writer=w,
            openclaw_base=tmp_path / "no-openclaw-here",
        )
        assert hasattr(report, "story1_action")
        assert hasattr(report, "story1_5_action")
        # Action values are documented strings
        assert report.story1_action in {"noop", "applied", "kept-existing", "overwritten"}
        assert report.story1_5_action in {"noop", "migrated", "skipped-marker"}


# -----------------------------------------------------------------------------
# render_report -- `hermes-mordred upgrade` must say what it did. UX review
# 2026-06-11: the CLI handler used to discard the report and print nothing,
# leaving a migration command silent even after migrating ~/.openclaw.
# -----------------------------------------------------------------------------


class TestRenderReport:
    @pytest.mark.parametrize(
        ("action", "phrase"),
        [
            ("noop", "already up to date"),
            ("applied", "applied"),
            ("kept-existing", "kept existing"),
            ("overwritten", "overwritten"),
        ],
    )
    def test_story1_actions_render_human_phrases(self, action: str, phrase: str) -> None:
        report = upgrade.UpgradeReport(story1_action=action, story1_5_action="noop")  # type: ignore[arg-type]
        assert phrase in upgrade.render_report(report)

    @pytest.mark.parametrize(
        ("action", "phrase"),
        [
            ("noop", "no OpenClaw install"),
            ("migrated", "migrated"),
            ("skipped-marker", "already migrated"),
        ],
    )
    def test_story1_5_actions_render_human_phrases(self, action: str, phrase: str) -> None:
        report = upgrade.UpgradeReport(story1_action="noop", story1_5_action=action)  # type: ignore[arg-type]
        assert phrase in upgrade.render_report(report)

    def test_cli_handler_prints_summary(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The argparse handler must surface the report, not swallow it."""
        import argparse

        from mordred_hermes.wizard import cli

        report = upgrade.UpgradeReport(story1_action="applied", story1_5_action="noop")
        monkeypatch.setattr(upgrade, "run", lambda **_kwargs: report)
        ns = argparse.Namespace(reset=False, non_interactive=False, audit_merge=None, policy_conflict=None)
        rc = cli._handle_upgrade(ns)
        assert rc == 0
        out = capsys.readouterr().out
        assert "applied" in out
        assert "OpenClaw" in out
