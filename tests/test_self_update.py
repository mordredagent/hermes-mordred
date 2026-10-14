"""``hermes-mordred update``: release selection, the install sequence, refusals, caching."""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes import _self_update as core
from mordred_hermes.wizard import update_cli

REPO = Path(__file__).resolve().parent.parent


def _installed(**overrides: Any) -> core.Installed:
    base = dict(
        version="0.2.0a1",
        kind="pypi",
        path=None,
        editable=False,
        extras=("macos",),
        from_member=False,
        python="/env/bin/python3",
        in_venv=True,
    )
    base.update(overrides)
    return core.Installed(**base)


def _releases(*versions: str, yanked: tuple[str, ...] = (), empty: tuple[str, ...] = ()) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for v in versions:
        if v in empty:
            out[v] = []
        else:
            out[v] = [{"filename": f"hermes_mordred-{v}-py3-none-any.whl", "yanked": v in yanked}]
    return out


class FakeRunner:
    """Records every argv; answers per step with configurable exit codes/output."""

    def __init__(
        self, freeze: str = "", requirements: str = "", fail: str | None = None, check_codes: list[int] | None = None
    ):
        self.calls: list[list[str]] = []
        self.freeze = freeze
        self.requirements = requirements
        self.fail = fail
        self.check_codes = check_codes or [0, 0]

    def __call__(self, argv: list[str]) -> core.CommandResult:
        self.calls.append(list(argv))
        step = self._step(argv)
        if step == self.fail:
            return core.CommandResult(1, f"boom in {step}\nline2")
        if step == "check":
            return core.CommandResult(self.check_codes.pop(0) if self.check_codes else 0, "")
        if step == "freeze":
            return core.CommandResult(0, self.freeze)
        if step == "read-requirements":
            return core.CommandResult(0, self.requirements)
        return core.CommandResult(0, "")

    @staticmethod
    def _step(argv: list[str]) -> str:
        if argv[1:3] == ["pip", "check"]:
            return "check"
        if argv[1:3] == ["pip", "freeze"]:
            return "freeze"
        if argv[1:3] == ["pip", "install"] and "--no-deps" in argv:
            return "install-package"
        if argv[1:3] == ["pip", "install"]:
            return "install-requirements"
        if "-c" in argv and core._REQUIREMENTS_SCRIPT in argv:
            return "read-requirements"
        if "-c" in argv and core._RECORD_MEMBER_SCRIPT in argv:
            return "record-member"
        raise AssertionError(f"unexpected command {argv!r}")


# -- agreement with the installer ---------------------------------------------------------


def test_version_floor_matches_installer() -> None:
    installer = (REPO / "scripts" / "install.sh").read_text(encoding="utf-8")
    match = re.search(r'^readonly MIN_MORDRED_VERSION="([^"]+)"$', installer, re.MULTILINE)
    assert match is not None
    assert match.group(1) == core.MIN_MORDRED_VERSION


def test_requirements_script_matches_installer() -> None:
    """The requirement filter is the installer's heredoc, verbatim."""
    installer = (REPO / "scripts" / "install.sh").read_text(encoding="utf-8")
    heredoc = installer.split("<<'PY' 2>/dev/null || true\n", 1)[1].split("\nPY\n", 1)[0]
    assert core._REQUIREMENTS_SCRIPT.strip() == heredoc.strip()


# -- select_latest -------------------------------------------------------------------------


class TestSelectLatest:
    def test_prerelease_user_sees_newer_prerelease_even_after_a_stable(self) -> None:
        releases = _releases("0.2.0a1", "0.2.0a2", "0.2.0", "0.3.0a1")
        assert core.select_latest(releases, "0.2.0a1") == "0.3.0a1"

    def test_stable_user_never_gets_a_prerelease(self) -> None:
        releases = _releases("0.2.0", "0.2.1", "0.3.0a1")
        assert core.select_latest(releases, "0.2.0") == "0.2.1"

    def test_stable_user_with_only_prereleases_ahead_gets_none(self) -> None:
        assert core.select_latest(_releases("0.2.0", "0.3.0a1"), "0.2.0") == "0.2.0"

    def test_yanked_and_empty_and_below_floor_are_skipped(self) -> None:
        releases = _releases("0.0.0.dev0", "0.1.0a15", "0.2.0a3", "0.2.0a4", yanked=("0.2.0a4",), empty=("0.1.0a15",))
        releases["not-a-version"] = [{"yanked": False}]
        assert core.select_latest(releases, "0.2.0a1") == "0.2.0a3"

    def test_nothing_qualifies(self) -> None:
        assert core.select_latest(_releases("0.0.0.dev0"), "0.2.0a1") is None
        assert core.select_latest({}, "0.2.0a1") is None


def test_is_newer_handles_garbage() -> None:
    assert core.is_newer("0.2.0a2", "0.2.0a1") is True
    assert core.is_newer("0.2.0a1", "0.2.0a1") is False
    assert core.is_newer(None, "0.2.0a1") is None
    assert core.is_newer("x", "0.2.0a1") is None


# -- fetch + check --------------------------------------------------------------------------


def test_fetch_releases_validates_the_answer() -> None:
    assert core.fetch_releases(lambda url: json.dumps({"releases": {"1.0": []}}).encode()) == {"1.0": []}
    with pytest.raises(core.UpdateCheckFailed, match="not JSON"):
        core.fetch_releases(lambda url: b"<html>")
    with pytest.raises(core.UpdateCheckFailed, match="no releases"):
        core.fetch_releases(lambda url: b"{}")
    with pytest.raises(core.UpdateCheckFailed, match="too large"):
        core.fetch_releases(lambda url: b"x" * (core.MAX_FETCH_BYTES + 1))
    with pytest.raises(core.UpdateCheckFailed, match="OSError"):
        core.fetch_releases(lambda url: (_ for _ in ()).throw(OSError("down")))


def test_check_uses_installed_version_and_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core, "installed", lambda: _installed(version="0.2.0a1"))
    seen: list[str] = []

    def fetch(url: str) -> bytes:
        seen.append(url)
        return json.dumps({"releases": _releases("0.2.0a1", "0.2.0a5")}).encode()

    result = core.check(fetch=fetch, now=lambda: 1000.0)
    assert seen == [core.PYPI_JSON_URL]
    assert result == core.CheckResult("0.2.0a1", "0.2.0a5", True, "pypi", 1000.0)


# -- Hermes's receipt, our cache, the opt-out -----------------------------------------------


def _write_receipt(home: Path, *, kind: str, finished: str, rows: list[dict[str, Any]], name: str = "a") -> None:
    directory = home / "logs" / "update_receipts"
    directory.mkdir(parents=True, exist_ok=True)
    data = {"schema": 1, "kind": kind, "finished_at": finished, "plugin_checks": rows}
    (directory / f"pm_{name}.json").write_text(json.dumps(data), encoding="utf-8")


ROW = {"name": "mordred", "class": "pip", "current": "0.2.0a1", "latest": "0.2.0a2", "update_available": True}


class TestHermesReceipt:
    NOW = 1_800_000_000.0

    def test_fresh_plugin_check_row_is_used(self, tmp_path: Path) -> None:
        _write_receipt(tmp_path, kind="plugin-check", finished="2027-01-15T00:00:00+00:00", rows=[ROW])
        stamp = core._iso_to_epoch("2027-01-15T00:00:00+00:00")
        assert stamp is not None
        result = core.hermes_receipt_check(tmp_path, now=lambda: stamp + 60)
        assert result == core.CheckResult("0.2.0a1", "0.2.0a2", True, "hermes-receipt", stamp)

    def test_stale_or_missing_or_other_kind_is_ignored(self, tmp_path: Path) -> None:
        assert core.hermes_receipt_check(tmp_path, now=lambda: self.NOW) is None
        _write_receipt(tmp_path, kind="sync", finished="2027-01-15T00:00:00+00:00", rows=[ROW], name="z")
        assert core.hermes_receipt_check(tmp_path, now=lambda: self.NOW) is None
        _write_receipt(tmp_path, kind="plugin-check", finished="2020-01-01T00:00:00+00:00", rows=[ROW], name="y")
        assert core.hermes_receipt_check(tmp_path, now=lambda: self.NOW) is None

    def test_stable_latest_for_prerelease_install_defers_to_our_lookup(self, tmp_path: Path) -> None:
        row = {**ROW, "latest": "0.2.0"}
        _write_receipt(tmp_path, kind="plugin-check", finished="2027-01-15T00:00:00+00:00", rows=[row])
        stamp = core._iso_to_epoch("2027-01-15T00:00:00+00:00")
        assert stamp is not None
        assert core.hermes_receipt_check(tmp_path, now=lambda: stamp + 1) is None

    def test_rows_for_other_plugins_do_not_match(self, tmp_path: Path) -> None:
        _write_receipt(
            tmp_path, kind="plugin-check", finished="2027-01-15T00:00:00+00:00", rows=[{**ROW, "name": "other"}]
        )
        stamp = core._iso_to_epoch("2027-01-15T00:00:00+00:00")
        assert stamp is not None
        assert core.hermes_receipt_check(tmp_path, now=lambda: stamp + 1) is None


class TestAutoCheckEnabled:
    @pytest.mark.parametrize(
        ("yaml", "expected"),
        [
            ("", True),
            ("plugins:\n  enabled: [mordred]\n", True),
            ("plugins:\n  auto_update_check_hours: 24\n", True),
            ("plugins:\n  auto_update_check_hours: 0\n", False),
            ("plugins:\n  auto_update_check_hours: false\n", False),
            ("plugins: []\n", True),
        ],
    )
    def test_reads_hermes_setting(self, tmp_path: Path, yaml: str, expected: bool) -> None:
        if yaml:
            (tmp_path / "config.yaml").write_text(yaml, encoding="utf-8")
        assert core.auto_check_enabled(tmp_path) is expected


class TestCache:
    def test_round_trip_and_expiry(self, tmp_path: Path) -> None:
        result = core.CheckResult("0.2.0a1", "0.2.0a2", True, "pypi", 1000.0)
        core.write_cache(result, tmp_path)
        path = tmp_path / "mordred" / core.CACHE_FILE_NAME
        if sys.platform != "win32":
            assert path.stat().st_mode & 0o777 == 0o600
        cached = core.read_cache(tmp_path, now=lambda: 1000.0 + core.CHECK_CACHE_SECONDS - 1)
        assert cached is not None and cached.source == "cache" and cached.latest == "0.2.0a2"
        assert core.read_cache(tmp_path, now=lambda: 1000.0 + core.CHECK_CACHE_SECONDS + 1) is None

    def test_failed_lookup_is_remembered_briefly(self, tmp_path: Path) -> None:
        core.write_cache(core.CheckResult("0.2.0a1", None, None, "pypi", 1000.0, "check failed: x"), tmp_path)
        assert core.read_cache(tmp_path, now=lambda: 1000.0 + core.FAILURE_CACHE_SECONDS - 1) is not None
        assert core.read_cache(tmp_path, now=lambda: 1000.0 + core.FAILURE_CACHE_SECONDS + 1) is None

    def test_garbage_is_ignored(self, tmp_path: Path) -> None:
        path = tmp_path / "mordred" / core.CACHE_FILE_NAME
        path.parent.mkdir()
        path.write_text("[]", encoding="utf-8")
        assert core.read_cache(tmp_path) is None
        path.write_text("{", encoding="utf-8")
        assert core.read_cache(tmp_path) is None


class TestCachedCheck:
    def test_order_receipt_cache_pypi(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(core, "installed", lambda: _installed(version="0.2.0a1"))
        calls: list[str] = []

        def fetch(url: str) -> bytes:
            calls.append(url)
            return json.dumps({"releases": _releases("0.2.0a1", "0.2.0a3")}).encode()

        clock = {"t": 1_800_000_000.0}
        first = core.cached_check(tmp_path, fetch=fetch, now=lambda: clock["t"])
        assert first is not None and first.source == "pypi" and first.latest == "0.2.0a3"
        assert calls == [core.PYPI_JSON_URL]
        clock["t"] += 3600
        second = core.cached_check(tmp_path, fetch=fetch, now=lambda: clock["t"])
        assert second is not None and second.source == "cache"
        assert len(calls) == 1  # no second request
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(clock["t"]))
        _write_receipt(tmp_path, kind="plugin-check", finished=stamp, rows=[{**ROW, "latest": "0.2.0a4"}])
        third = core.cached_check(tmp_path, fetch=fetch, now=lambda: clock["t"] + 10)
        assert third is not None and third.source == "hermes-receipt" and third.latest == "0.2.0a4"

    def test_cache_for_another_installed_version_is_not_reused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        core.write_cache(core.CheckResult("0.1.0a20", "0.2.0a1", True, "pypi", 1_800_000_000.0), tmp_path)
        monkeypatch.setattr(core, "installed", lambda: _installed(version="0.2.0a1"))
        fetch = lambda url: json.dumps({"releases": _releases("0.2.0a1")}).encode()  # noqa: E731
        result = core.cached_check(tmp_path, fetch=fetch, now=lambda: 1_800_000_000.0 + 5)
        assert result is not None and result.source == "pypi" and result.available is False

    def test_opt_out_asks_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "config.yaml").write_text("plugins:\n  auto_update_check_hours: 0\n", encoding="utf-8")
        monkeypatch.setattr(core, "installed", lambda: _installed())

        def fetch(url: str) -> bytes:
            raise AssertionError("must not contact PyPI")

        assert core.cached_check(tmp_path, fetch=fetch) is None

    def test_failure_is_cached(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(core, "installed", lambda: _installed())

        def fetch(url: str) -> bytes:
            raise OSError("offline")

        result = core.cached_check(tmp_path, fetch=fetch, now=lambda: 1_800_000_000.0)
        assert result is not None and result.latest is None and result.reason.startswith("check failed")
        assert core.read_cache(tmp_path, now=lambda: 1_800_000_000.0 + 1) is not None


# -- refusals -------------------------------------------------------------------------------


class TestRefusals:
    def test_windows(self) -> None:
        with pytest.raises(core.UpdateRefused) as info:
            core.refuse_if_unsupported(_installed(), uv=Path("/uv"), platform="win32")
        assert info.value.code == "windows"

    def test_not_a_venv(self) -> None:
        with pytest.raises(core.UpdateRefused) as info:
            core.refuse_if_unsupported(_installed(in_venv=False), uv=Path("/uv"), platform="darwin")
        assert info.value.code == "not-a-venv"

    def test_source_checkout(self) -> None:
        with pytest.raises(core.UpdateRefused) as info:
            core.refuse_if_unsupported(
                _installed(kind="path", path="/src", editable=True), uv=Path("/uv"), platform="linux"
            )
        assert info.value.code == "source-install"
        assert "--from-source" in info.value.message

    def test_pm_member_build_is_allowed(self) -> None:
        current = _installed(kind="path", path="/e/workspace/plugin-sources/mordred", from_member=True)
        core.refuse_if_unsupported(current, uv=Path("/uv"), platform="linux")

    def test_missing_uv(self) -> None:
        with pytest.raises(core.UpdateRefused) as info:
            core.refuse_if_unsupported(_installed(), uv=None, platform="linux")
        assert info.value.code == "no-uv"


def test_find_uv_prefers_path_then_hermes_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core.shutil, "which", lambda name, path=None: None)
    assert core.find_uv(tmp_path) is None
    for version in ("0.5.1", "0.7.3"):
        exe = tmp_path / "tools" / f"uv-{version}" / "uv"
        exe.parent.mkdir(parents=True)
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        exe.chmod(0o755)
    found = core.find_uv(tmp_path)
    assert found is not None and found.parent.name == "uv-0.7.3"
    monkeypatch.setattr(core.shutil, "which", lambda name, path=None: "/usr/local/bin/uv")
    assert core.find_uv(tmp_path) == Path("/usr/local/bin/uv")


def test_installed_adds_platform_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.desktop import member

    source = member.InstallSource("0.2.0a1", "pypi", None, False, ("extension",))
    monkeypatch.setattr(member, "install_source", lambda: source)
    monkeypatch.setattr(core, "_platform", lambda: "linux")
    current = core.installed()
    assert current.extras == ("extension", "keyvault")
    assert current.kind == "pypi" and current.from_member is False
    assert current.python == sys.executable


# -- apply ----------------------------------------------------------------------------------


FREEZE = """\
aiohttp==3.9.5
hermes-agent==0.22.0
hermes-mordred==0.2.0a1
mordred-hermes==0.1.0a20
-e /Users/x/hermes-agent
ruamel.yaml==0.18.6
"""


class TestApply:
    def test_sequence_mirrors_the_installer(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = FakeRunner(freeze=FREEZE, requirements="ruamel.yaml>=0.18\npsutil>=7.2.2\n")
        written: dict[str, str] = {}
        real_write = core._write_constraints

        def spy(freeze_output: str, path: Path) -> int:
            n = real_write(freeze_output, path)
            written["constraints"] = path.read_text(encoding="utf-8")
            return n

        monkeypatch.setattr(core, "_write_constraints", spy)
        monkeypatch.setattr(core, "_platform", lambda: "darwin")
        current = _installed(extras=("extension", "macos"))
        report = core.apply("0.2.0a5", current=current, uv=Path("/opt/uv"), runner=runner, home=tmp_path)

        assert report.previous == "0.2.0a1" and report.target == "0.2.0a5"
        assert report.steps == [
            "freeze",
            "install-package",
            "read-requirements",
            "install-requirements",
            "record-member",
        ]
        assert report.warnings == [] and report.member_recorded is True
        assert written["constraints"] == "aiohttp==3.9.5\nhermes-agent==0.22.0\nruamel.yaml==0.18.6\n"

        steps = [FakeRunner._step(c) for c in runner.calls]
        assert steps == [
            "check",
            "freeze",
            "install-package",
            "read-requirements",
            "install-requirements",
            "check",
            "record-member",
        ]
        install = runner.calls[2]
        assert install[:3] == ["/opt/uv", "pip", "install"]
        assert "--python" in install and install[install.index("--python") + 1] == "/env/bin/python3"
        assert "--no-python-downloads" in install and "--no-deps" in install
        assert install[install.index("--upgrade-package") + 1] == "hermes-mordred"
        assert install[-1] == f"hermes-mordred[extension,macos]==0.2.0a5,>={core.MIN_MORDRED_VERSION}"
        read = runner.calls[3]
        assert read[:3] == ["/env/bin/python3", "-I", "-c"] and read[-2:] == ["hermes-mordred", "extension,macos"]
        reqs = runner.calls[4]
        assert reqs[reqs.index("--constraint") + 1].endswith("constraints.txt")
        assert reqs[-2:] == ["ruamel.yaml>=0.18", "psutil>=7.2.2"]
        assert "--upgrade-package" not in reqs
        assert runner.calls[6][:3] == ["/env/bin/python3", "-I", "-c"]

    def test_failed_step_raises_with_tail(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, fail="install-package")
        with pytest.raises(core.UpdateFailed) as info:
            core.apply("0.2.0a5", current=_installed(), uv=Path("/opt/uv"), runner=runner, home=tmp_path)
        assert info.value.step == "install-package"
        assert info.value.output.endswith("line2")
        assert [FakeRunner._step(c) for c in runner.calls] == ["check", "freeze", "install-package"]

    def test_new_conflict_is_a_warning_only_when_it_was_clean_before(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, check_codes=[0, 1])
        report = core.apply(
            "0.2.0a5", current=_installed(), uv=Path("/opt/uv"), runner=runner, home=tmp_path, record_member=False
        )
        assert any("conflicting dependencies" in w for w in report.warnings)
        runner = FakeRunner(freeze=FREEZE, check_codes=[1, 1])
        report = core.apply(
            "0.2.0a5", current=_installed(), uv=Path("/opt/uv"), runner=runner, home=tmp_path, record_member=False
        )
        assert report.warnings == []

    def test_member_refresh_failure_is_a_warning(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, fail="record-member")
        report = core.apply("0.2.0a5", current=_installed(), uv=Path("/opt/uv"), runner=runner, home=tmp_path)
        assert report.member_recorded is False
        assert any("next start" in w for w in report.warnings)

    def test_refusals_run_before_anything_else(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE)
        with pytest.raises(core.UpdateRefused):
            core.apply(
                "0.2.0a5",
                current=_installed(kind="path", path="/src"),
                uv=Path("/opt/uv"),
                runner=runner,
                home=tmp_path,
            )
        with pytest.raises(core.UpdateRefused, match="PEP 440"):
            core.apply("latest", current=_installed(), uv=Path("/opt/uv"), runner=runner, home=tmp_path)
        assert runner.calls == []

    def test_no_requirements_skips_the_second_install(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, requirements="")
        report = core.apply(
            "0.2.0a5",
            current=_installed(extras=()),
            uv=Path("/opt/uv"),
            runner=runner,
            home=tmp_path,
            record_member=False,
        )
        assert "install-requirements" not in report.steps
        assert runner.calls[2][-1] == f"hermes-mordred==0.2.0a5,>={core.MIN_MORDRED_VERSION}"


# -- the CLI --------------------------------------------------------------------------------


class TestCli:
    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(core, "installed", lambda: _installed())
        monkeypatch.setattr(core, "find_uv", lambda home=None, env=None: Path("/opt/uv"))
        monkeypatch.setattr(core, "refuse_if_unsupported", lambda current, uv, platform=None: None)

    def test_check_reports_and_exits_10(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(core, "check", lambda **kw: core.CheckResult("0.2.0a1", "0.2.0a3", True, "pypi", 0.0))
        assert update_cli.run(update_cli.UpdateOptions(check_only=True)) == update_cli.EXIT_UPDATE_AVAILABLE
        out = capsys.readouterr().out
        assert "0.2.0a3 is available" in out and "hermes-mordred update" in out

    def test_up_to_date(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        monkeypatch.setattr(core, "check", lambda **kw: core.CheckResult("0.2.0a1", "0.2.0a1", False, "pypi", 0.0))
        assert update_cli.run(update_cli.UpdateOptions()) == update_cli.EXIT_OK
        assert "up to date" in capsys.readouterr().out

    def test_pypi_failure(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        def boom(**kw: Any) -> core.CheckResult:
            raise core.UpdateCheckFailed("offline")

        monkeypatch.setattr(core, "check", boom)
        assert update_cli.run(update_cli.UpdateOptions()) == update_cli.EXIT_FAILED
        assert "offline" in capsys.readouterr().err

    def test_non_interactive_without_yes_refuses(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(core, "check", lambda **kw: core.CheckResult("0.2.0a1", "0.2.0a3", True, "pypi", 0.0))
        applied: list[str] = []
        monkeypatch.setattr(core, "apply", lambda target, **kw: applied.append(target))
        assert update_cli.run(update_cli.UpdateOptions(interactive=False)) == update_cli.EXIT_REFUSED
        assert applied == [] and "--yes" in capsys.readouterr().err

    def test_yes_applies_and_prints_restart_hint(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(core, "check", lambda **kw: core.CheckResult("0.2.0a1", "0.2.0a3", True, "pypi", 0.0))
        seen: dict[str, Any] = {}

        def apply(target: str, **kw: Any) -> core.UpdateReport:
            seen.update(target=target, **kw)
            return core.UpdateReport("0.2.0a1", target, ("macos",), warnings=["w1"])

        monkeypatch.setattr(core, "apply", apply)
        assert update_cli.run(update_cli.UpdateOptions(yes=True, interactive=False)) == update_cli.EXIT_OK
        captured = capsys.readouterr()
        assert seen["target"] == "0.2.0a3" and seen["uv"] == Path("/opt/uv")
        assert "Updated hermes-mordred 0.2.0a1 -> 0.2.0a3." in captured.out
        assert update_cli.RESTART_HINT in captured.out and "w1" in captured.err

    def test_explicit_version_skips_pypi(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def no_check(**kw: Any) -> core.CheckResult:
            raise AssertionError("must not ask PyPI")

        monkeypatch.setattr(core, "check", no_check)
        monkeypatch.setattr(core, "apply", lambda target, **kw: core.UpdateReport("0.2.0a1", target, ()))
        assert update_cli.run(update_cli.UpdateOptions(version="0.2.0a9", yes=True)) == update_cli.EXIT_OK
        assert update_cli.run(update_cli.UpdateOptions(version="0.2.0a9", check_only=True)) == update_cli.EXIT_REFUSED

    def test_refusal_is_reported(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        monkeypatch.setattr(core, "check", lambda **kw: core.CheckResult("0.2.0a1", "0.2.0a3", True, "pypi", 0.0))

        def refuse(current: Any, uv: Any, platform: Any = None) -> None:
            raise core.UpdateRefused("windows", "no in-place updates on Windows")

        monkeypatch.setattr(core, "refuse_if_unsupported", refuse)
        assert update_cli.run(update_cli.UpdateOptions(yes=True)) == update_cli.EXIT_REFUSED
        assert "Windows" in capsys.readouterr().err

    def test_failed_apply(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        monkeypatch.setattr(core, "check", lambda **kw: core.CheckResult("0.2.0a1", "0.2.0a3", True, "pypi", 0.0))

        def apply(target: str, **kw: Any) -> core.UpdateReport:
            raise core.UpdateFailed("install-package", "resolver said no")

        monkeypatch.setattr(core, "apply", apply)
        assert update_cli.run(update_cli.UpdateOptions(yes=True)) == update_cli.EXIT_FAILED
        assert "resolver said no" in capsys.readouterr().err


def test_parser_wires_update_flags() -> None:
    from mordred_hermes.wizard.cli import _setup_subparser

    parser = argparse_parser()
    ns = parser.parse_args(["mordred", "update", "--check", "--yes", "--version", "0.2.0a9"])
    assert ns.check is True and ns.yes is True and ns.version == "0.2.0a9"
    assert ns.func.__name__ == "_handle_update"
    del _setup_subparser


def argparse_parser() -> Any:
    import argparse

    from mordred_hermes.wizard.cli import _setup_subparser

    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command")
    _setup_subparser(sub.add_parser("mordred"))
    return root
