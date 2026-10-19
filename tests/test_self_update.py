"""``hermes-mordred update``: release selection, the install sequence, refusals, caching."""

from __future__ import annotations

import json
import re
import subprocess
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
    """Records every command (argv, cwd, env, timeout); answers per step."""

    def __init__(
        self,
        freeze: str = "",
        requirements: str = "",
        closure: str | None = "aiohttp\nhermes-agent\nruamel-yaml\n",
        floor: str = ">=0.13.0\t0.22.0",
        fail: str | None = None,
        check_codes: list[int] | None = None,
        rollback_code: int = 0,
        stderr: str = "",
    ):
        self.calls: list[tuple[list[str], Path | None, dict[str, str] | None, float | None]] = []
        self.freeze = freeze
        self.requirements = requirements
        self.closure = closure
        self.floor = floor
        self.fail = fail
        self.check_codes = check_codes or [0, 0]
        self.rollback_code = rollback_code
        self.stderr = stderr

    @property
    def argvs(self) -> list[list[str]]:
        return [c[0] for c in self.calls]

    @property
    def steps(self) -> list[str]:
        return [self._step(a) for a in self.argvs]

    def __call__(self, argv: list[str], *, cwd=None, env=None, timeout=None) -> core.CommandResult:
        self.calls.append((list(argv), cwd, dict(env) if env is not None else None, timeout))
        step = self._step(argv)
        if step == self.fail:
            return core.CommandResult(1, f"boom in {step}\n", "line2\n")
        if step == "rollback":
            return core.CommandResult(self.rollback_code, "", "rollback said no\n" if self.rollback_code else "")
        if step == "check":
            return core.CommandResult(self.check_codes.pop(0) if self.check_codes else 0)
        if step == "freeze":
            return core.CommandResult(0, self.freeze, self.stderr)
        if step == "hermes-closure":
            return (
                core.CommandResult(3, "", "no hermes-agent\n")
                if self.closure is None
                else core.CommandResult(0, self.closure)
            )
        if step == "hermes-floor":
            return core.CommandResult(0, self.floor + "\n", self.stderr)
        if step == "read-requirements":
            return core.CommandResult(0, self.requirements, self.stderr)
        return core.CommandResult(0)

    @staticmethod
    def _step(argv: list[str]) -> str:
        if argv[1:3] == ["pip", "check"]:
            return "check"
        if argv[1:3] == ["pip", "freeze"]:
            return "freeze"
        if argv[1:3] == ["pip", "uninstall"]:
            return "remove-legacy"
        if argv[1:3] == ["pip", "install"] and "--reinstall-package" in argv:
            return "rollback"
        if argv[1:3] == ["pip", "install"] and "--no-deps" in argv:
            return "install-package"
        if argv[1:3] == ["pip", "install"]:
            return "install-requirements"
        if argv[1:3] == ["-I", "-c"]:
            script = argv[3]
            return {
                core._REQUIREMENTS_SCRIPT: "read-requirements",
                core._HERMES_CLOSURE_SCRIPT: "hermes-closure",
                core._HERMES_FLOOR_SCRIPT: "hermes-floor",
                core._RECORD_MEMBER_SCRIPT: "record-member",
            }[script]
        raise AssertionError(f"unexpected command {argv!r}")


# -- agreement with the installer ---------------------------------------------------------


def test_version_floor_matches_installer() -> None:
    installer = (REPO / "scripts" / "install.sh").read_text(encoding="utf-8")
    match = re.search(r'^readonly MIN_MORDRED_VERSION="([^"]+)"$', installer, re.MULTILINE)
    assert match is not None
    assert match.group(1) == core.MIN_MORDRED_VERSION


def test_requirements_script_is_the_installer_filter_minus_self_references() -> None:
    """Same filter as the installer's heredoc, plus dropping ``hermes-mordred[...]`` self-references."""
    installer = (REPO / "scripts" / "install.sh").read_text(encoding="utf-8")
    heredoc = installer.split("<<'PY' 2>/dev/null || true\n", 1)[1].split("\nPY\n", 1)[0]
    ours = (
        core._REQUIREMENTS_SCRIPT.strip()
        .replace('skip = {"hermes-agent", sys.argv[1].lower()}\n', "")
        .replace(
            'if req.name.lower().replace("_", "-") in skip:', 'if req.name.lower().replace("_", "-") == "hermes-agent":'
        )
    )
    assert ours == heredoc.strip()


def test_scripts_run_in_this_interpreter(tmp_path: Path) -> None:
    """The three ``-I -c`` scripts parse and run against real metadata."""
    import subprocess

    reqs = subprocess.run(
        [sys.executable, "-I", "-c", core._REQUIREMENTS_SCRIPT, "hermes-mordred", "keyvault"],
        capture_output=True,
        text=True,
        check=True,
    )
    names = {line.split(">=")[0].split("[")[0].lower() for line in reqs.stdout.splitlines()}
    assert "cryptography" in names and "hermes-agent" not in names and "hermes-mordred" not in names
    closure = subprocess.run(
        [sys.executable, "-I", "-c", core._HERMES_CLOSURE_SCRIPT], capture_output=True, text=True, check=False
    )
    assert closure.returncode == 0 and "hermes-agent" in closure.stdout.split() and "httpx" in closure.stdout.split()
    floor = subprocess.run(
        [sys.executable, "-I", "-c", core._HERMES_FLOOR_SCRIPT, "hermes-mordred"],
        capture_output=True,
        text=True,
        check=True,
    )
    spec, have = floor.stdout.strip().split("\t")
    assert spec.startswith(">=") and have


# -- select_latest -------------------------------------------------------------------------


class TestSelectLatest:
    def test_prerelease_user_sees_newer_prerelease_even_after_a_stable(self) -> None:
        releases = _releases("0.2.0a1", "0.2.0a2", "0.2.0", "0.3.0a1")
        assert core.select_latest(releases, "0.2.0a1") == "0.3.0a1"

    def test_stable_user_never_gets_a_prerelease(self) -> None:
        releases = _releases("0.2.0", "0.2.1", "0.3.0a1")
        assert core.select_latest(releases, "0.2.0") == "0.2.1"

    def test_stable_user_with_only_prereleases_ahead_stays_on_the_stable(self) -> None:
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


@pytest.mark.parametrize("source", ["receipt", "pypi"])
def test_deep_update_json_is_refused_with_large_recursion_limit(tmp_path: Path, source: str) -> None:
    script = """
import sys
from pathlib import Path
if sys.platform != "win32":
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
from mordred_hermes import _self_update as core
assert Path(core.__file__).resolve() == Path(sys.argv[3])
sys.setrecursionlimit(100000)
payload = "[" * 100000 + "]" * 100000
if sys.argv[1] == "receipt":
    path = Path(sys.argv[2])
    path.write_text(payload, encoding="utf-8")
    assert core._read_json(path) is None
else:
    try:
        core.fetch_releases(lambda url: payload.encode())
    except core.UpdateCheckFailed as exc:
        assert str(exc) == "PyPI answer is not JSON"
    else:
        raise AssertionError("deep PyPI JSON was not refused")
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-X",
            "faulthandler",
            "-c",
            script,
            source,
            str(tmp_path / "receipt.json"),
            str(Path(core.__file__).resolve()),
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("depth", [128, 129])
@pytest.mark.parametrize("container", ["array", "object"])
def test_update_metadata_nesting_boundary(tmp_path: Path, depth: int, container: str) -> None:
    opening, closing = ("[", "]") if container == "array" else ('{"value":', "}")
    path = tmp_path / "metadata.json"
    path.write_text(opening * depth + "0" + closing * depth, encoding="utf-8")
    value = core._read_json(path)
    if depth == 129:
        assert value is None
    else:
        for _ in range(depth):
            value = value[0] if container == "array" else value["value"]
        assert value == 0


@pytest.mark.parametrize(
    "encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"]
)
def test_release_json_preserves_encodings_and_quoted_brackets(encoding: str) -> None:
    releases = {"1.0": [{"filename": 'quoted " and slash \\ ' + "[{]}" * 200 + " 日本語"}]}
    payload = json.dumps({"releases": releases}, ensure_ascii=False).encode(encoding)
    assert core.fetch_releases(lambda url: payload) == releases


def test_receipt_json_ignores_quoted_brackets_and_escaped_quotes(tmp_path: Path) -> None:
    value = {"message": 'quoted " and slash \\ ' + "[{]}" * 200}
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(value), encoding="utf-8-sig")
    assert core._read_json(path) == value


def test_check_uses_installed_version_and_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core, "installed", lambda home=None: _installed(version="0.2.0a1"))
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
            ('plugins:\n  auto_update_check_hours: "0"\n', False),
            ('plugins:\n  auto_update_check_hours: "12"\n', True),
            ("plugins:\n  auto_update_check_hours: nonsense\n", True),
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

    def test_no_qualifying_release_is_a_day_long_answer(self, tmp_path: Path) -> None:
        core.write_cache(core.CheckResult("0.2.0a1", None, None, "pypi", 1000.0, "no release qualifies"), tmp_path)
        assert core.read_cache(tmp_path, now=lambda: 1000.0 + core.FAILURE_CACHE_SECONDS + 1) is not None

    def test_receipt_garbage_is_ignored(self, tmp_path: Path) -> None:
        _write_receipt(tmp_path, kind="plugin-check", finished="2027-01-15T00:00:00+00:00", rows=[ROW])
        directory = tmp_path / "logs" / "update_receipts"
        (directory / "pm_b.json").write_text(
            '{"kind": "plugin-check", "plugin_checks": 7, "finished_at": "2027-01-15T00:00:00+00:00"}'
        )
        (directory / "pm_c.json").write_text("[" * 100000 + "]" * 100000)
        stamp = core._iso_to_epoch("2027-01-15T00:00:00+00:00")
        assert stamp is not None
        # the newest usable plugin-check (pm_b) has no rows -> nothing, no crash
        assert core.hermes_receipt_check(tmp_path, now=lambda: stamp + 1) is None

    def test_garbage_is_ignored(self, tmp_path: Path) -> None:
        path = tmp_path / "mordred" / core.CACHE_FILE_NAME
        path.parent.mkdir()
        path.write_text("[]", encoding="utf-8")
        assert core.read_cache(tmp_path) is None
        path.write_text("{", encoding="utf-8")
        assert core.read_cache(tmp_path) is None


class TestCachedCheck:
    def test_order_receipt_cache_pypi(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(core, "installed", lambda home=None: _installed(version="0.2.0a1"))
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
        monkeypatch.setattr(core, "installed", lambda home=None: _installed(version="0.2.0a1"))
        fetch = lambda url: json.dumps({"releases": _releases("0.2.0a1")}).encode()  # noqa: E731
        result = core.cached_check(tmp_path, fetch=fetch, now=lambda: 1_800_000_000.0 + 5)
        assert result is not None and result.source == "pypi" and result.available is False

    def test_opt_out_asks_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "config.yaml").write_text("plugins:\n  auto_update_check_hours: 0\n", encoding="utf-8")
        monkeypatch.setattr(core, "installed", lambda home=None: _installed())

        def fetch(url: str) -> bytes:
            raise AssertionError("must not contact PyPI")

        assert core.cached_check(tmp_path, fetch=fetch) is None

    def test_failure_is_cached(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(core, "installed", lambda home=None: _installed())

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

    def test_foreign_source(self) -> None:
        with pytest.raises(core.UpdateRefused) as info:
            core.refuse_if_unsupported(
                _installed(foreign_source="/elsewhere/mordred_hermes"), uv=Path("/uv"), platform="darwin"
            )
        assert info.value.code == "foreign-source"

    def test_not_a_venv_wins_over_foreign_source(self) -> None:
        with pytest.raises(core.UpdateRefused) as info:
            core.refuse_if_unsupported(
                _installed(in_venv=False, foreign_source="/elsewhere/mordred_hermes"),
                uv=Path("/uv"),
                platform="darwin",
            )
        assert info.value.code == "not-a-venv"

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


@pytest.mark.parametrize("editable", [False, True])
def test_installed_adds_member_extras_for_pm_build(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, editable: bool
) -> None:
    from mordred_hermes.desktop import member

    venv = tmp_path / "environments" / "target" / "venv"
    source_dir = venv.parent / "workspace" / "plugin-sources" / "mordred"
    source_dir.mkdir(parents=True)
    venv.mkdir()
    source = member.InstallSource("0.2.0a1", "path", str(source_dir), editable, ())
    monkeypatch.setattr(member, "install_source", lambda: source)
    monkeypatch.setattr(
        member, "environment", lambda: member.Environment(str(venv / "bin" / "python"), str(venv), True)
    )
    monkeypatch.setattr(member, "running_package", lambda: source_dir / "mordred_hermes")
    monkeypatch.setattr(
        member,
        "member_status",
        lambda plugin_dir: {"present": True, "valid": True, "extras": ["extension", "telegram"]},
    )
    monkeypatch.setattr(core, "_platform", lambda: "darwin")
    current = core.installed(tmp_path)
    assert current.from_member is True and current.kind == "path"
    assert current.extras == ("extension", "macos", "telegram")
    core.refuse_if_unsupported(current, uv=Path("/uv"), platform="darwin")


@pytest.mark.parametrize("editable", [False, True])
@pytest.mark.parametrize("location", ["arbitrary", "other-environment"])
def test_installed_refuses_unmanaged_plugin_sources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, editable: bool, location: str
) -> None:
    from mordred_hermes.desktop import member

    venv = tmp_path / "environments" / "target" / "venv"
    venv.mkdir(parents=True)
    if location == "arbitrary":
        source_dir = tmp_path / "checkout" / "plugin-sources" / "mordred"
    else:
        source_dir = tmp_path / "environments" / "other" / "workspace" / "plugin-sources" / "mordred"
    source_dir.mkdir(parents=True)
    source = member.InstallSource("0.2.0a1", "path", str(source_dir), editable, ())
    monkeypatch.setattr(member, "install_source", lambda: source)
    monkeypatch.setattr(
        member, "environment", lambda: member.Environment(str(venv / "bin" / "python"), str(venv), True)
    )
    monkeypatch.setattr(member, "running_package", lambda: source_dir / "src" / "mordred_hermes")
    current = core.installed(tmp_path)
    with pytest.raises(core.UpdateRefused) as info:
        core.refuse_if_unsupported(current, uv=Path("/uv"), platform="linux")
    assert info.value.code == "source-install"
    assert current.from_member is False and current.foreign_source is None


def test_installed_adds_platform_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.desktop import member

    source = member.InstallSource("0.2.0a1", "pypi", None, False, ("extension",))
    monkeypatch.setattr(member, "install_source", lambda: source)
    monkeypatch.setattr(core, "_platform", lambda: "linux")
    current = core.installed()
    assert current.extras == ("extension", "keyvault")
    assert current.kind == "pypi" and current.from_member is False
    assert current.python == sys.executable


def test_installed_carries_environment_and_foreign_source(monkeypatch: pytest.MonkeyPatch) -> None:
    from mordred_hermes.desktop import member

    source = member.InstallSource(
        "0.2.0a1", "pypi", None, False, ("extension",), "/pm/venv/lib/python3.14/site-packages"
    )
    monkeypatch.setattr(member, "install_source", lambda: source)
    monkeypatch.setattr(member, "environment", lambda: member.Environment("/pm/venv/bin/python", "/pm/venv", True))
    monkeypatch.setattr(
        member, "foreign_source", lambda src, env=None: "/stray/mordred_hermes" if src is source and env else None
    )
    monkeypatch.setattr(core, "_platform", lambda: "linux")
    current = core.installed()
    assert current.python == "/pm/venv/bin/python" and current.in_venv is True
    assert current.foreign_source == "/stray/mordred_hermes"


class TestUpdateView:
    @pytest.fixture(autouse=True)
    def _api(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pytest.importorskip("fastapi")
        monkeypatch.setattr(core, "find_uv", lambda home=None: Path("/uv"))
        monkeypatch.setattr(core, "_platform", lambda: "linux")

    def test_foreign_source_refuses_and_offers_no_restart(self) -> None:
        from mordred_hermes.desktop import api

        view = api._update_view(None, current=_installed(version="0.2.0a1", foreign_source="/elsewhere"))
        assert view["restart_required"] is False
        assert view["foreign_source"] == "/elsewhere"
        assert view["supported"] is False
        assert view["refusal"]["code"] == "update_foreign_source"

    def test_version_difference_requires_restart_without_foreign_source(self) -> None:
        from mordred_hermes import __version__
        from mordred_hermes.desktop import api

        other = "0.0.1a0" if __version__ != "0.0.1a0" else "0.0.2a0"
        view = api._update_view(None, current=_installed(version=other, foreign_source=None))
        assert view["restart_required"] is True and view["foreign_source"] is None
        assert view["supported"] is True

    def test_unreadable_metadata_has_no_foreign_source(self) -> None:
        from mordred_hermes.desktop import api

        view = api._update_view(None, current=None)
        assert view["foreign_source"] is None and view["restart_required"] is False


# -- apply ----------------------------------------------------------------------------------


FREEZE = """\
aiohttp==3.9.5
hermes-agent==0.22.0
hermes-mordred==0.2.0a1
-e /Users/x/hermes-agent
ruamel.yaml==0.18.6
telethon==1.40.0
"""


def _apply(runner: FakeRunner, tmp_path: Path, **kw: Any) -> core.UpdateReport:
    kw.setdefault("current", _installed(extras=("extension", "macos")))
    kw.setdefault("uv", Path("/opt/uv"))
    return core.apply("0.2.0a5", runner=runner, home=tmp_path, **kw)


class TestApply:
    @pytest.fixture(autouse=True)
    def posix_update_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(core, "_platform", lambda: "linux")

    def test_sequence_mirrors_the_installer(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, requirements="ruamel.yaml>=0.18\ntelethon>=1.42\n")
        constraints: dict[str, str] = {}

        def spy(argv, *, cwd=None, env=None, timeout=None):
            if "--constraint" in argv:
                constraints["text"] = Path(argv[argv.index("--constraint") + 1]).read_text(encoding="utf-8")
            return FakeRunner.__call__(runner, argv, cwd=cwd, env=env, timeout=timeout)

        report = _apply(spy, tmp_path)  # type: ignore[arg-type]
        assert report.previous == "0.2.0a1" and report.target == "0.2.0a5"
        assert report.steps == [
            "freeze",
            "install-package",
            "hermes-floor",
            "read-requirements",
            "install-requirements",
            "record-member",
        ]
        assert report.warnings == [] and report.member_recorded is True
        # Only Hermes's closure is pinned: telethon (Mordred's) stays free to move.
        assert constraints["text"] == "aiohttp==3.9.5\nhermes-agent==0.22.0\nruamel.yaml==0.18.6\n"

        assert runner.steps == [
            "freeze",
            "hermes-closure",
            "check",
            "install-package",
            "hermes-floor",
            "read-requirements",
            "install-requirements",
            "check",
            "record-member",
        ]
        install = runner.argvs[3]
        assert Path(install[0]) == Path("/opt/uv")
        assert install[1:3] == ["pip", "install"] and "--no-config" in install
        assert install[install.index("--python") + 1] == "/env/bin/python3"
        assert "--no-python-downloads" in install and "--no-deps" in install
        assert install[install.index("--upgrade-package") + 1] == "hermes-mordred"
        assert install[-1] == f"hermes-mordred[extension,macos]==0.2.0a5,>={core.MIN_MORDRED_VERSION}"
        read = runner.argvs[5]
        assert read[:3] == ["/env/bin/python3", "-I", "-c"] and read[-2:] == ["hermes-mordred", "extension,macos"]
        reqs = runner.argvs[6]
        assert reqs[-2:] == ["ruamel.yaml>=0.18", "telethon>=1.42"] and "--upgrade-package" not in reqs
        assert runner.argvs[8][:3] == ["/env/bin/python3", "-I", "-c"]

    def test_commands_are_isolated_from_the_working_directory(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE)
        _apply(runner, tmp_path)
        for argv, cwd, _env, timeout in runner.calls:
            assert cwd is not None and cwd.name.startswith("mordred-update-"), argv
            assert timeout is not None and timeout > 0, argv
            if Path(argv[0]) == Path("/opt/uv"):
                assert "--no-config" in argv, argv
            else:
                assert argv[1] == "-I", argv
        record = runner.calls[-1]
        assert record[2] is not None and record[2]["HERMES_HOME"] == str(tmp_path)
        assert runner.calls[3][3] == core.INSTALL_TIMEOUT_SECONDS and runner.calls[0][3] == core.QUICK_TIMEOUT_SECONDS

    def test_stderr_never_becomes_a_requirement(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, requirements="psutil>=7.2.2\n", stderr="Error processing line 1 of x.pth\n")
        _apply(runner, tmp_path)
        reqs = runner.argvs[runner.steps.index("install-requirements")]
        assert reqs[-1] == "psutil>=7.2.2" and not any("pth" in a for a in reqs)

    def test_unknown_closure_pins_everything_with_a_warning(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, requirements="telethon>=1.42\n", closure=None)
        seen: dict[str, str] = {}

        def spy(argv, *, cwd=None, env=None, timeout=None):
            if "--constraint" in argv:
                seen["text"] = Path(argv[argv.index("--constraint") + 1]).read_text(encoding="utf-8")
            return runner(argv, cwd=cwd, env=env, timeout=timeout)

        report = _apply(spy, tmp_path)  # type: ignore[arg-type]
        assert seen["text"] == "aiohttp==3.9.5\nhermes-agent==0.22.0\nruamel.yaml==0.18.6\ntelethon==1.40.0\n"
        assert any("closure" in w for w in report.warnings)

    def test_legacy_package_is_removed_before_the_install(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE + "mordred-hermes==0.1.0a15\n")
        _apply(runner, tmp_path, record_member=False)
        steps = runner.steps
        assert steps.index("remove-legacy") < steps.index("install-package")
        assert runner.argvs[steps.index("remove-legacy")][-1] == "mordred-hermes"

    def test_failure_before_the_swap_has_nothing_to_undo(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, fail="install-package")
        with pytest.raises(core.UpdateFailed) as info:
            _apply(runner, tmp_path)
        assert info.value.step == "install-package" and info.value.rolled_back is None
        assert info.value.output.endswith("line2")
        assert "rollback" not in runner.steps

    def test_failure_after_the_swap_rolls_back(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, requirements="telethon>=1.42\n", fail="install-requirements")
        with pytest.raises(core.UpdateFailed) as info:
            _apply(runner, tmp_path)
        assert info.value.step == "install-requirements" and info.value.rolled_back is True
        back = runner.argvs[runner.steps.index("rollback")]
        assert "--no-deps" in back and back[back.index("--reinstall-package") + 1] == "hermes-mordred"
        assert back[-1] == "hermes-mordred[extension,macos]==0.2.0a1"  # no floor: the old release must come back
        assert "record-member" not in runner.steps

    def test_legacy_removal_arms_the_rollback(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE + "mordred-hermes==0.1.0a15\n", fail="install-package")
        with pytest.raises(core.UpdateFailed) as info:
            _apply(runner, tmp_path)
        assert info.value.rolled_back is True  # the legacy package owned the same files
        assert runner.steps.index("rollback") > runner.steps.index("install-package")

    def test_missing_executable_is_a_failed_step_with_rollback(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, requirements="x>=1\n")

        def flaky(argv, *, cwd=None, env=None, timeout=None):
            if FakeRunner._step(argv) == "install-requirements":
                return core._default_runner(["/nonexistent/uv", "pip", "install"], cwd=cwd, timeout=timeout)
            return runner(argv, cwd=cwd, env=env, timeout=timeout)

        with pytest.raises(core.UpdateFailed) as info:
            _apply(flaky, tmp_path)  # type: ignore[arg-type]
        assert info.value.step == "install-requirements" and "cannot run /nonexistent/uv" in info.value.output
        assert info.value.rolled_back is True

    def test_failed_rollback_is_reported(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, requirements="x>=1\n", fail="install-requirements", rollback_code=1)
        with pytest.raises(core.UpdateFailed) as info:
            _apply(runner, tmp_path)
        assert info.value.rolled_back is False and "rollback said no" in info.value.rollback_output

    def test_hermes_floor_unmet_restores_and_refuses(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, floor=">=0.30.0\t0.22.0")
        with pytest.raises(core.UpdateRefused) as info:
            _apply(runner, tmp_path)
        assert info.value.code == "hermes-too-old" and info.value.rolled_back is True
        assert "hermes-agent>=0.30.0" in info.value.message and "0.22.0" in info.value.message
        assert "previous release restored" in info.value.message
        assert "rollback" in runner.steps and "read-requirements" not in runner.steps

    def test_hermes_floor_unmet_with_failed_rollback_says_so(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, floor=">=0.30.0\t0.22.0", rollback_code=1)
        with pytest.raises(core.UpdateRefused) as info:
            _apply(runner, tmp_path)
        assert info.value.rolled_back is False and "FAILED" in info.value.message

    @pytest.mark.parametrize(
        ("line", "unmet"),
        [
            (">=0.13.0\t0.22.0", False),
            (">=0.13.0\t0.0.0", True),
            (">=0.13.0\t", True),
            ("\t0.22.0", False),
            (">=0.30.0a1\t0.30.0a2", False),
            ("garbage\t0.22.0", False),
            (">=0.13.0\tunknown", True),
        ],
    )
    def test_hermes_floor_rule(self, line: str, unmet: bool) -> None:
        assert (core._hermes_floor_unmet(line) is not None) is unmet

    def test_hermes_floor_placeholder_version_is_undetermined_not_too_old(self) -> None:
        message = core._hermes_floor_unmet(">=0.13.0\t0.0.0")
        assert message is not None and "no Hermes version could be determined" in message
        assert "update Hermes first" not in message

    def test_hermes_floor_script_reads_hermes_real_version(self, tmp_path: Path) -> None:
        """A source / Desktop Hermes is distribution 0.0.0; the probe asks hermes_cli.version_info."""
        site = tmp_path / "site"
        (site / "hermes_cli").mkdir(parents=True)
        (site / "hermes_cli" / "__init__.py").write_text('__version__ = "0.0.0"\n', encoding="utf-8")
        (site / "hermes_cli" / "version_info.py").write_text(
            "class _Info:\n    base_version = '0.22.0'\n\ndef get_version_info():\n    return _Info()\n",
            encoding="utf-8",
        )
        dists = (("hermes_agent-0.0.0", ""), ("hermes_mordred-0.3.0a2", "Requires-Dist: hermes-agent>=0.13.0\n"))
        for name, requires in dists:
            info = site / f"{name}.dist-info"
            info.mkdir()
            dist, _, version = name.partition("-")
            header = f"Metadata-Version: 2.1\nName: {dist.replace('_', '-')}\nVersion: {version}\n"
            info.joinpath("METADATA").write_text(header + requires, encoding="utf-8")
        script = f"import sys; sys.path.insert(0, {str(site)!r})\n" + core._HERMES_FLOOR_SCRIPT
        done = subprocess.run([sys.executable, "-I", "-c", script, "hermes-mordred"], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        assert done.stdout == ">=0.13.0\t0.22.0\n"
        assert core._hermes_floor_unmet(done.stdout) is None

    def test_new_conflict_is_a_warning_only_when_it_was_clean_before(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, check_codes=[0, 1])
        report = _apply(runner, tmp_path, record_member=False)
        assert any("conflicting dependencies" in w for w in report.warnings)
        runner = FakeRunner(freeze=FREEZE, check_codes=[1, 1])
        report = _apply(runner, tmp_path, record_member=False)
        assert report.warnings == []

    def test_member_refresh_failure_is_a_warning(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, fail="record-member")
        report = _apply(runner, tmp_path)
        assert report.member_recorded is False
        assert any("next start" in w for w in report.warnings)

    def test_refusals_run_before_anything_else(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE)
        with pytest.raises(core.UpdateRefused):
            _apply(runner, tmp_path, current=_installed(kind="path", path="/src"))
        with pytest.raises(core.UpdateRefused, match="PEP 440"):
            core.apply("latest", current=_installed(), uv=Path("/opt/uv"), runner=runner, home=tmp_path)
        assert runner.calls == []

    def test_no_requirements_skips_the_second_install(self, tmp_path: Path) -> None:
        runner = FakeRunner(freeze=FREEZE, requirements="")
        report = _apply(runner, tmp_path, current=_installed(extras=()), record_member=False)
        assert "install-requirements" not in report.steps
        assert runner.argvs[3][-1] == f"hermes-mordred==0.2.0a5,>={core.MIN_MORDRED_VERSION}"


def test_default_runner_reports_a_missing_executable() -> None:
    result = core._default_runner(["/nonexistent/uv", "pip", "check"], timeout=5)
    assert result.code == 127 and "cannot run /nonexistent/uv" in result.stderr


def test_check_and_cached_check_reuse_a_given_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_walk(home=None):
        raise AssertionError("installed() must not be called when current is given")

    monkeypatch.setattr(core, "installed", no_walk)
    fetch = lambda url: json.dumps({"releases": _releases("0.2.0a1", "0.2.0a2")}).encode()  # noqa: E731
    result = core.check(fetch=fetch, now=lambda: 1.0, current=_installed(version="0.2.0a1"))
    assert result.latest == "0.2.0a2" and result.installed == "0.2.0a1"
    cached = core.cached_check(tmp_path, fetch=fetch, now=lambda: 1.0, current=_installed(version="0.2.0a1"))
    assert cached is not None and cached.source == "pypi"


def test_default_runner_times_out_cleanly() -> None:
    result = core._default_runner([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.2)
    assert result.code == 124 and "timed out" in result.stderr


# -- the CLI --------------------------------------------------------------------------------


class TestCli:
    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(core, "installed", lambda home=None: _installed())
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

    def test_refusal_is_reported_before_pypi_is_asked(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        asked: list[int] = []

        def check(**kw: Any) -> core.CheckResult:
            asked.append(1)
            return core.CheckResult("0.2.0a1", "0.2.0a3", True, "pypi", 0.0)

        monkeypatch.setattr(core, "check", check)

        def refuse(current: Any, uv: Any, platform: Any = None) -> None:
            raise core.UpdateRefused("windows", "no in-place updates on Windows")

        monkeypatch.setattr(core, "refuse_if_unsupported", refuse)
        assert update_cli.run(update_cli.UpdateOptions(yes=True)) == update_cli.EXIT_REFUSED
        assert "Windows" in capsys.readouterr().err and asked == []
        # --check is read-only and still works where an in-place update cannot run.
        assert update_cli.run(update_cli.UpdateOptions(check_only=True)) == update_cli.EXIT_UPDATE_AVAILABLE
        assert asked == [1]

    @pytest.mark.parametrize(
        ("rolled_back", "expect"),
        [(None, "was not replaced"), (True, "was reinstalled"), (False, "FAILED as well")],
    )
    def test_failed_apply_says_what_state_was_left(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], rolled_back: bool | None, expect: str
    ) -> None:
        monkeypatch.setattr(core, "check", lambda **kw: core.CheckResult("0.2.0a1", "0.2.0a3", True, "pypi", 0.0))

        def apply(target: str, **kw: Any) -> core.UpdateReport:
            raise core.UpdateFailed(
                "install-package", "resolver said no", rolled_back=rolled_back, rollback_output="rb"
            )

        monkeypatch.setattr(core, "apply", apply)
        assert update_cli.run(update_cli.UpdateOptions(yes=True)) == update_cli.EXIT_FAILED
        err = capsys.readouterr().err
        assert "resolver said no" in err and expect in err

    def test_interactive_prompt_accepts_yes_and_declines_otherwise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(core, "check", lambda **kw: core.CheckResult("0.2.0a1", "0.2.0a3", True, "pypi", 0.0))
        applied: list[str] = []
        monkeypatch.setattr(
            core, "apply", lambda target, **kw: applied.append(target) or core.UpdateReport("0.2.0a1", target, ())
        )
        monkeypatch.setattr("builtins.input", lambda prompt: "n")
        assert update_cli.run(update_cli.UpdateOptions(interactive=True)) == update_cli.EXIT_REFUSED
        monkeypatch.setattr("builtins.input", lambda prompt: "Y")
        assert update_cli.run(update_cli.UpdateOptions(interactive=True)) == update_cli.EXIT_OK
        assert applied == ["0.2.0a3"]


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
