"""Update the installed ``hermes-mordred`` package in place.

This is the Python twin of ``scripts/install.sh``'s install step, used by
``hermes-mordred update`` and by the Hermes Desktop page's **Update Mordred**
button. It never installs a fresh Mordred: it moves an existing PyPI install
inside the environment this process runs in to a newer release, keeping the
same feature extras and never moving a package Hermes itself pins.

The sequence mirrors the installer so the two cannot drift in what they
leave behind:

1. ``uv pip freeze`` the environment into a constraints file (every package
   Hermes already has, pinned to its installed version; Mordred's own
   distributions excluded).
2. Install the new ``hermes-mordred[<extras>]==<version>`` with ``--no-deps``
   so resolving its ``hermes-agent`` requirement cannot re-resolve Hermes.
3. Install Mordred's own requirements for those extras (read from the *new*
   metadata in a fresh interpreter) under the constraints from step 1.
4. ``uv pip check`` and warn when the install introduced a conflict.
5. Best-effort: run the plugin's start-time placement (``ensure_page`` +
   ``ensure_member``) in a fresh interpreter so the new code records itself
   as the package-manager member (``desktop/member.py``) before the next
   Hermes rebuild; the plugin would do the same at its next start anyway.

Network policy: PyPI is contacted only by :func:`check` (an explicit user
action) and by :func:`cached_check` when no fresh answer exists, at most once
per :data:`CHECK_CACHE_SECONDS`, and never when the user disabled Hermes's own
plugin update check (``plugins.auto_update_check_hours: 0``). Hermes's own
daily plugin-check receipt is preferred to a request of our own whenever it
is fresh. Requests inherit the proxy environment the network runtime wrote,
so they follow the active Tor / VPN path.

Refusals (:class:`UpdateRefused`) cover Windows (file locks; the Windows
installer is the supported path), installs from a local checkout (``kind ==
"path"`` that is not pm's build of the member), a missing ``uv``, and a
process that is not running inside a virtual environment.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.request import Request, urlopen

from packaging.version import InvalidVersion, Version

from ._home import hermes_home

_LOG = logging.getLogger(__name__)

DISTRIBUTION: Final = "hermes-mordred"
LEGACY_DISTRIBUTION: Final = "mordred-hermes"
#: The Hermes entry-point name Mordred registers under (pyproject
#: ``[project.entry-points."hermes_agent.plugins"]``); Hermes's plugin-check
#: receipt rows carry this name, not the distribution name.
PLUGIN_ENTRY_NAME: Final = "mordred"
#: Keep in sync with ``readonly MIN_MORDRED_VERSION`` in ``scripts/install.sh``
#: (``tests/test_self_update.py`` asserts agreement). It keeps the permanent
#: ``0.0.0.dev0`` reservation stub from ever replacing a working install.
MIN_MORDRED_VERSION: Final = "0.1.0a16"
PYPI_JSON_URL: Final = f"https://pypi.org/pypi/{DISTRIBUTION}/json"
FETCH_TIMEOUT_SECONDS: Final = 10.0
MAX_FETCH_BYTES: Final = 4 * 1024 * 1024
#: How long a successful answer (ours or Hermes's receipt) is reused.
CHECK_CACHE_SECONDS: Final = 24 * 3600
#: How long a failed lookup is remembered before asking PyPI again.
FAILURE_CACHE_SECONDS: Final = 3600
CACHE_FILE_NAME: Final = "update-check.json"
RECEIPTS_DIR: Final = ("logs", "update_receipts")
_PLATFORM_EXTRA: Final[dict[str, str]] = {"darwin": "macos", "linux": "keyvault"}
_FROZEN_PIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[^ ]+$")


class UpdateRefused(Exception):
    """The update cannot run here; ``code`` is stable for callers, ``message`` for people."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class UpdateCheckFailed(Exception):
    """PyPI could not be asked (network, HTTP, malformed answer)."""


class UpdateFailed(Exception):
    """A step of the install sequence failed; ``output`` holds uv's tail."""

    def __init__(self, step: str, output: str) -> None:
        super().__init__(f"{step} failed")
        self.step = step
        self.output = output


# -- what is installed -------------------------------------------------------------------


@dataclass(frozen=True)
class Installed:
    version: str
    kind: str  # "pypi" | "path"
    path: str | None
    editable: bool
    extras: tuple[str, ...]
    from_member: bool
    python: str
    in_venv: bool


def _platform() -> str:
    return sys.platform


def platform_extra(platform: str | None = None) -> str | None:
    return _PLATFORM_EXTRA.get(platform or _platform())


def installed() -> Installed:
    """The running Mordred: version, origin and the extras it was installed with."""
    from .desktop import member

    source = member.install_source()
    extras = set(source.extras)
    extra = platform_extra()
    if extra:
        # The installer always adds the platform extra; a partial environment
        # (a missing optional wheel) must not drop it on update.
        extras.add(extra)
    return Installed(
        version=source.version,
        kind=source.kind,
        path=source.path,
        editable=source.editable,
        extras=tuple(sorted(extras)),
        from_member=member.built_from_member(source),
        python=sys.executable,
        in_venv=sys.prefix != sys.base_prefix,
    )


# -- which release is newest -------------------------------------------------------------


def _parse(version: str) -> Version | None:
    try:
        return Version(version)
    except InvalidVersion:
        return None


def select_latest(
    releases: Mapping[str, Any],
    installed_version: str,
    *,
    floor: str = MIN_MORDRED_VERSION,
) -> str | None:
    """The newest release in *releases* (PyPI's ``releases`` map) worth offering.

    Pre-releases are offered only to an install that already runs one, so a
    stable user never gets an alpha, and an alpha user keeps seeing newer
    alphas after a stable exists (PyPI's ``info.version`` would hide them).
    Releases with no files, or whose files are all yanked, and anything below
    *floor* are skipped. ``None`` when nothing qualifies.
    """
    current = _parse(installed_version)
    allow_pre = current is not None and current.is_prerelease
    minimum = _parse(floor)
    best: Version | None = None
    for text, files in releases.items():
        candidate = _parse(text)
        if candidate is None:
            continue
        if candidate.is_prerelease and not allow_pre:
            continue
        if minimum is not None and candidate < minimum:
            continue
        if not isinstance(files, list) or not files:
            continue
        if all(isinstance(f, dict) and f.get("yanked") for f in files):
            continue
        if best is None or candidate > best:
            best = candidate
    return str(best) if best is not None else None


def is_newer(latest: str | None, current: str) -> bool | None:
    """``None`` when either version cannot be compared."""
    if latest is None:
        return None
    a, b = _parse(latest), _parse(current)
    if a is None or b is None:
        return None
    return a > b


Fetch = Callable[[str], bytes]


def _default_fetch(url: str) -> bytes:
    request = Request(url, headers={"Accept": "application/json", "User-Agent": f"{DISTRIBUTION}-update"})
    with urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        return bytes(response.read(MAX_FETCH_BYTES + 1))


def fetch_releases(fetch: Fetch | None = None) -> dict[str, Any]:
    """PyPI's ``releases`` map for Mordred; raises :class:`UpdateCheckFailed`."""
    try:
        raw = (fetch or _default_fetch)(PYPI_JSON_URL)
    except Exception as exc:
        raise UpdateCheckFailed(f"{type(exc).__name__}: {exc}") from exc
    if len(raw) > MAX_FETCH_BYTES:
        raise UpdateCheckFailed("PyPI answer too large")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise UpdateCheckFailed("PyPI answer is not JSON") from exc
    releases = data.get("releases") if isinstance(data, dict) else None
    if not isinstance(releases, dict):
        raise UpdateCheckFailed("PyPI answer has no releases")
    return releases


@dataclass(frozen=True)
class CheckResult:
    installed: str
    latest: str | None
    available: bool | None
    source: str  # "pypi" | "hermes-receipt" | "cache"
    checked_at: float
    reason: str = ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def check(*, fetch: Fetch | None = None, now: Callable[[], float] = time.time) -> CheckResult:
    """Ask PyPI now (an explicit user action)."""
    current = installed().version
    releases = fetch_releases(fetch)
    latest = select_latest(releases, current)
    available = is_newer(latest, current)
    reason = "" if latest is not None else "no release qualifies"
    return CheckResult(current, latest, available, "pypi", now(), reason)


# -- reusing Hermes's own answer, and caching ours -------------------------------------


def _iso_to_epoch(text: Any) -> float | None:
    from datetime import datetime

    if not isinstance(text, str):
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def hermes_receipt_check(
    home: Path | None = None,
    *,
    now: Callable[[], float] = time.time,
    max_age: float = CHECK_CACHE_SECONDS,
) -> CheckResult | None:
    """Mordred's row from Hermes's newest ``plugin-check`` receipt, when fresh.

    Hermes (``hermes_cli/plugins_cadence.py``) compares every pip plugin with
    PyPI at gateway start and every ``plugins.auto_update_check_hours``; its
    receipts live under ``<home>/logs/update_receipts/``. Reusing that answer
    spares a request of our own. ``None`` when there is no fresh usable row.
    """
    base = home or hermes_home()
    directory = base.joinpath(*RECEIPTS_DIR)
    try:
        names = sorted(
            (p for p in directory.iterdir() if p.name.startswith("pm_") and p.suffix == ".json"), reverse=True
        )
    except OSError:
        return None
    for path in names[:40]:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or data.get("kind") != "plugin-check":
            continue
        stamp = _iso_to_epoch(data.get("finished_at")) or _iso_to_epoch(data.get("started_at"))
        if stamp is None or now() - stamp > max_age:
            return None  # the newest plugin-check is stale; older ones are staler
        for row in data.get("plugin_checks") or []:
            if not isinstance(row, dict) or row.get("name") != PLUGIN_ENTRY_NAME or row.get("class") != "pip":
                continue
            current, latest = row.get("current"), row.get("latest")
            if not isinstance(current, str) or not isinstance(latest, str):
                return None
            if _channel_mismatch(latest, current):
                # Hermes reads PyPI's ``info.version`` (stable-only once a stable
                # exists); a pre-release user needs our own channel-aware lookup.
                return None
            return CheckResult(current, latest, is_newer(latest, current), "hermes-receipt", stamp)
        return None
    return None


def _channel_mismatch(latest: str, current: str) -> bool:
    a, b = _parse(latest), _parse(current)
    return a is not None and b is not None and b.is_prerelease and not a.is_prerelease


def auto_check_enabled(home: Path | None = None) -> bool:
    """Hermes's ``plugins.auto_update_check_hours: 0`` also opts out of our check."""
    from ._yaml_io import load_yaml_mapping

    config = load_yaml_mapping((home or hermes_home()) / "config.yaml")
    plugins = config.get("plugins")
    if not isinstance(plugins, dict):
        return True
    hours = plugins.get("auto_update_check_hours")
    if isinstance(hours, bool):
        return hours
    if isinstance(hours, int | float):
        return hours > 0
    return True


def _cache_path(home: Path) -> Path:
    return home / "mordred" / CACHE_FILE_NAME


def read_cache(home: Path | None = None, *, now: Callable[[], float] = time.time) -> CheckResult | None:
    path = _cache_path(home or hermes_home())
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        result = CheckResult(
            installed=str(data["installed"]),
            latest=data.get("latest") if isinstance(data.get("latest"), str) else None,
            available=data.get("available") if isinstance(data.get("available"), bool) else None,
            source="cache",
            checked_at=float(data["checked_at"]),
            reason=str(data.get("reason") or ""),
        )
    except (KeyError, TypeError, ValueError):
        return None
    ttl = CHECK_CACHE_SECONDS if result.reason == "" else FAILURE_CACHE_SECONDS
    if now() - result.checked_at > ttl or result.checked_at > now() + 60:
        return None
    return result


def write_cache(result: CheckResult, home: Path | None = None) -> None:
    path = _cache_path(home or hermes_home())
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(result.to_json()), encoding="utf-8")
        tmp.chmod(0o600)
        os.replace(tmp, path)
    except OSError:
        _LOG.debug("update-check cache write failed", exc_info=True)


def cached_check(
    home: Path | None = None,
    *,
    fetch: Fetch | None = None,
    now: Callable[[], float] = time.time,
) -> CheckResult | None:
    """The answer for a page that merely wants to know, with no fresh request if avoidable.

    Order: Hermes's fresh receipt, then our cache, then (only when the user has
    not disabled Hermes's own check) one request, cached. ``None`` means
    nothing is known and nothing was asked.
    """
    base = home or hermes_home()
    current = installed().version
    receipt = hermes_receipt_check(base, now=now)
    if receipt is not None and receipt.installed == current:
        return receipt
    cached = read_cache(base, now=now)
    if cached is not None and cached.installed == current:
        return cached
    if not auto_check_enabled(base):
        return None
    try:
        result = check(fetch=fetch, now=now)
    except UpdateCheckFailed as exc:
        result = CheckResult(current, None, None, "pypi", now(), f"check failed: {exc}")
    write_cache(result, base)
    return result


# -- applying -----------------------------------------------------------------------------


@dataclass
class CommandResult:
    code: int
    output: str


Runner = Callable[[list[str]], CommandResult]


def _default_runner(argv: list[str]) -> CommandResult:
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    output = (proc.stdout or "") + (proc.stderr or "")
    return CommandResult(proc.returncode, output)


def find_uv(home: Path | None = None, *, env: Mapping[str, str] | None = None) -> Path | None:
    """``uv`` on PATH, else the newest one Hermes Desktop ships under ``<home>/tools``."""
    found = shutil.which("uv", path=(env or os.environ).get("PATH"))
    if found:
        return Path(found)
    candidates = sorted((home or hermes_home()).glob("tools/uv-*/uv"))
    for candidate in reversed(candidates):
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def _tail(text: str, lines: int = 30) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


@dataclass
class UpdateReport:
    previous: str
    target: str
    extras: tuple[str, ...]
    steps: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    member_recorded: bool = False

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


_REQUIREMENTS_SCRIPT = """\
import sys
from importlib.metadata import requires
from packaging.requirements import Requirement

extras = {e for e in sys.argv[2].split(",") if e}
for line in requires(sys.argv[1]) or []:
    req = Requirement(line)
    if req.name.lower().replace("_", "-") == "hermes-agent":
        continue
    if req.marker is None or any(req.marker.evaluate({"extra": e}) for e in extras | {""}):
        req.marker = None
        print(req)
"""


def refuse_if_unsupported(current: Installed, *, uv: Path | None, platform: str | None = None) -> None:
    """Every reason an in-place update must not run here, in the order a person would check."""
    if (platform or _platform()) == "win32":
        raise UpdateRefused(
            "windows",
            "In-place updates are not supported on Windows. Rerun the Windows installer, "
            "keeping the existing Hermes home and custody keys, then restart Hermes.",
        )
    if not current.in_venv:
        raise UpdateRefused(
            "not-a-venv", f"{current.python} is not inside a virtual environment; refusing to modify it."
        )
    if current.kind == "path" and not current.from_member:
        how = "editable checkout" if current.editable else "local checkout"
        raise UpdateRefused(
            "source-install",
            f"Mordred was installed from a {how} ({current.path}); update it with "
            "scripts/install.sh --from-source <checkout> instead.",
        )
    if uv is None:
        raise UpdateRefused(
            "no-uv", "uv was not found on PATH or under <hermes home>/tools; install uv or reload the shell."
        )


def _run(runner: Runner, step: str, argv: list[str], report: UpdateReport) -> CommandResult:
    _LOG.info("update step %s: %s", step, " ".join(argv))
    result = runner(argv)
    if result.code != 0:
        raise UpdateFailed(step, _tail(result.output))
    report.steps.append(step)
    return result


def _write_constraints(freeze_output: str, path: Path) -> int:
    pins = [
        line.strip()
        for line in freeze_output.splitlines()
        if _FROZEN_PIN_RE.match(line.strip())
        and not line.strip().lower().startswith((f"{DISTRIBUTION}==", f"{LEGACY_DISTRIBUTION}=="))
    ]
    path.write_text("\n".join(pins) + ("\n" if pins else ""), encoding="utf-8")
    return len(pins)


def apply(
    target: str,
    *,
    current: Installed | None = None,
    uv: Path | None = None,
    runner: Runner | None = None,
    home: Path | None = None,
    record_member: bool = True,
) -> UpdateReport:
    """Move the install in this environment to *target*; see the module docstring."""
    current = current or installed()
    base = home or hermes_home()
    uv = uv or find_uv(base)
    refuse_if_unsupported(current, uv=uv)
    assert uv is not None  # refuse_if_unsupported raised otherwise
    run = runner or _default_runner
    if _parse(target) is None:
        raise UpdateRefused("bad-version", f"not a PEP 440 version: {target!r}")
    extras = ",".join(current.extras)
    spec = (
        f"{DISTRIBUTION}[{extras}]=={target},>={MIN_MORDRED_VERSION}"
        if extras
        else f"{DISTRIBUTION}=={target},>={MIN_MORDRED_VERSION}"
    )
    report = UpdateReport(previous=current.version, target=target, extras=current.extras)
    python = current.python
    common = ["--python", python, "--no-python-downloads"]

    was_consistent = run([str(uv), "pip", "check", "--python", python]).code == 0
    with tempfile.TemporaryDirectory(prefix="mordred-update-") as tmp:
        constraints = Path(tmp) / "constraints.txt"
        freeze = _run(run, "freeze", [str(uv), "pip", "freeze", "--python", python], report)
        _write_constraints(freeze.output, constraints)
        _run(
            run,
            "install-package",
            [str(uv), "pip", "install", *common, "--upgrade-package", DISTRIBUTION, "--no-deps", spec],
            report,
        )
        requirements = _run(
            run, "read-requirements", [python, "-I", "-c", _REQUIREMENTS_SCRIPT, DISTRIBUTION, extras], report
        )
        needed = [line.strip() for line in requirements.output.splitlines() if line.strip()]
        if needed:
            _run(
                run,
                "install-requirements",
                [str(uv), "pip", "install", *common, "--constraint", str(constraints), *needed],
                report,
            )
    if was_consistent and run([str(uv), "pip", "check", "--python", python]).code != 0:
        report.warnings.append(
            "the update left conflicting dependencies in Hermes's environment; "
            f"inspect with: uv pip check --python {python}"
        )
    if record_member:
        report.member_recorded = _record_member(python, run, report)
    return report


_RECORD_MEMBER_SCRIPT = """\
from mordred_hermes.desktop.install import ensure_member, ensure_page

ensure_page()
ensure_member()
"""


def _record_member(python: str, run: Runner, report: UpdateReport) -> bool:
    """Re-place the page and re-register the pm member from the *new* code.

    The same two calls the plugin makes at start (``plugin.py``); a fresh
    interpreter sees the new metadata. Best effort: the next start repeats it.
    """
    result = run([python, "-I", "-c", _RECORD_MEMBER_SCRIPT])
    if result.code != 0:
        report.warnings.append(
            "could not refresh the Hermes Desktop page and package-manager member now; "
            "they are refreshed at the next start"
        )
        return False
    report.steps.append("record-member")
    return True


__all__ = [
    "CHECK_CACHE_SECONDS",
    "DISTRIBUTION",
    "MIN_MORDRED_VERSION",
    "PLUGIN_ENTRY_NAME",
    "CheckResult",
    "CommandResult",
    "Installed",
    "UpdateCheckFailed",
    "UpdateFailed",
    "UpdateRefused",
    "UpdateReport",
    "apply",
    "auto_check_enabled",
    "cached_check",
    "check",
    "fetch_releases",
    "find_uv",
    "hermes_receipt_check",
    "installed",
    "is_newer",
    "platform_extra",
    "read_cache",
    "refuse_if_unsupported",
    "select_latest",
    "write_cache",
]
