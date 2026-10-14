"""Update the installed ``hermes-mordred`` package in place.

This is the Python twin of ``scripts/install.sh``'s install step, used by
``hermes-mordred update`` and by the Hermes Desktop page's **Update Mordred**
button. It never installs a fresh Mordred: it moves an existing PyPI install
inside the environment this process runs in to a newer release, keeping the
same feature extras and never moving a package Hermes itself depends on.

The sequence (every ``uv`` call runs with ``--no-config`` from a private
temporary directory, so a ``uv.toml`` / ``pyproject.toml`` in the caller's
working directory cannot redirect where packages come from):

1. ``uv pip freeze`` the environment and pin, in a constraints file, every
   package in **Hermes's own dependency closure** (read from ``hermes-agent``'s
   metadata in the target interpreter) to its installed version. Packages
   only Mordred needs stay free to move, or a release that raises one of
   their floors could never be applied. When that closure cannot be read,
   everything is pinned, as the installer does.
2. Remove a co-installed legacy ``mordred-hermes`` (it owns the same files).
3. Install the new ``hermes-mordred[<extras>]==<version>`` with ``--no-deps``
   so resolving its ``hermes-agent`` requirement cannot re-resolve Hermes.
4. Check the new release's ``hermes-agent`` floor against the Hermes actually
   installed (``hermes_cli.__version__`` for a source / Desktop Hermes whose
   distribution says ``0.0.0``).
5. Install Mordred's own requirements for those extras (read from the *new*
   metadata in a fresh interpreter, stdout only, self-references and
   ``hermes-agent`` dropped) under the constraints from step 1.
6. ``uv pip check`` and warn when the install introduced a conflict.
7. Best-effort: run the plugin's start-time placement (``ensure_page`` +
   ``ensure_member``) in a fresh interpreter so the new code records itself
   as the package-manager member (``desktop/member.py``) before the next
   Hermes rebuild; the plugin would do the same at its next start anyway.

A failure after step 3 rolls the package back to the previous release
(``--no-deps``; the dependencies it had are still there), so the environment
never stays half-updated; :class:`UpdateFailed` says whether that worked.

Network policy: PyPI is contacted only by :func:`check` (an explicit user
action) and by :func:`cached_check` when no fresh answer exists, at most once
per :data:`CHECK_CACHE_SECONDS`, and never when the user disabled Hermes's own
plugin update check (``plugins.auto_update_check_hours: 0``). Hermes's own
daily plugin-check receipt is preferred to a request of our own whenever it
is fresh. Inside the Hermes process the request honours the proxy variables
the network runtime wrote (``httpx`` + ``socksio``, which Hermes ships, speak
SOCKS; the stdlib fallback does not and fails closed under Tor). A shell
``hermes-mordred update`` has no such variables, like the installer, so its
requests and uv's downloads go to PyPI directly.

Refusals (:class:`UpdateRefused`) cover Windows (file locks; the Windows
installer is the supported path), installs from a local checkout (``kind ==
"path"`` that is not pm's build of the member), a missing ``uv``, a process
outside a virtual environment, and a release that needs a newer Hermes.
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
from typing import Any, Final, Protocol

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ._home import hermes_home

_LOG = logging.getLogger(__name__)

DISTRIBUTION: Final = "hermes-mordred"
LEGACY_DISTRIBUTION: Final = "mordred-hermes"
HERMES_DISTRIBUTION: Final = "hermes-agent"
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
#: Subprocess limits: installs download; the rest must be quick. ``ensure_member``
#: waits on a lock another Mordred process may hold.
INSTALL_TIMEOUT_SECONDS: Final = 15 * 60
QUICK_TIMEOUT_SECONDS: Final = 2 * 60
MEMBER_TIMEOUT_SECONDS: Final = 5 * 60
_PLATFORM_EXTRA: Final[dict[str, str]] = {"darwin": "macos", "linux": "keyvault"}
_FROZEN_PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==[^ ]+$")
_FAILURE_PREFIX: Final = "check failed"


class UpdateRefused(Exception):
    """The update cannot run here; ``code`` is stable for callers, ``message`` for people."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class UpdateCheckFailed(Exception):
    """PyPI could not be asked (network, HTTP, malformed answer)."""


class UpdateFailed(Exception):
    """A step of the install sequence failed; ``output`` holds the command's tail.

    ``rolled_back`` is ``None`` when the previous release was never replaced
    (nothing to undo), ``True`` when it was reinstalled, ``False`` when that
    reinstall failed too (``rollback_output`` says why).
    """

    def __init__(self, step: str, output: str, *, rolled_back: bool | None = None, rollback_output: str = "") -> None:
        super().__init__(f"{step} failed")
        self.step = step
        self.output = output
        self.rolled_back = rolled_back
        self.rollback_output = rollback_output


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


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def installed(home: Path | None = None) -> Installed:
    """The running Mordred: version, origin and the extras it was installed with.

    pm's build of the member declares no extras, so for an install running
    from it the extras recorded in the member (``[tool.hermes-mordred]``) are
    added; the platform extra is always added, as the installer does.
    """
    from .desktop import member
    from .desktop.install import plugin_dir

    source = member.install_source()
    from_member = member.built_from_member(source)
    extras = set(source.extras)
    if from_member:
        recorded = member.member_status(plugin_dir(home))
        if recorded.get("present") and recorded.get("valid"):
            extras.update(str(e) for e in recorded.get("extras") or [])
    extra = platform_extra()
    if extra:
        extras.add(extra)
    return Installed(
        version=source.version,
        kind=source.kind,
        path=source.path,
        editable=source.editable,
        extras=tuple(sorted(extras)),
        from_member=from_member,
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
        candidate = _parse(str(text))
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

_HEADERS: Final = {"Accept": "application/json", "User-Agent": f"{DISTRIBUTION}-update"}


def _default_fetch(url: str) -> bytes:
    """One GET. ``httpx`` honours ``HTTPS_PROXY`` including SOCKS (Hermes ships ``socksio``)."""
    try:
        import httpx
    except ImportError:
        from urllib.request import Request, urlopen

        with urlopen(Request(url, headers=_HEADERS), timeout=FETCH_TIMEOUT_SECONDS) as response:
            return bytes(response.read(MAX_FETCH_BYTES + 1))
    with httpx.Client(timeout=FETCH_TIMEOUT_SECONDS, trust_env=True, follow_redirects=False) as client:
        response = client.get(url, headers=_HEADERS)
        response.raise_for_status()
        return bytes(response.content[: MAX_FETCH_BYTES + 1])


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
    except (ValueError, RecursionError, TypeError) as exc:
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

    @property
    def failed(self) -> bool:
        return self.reason.startswith(_FAILURE_PREFIX)

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


def _read_json(path: Path) -> Any:
    """``None`` for anything unreadable or malformed (a receipt or cache is never trusted)."""
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return None


def _receipt_row(data: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    rows = data.get("plugin_checks")
    if not isinstance(rows, list):
        return None
    for row in rows:
        if isinstance(row, dict) and row.get("name") == PLUGIN_ENTRY_NAME and row.get("class") == "pip":
            return row
    return None


def _channel_mismatch(latest: str, current: str) -> bool:
    a, b = _parse(latest), _parse(current)
    return a is not None and b is not None and b.is_prerelease and not a.is_prerelease


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
    directory = (home or hermes_home()).joinpath(*RECEIPTS_DIR)
    try:
        names = sorted(
            (p for p in directory.iterdir() if p.name.startswith("pm_") and p.suffix == ".json"), reverse=True
        )
    except OSError:
        return None
    for path in names[:40]:
        data = _read_json(path)
        if not isinstance(data, dict) or data.get("kind") != "plugin-check":
            continue
        stamp = _iso_to_epoch(data.get("finished_at")) or _iso_to_epoch(data.get("started_at"))
        if stamp is None or now() - stamp > max_age:
            return None  # the newest plugin-check is stale; older ones are staler
        row = _receipt_row(data)
        if row is None:
            return None
        current, latest = row.get("current"), row.get("latest")
        if not isinstance(current, str) or not isinstance(latest, str) or _channel_mismatch(latest, current):
            # Hermes reads PyPI's ``info.version`` (stable-only once a stable
            # exists); a pre-release user needs our own channel-aware lookup.
            return None
        return CheckResult(current, latest, is_newer(latest, current), "hermes-receipt", stamp)
    return None


def auto_check_enabled(home: Path | None = None) -> bool:
    """Hermes's ``plugins.auto_update_check_hours: 0`` also opts out of our check.

    Read the way Hermes does (``float(value)``): a quoted ``"0"`` disables too.
    """
    from ._yaml_io import load_yaml_mapping

    config = load_yaml_mapping((home or hermes_home()) / "config.yaml")
    plugins = config.get("plugins")
    if not isinstance(plugins, dict) or "auto_update_check_hours" not in plugins:
        return True
    hours = plugins.get("auto_update_check_hours")
    if isinstance(hours, bool):
        return hours
    if hours is None:
        return True
    try:
        return float(str(hours).strip()) > 0
    except ValueError:
        return True


def _cache_path(home: Path) -> Path:
    return home / "mordred" / CACHE_FILE_NAME


def read_cache(home: Path | None = None, *, now: Callable[[], float] = time.time) -> CheckResult | None:
    data = _read_json(_cache_path(home or hermes_home()))
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
    ttl = FAILURE_CACHE_SECONDS if result.failed else CHECK_CACHE_SECONDS
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
    current = installed(base).version
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
        result = CheckResult(current, None, None, "pypi", now(), f"{_FAILURE_PREFIX}: {exc}")
    write_cache(result, base)
    return result


# -- applying -----------------------------------------------------------------------------


@dataclass
class CommandResult:
    code: int
    stdout: str = ""
    stderr: str = ""

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


class Runner(Protocol):
    def __call__(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> CommandResult: ...


def _default_runner(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
) -> CommandResult:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            check=False,
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env is not None else None,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return CommandResult(124, str(out), f"timed out after {timeout:.0f}s\n" if timeout else "timed out\n")
    return CommandResult(proc.returncode, proc.stdout or "", proc.stderr or "")


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


# Run with ``python -I -c`` in the target interpreter: prints Mordred's own
# requirements for the given extras, markers evaluated for this machine,
# without ``hermes-agent`` (never re-resolve Hermes) and without
# self-references (``hermes-mordred[x]``, which would drag ``hermes-agent``
# back in). The installer's heredoc keeps self-references; hatchling flattens
# them today, this does not rely on that.
_REQUIREMENTS_SCRIPT: Final = """\
import sys
from importlib.metadata import requires
from packaging.requirements import Requirement

extras = {e for e in sys.argv[2].split(",") if e}
skip = {"hermes-agent", sys.argv[1].lower()}
for line in requires(sys.argv[1]) or []:
    req = Requirement(line)
    if req.name.lower().replace("_", "-") in skip:
        continue
    if req.marker is None or any(req.marker.evaluate({"extra": e}) for e in extras | {""}):
        req.marker = None
        print(req)
"""

# Prints the canonical names of every distribution in hermes-agent's dependency
# closure (what the constraints file must pin). Exit 3 when hermes-agent's
# metadata is not readable here.
_HERMES_CLOSURE_SCRIPT: Final = """\
import re
import sys
from importlib.metadata import PackageNotFoundError, requires
from packaging.requirements import Requirement

def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()

try:
    requires("hermes-agent")
except PackageNotFoundError:
    sys.exit(3)
pending = [("hermes-agent", frozenset())]
seen = {}
while pending:
    name, extras = pending.pop()
    key = canonical(name)
    if key in seen and extras <= seen[key]:
        continue
    seen[key] = seen.get(key, frozenset()) | extras
    try:
        lines = requires(name) or []
    except PackageNotFoundError:
        continue
    for line in lines:
        req = Requirement(line)
        if req.marker is not None:
            envs = [{"extra": e} for e in extras] or [{"extra": ""}]
            try:
                if not any(req.marker.evaluate(e) for e in envs):
                    continue
            except Exception:
                continue
        pending.append((req.name, frozenset(req.extras)))
for key in sorted(seen):
    print(key)
"""

# Prints "<hermes-agent specifier of the installed hermes-mordred>\\t<Hermes version>".
# A source / Desktop Hermes reports 0.0.0 as a distribution; its real version
# is hermes_cli.__version__ (the install stamp).
_HERMES_FLOOR_SCRIPT: Final = """\
import sys
from importlib.metadata import PackageNotFoundError, requires, version
from packaging.requirements import Requirement

spec = ""
for line in requires(sys.argv[1]) or []:
    req = Requirement(line)
    if req.name.lower().replace("_", "-") == "hermes-agent":
        spec = str(req.specifier)
        break
try:
    have = version("hermes-agent")
except PackageNotFoundError:
    have = ""
if have in ("", "0.0.0"):
    try:
        import hermes_cli
        have = str(hermes_cli.__version__)
    except Exception:
        pass
print(spec + "\\t" + have)
"""

_RECORD_MEMBER_SCRIPT: Final = """\
from mordred_hermes.desktop.install import ensure_member, ensure_page

ensure_page()
ensure_member()
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


def _spec(extras: tuple[str, ...], version: str) -> str:
    joined = ",".join(extras)
    name = f"{DISTRIBUTION}[{joined}]" if joined else DISTRIBUTION
    return f"{name}=={version},>={MIN_MORDRED_VERSION}"


def _frozen_names(freeze_output: str) -> list[tuple[str, str]]:
    """``(canonical name, pin line)`` for every ``name==version`` line of ``uv pip freeze``."""
    out = []
    for raw in freeze_output.splitlines():
        line = raw.strip()
        match = _FROZEN_PIN_RE.match(line)
        if match:
            out.append((_canonical(match.group(1)), line))
    return out


def _constraints(freeze_output: str, closure: set[str] | None) -> list[str]:
    """Pins for the constraints file: Hermes's closure only, or everything when it is unknown."""
    return [
        line
        for name, line in _frozen_names(freeze_output)
        if name not in {DISTRIBUTION, LEGACY_DISTRIBUTION} and (closure is None or name in closure)
    ]


def _hermes_floor_unmet(output: str) -> str | None:
    """A message when the new release's ``hermes-agent`` floor is not met, else ``None``."""
    spec_text, _, have = output.strip().partition("\t")
    if not spec_text:
        return None
    try:
        spec = SpecifierSet(spec_text)
    except InvalidSpecifier:
        return None
    if not have:
        return f"the new release requires hermes-agent{spec_text}, but no Hermes version could be determined"
    if _parse(have) is None or spec.contains(have, prereleases=True):
        return None
    return f"the new release requires hermes-agent{spec_text}, but Hermes {have} is installed; update Hermes first"


class _Session:
    """One update: the commands, their isolation, and the record of what ran."""

    def __init__(self, uv: Path, python: str, run: Runner, workdir: Path, report: UpdateReport) -> None:
        self.uv, self.python, self.run, self.workdir, self.report = uv, python, run, workdir, report
        self.replaced = False  # the previous release has been swapped out

    def uv_cmd(self, verb: str, *args: str) -> list[str]:
        return [str(self.uv), "pip", verb, "--no-config", "--python", self.python, *args]

    def python_cmd(self, script: str, *args: str) -> list[str]:
        return [self.python, "-I", "-c", script, *args]

    def probe(self, argv: list[str], *, timeout: float, env: Mapping[str, str] | None = None) -> CommandResult:
        return self.run(argv, cwd=self.workdir, env=env, timeout=timeout)

    def step(self, name: str, argv: list[str], *, timeout: float) -> CommandResult:
        _LOG.info("update step %s: %s", name, " ".join(argv))
        result = self.probe(argv, timeout=timeout)
        if result.code != 0:
            raise self.failure(name, _tail(result.output))
        self.report.steps.append(name)
        return result

    def failure(self, step: str, output: str) -> UpdateFailed:
        """Roll back to the previous release when it was already replaced, then describe the failure."""
        if not self.replaced:
            return UpdateFailed(step, output)
        argv = self.uv_cmd(
            "install",
            "--no-python-downloads",
            "--no-deps",
            "--reinstall-package",
            DISTRIBUTION,
            _spec(self.report.extras, self.report.previous),
        )
        _LOG.warning("update step %s failed; reinstalling %s %s", step, DISTRIBUTION, self.report.previous)
        back = self.probe(argv, timeout=INSTALL_TIMEOUT_SECONDS)
        return UpdateFailed(step, output, rolled_back=back.code == 0, rollback_output=_tail(back.output))


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
    base = home or hermes_home()
    current = current or installed(base)
    uv = uv or find_uv(base)
    refuse_if_unsupported(current, uv=uv)
    assert uv is not None  # refuse_if_unsupported raised otherwise
    if _parse(target) is None:
        raise UpdateRefused("bad-version", f"not a PEP 440 version: {target!r}")
    report = UpdateReport(previous=current.version, target=target, extras=current.extras)
    with tempfile.TemporaryDirectory(prefix="mordred-update-") as tmp:
        session = _Session(uv, current.python, runner or _default_runner, Path(tmp), report)
        _write_constraints(session)
        _install(session, target, current)
        _finish(session, base, record_member=record_member)
    return report


def _write_constraints(session: _Session) -> Path:
    """Steps 1-2: the constraints file (Hermes's closure pinned) and the legacy package."""
    quick = QUICK_TIMEOUT_SECONDS
    freeze = session.step("freeze", session.uv_cmd("freeze"), timeout=quick)
    closure_result = session.probe(session.python_cmd(_HERMES_CLOSURE_SCRIPT), timeout=quick)
    closure: set[str] | None = None
    if closure_result.code == 0:
        closure = {line.strip() for line in closure_result.stdout.splitlines() if line.strip()}
    else:
        session.report.warnings.append("could not read Hermes's dependency closure; every installed package was pinned")
    constraints = session.workdir / "constraints.txt"
    pins = _constraints(freeze.stdout, closure)
    constraints.write_text("\n".join(pins) + ("\n" if pins else ""), encoding="utf-8")
    if any(name == LEGACY_DISTRIBUTION for name, _ in _frozen_names(freeze.stdout)):
        session.step("remove-legacy", session.uv_cmd("uninstall", LEGACY_DISTRIBUTION), timeout=quick)
    return constraints


def _install(session: _Session, target: str, current: Installed) -> None:
    """Steps 3-5: the package, its Hermes floor, its requirements under the constraints."""
    quick, slow = QUICK_TIMEOUT_SECONDS, INSTALL_TIMEOUT_SECONDS
    was_consistent = session.probe(session.uv_cmd("check"), timeout=quick).code == 0
    session.step(
        "install-package",
        session.uv_cmd(
            "install",
            "--no-python-downloads",
            "--upgrade-package",
            DISTRIBUTION,
            "--no-deps",
            _spec(current.extras, target),
        ),
        timeout=slow,
    )
    session.replaced = True
    floor = session.step("hermes-floor", session.python_cmd(_HERMES_FLOOR_SCRIPT, DISTRIBUTION), timeout=quick)
    unmet = _hermes_floor_unmet(floor.stdout)
    if unmet is not None:
        failed = session.failure("hermes-floor", unmet)
        restored = " (previous release restored)" if failed.rolled_back else " (restoring the previous release FAILED)"
        raise UpdateRefused("hermes-too-old", unmet + restored)
    extras = ",".join(current.extras)
    requirements = session.step(
        "read-requirements", session.python_cmd(_REQUIREMENTS_SCRIPT, DISTRIBUTION, extras), timeout=quick
    )
    needed = [line.strip() for line in requirements.stdout.splitlines() if line.strip()]
    if needed:
        constraints = session.workdir / "constraints.txt"
        session.step(
            "install-requirements",
            session.uv_cmd("install", "--no-python-downloads", "--constraint", str(constraints), *needed),
            timeout=slow,
        )
    if was_consistent and session.probe(session.uv_cmd("check"), timeout=quick).code != 0:
        session.report.warnings.append(
            "the update left conflicting dependencies in Hermes's environment; "
            f"inspect with: uv pip check --python {session.python}"
        )


def _finish(session: _Session, home: Path, *, record_member: bool) -> None:
    """Step 7: the Desktop page and the package-manager member, from the new code (best effort)."""
    if not record_member:
        return
    env = {**os.environ, "HERMES_HOME": str(home)}
    result = session.probe(session.python_cmd(_RECORD_MEMBER_SCRIPT), env=env, timeout=MEMBER_TIMEOUT_SECONDS)
    if result.code == 0:
        session.report.steps.append("record-member")
        session.report.member_recorded = True
    else:
        session.report.warnings.append(
            "could not refresh the Hermes Desktop page and package-manager member now; "
            "they are refreshed at the next start"
        )


__all__ = [
    "CHECK_CACHE_SECONDS",
    "DISTRIBUTION",
    "MIN_MORDRED_VERSION",
    "PLUGIN_ENTRY_NAME",
    "CheckResult",
    "CommandResult",
    "Installed",
    "Runner",
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
