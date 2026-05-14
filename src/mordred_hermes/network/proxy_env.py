"""Proxy environment variables — pure mapping from network path to env vars.

This module is read-only by design. It computes the ``{HTTPS_PROXY: ...}``
dict that **should** be in ``os.environ`` for a given network path; PR2
``runtime`` is the sole writer that actually mutates the process
environment (and tracks the prior values so it can restore on
``on_session_end``).

The Tor URL scheme is always ``socks5h://`` so DNS resolution happens
inside the Tor circuit (TODO §3.1 L317). Plain ``http://`` proxy URLs are
forbidden because the system resolver leaks queries before the request
ever hits the proxy.

``NO_PROXY`` always contains ``localhost,127.0.0.1,::1`` regardless of
path — Phase 2 ``mordred-local`` health probes break if proxy_env forces
the localhost LLM through Tor (TODO §3.1 L316).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final, Literal

from ._exceptions import UnknownPath

ActivePath = Literal["tor", "vpn", "clearnet"]

_LOCALHOST_DEFAULTS: Final[tuple[str, ...]] = ("localhost", "127.0.0.1", "::1")
# Codex round 5 P1 (2026-05-14): include lowercase variants. POSIX tools
# (curl, wget, python ``requests`` httplib) honour the lowercase forms;
# if we only manage the uppercase keys, pre-existing ``https_proxy=...``
# in the parent env would survive a Tor switch and leak child traffic
# through the old clearnet proxy.
_UPPER_PROXY_KEYS: Final[tuple[str, ...]] = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY")
_LOWER_PROXY_KEYS: Final[tuple[str, ...]] = ("https_proxy", "http_proxy", "all_proxy")
_PROXY_KEYS: Final[tuple[str, ...]] = (*_UPPER_PROXY_KEYS, *_LOWER_PROXY_KEYS)
_MANAGED_KEYS: Final[frozenset[str]] = frozenset((*_PROXY_KEYS, "NO_PROXY", "no_proxy"))

DEFAULT_TOR_SOCKS_PORT: Final[int] = 9050


def managed_var_names() -> set[str]:
    """Return the set of env var names this module manages.

    PR2 ``runtime`` enumerates this set when switching paths to know
    which keys to clear from ``os.environ`` before applying the new
    desired set.
    """
    return set(_MANAGED_KEYS)


def desired_env(
    *,
    path: ActivePath,
    tor_socks_port: int = DEFAULT_TOR_SOCKS_PORT,
    no_proxy_extra: Iterable[str] = (),
) -> dict[str, str]:
    """Compute the env vars that should be set for the given path.

    Returns only keys that *should* be present — callers must clear
    keys in :func:`managed_var_names` that are absent from the result.

    Raises :class:`UnknownPath` for any value outside ``tor`` / ``vpn``
    / ``clearnet``. The narrow ``Literal`` typing catches this at
    static-check time; the runtime check defends against
    config-file-driven flips (the policy.json field is plain string at
    the storage layer).
    """
    if path not in ("tor", "vpn", "clearnet"):
        raise UnknownPath(f"unknown network path: {path!r}")

    env: dict[str, str] = {}
    if path == "tor":
        proxy_url = f"socks5h://127.0.0.1:{tor_socks_port}"
        for key in _PROXY_KEYS:
            env[key] = proxy_url

    # Codex round 5 P1 (2026-05-14): emit both casings so POSIX tools
    # using ``no_proxy`` (e.g. curl, requests' httplib) honour the same
    # bypass list as tools reading ``NO_PROXY``.
    no_proxy_value = _build_no_proxy(no_proxy_extra)
    env["NO_PROXY"] = no_proxy_value
    env["no_proxy"] = no_proxy_value
    return env


def _build_no_proxy(extras: Iterable[str]) -> str:
    """Join localhost defaults + user extras, deduped, order preserved."""
    seen: set[str] = set()
    ordered: list[str] = []
    for entry in (*_LOCALHOST_DEFAULTS, *extras):
        if entry in seen:
            continue
        seen.add(entry)
        ordered.append(entry)
    return ",".join(ordered)


# --------------------------------------------------------------------------- #
# Phase 3 PR3a Task #4: SOCKS5h library compatibility allowlist               #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class LibraryRequirement:
    """Minimum HTTP client library version that grew ``socks5h://`` support.

    Pinned conservatively in PR3a (PR3c playbook flips
    ``unverified_baseline=True`` per entry after operator pins the
    installed versions seen in the field). ``notes`` carries the documented
    caveat for the operator -- usually pointing at a release-notes URL or
    an upstream issue.
    """

    library: str
    min_version: str
    notes: str
    unverified_baseline: bool = True


SOCKS5H_LIBRARY_REQUIREMENTS: Final[Mapping[str, LibraryRequirement]] = {
    "httpx": LibraryRequirement(
        library="httpx",
        min_version="0.27.0",
        notes=(
            "httpx[socks] grew socks5h:// URL-scheme support in 0.27.x. "
            "Earlier releases silently coerce socks5h:// → socks5:// and "
            "leak DNS through the system resolver."
        ),
    ),
    "urllib3": LibraryRequirement(
        library="urllib3",
        min_version="2.0.0",
        notes=(
            "Used via requests[socks]; SOCKSProxyManager learned socks5h:// "
            "in 2.x. Older 1.26.x branch only knows socks5://."
        ),
    ),
    "requests": LibraryRequirement(
        library="requests",
        min_version="2.32.0",
        notes=(
            "requests[socks] needs PySocks + urllib3 with socks5h support. Pin both upper bounds during PR3c playbook."
        ),
    ),
    "aiohttp": LibraryRequirement(
        library="aiohttp",
        min_version="3.10.0",
        notes=(
            "aiohttp historically routes SOCKS via aiohttp-socks. "
            "Pre-3.10.x releases lack socks5h:// scheme parsing -- the "
            "DNS query runs locally even when the URL says socks5h."
        ),
    ),
}


def evaluate_library_compatibility(
    *,
    active_path: ActivePath,
    declared_libs: Iterable[str],
) -> list[str]:
    """Surface SOCKS5h-incompatibility warnings for declared HTTP libraries.

    The runtime / hooks layer or wizard can pass a list of libraries the
    user's environment ships (auto-detected via ``pip list`` or declared in
    their config). This helper checks each against the allowlist:

    - Off-path (clearnet / vpn): SOCKS5h does not apply, return ``[]``.
    - Library on allowlist: trust it (PR3c playbook ensures min_version
      is achievable). No warning.
    - Library NOT on allowlist: emit one human-readable warning per
      library pointing the operator at the unknown entry.

    v1 is advisory only -- the warnings surface to logs / CLI output;
    they do not block session start. v2 may auto-detect installed
    versions and downgrade lenient/abort.
    """
    if active_path != "tor":
        return []
    warnings: list[str] = []
    for lib in declared_libs:
        if lib in SOCKS5H_LIBRARY_REQUIREMENTS:
            continue
        warnings.append(
            f"{lib}: unknown SOCKS5h compatibility (not in v1 allowlist); "
            "verify the library honours socks5h:// URL scheme or add an entry "
            "to mordred-hermes proxy_env.SOCKS5H_LIBRARY_REQUIREMENTS"
        )
    return warnings
