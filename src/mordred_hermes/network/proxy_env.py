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

from collections.abc import Iterable
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
