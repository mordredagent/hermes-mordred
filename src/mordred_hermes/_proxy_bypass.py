"""Early process-proxy bypass for loopback-only Mordred traffic.

Hermes resolves ambient proxy variables when it constructs its shared httpx
clients.  Updating ``NO_PROXY`` later from ``pre_api_request`` protects the
health probe, but cannot change a client that already captured an explicit
proxy.  Keep this helper dependency-free so the interpreter-startup bootstrap
and the llm-guard plugin entry point can both run it before client creation.
"""

from __future__ import annotations

import os
from collections.abc import MutableMapping
from typing import Final

_NO_PROXY_KEYS: Final[tuple[str, ...]] = ("NO_PROXY", "no_proxy")
_LOOPBACK_HOSTS: Final[tuple[str, ...]] = ("localhost", "127.0.0.1", "::1")


def _effective_value(
    environ: MutableMapping[str, str],
    *,
    uppercase: str,
    lowercase: str,
) -> str:
    """Return the value proxy-aware stdlib/httpx consumers will observe.

    On POSIX, a present lowercase spelling overrides the uppercase spelling,
    including when it is deliberately empty.  Windows environment mappings
    are case-insensitive, so the same lookup also returns their single
    effective value.  Unioning both spellings would broaden ``NO_PROXY`` and
    can silently turn a previously proxied cloud endpoint into direct egress.
    """
    if lowercase in environ:
        return environ.get(lowercase, "")
    return environ.get(uppercase, "")


def ensure_loopback_proxy_bypass(environ: MutableMapping[str, str] | None = None) -> None:
    """Add exact loopback hosts to both ``NO_PROXY`` spellings.

    The environment is changed only when an ambient HTTP/SOCKS proxy is
    configured.  Entries from the effective ``NO_PROXY`` spelling are retained
    in order and compared case-insensitively; a shadowed spelling is not
    unioned because that would broaden direct egress. ``environ`` is injectable
    for deterministic tests; production callers use :data:`os.environ`.
    """
    target = os.environ if environ is None else environ
    effective_proxies = (
        _effective_value(target, uppercase="HTTPS_PROXY", lowercase="https_proxy"),
        _effective_value(target, uppercase="HTTP_PROXY", lowercase="http_proxy"),
        _effective_value(target, uppercase="ALL_PROXY", lowercase="all_proxy"),
    )
    if not any(value.strip() for value in effective_proxies):
        return

    values: list[str] = []
    seen: set[str] = set()
    effective_no_proxy = _effective_value(target, uppercase="NO_PROXY", lowercase="no_proxy")
    for raw_value in effective_no_proxy.split(","):
        value = raw_value.strip()
        folded = value.casefold()
        if value and folded not in seen:
            values.append(value)
            seen.add(folded)
    for value in _LOOPBACK_HOSTS:
        if value.casefold() not in seen:
            values.append(value)
            seen.add(value.casefold())

    combined = ",".join(values)
    for key in _NO_PROXY_KEYS:
        target[key] = combined
