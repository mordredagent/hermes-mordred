"""Provider-vs-transport compatibility flagger.

For each Hermes provider, decide whether the configured ``HTTPS_PROXY`` /
SOCKS5h transport actually reaches the upstream API — or whether the SDK
will bypass the proxy (DNS leak, plain TCP, etc.) and surface as silent
deanonymization.

PR1 ships a **baseline allowlist** marked ``unverified_baseline=True``.
PR3 runs the real-traffic verifications from TODO §0.8 L110-117
(Wireshark / Tor circuit log per provider) and flips the flag once each
entry has empirical backing.

Severity policy:

============ =========================== ======== ==============================================
mode          provider state              flag     notes
============ =========================== ======== ==============================================
off           any                         —        no flags emitted
strict        tor + respects_socks5h=False abort   prevent the strict-mode session from starting
strict        clearnet + respects_proxy=False warning informational
strict        unknown provider            warning   no data; surface for user investigation
lenient       any abortable flag          warning   downgraded; user is informed but continues
============ =========================== ======== ==============================================

Localhost-only providers (``mordred-local``) are exempt — Phase 2
``proxy_env.NO_PROXY`` keeps ``localhost`` out of the proxy regardless of
path.

User overrides via ``policy.json provider_overrides`` may **add** new
providers (e.g. an internal LLM proxy) but cannot replace baseline
entries: a malicious override that flips ``anthropic.respects_socks5h``
to ``False`` would be a silent strict-mode bypass.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final, Literal

from .proxy_env import ActivePath

PolicyMode = Literal["strict", "lenient", "off"]
Severity = Literal["abort", "warning"]


@dataclass(frozen=True, slots=True)
class ProviderEntry:
    """Empirical (or baseline) facts about one Hermes provider adapter."""

    name: str
    transport: str
    respects_proxy: bool | Literal["partial"]
    respects_socks5h: bool
    localhost_only: bool = False
    dns_quirk: bool = False
    unverified_baseline: bool = True


@dataclass(frozen=True, slots=True)
class Flag:
    """A single compatibility concern between active path and a provider."""

    provider: str
    severity: Severity
    reason: str


KNOWN_PROVIDERS: Final[Mapping[str, ProviderEntry]] = {
    "anthropic": ProviderEntry(
        name="anthropic",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
    ),
    "openai": ProviderEntry(
        name="openai",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
    ),
    "gemini": ProviderEntry(
        name="gemini",
        transport="requests",
        respects_proxy=True,
        respects_socks5h=True,
    ),
    "mordred-local": ProviderEntry(
        name="mordred-local",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        localhost_only=True,
    ),
    "bedrock": ProviderEntry(
        name="bedrock",
        transport="boto3",
        respects_proxy=True,
        respects_socks5h=False,
        dns_quirk=True,
    ),
    "vertex": ProviderEntry(
        name="vertex",
        transport="google-cloud",
        respects_proxy="partial",
        respects_socks5h=False,
    ),
}


def evaluate(
    *,
    active_path: ActivePath,
    providers: Iterable[str],
    policy_mode: PolicyMode,
    overrides: Mapping[str, ProviderEntry] | None = None,
) -> list[Flag]:
    """Inspect each provider and return any compatibility flags.

    See module docstring for the severity matrix.
    """
    if policy_mode == "off":
        return []

    catalog = _resolve_catalog(overrides)
    flags: list[Flag] = []
    for provider in providers:
        entry = catalog.get(provider)
        if entry is None:
            flags.append(
                Flag(
                    provider=provider,
                    severity=_downgrade("warning", policy_mode),
                    reason="unknown provider; not in baseline allowlist",
                )
            )
            continue
        if entry.localhost_only:
            continue
        flag = _flag_for(entry, active_path, policy_mode)
        if flag is not None:
            flags.append(flag)
    return flags


def _flag_for(
    entry: ProviderEntry,
    active_path: ActivePath,
    policy_mode: PolicyMode,
) -> Flag | None:
    if active_path == "tor" and not entry.respects_socks5h:
        return Flag(
            provider=entry.name,
            severity=_downgrade("abort", policy_mode),
            reason=f"{entry.name} transport {entry.transport!r} does not honor socks5h",
        )
    if active_path == "clearnet" and entry.respects_proxy is False:
        return Flag(
            provider=entry.name,
            severity="warning",
            reason=f"{entry.name} ignores HTTPS_PROXY entirely",
        )
    return None


def _downgrade(severity: Severity, policy_mode: PolicyMode) -> Severity:
    if policy_mode == "lenient" and severity == "abort":
        return "warning"
    return severity


def _resolve_catalog(
    overrides: Mapping[str, ProviderEntry] | None,
) -> dict[str, ProviderEntry]:
    """Merge baseline + overrides, refusing to replace baseline entries.

    Overrides may add new entries (internal LLMs) but the baseline is
    immutable — a malicious replacement could flip a Tor-incompatible
    provider to "safe" and silently bypass strict mode.
    """
    catalog = dict(KNOWN_PROVIDERS)
    if not overrides:
        return catalog
    for name, entry in overrides.items():
        if name in KNOWN_PROVIDERS:
            raise ValueError(
                f"override {name!r} conflicts with immutable baseline entry; "
                "policy.json provider_overrides may only add new providers"
            )
        catalog[name] = entry
    return catalog
