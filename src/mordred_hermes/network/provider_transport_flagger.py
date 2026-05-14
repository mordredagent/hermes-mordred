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
TransportClass = Literal["http", "tcp", "udp", "quic", "grpc", "websocket"]


@dataclass(frozen=True, slots=True)
class ProviderEntry:
    """Empirical (or baseline) facts about one Hermes provider adapter.

    Phase 3 PR3a Task #3 added ``transport_class`` and
    ``respects_ipv6_proxy`` so the flagger can warn on non-HTTP transports
    (which never honour ``HTTPS_PROXY``) and on IPv6 leaks (SDKs that route
    around the SOCKS5h proxy when the resolved endpoint is IPv6).
    """

    name: str
    transport: str
    respects_proxy: bool | Literal["partial"]
    respects_socks5h: bool
    localhost_only: bool = False
    dns_quirk: bool = False
    unverified_baseline: bool = True
    # Phase 3 PR3a Task #3 — defaults preserve existing baseline semantics.
    transport_class: TransportClass = "http"
    respects_ipv6_proxy: bool = False


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
        transport_class="http",
        respects_ipv6_proxy=True,
    ),
    "openai": ProviderEntry(
        name="openai",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=True,
    ),
    "gemini": ProviderEntry(
        name="gemini",
        transport="requests",
        respects_proxy=True,
        respects_socks5h=True,
        transport_class="http",
        respects_ipv6_proxy=True,
    ),
    "mordred-local": ProviderEntry(
        name="mordred-local",
        transport="httpx",
        respects_proxy=True,
        respects_socks5h=True,
        localhost_only=True,
        transport_class="http",
        # localhost-only never reaches the proxy regardless of IPv6;
        # marking True so an override that drops `localhost_only` still
        # behaves correctly under the IPv6 check.
        respects_ipv6_proxy=True,
    ),
    "bedrock": ProviderEntry(
        name="bedrock",
        transport="boto3",
        respects_proxy=True,
        respects_socks5h=False,
        dns_quirk=True,
        transport_class="http",
        # boto3 IPv6 routing historically bypasses HTTPS_PROXY (PR3 live
        # verify needed; flagged True under unverified_baseline).
        respects_ipv6_proxy=False,
    ),
    "vertex": ProviderEntry(
        name="vertex",
        transport="google-cloud",
        respects_proxy="partial",
        respects_socks5h=False,
        transport_class="http",
        # google-cloud SDK has known IPv6 vs proxy quirks; pending PR3 verify.
        respects_ipv6_proxy=False,
    ),
}


def evaluate(
    *,
    active_path: ActivePath,
    providers: Iterable[str],
    policy_mode: PolicyMode,
    overrides: Mapping[str, ProviderEntry] | None = None,
    disable_ipv6: bool = False,
) -> list[Flag]:
    """Inspect each provider and return any compatibility flags.

    See module docstring for the severity matrix. ``disable_ipv6`` is the
    runtime's policy-level IPv6-leak defence: when ``True`` (strict
    default), the kernel resolver is hinted to drop AAAA records so
    ``respects_ipv6_proxy=False`` providers no longer produce a leak flag.
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
        flags.extend(
            _flag_for_all(
                entry,
                active_path,
                policy_mode,
                disable_ipv6=disable_ipv6,
            )
        )
    return flags


def _flag_for_all(
    entry: ProviderEntry,
    active_path: ActivePath,
    policy_mode: PolicyMode,
    *,
    disable_ipv6: bool,
) -> list[Flag]:
    """Run every flag branch and return the accumulated flags.

    Multiple independent concerns can co-exist (e.g. ``bedrock`` is both
    ``respects_socks5h=False`` and ``respects_ipv6_proxy=False``), so the
    flagger emits one ``Flag`` per concern instead of collapsing to the
    "worst" one. The CLI / hooks layer is responsible for aggregating
    them in the final user-facing message.
    """
    flags: list[Flag] = []
    socks_flag = _flag_for_socks5h(entry, active_path, policy_mode)
    if socks_flag is not None:
        flags.append(socks_flag)
    proxy_flag = _flag_for_clearnet_proxy(entry, active_path)
    if proxy_flag is not None:
        flags.append(proxy_flag)
    ipv6_flag = _flag_for_ipv6(entry, active_path, policy_mode, disable_ipv6=disable_ipv6)
    if ipv6_flag is not None:
        flags.append(ipv6_flag)
    non_http_flag = _flag_for_non_http(entry, active_path, policy_mode)
    if non_http_flag is not None:
        flags.append(non_http_flag)
    return flags


def _flag_for_socks5h(
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
    return None


def _flag_for_clearnet_proxy(entry: ProviderEntry, active_path: ActivePath) -> Flag | None:
    if active_path == "clearnet" and entry.respects_proxy is False:
        return Flag(
            provider=entry.name,
            severity="warning",
            reason=f"{entry.name} ignores HTTPS_PROXY entirely",
        )
    return None


def _flag_for_ipv6(
    entry: ProviderEntry,
    active_path: ActivePath,
    policy_mode: PolicyMode,
    *,
    disable_ipv6: bool,
) -> Flag | None:
    """Flag SDKs whose IPv6 path bypasses HTTPS_PROXY.

    Only fires on Tor (clearnet has no anonymity contract) and only when
    IPv6 is not disabled at the resolver hint level. If the user pinned
    ``disable_ipv6=True`` (strict default) we trust that downstream AAAA
    queries return nothing and skip the flag.
    """
    if active_path != "tor":
        return None
    if disable_ipv6:
        return None
    if entry.respects_ipv6_proxy:
        return None
    return Flag(
        provider=entry.name,
        severity=_downgrade("abort", policy_mode),
        reason=(f"{entry.name} may resolve IPv6 endpoints and bypass socks5h (disable_ipv6=False; v1 advisory only)"),
    )


def _flag_for_non_http(
    entry: ProviderEntry,
    active_path: ActivePath,
    policy_mode: PolicyMode,
) -> Flag | None:
    """Flag non-HTTP transports (gRPC, raw TCP/UDP, QUIC, WebSocket).

    ``HTTPS_PROXY`` is an HTTP-layer contract; non-HTTP transports do not
    honour it. On Tor that's an abort (the tunnel is bypassed entirely);
    on clearnet it's an informational warning so the user knows the
    provider talks raw, not via HTTP. ``off`` mode skips at the call-site
    of ``evaluate`` and never reaches here.
    """
    if entry.transport_class == "http":
        return None
    severity: Severity = "abort" if active_path == "tor" else "warning"
    return Flag(
        provider=entry.name,
        severity=_downgrade(severity, policy_mode),
        reason=(f"{entry.name} uses non-HTTP transport_class={entry.transport_class!r}; HTTPS_PROXY is not honoured"),
    )


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
