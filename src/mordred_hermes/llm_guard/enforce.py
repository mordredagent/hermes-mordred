"""mordred_llm_guard.enforce — Phase 2 PR2 session-scoped policy enforcement.

**v1 = refuse-only** (Codex B2 / Phase 2 PR1 prep findings). Hermes resolves
the active provider BEFORE ``on_session_start`` fires
(``HOOK_PAYLOADS.md`` §5), so a mid-session config patch cannot redirect
the current turn. The v1 contract is therefore: refuse the session at
startup when policy says the user shouldn't be reaching the resolved
provider. Auto-swap (``policy.strict.provider_override_at_session_start``)
is deferred to v2 (POLICY.md row 11).

Cycle A surface: off / lenient → silent no-op; strict + cloud provider in
``cloud_provider_allowlist`` with ``allow_cloud_llm: true`` → ``allow``
audit. Refuse paths and the mordred-local branch land in later cycles.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Final, Literal, TypeAlias
from urllib.parse import urlsplit, urlunsplit

from .._audit_support import AuditWriter as _AuditWriter
from .._audit_support import safe_audit_append
from .._policy_io import load_policy_mapping
from .._provider_identity import canonicalize_provider
from .._proxy_bypass import ensure_loopback_proxy_bypass as _ensure_loopback_proxy_bypass
from . import health
from ._exceptions import MordredLocalUnreachable, MordredSessionRefused
from .local_adapter import LOCAL_PROVIDER_NAME

_LOG = logging.getLogger("mordred.llm_guard.enforce")

# What strict mode does when a non-allowlisted cloud provider is reached.
# Mirrors the wizard's ``PolicySnapshot.cloud_attempt_action`` Literal
# (``wizard/policy_writer.py``). ``always-block`` is the safe default;
# ``prompt-once`` asks the operator once per provider at an interactive
# terminal (see :func:`_resolve_cloud_attempt`).
CloudAttemptAction: TypeAlias = Literal["always-block", "prompt-once"]

# Interactive verdict for a single non-allowlisted cloud attempt under
# ``prompt-once``. ``True`` allow, ``False`` deny, ``None`` no interactive
# terminal (caller fails closed). Injected like ``health_probe`` so tests
# never touch a real TTY.
PromptFn: TypeAlias = Callable[[str], bool | None]

# Audit reasons — POLICY.md §Audit log reason enum (frozen 12 codes).
_REASON_CLOUD_ALLOWLISTED: Final = "policy.strict.cloud_allowlisted"
_REASON_CLOUD_NOT_ALLOWLISTED: Final = "policy.strict.cloud_not_allowlisted"
_REASON_SESSION_REFUSED: Final = "policy.strict.session_refused"
_REASON_UNCONDITIONAL_OVERRIDE: Final = "policy.strict.unconditional_override"
_REASON_NO_RESOLVED_PROVIDER: Final = "mordred.degraded.no_resolved_provider"
# prompt-once decision records (POLICY.md — emitted by _resolve_cloud_attempt).
_REASON_CLOUD_PROMPTED_ALLOW: Final = "policy.strict.cloud_prompted_allow"
_REASON_CLOUD_PROMPTED_DENY: Final = "policy.strict.cloud_prompted_deny"
_REASON_CLOUD_ENDPOINT_MISMATCH: Final = "policy.strict.cloud_endpoint_mismatch"

# Canonical name of the local provider — re-exported from local_adapter so
# this module and the profile constructor share a single source of truth.
_LOCAL_PROVIDER_NAME: Final = LOCAL_PROVIDER_NAME

# One-shot flag for the degraded "no provider info" path (POLICY.md row 6).
# Module-level state — tests reset via :func:`_reset_state`.
_no_resolved_provider_emitted = False

# prompt-once decisions, keyed by normalized provider id, cached for the
# life of the process so the operator is asked at most once per provider.
# ``None`` verdicts (no terminal) are deliberately NOT cached. Tests reset
# via :func:`_reset_state`.
_cloud_prompt_decisions: dict[str, bool] = {}
_STRICT_LOOPBACK_LITERALS: Final[frozenset[str]] = frozenset({"127.0.0.1", "::1"})
_MAX_ENDPOINT_DISPLAY_LENGTH: Final = 256

# Hermes 0.19 exposes a few different slugs for the same policy-level
# provider depending on whether a route came from auth.py, models.py, or the
# models.dev catalog. Keep the faithful models.py alias replica untouched and
# collapse only those cross-registry identities at this enforcement boundary.
_POLICY_PROVIDER_EQUIVALENTS: Final[Mapping[str, str]] = {
    "deep-infra": "deepinfra",
    "deepinfra-ai": "deepinfra",
    "kimi-for-coding": "kimi-coding",
    "minimax-oauth": "minimax",
    "openai-api": "openai",
    "solar": "upstage",
    "xai-oauth": "xai",
}

# Provider identity is not an endpoint grant. Hermes permits ``base_url``
# overrides for first-class providers, so checking only ``provider`` lets a
# process label an arbitrary collector as e.g. ``openai`` and inherit the
# allow-list entry. These are the provider-owned endpoint hosts exposed by
# Hermes 0.19's built-in profiles. A leading dot means "this DNS suffix";
# exact entries never accept a sibling/lookalike hostname.
#
# Every key must already be a ``policy_provider_id`` output. An alias key (e.g.
# ``xai-oauth``) is unreachable for lookups — callers canonicalize first — and
# would additionally let ``infer_cloud_provider`` return a non-canonical
# identity that no allow-list entry can match.
_CLOUD_ENDPOINT_HOSTS: Final[Mapping[str, tuple[str, ...]]] = {
    "alibaba": ("dashscope-intl.aliyuncs.com",),
    "alibaba-coding-plan": ("coding-intl.dashscope.aliyuncs.com",),
    "anthropic": ("api.anthropic.com",),
    "arcee": ("api.arcee.ai",),
    # Azure resource subdomains select an operator/tenant, so a vendor suffix
    # is not sufficient destination ownership. Strict refuses Azure Foundry
    # until policy.json has a separately persisted exact-endpoint pin.
    "azure-foundry": (),
    # Bedrock and Vertex have shape-specific matchers below. Deliberately do
    # not use broad ``.amazonaws.com`` / ``.googleapis.com`` suffixes: those
    # would grant unrelated services such as S3 or Cloud Storage.
    "bedrock": (),
    "copilot": ("api.githubcopilot.com",),
    "deepinfra": ("api.deepinfra.com",),
    "deepseek": ("api.deepseek.com",),
    "fireworks": ("api.fireworks.ai",),
    "gemini": ("generativelanguage.googleapis.com",),
    "gmi": ("api.gmi-serving.com",),
    "huggingface": ("router.huggingface.co",),
    "kilocode": ("api.kilo.ai",),
    "kimi-coding": ("api.kimi.com", "api.moonshot.ai"),
    "kimi-coding-cn": ("api.moonshot.cn",),
    "minimax": ("api.minimax.io",),
    "minimax-cn": ("api.minimaxi.com",),
    "nous": ("inference-api.nousresearch.com",),
    "novita": ("api.novita.ai",),
    "nvidia": ("integrate.api.nvidia.com",),
    "ollama-cloud": ("ollama.com",),
    "openai": ("api.openai.com",),
    "openai-codex": ("chatgpt.com",),
    "opencode-go": ("opencode.ai",),
    "opencode-zen": ("opencode.ai",),
    "openrouter": ("openrouter.ai",),
    "qwen-oauth": ("portal.qwen.ai",),
    "stepfun": ("api.stepfun.ai", "api.stepfun.com"),
    "tencent-tokenhub": ("tokenhub.tencentmaas.com",),
    "upstage": ("api.upstage.ai",),
    "vertex": (),
    "xai": ("api.x.ai",),
    "xiaomi": ("api.xiaomimimo.com",),
    # Hermes probes both the global Z.AI host and its China service
    # (``hermes_cli.auth.ZAI_ENDPOINTS``); vision resolution uses the same
    # pair directly.
    "zai": ("api.z.ai", "open.bigmodel.cn"),
}

_BEDROCK_ENDPOINT_RE: Final = re.compile(
    r"^bedrock-runtime(?:-fips)?\.[a-z0-9-]+\."
    r"(?:amazonaws\.com(?:\.cn)?|api\.aws)$"
)
_VERTEX_ENDPOINT_RE: Final = re.compile(r"^(?:[a-z0-9-]+-)?aiplatform\.googleapis\.com$")


def policy_provider_id(provider_id: str) -> str:
    """Return the stable provider identity used by Mordred policy files."""
    canonical = canonicalize_provider(provider_id)
    return _POLICY_PROVIDER_EQUIVALENTS.get(canonical, canonical)


class _InvalidLocalEndpoint(ValueError):
    """A strict-mode ``mordred-local`` endpoint is not safely loopback-only."""


def safe_endpoint_for_audit(endpoint: object) -> str:
    """Return a bounded URL display with all credential-bearing parts removed."""
    if not isinstance(endpoint, str) or not endpoint:
        return "<missing>"
    if endpoint != endpoint.strip() or any(ord(char) < 0x20 or ord(char) == 0x7F for char in endpoint):
        return "<invalid>"
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except (TypeError, ValueError):
        return "<invalid>"
    scheme = parsed.scheme.casefold()
    hostname = parsed.hostname
    if scheme not in {"http", "https"} or not hostname:
        return "<invalid>"
    host = hostname.rstrip(".").casefold()
    if not host:
        return "<invalid>"
    rendered_host = f"[{host}]" if ":" in host else host
    authority = rendered_host if port is None else f"{rendered_host}:{port}"
    # Paths can also contain bearer/project secrets on custom or rejected
    # endpoints. Audit needs only the destination origin; internal route keys
    # retain normalized paths where provider disambiguation requires them.
    sanitized = urlunsplit((scheme, authority, "", "", ""))
    if len(sanitized) > _MAX_ENDPOINT_DISPLAY_LENGTH:
        return sanitized[: _MAX_ENDPOINT_DISPLAY_LENGTH - 3] + "..."
    return sanitized


def _safe_audit_append(audit: _AuditWriter, entry: Mapping[str, Any]) -> None:
    """Best-effort audit write binding this module's logger.

    Thin wrapper over :func:`mordred_hermes._audit_support.safe_audit_append`
    (Codex review P1 round 6): the strict-mode refusal raises
    :class:`MordredSessionRefused` (``BaseException``-derived) and must still
    fire even if the audit write itself raises a plain ``Exception`` before
    the refusal -- otherwise Hermes' ``except Exception`` filters would
    swallow it and continue (fail-open).
    """
    safe_audit_append(audit, entry, logger=_LOG)


def check_session_provider(
    *,
    policy_mode: str,
    policy_json_path: Path,
    active_provider: str | None,
    audit: _AuditWriter,
    health_probe: Callable[[str], None] | None = None,
) -> None:
    """Apply the refuse-only decision matrix at ``on_session_start``.

    Cycle A: only the no-raise paths. ``policy_mode`` values that are
    neither ``"strict"`` nor ``"off"`` are treated as lenient (defense in
    depth, mirroring :func:`harness_detect.check_harness_primary`).
    """
    if policy_mode == "off":
        return  # silent no-op

    if policy_mode != "strict":
        # lenient and any unknown mode — stay silent in v1.
        return

    settings = _read_policy_settings(policy_json_path)

    if active_provider is None:
        _refuse_degraded(audit=audit, settings=settings)
        return  # unreachable — _refuse_degraded raises.

    active_provider = policy_provider_id(active_provider)
    if active_provider == _LOCAL_PROVIDER_NAME:
        _probe_local(
            audit=audit,
            settings=settings,
            health_probe=health_probe or _default_health_probe,
        )
        return

    if active_provider in settings.cloud_allowlist and settings.allow_cloud_llm:
        _safe_audit_append(
            audit,
            {
                "event": "on_session_start",
                "decision": "allow",
                "reason": _REASON_CLOUD_ALLOWLISTED,
                "provider_id": active_provider,
            },
        )
        return

    _refuse_cloud_not_allowlisted(
        audit=audit,
        provider_id=active_provider,
        allow_cloud_llm=settings.allow_cloud_llm,
    )


def _refuse_degraded(*, audit: _AuditWriter, settings: _PolicySettings) -> None:
    """Strict + active provider unknown → one-shot degraded audit + action + raise.

    Emits two audit entries:

    1. ``mordred.degraded.no_resolved_provider`` (one-shot per process,
       POLICY.md row 6) — observers can correlate the degradation with
       the resulting refusal.
    2. ``policy.strict.unconditional_override`` (action, POLICY.md row 9)
       — what v2 auto-swap would have done; in v1 we refuse instead
       because the live provider has already been resolved upstream
       (Codex B2).

    Then raises :class:`MordredSessionRefused` (BaseException).
    """
    global _no_resolved_provider_emitted
    if not _no_resolved_provider_emitted:
        _safe_audit_append(
            audit,
            {
                "event": "on_session_start",
                "decision": "block",
                "reason": _REASON_NO_RESOLVED_PROVIDER,
            },
        )
        _no_resolved_provider_emitted = True

    _safe_audit_append(
        audit,
        {
            "event": "on_session_start",
            "decision": "block",
            "reason": _REASON_UNCONDITIONAL_OVERRIDE,
        },
    )

    msg = (
        "Mordred strict mode: active provider could not be resolved; refusing the session. "
        "Configure a provider in ~/.hermes/auth.json or ~/.hermes/config.yaml model.provider "
        f"(intended fallback local endpoint: {safe_endpoint_for_audit(settings.local_endpoint)})."
    )
    _LOG.error(msg)
    raise MordredSessionRefused(msg)


def _refuse_cloud_not_allowlisted(
    *,
    audit: _AuditWriter,
    provider_id: str,
    allow_cloud_llm: bool,
) -> None:
    """Strict + cloud provider not allowed → classification + action audit + raise.

    Codex N1 (POLICY.md row 8): the classification reason
    ``policy.strict.cloud_not_allowlisted`` is emitted as its own audit
    entry alongside (immediately before) the action
    ``policy.strict.session_refused``. Consumers can filter on either
    axis.
    """
    _safe_audit_append(
        audit,
        {
            "event": "on_session_start",
            "decision": "block",
            "reason": _REASON_CLOUD_NOT_ALLOWLISTED,
            "provider_id": provider_id,
            "allow_cloud_llm": allow_cloud_llm,
        },
    )
    _safe_audit_append(
        audit,
        {
            "event": "on_session_start",
            "decision": "block",
            "reason": _REASON_SESSION_REFUSED,
            "provider_id": provider_id,
        },
    )

    if not allow_cloud_llm:
        detail = "allow_cloud_llm is false"
    else:
        detail = f"{provider_id!r} is not in cloud_provider_allowlist"
    msg = (
        f"Mordred strict mode: refusing session because {detail}. "
        "Switch to mordred-local, add the provider to cloud_provider_allowlist, "
        "or rerun `hermes-mordred configure` to lower the policy."
    )
    _LOG.error(msg)
    raise MordredSessionRefused(msg)


def _refuse_cloud_endpoint_mismatch(
    *,
    audit: _AuditWriter,
    provider_id: str,
    runtime_base_url: str | None,
    overridden: bool = True,
) -> None:
    """Refuse an allow-listed provider whose actual destination is unbound.

    ``overridden`` distinguishes the two causes so the remedy is correct: an
    operator-supplied ``base_url`` that is not provider-owned, versus a provider
    that has no single owned default endpoint and therefore needs one pinned.
    """
    safe_endpoint = safe_endpoint_for_audit(runtime_base_url)
    _safe_audit_append(
        audit,
        {
            "event": "pre_api_request",
            "decision": "block",
            "reason": _REASON_CLOUD_ENDPOINT_MISMATCH,
            "provider_id": provider_id,
            "runtime_base_url": safe_endpoint,
            "base_url_overridden": overridden,
        },
    )
    _safe_audit_append(
        audit,
        {
            "event": "pre_api_request",
            "decision": "block",
            "reason": _REASON_SESSION_REFUSED,
            "provider_id": provider_id,
            "runtime_base_url": safe_endpoint,
        },
    )
    msg = (
        (
            "Mordred strict mode: refusing request because the runtime endpoint "
            f"{safe_endpoint!r} is not a provider-owned endpoint for {provider_id!r}. "
            "Remove the base_url override or use a provider whose endpoint is explicitly supported."
        )
        if overridden
        else (
            f"Mordred strict mode: refusing request because provider {provider_id!r} has no single "
            "provider-owned default endpoint (its destination selects a tenant, region, or project). "
            "Configure an explicit base_url for it, or use a provider with a fixed endpoint."
        )
    )
    _LOG.error(msg)
    raise MordredSessionRefused(msg)


def _local_endpoint_matches_configured(
    runtime_endpoint: str,
    configured_endpoint: str,
) -> bool:
    """Bind a local client to the policy endpoint, tolerating one URL slash."""
    if runtime_endpoint != runtime_endpoint.strip() or configured_endpoint != configured_endpoint.strip():
        return False
    return runtime_endpoint.rstrip("/") == configured_endpoint.rstrip("/")


def _refuse_local_endpoint_mismatch(
    *,
    audit: _AuditWriter,
    runtime_endpoint: str,
    configured_endpoint: str,
) -> None:
    safe_runtime = safe_endpoint_for_audit(runtime_endpoint)
    safe_configured = safe_endpoint_for_audit(configured_endpoint)
    _safe_audit_append(
        audit,
        {
            "event": "pre_api_request",
            "decision": "block",
            "reason": _REASON_SESSION_REFUSED,
            "provider_id": _LOCAL_PROVIDER_NAME,
            "runtime_base_url": safe_runtime,
            "configured_local_endpoint": safe_configured,
            "cause": "runtime local endpoint differs from policy pin",
        },
    )
    msg = (
        "Mordred strict mode: refusing mordred-local because its runtime "
        f"endpoint {safe_runtime!r} differs from the configured endpoint "
        f"{safe_configured!r}. Restart/reconfigure Hermes so the resolved "
        "client matches policy.json."
    )
    _LOG.error(msg)
    raise MordredSessionRefused(msg)


def _probe_local(
    *,
    audit: _AuditWriter,
    settings: _PolicySettings,
    health_probe: Callable[[str], None],
    probe_endpoint: str | None = None,
) -> None:
    """Strict + active provider is ``mordred-local`` → probe; allow or refuse.

    ``probe_endpoint`` (Codex review P2 round 7) lets ``pre_api_request``
    callers target the runtime ``base_url`` (the URL the outbound API
    call will actually use) instead of the ``policy.json`` mirror — the
    two can diverge in long-lived processes after a ``configure`` rerun.
    Defaults to ``settings.local_endpoint`` so the ``on_session_start``
    caller still probes the configured local endpoint.

    Before probing, the endpoint must pass the strict loopback-only boundary
    in :func:`_validate_loopback_endpoint`. Invalid endpoints are audited and
    refused without making a network request. On success the local endpoint
    constrains traffic, so the action is ``allow`` with reason
    ``policy.strict.cloud_allowlisted``.

    On probe failure Codex review P2 round 2 / ``_exceptions.py`` H2
    contract apply: :class:`MordredLocalUnreachable` is
    :class:`Exception`-derived, so Hermes' hook dispatch
    (``hermes_cli/plugins.py::invoke_hook`` line 1112) would swallow it
    and continue the session. We translate to
    :class:`MordredSessionRefused` (``BaseException``-derived) here so
    the session actually aborts, chaining the original probe error via
    ``__cause__`` for diagnosability. The block audit entry is written
    BEFORE the raise so a refusal is recorded even if the exception is
    later caught further up.
    """
    endpoint = probe_endpoint if probe_endpoint else settings.local_endpoint
    try:
        _validate_loopback_endpoint(endpoint)
    except _InvalidLocalEndpoint as e:
        _safe_audit_append(
            audit,
            {
                "event": "on_session_start",
                "decision": "block",
                "reason": _REASON_SESSION_REFUSED,
                "provider_id": _LOCAL_PROVIDER_NAME,
                "cause": str(e),
            },
        )
        msg = f"Mordred strict mode: mordred-local requires a loopback HTTP(S) endpoint ({e}); refusing the session."
        _LOG.error(msg)
        raise MordredSessionRefused(msg) from e

    try:
        health_probe(endpoint)
    except MordredLocalUnreachable as e:
        safe_endpoint = safe_endpoint_for_audit(endpoint)
        safe_cause = MordredLocalUnreachable(f"local LLM health probe failed ({type(e).__name__})")
        _safe_audit_append(
            audit,
            {
                "event": "on_session_start",
                "decision": "block",
                "reason": _REASON_SESSION_REFUSED,
                "provider_id": _LOCAL_PROVIDER_NAME,
                "cause": "local LLM health probe failed",
                "error_type": type(e).__name__,
                "runtime_base_url": safe_endpoint,
            },
        )
        msg = (
            f"Mordred strict mode: local LLM endpoint {safe_endpoint!r} is unreachable "
            f"({type(e).__name__}); refusing the session."
        )
        _LOG.error(msg)
        raise MordredSessionRefused(msg) from safe_cause
    _safe_audit_append(
        audit,
        {
            "event": "on_session_start",
            "decision": "allow",
            "reason": _REASON_CLOUD_ALLOWLISTED,
            "provider_id": _LOCAL_PROVIDER_NAME,
        },
    )


def _validate_loopback_endpoint(endpoint: str) -> None:
    """Require a strict-mode local endpoint to stay on the host loopback.

    Literal IPv4/IPv6 hosts must be loopback addresses. The only accepted DNS
    name is ``localhost``, and every address it currently resolves to must also
    be loopback. Restricting the hostname as well as its current resolution
    avoids treating an arbitrary self-hosted or cloud URL as ``mordred-local``.
    """
    if not endpoint or endpoint != endpoint.strip():
        raise _InvalidLocalEndpoint("endpoint must be a non-empty URL without surrounding whitespace")

    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError as e:
        raise _InvalidLocalEndpoint("endpoint URL is malformed") from e

    if parsed.scheme not in {"http", "https"}:
        raise _InvalidLocalEndpoint("endpoint scheme must be http or https")
    if parsed.username is not None or parsed.password is not None:
        raise _InvalidLocalEndpoint("endpoint URL must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise _InvalidLocalEndpoint("endpoint URL must not contain a query or fragment")

    hostname = parsed.hostname
    if not hostname:
        raise _InvalidLocalEndpoint("endpoint URL must include a host")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if hostname != "localhost":
            raise _InvalidLocalEndpoint("endpoint host must be a loopback IP address or localhost") from None
        _validate_localhost_resolution(port or (443 if parsed.scheme == "https" else 80))
        _ensure_loopback_proxy_bypass()
        return

    # Network proxy bypass is portable only for these exact literal forms.
    # Accepting e.g. 127.0.0.2 because the whole /8 is loopback would let
    # clients whose NO_PROXY supports only exact hosts send a supposedly local
    # request through HTTP_PROXY/Tor instead.
    if str(address) not in _STRICT_LOOPBACK_LITERALS:
        raise _InvalidLocalEndpoint("endpoint IP address must be 127.0.0.1 or ::1")
    _ensure_loopback_proxy_bypass()


def _validate_localhost_resolution(port: int) -> None:
    """Require every current ``localhost`` DNS result to be loopback."""
    try:
        results = socket.getaddrinfo("localhost", port, type=socket.SOCK_STREAM)
    except OSError as e:
        raise _InvalidLocalEndpoint("localhost could not be resolved") from e
    if not results:
        raise _InvalidLocalEndpoint("localhost did not resolve to any address")

    for result in results:
        sockaddr = result[4]
        if not isinstance(sockaddr, tuple) or not sockaddr or not isinstance(sockaddr[0], str):
            raise _InvalidLocalEndpoint("localhost resolved to an unsupported address")
        address_text = sockaddr[0].split("%", 1)[0]
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            raise _InvalidLocalEndpoint("localhost resolved to a malformed address") from None
        if not address.is_loopback:
            raise _InvalidLocalEndpoint("localhost resolved to a non-loopback address")


def _default_health_probe(endpoint: str) -> None:
    """Default health probe — production binding to :func:`health.probe`."""
    health.probe(endpoint=endpoint)


def _reset_state() -> None:
    """Reset module-level one-shot flags. Tests call between scenarios."""
    global _no_resolved_provider_emitted
    _no_resolved_provider_emitted = False
    _cloud_prompt_decisions.clear()


def _default_prompt(provider_id: str) -> bool | None:
    """Ask whether to allow this provider for the remainder of the process.

    Returns ``None`` when there is no interactive terminal — stdin OR
    stdout is not a TTY (the headless / harness / CI case) or input hits
    EOF / interrupt — so :func:`_resolve_cloud_attempt` fails closed to a
    block. Only an explicit ``y`` / ``yes`` allows; anything else denies.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return None
    try:
        answer = input(f"Mordred strict mode: allow all cloud calls to {provider_id!r} for this Hermes process? [y/N] ")
    except (EOFError, KeyboardInterrupt, ValueError):
        # EOF / Ctrl-C, or ValueError("I/O operation on closed file") when a
        # harness closed fd 0 rather than sending EOF. All fail closed — never
        # let the exception escape to Hermes' ``except Exception`` (fail-open).
        return None
    return answer.strip().lower() in {"y", "yes"}


def _resolve_cloud_attempt(
    *,
    action: CloudAttemptAction,
    provider_id: str,
    audit: _AuditWriter,
    prompt_fn: PromptFn,
    route_key: str | None = None,
    runtime_base_url: str | None = None,
) -> bool:
    """Decide a non-allowlisted cloud attempt under strict mode.

    Returns ``True`` to allow the call (caller returns early), ``False`` to
    refuse it (caller falls through to :func:`_refuse_cloud_not_allowlisted`).

    ``always-block`` always refuses without prompting. ``prompt-once`` asks
    the operator once per provider (caching the verdict for the process) and
    records the decision via audit. An unavailable terminal fails closed and
    is not cached, so a later interactive call can still ask.
    """
    if action != "prompt-once":
        return False

    cache_key = route_key or provider_id
    cached = _cloud_prompt_decisions.get(cache_key)
    if cached is not None:
        # Already asked this provider this session — stay silent. A cached deny
        # still gets audited downstream by _refuse_cloud_not_allowlisted
        # (cloud_not_allowlisted + session_refused) on every call; only the
        # one-time cloud_prompted_deny decision record is not repeated.
        return cached

    verdict = prompt_fn(provider_id)
    if verdict is True:
        _cloud_prompt_decisions[cache_key] = True
        _safe_audit_append(
            audit,
            {
                "event": "pre_api_request",
                "decision": "allow",
                "reason": _REASON_CLOUD_PROMPTED_ALLOW,
                "provider_id": provider_id,
                **({"runtime_base_url": safe_endpoint_for_audit(runtime_base_url)} if runtime_base_url else {}),
            },
        )
        return True
    if verdict is False:
        _cloud_prompt_decisions[cache_key] = False
        _safe_audit_append(
            audit,
            {
                "event": "pre_api_request",
                "decision": "block",
                "reason": _REASON_CLOUD_PROMPTED_DENY,
                "provider_id": provider_id,
                **({"runtime_base_url": safe_endpoint_for_audit(runtime_base_url)} if runtime_base_url else {}),
            },
        )
        return False
    # verdict is None — no interactive terminal. Fail closed; do NOT cache so
    # a later call from a real terminal can still prompt.
    _safe_audit_append(
        audit,
        {
            "event": "pre_api_request",
            "decision": "block",
            "reason": _REASON_CLOUD_PROMPTED_DENY,
            "provider_id": provider_id,
            "prompt_unavailable": True,
            **({"runtime_base_url": safe_endpoint_for_audit(runtime_base_url)} if runtime_base_url else {}),
        },
    )
    return False


def _normalized_cloud_endpoint(runtime_base_url: str | None) -> tuple[str, str] | None:
    """Return ``(host, normalized route id)`` for a safe cloud URL."""
    if not isinstance(runtime_base_url, str) or not runtime_base_url.strip():
        return None
    if runtime_base_url != runtime_base_url.strip() or any(
        ord(char) < 0x20 or ord(char) == 0x7F for char in runtime_base_url
    ):
        return None
    raw = runtime_base_url.strip()
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.casefold() != "https" or parsed.username is not None or parsed.password is not None:
        return None
    if parsed.query or parsed.fragment:
        return None
    host = (parsed.hostname or "").rstrip(".").casefold()
    if not host:
        return None
    default_port = port in (None, 443)
    authority = host if default_port else f"{host}:{port}"
    path = parsed.path.rstrip("/") or "/"
    return host, f"https://{authority}{path}"


def _host_matches_constraint(host: str, constraint: str) -> bool:
    if constraint.startswith("."):
        suffix = constraint[1:]
        return host == suffix or host.endswith(constraint)
    return host == constraint


def _path_at_or_below(path: str, base: str) -> bool:
    return path == base or path.startswith(f"{base}/")


def cloud_endpoint_matches_provider(provider_id: str, runtime_base_url: str | None) -> bool:
    """Whether a runtime URL belongs to the named built-in cloud provider."""
    parsed = _normalized_cloud_endpoint(runtime_base_url)
    provider = policy_provider_id(provider_id)
    if parsed is None:
        return False
    host = parsed[0]
    path = urlsplit(parsed[1]).path
    if provider == "bedrock":
        return _BEDROCK_ENDPOINT_RE.fullmatch(host) is not None
    if provider == "vertex":
        return _VERTEX_ENDPOINT_RE.fullmatch(host) is not None
    if provider == "opencode-go":
        return host == "opencode.ai" and _path_at_or_below(path, "/zen/go/v1")
    if provider == "opencode-zen":
        return host == "opencode.ai" and _path_at_or_below(path, "/zen/v1")
    constraints = _CLOUD_ENDPOINT_HOSTS.get(provider)
    return bool(constraints and any(_host_matches_constraint(parsed[0], constraint) for constraint in constraints))


# Provider SDKs silently redirect to these when the caller passes no
# ``base_url``. Hermes then reports ``base_url=""`` while the request actually
# leaves for the override, so an absent runtime endpoint may only be trusted
# once none of these is set. Enumerated from the installed
# ``openai`` / ``anthropic`` / ``google`` clients rather than guessed.
_SDK_BASE_URL_ENV_VARS: Final[tuple[str, ...]] = (
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_FOUNDRY_BASE_URL",
    "ANTHROPIC_VERTEX_BASE_URL",
    "AZURE_OPENAI_ENDPOINT",
    "GEMINI_NEXT_GEN_API_BASE_URL",
    "OPENAI_BASE_URL",
)


def ambient_base_url_override() -> str | None:
    """Return the first provider-SDK endpoint override present in the env.

    ``None`` means no ambient redirect exists, so a client constructed without
    an explicit ``base_url`` really does reach the vendor default.
    """
    for name in _SDK_BASE_URL_ENV_VARS:
        raw = os.environ.get(name)
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return None


def cloud_provider_has_owned_default(provider_id: str) -> bool:
    """Whether omitting ``base_url`` still lands on a provider-owned endpoint.

    Hermes leaves ``base_url`` unset whenever the provider SDK supplies its own
    endpoint (``agent.base_url = base_url or ""`` in ``agent/agent_init.py``);
    native Anthropic is the common case. That is NOT an unbound destination — it
    is the vendor default — so it must not be treated like an operator override
    pointing at an arbitrary collector.

    Providers whose destination selects a tenant, region, or project (Azure
    Foundry, Bedrock, Vertex) have no single owned default. They keep failing
    closed until an explicit endpoint is configured, which is exactly what their
    empty :data:`_CLOUD_ENDPOINT_HOSTS` entries encode.
    """
    provider = policy_provider_id(provider_id)
    return bool(_CLOUD_ENDPOINT_HOSTS.get(provider))


def infer_cloud_provider(runtime_base_url: str | None) -> str | None:
    """Infer a unique built-in provider from an actual endpoint."""
    parsed = _normalized_cloud_endpoint(runtime_base_url)
    if parsed is None:
        return None
    matches = [
        provider for provider in _CLOUD_ENDPOINT_HOSTS if cloud_endpoint_matches_provider(provider, runtime_base_url)
    ]
    if not matches:
        return None
    # Several Hermes aliases intentionally share one service endpoint. Prefer
    # a policy identity already canonical in the public allow-list.
    priority = ("openai", "anthropic", "gemini", "bedrock", "vertex", "openrouter")
    return next((provider for provider in priority if provider in matches), sorted(matches)[0])


def _resolve_cloud_endpoint_binding(
    provider_id: str,
    runtime_base_url: str | None,
) -> tuple[bool, str | None, bool]:
    """Decide whether the request's real destination belongs to ``provider_id``.

    Returns ``(bound, effective_base_url, overridden)``.

    Endpoint identity is a prerequisite, not an approval decision: an allow-list
    entry or a provider-only prompt must never bless
    ``provider=openai, base_url=https://collector...``.

    An absent/blank ``base_url`` is NOT an unbound destination. Hermes stores
    ``base_url or ""`` and omits it whenever the provider SDK supplies its own
    endpoint, so the request goes to the vendor default. Such a client is still
    redirectable through the SDK's own environment overrides while Hermes keeps
    reporting ``base_url=""``, so bind against the ambient value when one exists
    and otherwise require the provider to own a single default endpoint.
    """
    overridden = isinstance(runtime_base_url, str) and bool(runtime_base_url.strip())
    if not overridden:
        ambient = ambient_base_url_override()
        if ambient is not None:
            return cloud_endpoint_matches_provider(provider_id, ambient), ambient, True
        return cloud_provider_has_owned_default(provider_id), runtime_base_url, False
    return cloud_endpoint_matches_provider(provider_id, runtime_base_url), runtime_base_url, True


def _cloud_route_key(provider_id: str, runtime_base_url: str | None) -> str:
    parsed = _normalized_cloud_endpoint(runtime_base_url)
    endpoint = parsed[1] if parsed is not None else "<missing-or-invalid-endpoint>"
    return f"{provider_id}@{endpoint}"


# --------------------------------------------------------------------------- #
# policy.json reader                                                          #
# --------------------------------------------------------------------------- #


class _PolicySettings:
    """Subset of ``policy.json`` consumed by enforce."""

    __slots__ = ("allow_cloud_llm", "cloud_allowlist", "cloud_attempt_action", "local_endpoint")

    def __init__(
        self,
        *,
        allow_cloud_llm: bool,
        cloud_allowlist: frozenset[str],
        local_endpoint: str,
        cloud_attempt_action: CloudAttemptAction = "always-block",
    ) -> None:
        self.allow_cloud_llm = allow_cloud_llm
        self.cloud_allowlist = cloud_allowlist
        self.local_endpoint = local_endpoint
        self.cloud_attempt_action = cloud_attempt_action


_DEFAULT_LOCAL_ENDPOINT: Final = "http://localhost:1234/v1"


def _read_policy_settings(policy_json_path: Path) -> _PolicySettings:
    """Read ``allow_cloud_llm`` / ``cloud_provider_allowlist`` / ``local_llm_endpoint``.

    Missing or malformed fields fall back to the safe-by-default values:
    ``allow_cloud_llm=False``, empty allowlist, default local endpoint.
    Under strict mode these defaults result in refusal for any cloud
    provider — i.e. failure-closed. A missing / unreadable / malformed /
    non-object ``policy.json`` loads as ``{}`` (via
    :func:`_policy_io.load_policy_mapping`), so the ``.get(...)`` chain
    below reproduces exactly those safe-by-default values.
    """
    data = load_policy_mapping(policy_json_path, log=_LOG)

    # Codex review P2: ``bool("false")`` is ``True`` in Python — using
    # ``bool(...)`` here would let a hand-edited or migrated
    # ``allow_cloud_llm: "false"`` (string) flip strict mode open. Require
    # the JSON value to be a real boolean ``true``; anything else is
    # failure-closed False.
    allow_cloud_llm = data.get("allow_cloud_llm") is True
    raw_allowlist = data.get("cloud_provider_allowlist", [])
    # Codex review P2 round 5 (revised): normalize allowlist entries through
    # the SAME alias table the runtime provider id is canonicalized through
    # (``__init__.py::_on_pre_api_request_enforce`` /
    # ``_resolve_active_provider`` both call ``canonicalize_provider``). A
    # bare ``.strip().lower()`` here handled casing/whitespace but not
    # aliases: a hand-edited ``cloud_provider_allowlist: ["claude"]`` (a real
    # Hermes alias for ``"anthropic"``) or ``["google"]`` / ``["aws"]`` would
    # never match the canonicalized runtime id and strict mode would refuse
    # a provider the user clearly intended to allow. ``canonicalize_provider``
    # already strips + lowers before the alias lookup, so this is not a
    # double-normalization. Empty strings still drop out (``if s``) so a
    # stray comma in the wizard CSV doesn't widen the allowlist.
    #
    # ``"custom"`` is dropped: it is Hermes' wildcard bucket for an arbitrary
    # OpenAI-compatible ``base_url`` (and the canonical form of the ``ollama``
    # local-endpoint alias). Letting an allowlist entry resolve to it would turn
    # a narrow grant (e.g. a user writing ``["ollama"]`` meaning "allow my local
    # model") into permission for ANY custom cloud endpoint — a fail-open
    # widening in a strict CLOUD allowlist. Fail closed instead; a deliberate
    # arbitrary-endpoint grant is not something strict mode should make easy.
    cloud_allowlist = (
        frozenset(
            s for s in (policy_provider_id(x) for x in raw_allowlist if isinstance(x, str)) if s and s != "custom"
        )
        if isinstance(raw_allowlist, list)
        else frozenset()
    )
    raw_endpoint = data.get("local_llm_endpoint")
    local_endpoint = raw_endpoint if isinstance(raw_endpoint, str) and raw_endpoint else _DEFAULT_LOCAL_ENDPOINT
    # Only the exact string ``"prompt-once"`` opts into the prompt path;
    # missing / unknown / non-string values fall back to the safe default
    # ``"always-block"`` (failure-closed, mirroring the allow_cloud_llm
    # ``is True`` coercion above).
    cloud_attempt_action: CloudAttemptAction = (
        "prompt-once" if data.get("cloud_attempt_action") == "prompt-once" else "always-block"
    )
    return _PolicySettings(
        allow_cloud_llm=allow_cloud_llm,
        cloud_allowlist=cloud_allowlist,
        local_endpoint=local_endpoint,
        cloud_attempt_action=cloud_attempt_action,
    )


def check_runtime_provider(
    *,
    policy_mode: str,
    policy_json_path: Path,
    active_provider: str | None,
    audit: _AuditWriter,
    health_probe: Callable[[str], None] | None = None,
    runtime_base_url: str | None = None,
    prompt_fn: PromptFn | None = None,
) -> None:
    """Per-request runtime enforcement (Codex review P1 round 3 + P2 round 4).

    ``on_session_start`` only has access to disk-based provider state, so
    runtime overrides (``hermes --provider …``,
    ``HERMES_INFERENCE_PROVIDER``, oneshot / gateway model switches) would
    bypass strict-mode policy if we relied on it alone.
    ``pre_api_request`` carries the actually-resolved runtime ``provider``
    kwarg (verified at ``run_agent.py:11327``) — this function is the
    authoritative enforcement against that runtime value.

    Differences from :func:`check_session_provider`:

    - **Allow paths stay silent**: fires on every API call, so allow
      audits would spam the log.
    - **Degraded silent**: ``on_session_start`` already audits
      ``no_resolved_provider`` when applicable; duplicating per call
      would double-emit. If pre_api_request itself lacks a provider we
      treat it as a malformed call upstream and stay silent.
    - **Probe still runs for mordred-local** (Codex P2 round 4): the
      disk state may have said cloud while the runtime is local, so
      session_start's probe could not have run. Probe failures
      translate to :class:`MordredSessionRefused` here just like in
      :func:`_probe_local`.

    Refuse paths write to audit and raise
    :class:`MordredSessionRefused` (``BaseException``-derived) so
    Hermes' ``except Exception`` filters at
    ``hermes_cli/plugins.py:1112`` and ``run_agent.py:11337`` cannot
    mask the refusal.
    """
    if policy_mode == "off":
        return
    if policy_mode != "strict":
        return  # lenient + unknown modes stay silent (defense in depth)
    settings = _read_policy_settings(policy_json_path)
    if active_provider is None:
        # Codex review P1 round 5: session_start enforce is now log-only,
        # so the degraded path MUST refuse here — otherwise strict mode
        # silently allows unresolved-provider API calls.
        _refuse_degraded(audit=audit, settings=settings)
        return  # unreachable — _refuse_degraded raises
    active_provider = policy_provider_id(active_provider)
    if active_provider == _LOCAL_PROVIDER_NAME:
        # Codex review P2 round 7: probe the runtime ``base_url`` (the URL
        # the request will actually use), not the policy.json mirror —
        # AIAgent's resolved profile can be stale in long-lived processes
        # after a ``configure`` rerun. Fall back to policy.json only when
        # the hook payload doesn't supply a usable base_url (e.g.
        # synthetic test payloads or future hook payload changes).
        runtime_endpoint = runtime_base_url if isinstance(runtime_base_url, str) and runtime_base_url.strip() else None
        if runtime_endpoint is not None and not _local_endpoint_matches_configured(
            runtime_endpoint,
            settings.local_endpoint,
        ):
            _refuse_local_endpoint_mismatch(
                audit=audit,
                runtime_endpoint=runtime_endpoint,
                configured_endpoint=settings.local_endpoint,
            )
        probe_endpoint = runtime_endpoint or settings.local_endpoint
        _probe_local(
            audit=_RefuseOnlyAuditWriter(audit),
            settings=settings,
            health_probe=health_probe or _default_health_probe,
            probe_endpoint=probe_endpoint,
        )
        return
    provider_allowlisted = active_provider in settings.cloud_allowlist and settings.allow_cloud_llm
    endpoint_bound, runtime_base_url, overridden = _resolve_cloud_endpoint_binding(
        active_provider,
        runtime_base_url,
    )
    if not endpoint_bound:
        _refuse_cloud_endpoint_mismatch(
            audit=audit,
            provider_id=active_provider,
            runtime_base_url=runtime_base_url,
            overridden=overridden,
        )
    if provider_allowlisted:
        return
    # Non-allowlisted cloud under strict mode. ``always-block`` (default)
    # refuses; ``prompt-once`` asks the operator once per provider via an
    # interactive terminal, failing closed to a refuse when none is present.
    if _resolve_cloud_attempt(
        action=settings.cloud_attempt_action,
        provider_id=active_provider,
        audit=audit,
        prompt_fn=prompt_fn or _default_prompt,
        route_key=_cloud_route_key(active_provider, runtime_base_url),
        runtime_base_url=runtime_base_url,
    ):
        return
    _refuse_cloud_not_allowlisted(
        audit=audit,
        provider_id=active_provider,
        allow_cloud_llm=settings.allow_cloud_llm,
    )


class _RefuseOnlyAuditWriter:
    """Audit writer wrapper that drops ``decision=allow`` entries.

    Lets :func:`_probe_local` be reused at ``pre_api_request`` without
    emitting an allow entry on every successful call (would spam the
    log). Block entries are still passed through.
    """

    def __init__(self, inner: _AuditWriter) -> None:
        self._inner = inner

    def append(self, entry: Mapping[str, Any]) -> None:
        if entry.get("decision") == "allow":
            return
        self._inner.append(entry)


__all__ = [
    "check_runtime_provider",
    "check_session_provider",
    "cloud_endpoint_matches_provider",
    "cloud_provider_has_owned_default",
    "infer_cloud_provider",
    "policy_provider_id",
    "safe_endpoint_for_audit",
]
