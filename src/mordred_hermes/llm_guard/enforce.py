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

Cloud provider identity/endpoint matching lives in :mod:`._cloud_endpoint`
and the ``policy.json`` reader lives in :mod:`._policy_settings` (LOC-reduction
sweep) — both are re-imported here so this module keeps deciding and
auditing against them without callers noticing the split. Several of their
names are further re-exported (listed in ``__all__``) so existing callers —
tests and :mod:`.auxiliary_guard` — that reach them as ``enforce.X`` keep
working unchanged.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Final, TypeAlias
from urllib.parse import urlsplit

from .._audit_support import AuditWriter as _AuditWriter
from .._audit_support import safe_audit_append
from .._proxy_bypass import ensure_loopback_proxy_bypass as _ensure_loopback_proxy_bypass
from . import health
from ._cloud_endpoint import _CLOUD_ENDPOINT_HOSTS as _CLOUD_ENDPOINT_HOSTS
from ._cloud_endpoint import _SDK_BASE_URL_ENV_VARS as _SDK_BASE_URL_ENV_VARS
from ._cloud_endpoint import _cloud_route_key, _resolve_cloud_endpoint_binding
from ._cloud_endpoint import ambient_base_url_override as ambient_base_url_override
from ._cloud_endpoint import cloud_endpoint_matches_provider as cloud_endpoint_matches_provider
from ._cloud_endpoint import cloud_provider_has_owned_default as cloud_provider_has_owned_default
from ._cloud_endpoint import infer_cloud_provider as infer_cloud_provider
from ._cloud_endpoint import policy_provider_id as policy_provider_id
from ._cloud_endpoint import safe_endpoint_for_audit as safe_endpoint_for_audit
from ._exceptions import MordredLocalUnreachable, MordredSessionRefused
from ._policy_settings import CloudAttemptAction, _PolicySettings, _read_policy_settings
from .local_adapter import LOCAL_PROVIDER_NAME

_LOG = logging.getLogger("mordred.llm_guard.enforce")

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


class _InvalidLocalEndpoint(ValueError):
    """A strict-mode ``mordred-local`` endpoint is not safely loopback-only."""


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
        _check_runtime_local(
            settings=settings,
            audit=audit,
            health_probe=health_probe,
            runtime_base_url=runtime_base_url,
        )
        return
    _check_runtime_cloud(
        settings=settings,
        active_provider=active_provider,
        audit=audit,
        runtime_base_url=runtime_base_url,
        prompt_fn=prompt_fn,
    )


def _check_runtime_local(
    *,
    settings: _PolicySettings,
    audit: _AuditWriter,
    health_probe: Callable[[str], None] | None,
    runtime_base_url: str | None,
) -> None:
    """``pre_api_request`` phase for a runtime-resolved ``mordred-local``.

    Codex review P2 round 7: probe the runtime ``base_url`` (the URL
    the request will actually use), not the policy.json mirror —
    AIAgent's resolved profile can be stale in long-lived processes
    after a ``configure`` rerun. Fall back to policy.json only when
    the hook payload doesn't supply a usable base_url (e.g.
    synthetic test payloads or future hook payload changes).
    """
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


def _check_runtime_cloud(
    *,
    settings: _PolicySettings,
    active_provider: str,
    audit: _AuditWriter,
    runtime_base_url: str | None,
    prompt_fn: PromptFn | None,
) -> None:
    """``pre_api_request`` phase for a runtime-resolved cloud provider.

    Endpoint binding is validated before the allow-list short-circuit, so an
    allow-listed provider pointed at a destination it does not own is still
    refused.
    """
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
    "_CLOUD_ENDPOINT_HOSTS",
    "_SDK_BASE_URL_ENV_VARS",
    "ambient_base_url_override",
    "check_runtime_provider",
    "check_session_provider",
    "cloud_endpoint_matches_provider",
    "cloud_provider_has_owned_default",
    "infer_cloud_provider",
    "policy_provider_id",
    "safe_endpoint_for_audit",
]
