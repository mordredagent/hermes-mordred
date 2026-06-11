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

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, Protocol

from . import health
from ._exceptions import MordredLocalUnreachable, MordredSessionRefused
from .local_adapter import LOCAL_PROVIDER_NAME

_LOG = logging.getLogger("mordred.llm_guard.enforce")

# Audit reasons — POLICY.md §Audit log reason enum (frozen 12 codes).
_REASON_CLOUD_ALLOWLISTED: Final = "policy.strict.cloud_allowlisted"
_REASON_CLOUD_NOT_ALLOWLISTED: Final = "policy.strict.cloud_not_allowlisted"
_REASON_SESSION_REFUSED: Final = "policy.strict.session_refused"
_REASON_UNCONDITIONAL_OVERRIDE: Final = "policy.strict.unconditional_override"
_REASON_NO_RESOLVED_PROVIDER: Final = "mordred.degraded.no_resolved_provider"

# Canonical name of the local provider — re-exported from local_adapter so
# this module and the profile constructor share a single source of truth.
_LOCAL_PROVIDER_NAME: Final = LOCAL_PROVIDER_NAME

# One-shot flag for the degraded "no provider info" path (POLICY.md row 6).
# Module-level state — tests reset via :func:`_reset_state`.
_no_resolved_provider_emitted = False


class _AuditWriter(Protocol):
    """Structural protocol mirroring ``privacy_check.audit.Writer``.

    Declared inline (instead of importing) to keep cross-plugin coupling
    out of llm_guard. ``NDJSONWriter`` is duck-compatible.
    """

    def append(self, entry: dict[str, Any]) -> None: ...


def _safe_audit_append(audit: _AuditWriter, entry: dict[str, Any]) -> None:
    """Best-effort audit write.

    Codex review P1 round 6: a strict-mode refusal path must raise
    :class:`MordredSessionRefused` (``BaseException``-derived) so it
    escapes Hermes' ``except Exception`` filters at
    ``hermes_cli/plugins.py:1112`` and ``run_agent.py:11337``. If the
    audit writer itself raises a plain :class:`Exception` (disk full,
    broken NDJSON path, permission denied) BEFORE we get to the raise,
    Hermes would catch it and continue — fail-open. This wrapper
    swallows audit-side failures so the BaseException refusal still
    fires. The underlying error is logged so operators can investigate.
    """
    try:
        audit.append(entry)
    except Exception as e:
        _LOG.error("audit append failed for entry %r: %s", entry, e)


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
        f"(intended fallback local endpoint: {settings.local_endpoint})."
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

    On success the local endpoint constrains traffic, so the action is
    ``allow`` with reason ``policy.strict.cloud_allowlisted``.

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
        health_probe(endpoint)
    except MordredLocalUnreachable as e:
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
        msg = f"Mordred strict mode: local LLM endpoint {endpoint!r} is unreachable ({e}); refusing the session."
        _LOG.error(msg)
        raise MordredSessionRefused(msg) from e
    _safe_audit_append(
        audit,
        {
            "event": "on_session_start",
            "decision": "allow",
            "reason": _REASON_CLOUD_ALLOWLISTED,
            "provider_id": _LOCAL_PROVIDER_NAME,
        },
    )


def _default_health_probe(endpoint: str) -> None:
    """Default health probe — production binding to :func:`health.probe`."""
    health.probe(endpoint=endpoint)


def _reset_state() -> None:
    """Reset module-level one-shot flags. Tests call between scenarios."""
    global _no_resolved_provider_emitted
    _no_resolved_provider_emitted = False


# --------------------------------------------------------------------------- #
# policy.json reader                                                          #
# --------------------------------------------------------------------------- #


class _PolicySettings:
    """Subset of ``policy.json`` consumed by enforce."""

    __slots__ = ("allow_cloud_llm", "cloud_allowlist", "local_endpoint")

    def __init__(
        self,
        *,
        allow_cloud_llm: bool,
        cloud_allowlist: frozenset[str],
        local_endpoint: str,
    ) -> None:
        self.allow_cloud_llm = allow_cloud_llm
        self.cloud_allowlist = cloud_allowlist
        self.local_endpoint = local_endpoint


_DEFAULT_LOCAL_ENDPOINT: Final = "http://localhost:1234/v1"


def _read_policy_settings(policy_json_path: Path) -> _PolicySettings:
    """Read ``allow_cloud_llm`` / ``cloud_provider_allowlist`` / ``local_llm_endpoint``.

    Missing or malformed fields fall back to the safe-by-default values:
    ``allow_cloud_llm=False``, empty allowlist, default local endpoint.
    Under strict mode these defaults result in refusal for any cloud
    provider — i.e. failure-closed.
    """
    safe_default = _PolicySettings(
        allow_cloud_llm=False,
        cloud_allowlist=frozenset(),
        local_endpoint=_DEFAULT_LOCAL_ENDPOINT,
    )
    if not policy_json_path.exists():
        return safe_default
    try:
        with policy_json_path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        _LOG.warning("could not read %s: %s; using safe defaults", policy_json_path, e)
        return safe_default
    if not isinstance(data, dict):
        return safe_default

    # Codex review P2: ``bool("false")`` is ``True`` in Python — using
    # ``bool(...)`` here would let a hand-edited or migrated
    # ``allow_cloud_llm: "false"`` (string) flip strict mode open. Require
    # the JSON value to be a real boolean ``true``; anything else is
    # failure-closed False.
    allow_cloud_llm = data.get("allow_cloud_llm") is True
    raw_allowlist = data.get("cloud_provider_allowlist", [])
    # Codex review P2 round 5: normalize allowlist entries (strip + lower)
    # because callers compare against ``.strip().lower()``-normalized
    # runtime provider names (see ``__init__.py::_on_pre_api_request_enforce``).
    # Hand-edited / wizard-collected entries like ``"OpenAI"`` or
    # ``" anthropic "`` must still match the runtime ``"openai"`` /
    # ``"anthropic"``. Empty strings drop out so a stray comma in the
    # wizard CSV doesn't widen the allowlist.
    cloud_allowlist = (
        frozenset(s for s in (str(x).strip().lower() for x in raw_allowlist if isinstance(x, str)) if s)
        if isinstance(raw_allowlist, list)
        else frozenset()
    )
    raw_endpoint = data.get("local_llm_endpoint")
    local_endpoint = raw_endpoint if isinstance(raw_endpoint, str) and raw_endpoint else _DEFAULT_LOCAL_ENDPOINT
    return _PolicySettings(
        allow_cloud_llm=allow_cloud_llm,
        cloud_allowlist=cloud_allowlist,
        local_endpoint=local_endpoint,
    )


def check_runtime_provider(
    *,
    policy_mode: str,
    policy_json_path: Path,
    active_provider: str | None,
    audit: _AuditWriter,
    health_probe: Callable[[str], None] | None = None,
    runtime_base_url: str | None = None,
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
    if active_provider == _LOCAL_PROVIDER_NAME:
        # Codex review P2 round 7: probe the runtime ``base_url`` (the URL
        # the request will actually use), not the policy.json mirror —
        # AIAgent's resolved profile can be stale in long-lived processes
        # after a ``configure`` rerun. Fall back to policy.json only when
        # the hook payload doesn't supply a usable base_url (e.g.
        # synthetic test payloads or future hook payload changes).
        probe_endpoint = (
            runtime_base_url.strip()
            if isinstance(runtime_base_url, str) and runtime_base_url.strip()
            else settings.local_endpoint
        )
        _probe_local(
            audit=_RefuseOnlyAuditWriter(audit),
            settings=settings,
            health_probe=health_probe or _default_health_probe,
            probe_endpoint=probe_endpoint,
        )
        return
    if active_provider in settings.cloud_allowlist and settings.allow_cloud_llm:
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

    def append(self, entry: dict[str, Any]) -> None:
        if entry.get("decision") == "allow":
            return
        self._inner.append(entry)


__all__ = ["check_runtime_provider", "check_session_provider"]
