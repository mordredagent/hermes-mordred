"""mordred_llm_guard — local LLM enforcement (Phase 2 PR1 + PR2).

PR1 wiring (Codex review applied):

1. **Provider registration** — :func:`register` explicitly calls
   :func:`local_adapter.register_mordred_local` (Codex B1: the upstream
   ``providers._discover_providers()`` scanner does not see entry-point
   plugins, so module-import side effects would never land the profile in
   the registry).

2. **Harness primary detection** — ``on_session_start`` hook invokes
   :func:`harness_detect.check_harness_primary` to refuse strict-mode
   sessions whose primary is a harness (Codex / Claude CLI / Cursor /
   ACP client). Lenient mode warns + audits and continues.

PR2 additions:

3. **Session-scoped enforce** — a second ``on_session_start`` callback
   registered AFTER ``harness_detect`` so harness refusals take precedence
   (HOOK_PAYLOADS.md §1: callbacks fire in registration order). Reads the
   active provider via :func:`_resolve_active_provider` and applies the
   refuse-only decision matrix in :func:`enforce.check_session_provider`.

This module is intentionally side-effect-free at import time: provider
registration only happens via :func:`register`. Tests verify this
invariant (``test_llm_guard_register.py``).
"""

from __future__ import annotations

import functools
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .._audit_support import build_audit_writer
from .._home import HERMES_BASE
from .._policy_io import read_policy_mode_fail_closed
from .._provider_identity import canonicalize_provider
from .._provider_resolution import (
    read_auth_active_provider,
    read_config_model_provider,
    resolve_disk_provider,
)
from .._proxy_bypass import ensure_loopback_proxy_bypass
from . import auxiliary_guard, enforce, harness_detect, local_adapter
from ._exceptions import MordredLocalUnreachable, MordredSessionRefused
from ._typing import PluginContext

if TYPE_CHECKING:
    # Type-only import — keeps :func:`register` cheap and side-effect-free by
    # avoiding privacy_check load at plugin-discovery time (the runtime body
    # of :func:`_build_audit_writer` does the lazy import on first call).
    from ..privacy_check.audit import Writer

_LOG = logging.getLogger("mordred.llm_guard")

# Codex L1 follow-up: inline literal lifted to a module constant for
# grep-ability; ``_read_policy_mode`` returned ``"lenient"`` from five sites.
_DEFAULT_POLICY_MODE = "lenient"

DEFAULT_CONFIG_PATH: Path = HERMES_BASE / "config.yaml"
DEFAULT_POLICY_JSON_PATH: Path = HERMES_BASE / "mordred" / "policy.json"
DEFAULT_AUDIT_PATH: Path = HERMES_BASE / "mordred" / "audit.log"
DEFAULT_AUTH_JSON_PATH: Path = HERMES_BASE / "auth.json"


def register(ctx: PluginContext) -> None:
    """Hermes plugin entry point — wires PR1 + PR2 surface.

    Steps:

    1. Register the ``mordred-local`` synthetic provider with the upstream
       provider registry.
    2. Register the harness-primary detector on ``on_session_start``.
    3. Register the enforce handler on the same hook (after step 2 so
       harness refusals propagate first).
    """
    # Hermes discovers plugins before constructing AIAgent, while the later
    # on_session_start/pre_api_request hooks run after its shared httpx client
    # has already captured ambient proxy settings.  Establish the bypass here
    # as a defense-in-depth path for embedded callers that do not execute the
    # wheel's interpreter-startup .pth hook.
    ensure_loopback_proxy_bypass()
    local_adapter.register_mordred_local(policy_json_path=DEFAULT_POLICY_JSON_PATH)
    # Hermes 0.19 does not emit ``pre_api_request`` for auxiliary LLM calls.
    # Install guards at its client-resolver seams before any side task can
    # construct/cache a client; strict mode verifies installation again at
    # session start and refuses if upstream drift removed a seam.
    auxiliary_guard.install(
        policy_json_path=DEFAULT_POLICY_JSON_PATH,
        audit_path=DEFAULT_AUDIT_PATH,
    )
    from ..privacy_check.hooks import check_plugin_integrity

    ctx.register_hook("on_session_start", check_plugin_integrity)
    ctx.register_hook("on_session_start", _on_session_start_harness)
    ctx.register_hook("on_session_start", _on_session_start_auxiliary)
    ctx.register_hook("on_session_start", _on_session_start_enforce)
    # Codex review P1 round 3: ``on_session_start`` only sees disk-based
    # state, so runtime overrides (``hermes --provider …``,
    # ``HERMES_INFERENCE_PROVIDER``, oneshot/gateway switches) would
    # bypass strict mode otherwise. ``pre_api_request`` is the only hook
    # whose payload carries the resolved runtime ``provider`` kwarg
    # (run_agent.py:11327).
    ctx.register_hook("pre_api_request", _on_pre_api_request_enforce)


def _on_session_start_harness(**_kwargs: Any) -> None:
    """First callback — harness detection (PR1)."""
    policy_mode = _read_policy_mode(DEFAULT_POLICY_JSON_PATH)
    audit = _build_audit_writer(DEFAULT_AUDIT_PATH)
    harness_detect.check_harness_primary(
        policy_mode=policy_mode,
        config_path=DEFAULT_CONFIG_PATH,
        audit=audit,
    )


def _on_session_start_auxiliary(**_kwargs: Any) -> None:
    """Fail early on declared auxiliary routes that violate strict policy."""
    auxiliary_guard.validate_session(
        policy_json_path=DEFAULT_POLICY_JSON_PATH,
        config_path=DEFAULT_CONFIG_PATH,
        audit_path=DEFAULT_AUDIT_PATH,
    )


def _on_session_start_enforce(**_kwargs: Any) -> None:
    """Second callback — audit-only disk-state pre-check (PR2).

    Refreshes the ``mordred-local`` profile from ``policy.json`` so a
    mid-process ``hermes mordred configure`` rerun updates ``base_url``
    before the next session start (Codex M1 PR2 follow-up — the previous
    in-process value would otherwise stay stale until process restart).

    Codex review P2 round 4: this hook can only see disk-based provider
    state (``config.yaml model.provider`` / ``auth.json active_provider``),
    not runtime overrides (``hermes --provider …``,
    ``HERMES_INFERENCE_PROVIDER``, oneshot / gateway model switches).
    Raising :class:`MordredSessionRefused` here on a stale-disk mismatch
    would falsely reject sessions whose actual runtime is allowed.

    The strict-mode refusal exceptions are therefore swallowed at this
    boundary — the audit entries written by
    :func:`enforce.check_session_provider` BEFORE the raise are still
    persisted, so observers see the disk-based pre-check signal.
    Authoritative refusal happens at :func:`_on_pre_api_request_enforce`
    where the actually-resolved runtime provider is known.
    """
    local_adapter.register_mordred_local(policy_json_path=DEFAULT_POLICY_JSON_PATH)
    policy_mode = _read_policy_mode(DEFAULT_POLICY_JSON_PATH)
    audit = _build_audit_writer(DEFAULT_AUDIT_PATH)
    active_provider = _resolve_active_provider(
        auth_json_path=DEFAULT_AUTH_JSON_PATH,
        config_path=DEFAULT_CONFIG_PATH,
    )
    try:
        enforce.check_session_provider(
            policy_mode=policy_mode,
            policy_json_path=DEFAULT_POLICY_JSON_PATH,
            active_provider=active_provider,
            audit=audit,
        )
    except MordredSessionRefused as e:
        _LOG.info(
            "on_session_start enforce: disk-state pre-check would refuse (%s); "
            "deferring authoritative decision to pre_api_request",
            e,
        )
    except MordredLocalUnreachable as e:
        _LOG.info(
            "on_session_start enforce: local probe failed for disk-configured "
            "endpoint (%s); deferring to pre_api_request",
            e,
        )


def _on_pre_api_request_enforce(**kwargs: Any) -> None:
    """Per-request authoritative enforcement against the resolved runtime provider.

    ``run_agent.py:11320-11338`` fires this hook just before the outbound
    API call with kwargs that include ``provider`` — the actually-resolved
    runtime provider (after CLI overrides, env vars, and oneshot/gateway
    switches). Strict-mode block paths raise
    :class:`MordredSessionRefused` (``BaseException``-derived) which
    escapes both the plugin manager's ``except Exception`` filter
    (``hermes_cli/plugins.py:1112``) and the call site's wrapper
    (``run_agent.py:11337``), so the API request is actually aborted.

    Codex review P1 round 3: this is the only enforcement point that
    cannot be bypassed by a runtime provider override; ``on_session_start``
    enforce remains as best-effort early refusal based on disk state.
    """
    provider = kwargs.get("provider")
    # Canonicalize aliases (e.g. ``claude`` → ``anthropic``) so the runtime
    # provider matches the strict-mode allowlist / transport registry keys,
    # not the raw Hermes alias the user happened to configure.
    active_provider = canonicalize_provider(provider) if isinstance(provider, str) and provider.strip() else None
    # Codex review P2 round 7: the runtime ``base_url`` is what the
    # outbound call will actually use; in long-lived processes it can
    # diverge from policy.json's ``local_llm_endpoint`` mirror after a
    # configure rerun. For the mordred-local path we want to probe
    # *that* URL, not the disk mirror.
    base_url = kwargs.get("base_url")
    runtime_base_url = base_url if isinstance(base_url, str) and base_url.strip() else None
    policy_mode = _read_policy_mode(DEFAULT_POLICY_JSON_PATH)
    audit = _build_audit_writer(DEFAULT_AUDIT_PATH)
    enforce.check_runtime_provider(
        policy_mode=policy_mode,
        policy_json_path=DEFAULT_POLICY_JSON_PATH,
        active_provider=active_provider,
        audit=audit,
        runtime_base_url=runtime_base_url,
    )


def _resolve_active_provider(*, auth_json_path: Path, config_path: Path) -> str | None:
    """Resolve the active provider id Hermes will actually run.

    Mirrors ``hermes_cli/runtime_provider.py::resolve_requested_provider``
    (the function that drives runtime inference, NOT the "is this
    configured?" predicate ``is_provider_explicitly_configured`` which
    earlier revisions of this function copied). Order:

    1. ``~/.hermes/config.yaml`` → ``model.provider`` — the persistent
       source of truth when it names a concrete provider.
    2. ``~/.hermes/auth.json`` → ``active_provider`` — fallback used when
       ``model.provider`` is missing, empty, or ``"auto"`` (Hermes'
       auto-resolution path).

    Codex review P1: enforce must NOT defer to a stale auth.json when
    ``model.provider`` names a different runtime; that scenario allowed
    cloud sessions to slip past strict mode against the wrong identifier.

    Returns ``None`` when neither source yields a usable string. The
    caller (enforce) treats ``None`` as the degraded
    ``no_resolved_provider`` path (POLICY.md row 6).
    """
    resolved = resolve_disk_provider(
        config_path=config_path,
        auth_json_path=auth_json_path,
        config_reader=_read_config_model_provider,
        auth_reader=_read_auth_active_provider,
    )
    return canonicalize_provider(resolved) if resolved else None


def _read_auth_active_provider(auth_json_path: Path) -> str | None:
    """Compatibility seam over the shared persistent-provider reader."""
    return read_auth_active_provider(auth_json_path, log=_LOG)


def _read_config_model_provider(config_path: Path) -> str | None:
    """Compatibility seam over the shared persistent-provider reader."""
    return read_config_model_provider(config_path, log=_LOG)


def _read_policy_mode(policy_json_path: Path) -> str:
    """Read ``policy`` from ``policy.json``, failing CLOSED on a damaged file.

    M1 port (originally landed only in ``network.hooks``): an absent file is
    a fresh install and keeps the ``"lenient"`` default, but a policy.json
    that EXISTS and cannot be read or parsed — or carries an invalid mode —
    reads as ``"strict"``. Falling back to lenient meant corrupting or
    chmod-ing policy.json silently downgraded the pre-API-request
    enforcement point, the one gate this plugin documents as impossible to
    bypass.
    """
    return read_policy_mode_fail_closed(policy_json_path, default=_DEFAULT_POLICY_MODE, log=_LOG)


@functools.lru_cache(maxsize=1)
def _build_audit_writer(path: Path) -> Writer:
    """Module-local reference to the process-wide writer for ``path``.

    The local ``lru_cache`` avoids repeated registry lookups and preserves the
    ``cache_clear()`` test API. It does not own writer lifecycle.

    Construction is delegated to the shared
    :func:`mordred_hermes._audit_support.build_audit_writer`, which returns the
    same normalized-path singleton used by privacy_check, network and
    extension-sign. Clearing this local cache therefore cannot wipe an active
    MRAL DEK or create a competing writer. The lazy privacy_check import keeps
    ``register`` cheap.
    """
    return build_audit_writer(path)
