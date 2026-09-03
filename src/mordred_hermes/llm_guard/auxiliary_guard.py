"""Strict-policy guard for Hermes auxiliary LLM routes.

Hermes 0.19 invokes ``pre_api_request`` only for the primary conversation
client. Auxiliary calls (compression, vision, title generation, configured
fallbacks, and the built-in auto chain) resolve clients and call them
directly. This module installs a narrow compatibility shim at those resolver
choke points: every returned client is checked against the same
provider/endpoint policy before the caller can issue a request.

The session hook also validates user-declared auxiliary and fallback routes so
obvious policy conflicts fail before any side task runs. ``auto`` remains
usable because its concrete client is guarded after resolution.
"""

from __future__ import annotations

import functools
import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, NoReturn

from .._audit_support import AuditWriter, build_audit_writer, safe_audit_append
from .._policy_io import load_policy_mapping, read_policy_mode_fail_closed
from .._provider_identity import canonicalize_provider
from .._yaml_io import load_yaml_mapping
from . import enforce
from ._exceptions import MordredSessionRefused
from .local_adapter import LOCAL_PROVIDER_NAME

_LOG = logging.getLogger("mordred.llm_guard.auxiliary")
_WRAPPED_MARKER: Final = "__mordred_auxiliary_route_guard__"
_BOUND_PATHS_MARKER: Final = "__mordred_auxiliary_route_guard_paths__"

_installed = False
_install_error: str | None = None
_installed_paths: tuple[Path, Path] | None = None

# Hot-path memos. Both are keyed on evidence that changes whenever the guarded
# state changes, so neither can serve a decision the current policy would refuse.
_GUARD_INPUT_LOCK: Final = threading.Lock()
_guard_input_cache: dict[Path, tuple[tuple[int, int, int, int], str, str]] = {}
_PROBE_LOCK: Final = threading.Lock()
_probe_ok_until: dict[str, float] = {}
# Short enough that a local LLM going away is noticed almost immediately, long
# enough that a burst of auxiliary calls shares one probe.
_PROBE_TTL_SECONDS: Final = 5.0
_REQUIRED_RESOLVER_SEAMS: Final = (
    "_get_cached_client",
    "_get_provider_chain",
    "resolve_provider_client",
    "resolve_vision_provider_client",
)


def _policy_mode(policy_json_path: Path) -> str:
    return read_policy_mode_fail_closed(
        policy_json_path,
        default="lenient",
        log=_LOG,
    )


def _policy_identity(policy_json_path: Path) -> tuple[int, int, int, int] | None:
    """Stat-based identity of ``policy.json``, or ``None`` when unusable.

    Any edit changes ``st_mtime_ns``/``st_size``, and a replacement changes the
    inode, so this is a safe cache key. ``None`` (absent/unreadable) always
    forces a fresh read so fail-closed handling is never served from a memo.
    """
    try:
        info = policy_json_path.stat()
    except OSError:
        return None
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size)


def _guard_inputs(policy_json_path: Path) -> tuple[str, str]:
    """Return ``(policy_mode, local_endpoint)`` with one memoized file read.

    ``_get_cached_client`` is wrapped, so this runs on *every* auxiliary request
    including cache hits. Reading and re-parsing ``policy.json`` several times
    per request was pure overhead on a path whose whole purpose is to be cheap.
    """
    identity = _policy_identity(policy_json_path)
    if identity is not None:
        with _GUARD_INPUT_LOCK:
            cached = _guard_input_cache.get(policy_json_path)
        if cached is not None and cached[0] == identity:
            return cached[1], cached[2]

    mode = _policy_mode(policy_json_path)
    local_endpoint = _policy_cloud_settings(policy_json_path).local_endpoint
    if identity is not None and identity == _policy_identity(policy_json_path):
        # Only memoize when the file did not change under us mid-read.
        with _GUARD_INPUT_LOCK:
            _guard_input_cache[policy_json_path] = (identity, mode, local_endpoint)
    return mode, local_endpoint


def reset_caches() -> None:
    """Drop both hot-path memos. Tests call this between scenarios."""
    with _GUARD_INPUT_LOCK:
        _guard_input_cache.clear()
    with _PROBE_LOCK:
        _probe_ok_until.clear()


def _memoized_health_probe(endpoint: str) -> None:
    """Probe the local endpoint at most once per :data:`_PROBE_TTL_SECONDS`.

    Only *successful* probes are cached, so an unreachable local LLM still fails
    closed on the very next auxiliary call. Without this, every compression /
    title / vision request issued its own synchronous ``GET /models``.
    """
    now = time.monotonic()
    with _PROBE_LOCK:
        fresh_until = _probe_ok_until.get(endpoint)
    if fresh_until is not None and now < fresh_until:
        return
    enforce._default_health_probe(endpoint)
    with _PROBE_LOCK:
        _probe_ok_until[endpoint] = time.monotonic() + _PROBE_TTL_SECONDS


def _client_base_url(client: Any) -> str | None:
    raw = getattr(client, "base_url", None)
    if raw is None:
        inner = getattr(client, "_client", None)
        raw = getattr(inner, "base_url", None)
    text = str(raw or "").strip()
    return text or None


def _effective_provider(provider: object, base_url: str | None) -> str | None:
    raw = str(provider or "").strip()
    normalized = canonicalize_provider(raw) if raw else ""
    if normalized and not _provider_requires_endpoint_inference(normalized):
        return normalized
    return enforce.infer_cloud_provider(base_url)


def _provider_requires_endpoint_inference(provider: str) -> bool:
    """Whether a Hermes route label is metadata rather than an identity."""
    return provider in {"api-key", "auto", "custom", "local/custom"} or provider.startswith(
        ("custom:", "fallback_chain[", "main-agent(")
    )


def _same_configured_endpoint(left: str | None, right: str) -> bool:
    """Compare client-normalized and configured base URLs.

    OpenAI-compatible clients commonly add one trailing slash to ``base_url``.
    Treat only that representation difference as equal; the resulting local
    route still goes through enforce's loopback validation and health probe.
    """
    return bool(left and left.strip().rstrip("/") == right.strip().rstrip("/"))


def _guard_resolved_client(
    *,
    provider: object,
    client: Any,
    policy_json_path: Path,
    audit_path: Path,
) -> None:
    if client is None:
        return
    policy_mode, local_endpoint = _guard_inputs(policy_json_path)
    if policy_mode != "strict":
        return
    base_url = _client_base_url(client)
    effective_provider = (
        LOCAL_PROVIDER_NAME
        if _same_configured_endpoint(base_url, local_endpoint)
        else _effective_provider(provider, base_url)
    )
    audit = build_audit_writer(audit_path)
    if effective_provider is None:
        _refuse_auxiliary(
            audit=audit,
            provider_id=str(provider or "auto"),
            base_url=base_url,
            cause="the resolved auxiliary endpoint has no trusted provider identity",
        )
    assert effective_provider is not None
    enforce.check_runtime_provider(
        policy_mode="strict",
        policy_json_path=policy_json_path,
        active_provider=effective_provider,
        audit=audit,
        runtime_base_url=base_url,
        # Background auxiliary calls must never open an interactive approval
        # surface. Explicit policy configuration is required.
        prompt_fn=lambda _provider: None,
        # One probe per short TTL instead of one per auxiliary request; a failing
        # probe is never memoized, so the local route still fails closed.
        health_probe=_memoized_health_probe,
    )


def _prepare_rebind(*, module: Any, name: str, bound_paths: tuple[Path, Path]) -> Callable[..., Any] | None:
    """Return the callable to wrap, or ``None`` when the seam is already guarded.

    ``None`` means ``module.name`` is our own wrapper bound to these exact
    policy/audit paths, so rebinding it would be a no-op. A wrapper bound to
    different paths is unwrapped via ``__wrapped__`` so guards never stack.
    """
    current = getattr(module, name)
    if bool(getattr(current, _WRAPPED_MARKER, False)) and getattr(current, _BOUND_PATHS_MARKER, None) == bound_paths:
        return None
    original: Callable[..., Any] | None = (
        getattr(current, "__wrapped__", None) if bool(getattr(current, _WRAPPED_MARKER, False)) else current
    )
    if not callable(original):
        raise RuntimeError(f"Hermes auxiliary resolver {name!r} cannot be rebound")
    return original


def _finish_rebind(*, module: Any, name: str, guarded: Callable[..., Any], bound_paths: tuple[Path, Path]) -> None:
    """Stamp the guard markers onto ``guarded`` and bind it onto the module.

    Keyword-only (like :func:`_prepare_rebind`): ``module`` and ``guarded``
    are both untyped-ish objects, so a transposed positional call would bind
    the guard onto the wrong object without any type error.
    """
    setattr(guarded, _WRAPPED_MARKER, True)
    setattr(guarded, _BOUND_PATHS_MARKER, bound_paths)
    setattr(module, name, guarded)


def _wrap_pair_resolver(
    module: Any,
    name: str,
    *,
    policy_json_path: Path,
    audit_path: Path,
) -> None:
    bound_paths = (policy_json_path, audit_path)
    original = _prepare_rebind(module=module, name=name, bound_paths=bound_paths)
    if original is None:
        return

    @functools.wraps(original)
    def guarded(provider: object, *args: Any, **kwargs: Any) -> Any:
        result = original(provider, *args, **kwargs)
        if isinstance(result, tuple) and result:
            _guard_resolved_client(
                provider=provider,
                client=result[0],
                policy_json_path=policy_json_path,
                audit_path=audit_path,
            )
        return result

    _finish_rebind(module=module, name=name, guarded=guarded, bound_paths=bound_paths)


def _wrap_vision_resolver(
    module: Any,
    *,
    policy_json_path: Path,
    audit_path: Path,
) -> None:
    name = "resolve_vision_provider_client"
    bound_paths = (policy_json_path, audit_path)
    original = _prepare_rebind(module=module, name=name, bound_paths=bound_paths)
    if original is None:
        return

    @functools.wraps(original)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        if isinstance(result, tuple) and len(result) >= 2:
            _guard_resolved_client(
                provider=result[0] or kwargs.get("provider"),
                client=result[1],
                policy_json_path=policy_json_path,
                audit_path=audit_path,
            )
        return result

    _finish_rebind(module=module, name=name, guarded=guarded, bound_paths=bound_paths)


def _wrap_provider_chain(
    module: Any,
    *,
    policy_json_path: Path,
    audit_path: Path,
) -> None:
    name = "_get_provider_chain"
    bound_paths = (policy_json_path, audit_path)
    original = _prepare_rebind(module=module, name=name, bound_paths=bound_paths)
    if original is None:
        return

    @functools.wraps(original)
    def guarded() -> list[tuple[str, Callable[..., Any]]]:
        chain = original()
        result: list[tuple[str, Callable[..., Any]]] = []
        for label, resolver in chain:

            def guarded_candidate(
                *args: Any,
                __label: str = label,
                __resolver: Callable[..., Any] = resolver,
                **kwargs: Any,
            ) -> Any:
                resolved = __resolver(*args, **kwargs)
                if isinstance(resolved, tuple) and resolved:
                    _guard_resolved_client(
                        provider=__label,
                        client=resolved[0],
                        policy_json_path=policy_json_path,
                        audit_path=audit_path,
                    )
                return resolved

            result.append((label, guarded_candidate))
        return result

    _finish_rebind(module=module, name=name, guarded=guarded, bound_paths=bound_paths)


def install(*, policy_json_path: Path, audit_path: Path) -> bool:
    """Install auxiliary resolver guards, returning whether all seams exist."""
    global _installed, _install_error, _installed_paths
    requested_paths = (policy_json_path, audit_path)
    if _installed:
        if _installed_paths != requested_paths:
            _install_error = (
                "auxiliary route guard is already bound to different policy/audit paths; "
                "restart Hermes to change its security boundary"
            )
            return False
        if _runtime_seams_guarded():
            return True
        # A force re-discovery or upstream mutation replaced at least one
        # guarded callable. Re-run the idempotent wrappers below.
        _installed = False
    try:
        from agent import auxiliary_client  # type: ignore[import-untyped]

        for required in _REQUIRED_RESOLVER_SEAMS:
            if not callable(getattr(auxiliary_client, required, None)):
                raise RuntimeError(f"Hermes auxiliary resolver {required!r} is unavailable")
        _wrap_pair_resolver(
            auxiliary_client,
            "resolve_provider_client",
            policy_json_path=policy_json_path,
            audit_path=audit_path,
        )
        _wrap_pair_resolver(
            auxiliary_client,
            "_get_cached_client",
            policy_json_path=policy_json_path,
            audit_path=audit_path,
        )
        _wrap_vision_resolver(
            auxiliary_client,
            policy_json_path=policy_json_path,
            audit_path=audit_path,
        )
        _wrap_provider_chain(
            auxiliary_client,
            policy_json_path=policy_json_path,
            audit_path=audit_path,
        )
    except Exception as exc:
        _install_error = str(exc)
        _LOG.error("could not install Hermes auxiliary route guard: %s", exc)
        return False
    _install_error = None
    _installed = True
    _installed_paths = requested_paths
    return True


def _runtime_seams_guarded() -> bool:
    """Re-prove that Hermes still exposes our four wrapped resolver seams."""
    try:
        from agent import auxiliary_client
    except Exception:
        return False
    expected_paths = _installed_paths
    return expected_paths is not None and all(
        callable(candidate)
        and bool(getattr(candidate, _WRAPPED_MARKER, False))
        and getattr(candidate, _BOUND_PATHS_MARKER, None) == expected_paths
        for name in _REQUIRED_RESOLVER_SEAMS
        for candidate in (getattr(auxiliary_client, name, None),)
    )


def _refuse_auxiliary(
    *,
    audit: AuditWriter,
    provider_id: str,
    base_url: str | None,
    cause: str,
    task: str | None = None,
) -> NoReturn:
    safe_endpoint = enforce.safe_endpoint_for_audit(base_url)
    safe_audit_append(
        audit,
        {
            "event": "on_session_start" if task else "pre_api_request",
            "decision": "block",
            "reason": "policy.strict.session_refused",
            "provider_id": provider_id,
            "runtime_base_url": safe_endpoint,
            "auxiliary": True,
            **({"auxiliary_task": task} if task else {}),
            "cause": cause,
        },
        logger=_LOG,
    )
    msg = f"Mordred strict mode: refusing auxiliary LLM route {provider_id!r}"
    if task:
        msg += f" for task {task!r}"
    msg += f": {cause}."
    raise MordredSessionRefused(msg)


@dataclass(frozen=True, slots=True)
class _CloudRouteSettings:
    """The ``policy.json`` knobs a declared auxiliary route is judged against."""

    allow_cloud: bool
    allowlist: frozenset[str]
    local_endpoint: str


def _policy_cloud_settings(policy_json_path: Path) -> _CloudRouteSettings:
    data = load_policy_mapping(policy_json_path, log=_LOG)
    allow_cloud = data.get("allow_cloud_llm") is True
    raw_allowlist = data.get("cloud_provider_allowlist")
    allowlist = (
        frozenset(
            provider
            for provider in (enforce.policy_provider_id(value) for value in raw_allowlist if isinstance(value, str))
            if provider and provider != "custom"
        )
        if isinstance(raw_allowlist, list)
        else frozenset()
    )
    local_endpoint = data.get("local_llm_endpoint")
    return _CloudRouteSettings(
        allow_cloud=allow_cloud,
        allowlist=allowlist,
        local_endpoint=(
            local_endpoint.strip()
            if isinstance(local_endpoint, str) and local_endpoint.strip()
            else "http://localhost:1234/v1"
        ),
    )


def _validate_declared_route(
    *,
    task: str,
    candidate: Mapping[str, Any],
    settings: _CloudRouteSettings,
    audit: AuditWriter,
) -> None:
    raw_provider = str(candidate.get("provider") or "auto").strip()
    base_url = str(candidate.get("base_url") or "").strip() or None
    provider = enforce.policy_provider_id(raw_provider)
    if provider == "auto" and base_url is None:
        return  # the concrete result is guarded by the resolver wrapper
    if _same_configured_endpoint(base_url, settings.local_endpoint):
        return
    if provider == LOCAL_PROVIDER_NAME:
        if base_url is None:
            return
        _refuse_auxiliary(
            audit=audit,
            provider_id=provider,
            base_url=base_url,
            task=task,
            cause="mordred-local base_url differs from the strict local endpoint",
        )
    if _provider_requires_endpoint_inference(provider):
        inferred = enforce.infer_cloud_provider(base_url)
        if inferred is None:
            _refuse_auxiliary(
                audit=audit,
                provider_id=provider,
                base_url=base_url,
                task=task,
                cause="custom/auto endpoint is not owned by a known provider",
            )
        provider = inferred
    if not settings.allow_cloud or provider not in settings.allowlist:
        _refuse_auxiliary(
            audit=audit,
            provider_id=provider,
            base_url=base_url,
            task=task,
            cause="provider is not enabled by the strict cloud allow-list",
        )
    if base_url is not None and not enforce.cloud_endpoint_matches_provider(provider, base_url):
        _refuse_auxiliary(
            audit=audit,
            provider_id=provider,
            base_url=base_url,
            task=task,
            cause="declared base_url is not a provider-owned endpoint",
        )


def validate_session(
    *,
    policy_json_path: Path,
    config_path: Path,
    audit_path: Path,
) -> None:
    """Validate declared auxiliary routes and ensure runtime seams are guarded."""
    if _policy_mode(policy_json_path) != "strict":
        return
    audit = build_audit_writer(audit_path)
    expected_paths = (policy_json_path, audit_path)
    if not _installed or _installed_paths != expected_paths or not _runtime_seams_guarded():
        _refuse_auxiliary(
            audit=audit,
            provider_id="auxiliary",
            base_url=None,
            cause=(
                "Hermes auxiliary interception is unavailable or resolver seams were replaced "
                f"({_install_error or 'guard marker missing'})"
            ),
        )

    settings = _policy_cloud_settings(policy_json_path)
    config = load_yaml_mapping(config_path, catch=(Exception,), log=_LOG)
    _validate_root_fallbacks(
        config=config,
        settings=settings,
        audit=audit,
    )
    auxiliary = config.get("auxiliary")
    if not isinstance(auxiliary, dict):
        return
    _validate_auxiliary_config(
        auxiliary=auxiliary,
        settings=settings,
        audit=audit,
    )


def _validate_root_fallbacks(
    *,
    config: Mapping[str, Any],
    settings: _CloudRouteSettings,
    audit: AuditWriter,
) -> None:
    """Validate main fallback routes that ``provider: auto`` may inherit."""
    for key in ("fallback_providers", "fallback_model"):
        raw_chain = config.get(key)
        if raw_chain is None:
            continue
        entries = [raw_chain] if isinstance(raw_chain, dict) else raw_chain
        if not isinstance(entries, list):
            _refuse_auxiliary(
                audit=audit,
                provider_id=key,
                base_url=None,
                task=key,
                cause=f"{key} is neither a mapping nor a list",
            )
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                _refuse_auxiliary(
                    audit=audit,
                    provider_id=key,
                    base_url=None,
                    task=f"{key}[{index}]",
                    cause="fallback entry is not a mapping",
                )
            # Hermes ignores incomplete entries; they cannot become a route.
            if not str(entry.get("provider") or "").strip() or not str(entry.get("model") or "").strip():
                continue
            _validate_declared_route(
                task=f"{key}[{index}]",
                candidate=entry,
                settings=settings,
                audit=audit,
            )


def _validate_auxiliary_config(
    *,
    auxiliary: Mapping[object, object],
    settings: _CloudRouteSettings,
    audit: AuditWriter,
) -> None:
    """Validate every declared task and each configured fallback entry."""
    for task, raw_task in auxiliary.items():
        if not isinstance(task, str) or not isinstance(raw_task, dict):
            continue
        if raw_task.get("enabled") is False:
            continue
        _validate_declared_route(
            task=task,
            candidate=raw_task,
            settings=settings,
            audit=audit,
        )
        chain = raw_task.get("fallback_chain")
        if chain is None:
            continue
        if not isinstance(chain, list):
            _refuse_auxiliary(
                audit=audit,
                provider_id="fallback_chain",
                base_url=None,
                task=task,
                cause="fallback_chain is not a list",
            )
        for index, entry in enumerate(chain):
            if not isinstance(entry, dict):
                _refuse_auxiliary(
                    audit=audit,
                    provider_id="fallback_chain",
                    base_url=None,
                    task=task,
                    cause=f"fallback_chain[{index}] is not a mapping",
                )
            _validate_declared_route(
                task=f"{task}.fallback_chain[{index}]",
                candidate=entry,
                settings=settings,
                audit=audit,
            )


__all__ = ["install", "reset_caches", "validate_session"]
