"""Module-level state for the privacy_check plugin.

Loaded lazily by hook handlers — keeps ``register(ctx)`` cheap and
test-friendly. State is reset between tests via :func:`reset_state_for_tests`.

H3 Path B (HOOK_PAYLOADS.md §2): sibling-disable detection prefers
``hermes_cli.plugins._get_disabled_plugins`` / ``_get_enabled_plugins``
when available, falling back to direct ``~/.hermes/config.yaml`` reads.

Why "poison flag" alongside ``SystemExit``: Hermes's ``invoke_hook``
wraps every callback in ``try: ... except Exception:`` and logs as a
warning. ``SystemExit`` (from ``BaseException``) propagates past that
guard, but if a higher-level harness catches it, the in-process poison
flag still forces ``pre_tool_call`` to refuse every tool — defense in
depth for strict mode.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from .._home import HERMES_BASE, hermes_home
from .audit import Writer, make_audit_writer
from .policy import PolicyMode

_LOG = logging.getLogger("mordred.privacy_check")

SIBLING_PLUGINS: Final = (
    "mordred_network",
    "mordred_llm_guard",
    "mordred_keyvault",
    "mordred_wizard",
)

# Backwards-compat aliases — pre-Phase-1.3 code (and in-module uses below)
# read these names directly. The resolver itself was promoted to
# ``mordred_hermes._home`` so wizard / network / keyvault can share it
# without copy-paste.
_hermes_home = hermes_home
_HERMES_BASE: Final = HERMES_BASE
DEFAULT_AUDIT_PATH: Final = _HERMES_BASE / "mordred" / "audit.log"
DEFAULT_HERMES_CONFIG_PATH: Final = _HERMES_BASE / "config.yaml"


@dataclass(frozen=True, slots=True)
class PluginState:
    """Resolved policy snapshot + audit writer."""

    policy_mode: PolicyMode
    allow_cloud_llm: bool
    cloud_provider_allowlist: tuple[str, ...]
    audit: Writer
    config_path: Path


_state: PluginState | None = None
_state_lock = threading.Lock()
_poison_reason: str | None = None
_degraded_no_origin_skill_emitted = False


def ensure_state(
    *,
    config_path: Path | None = None,
    audit_path: Path | None = None,
) -> PluginState:
    """Load PluginState on first call, return cached state thereafter.

    Test code calls :func:`reset_state_for_tests` between scenarios.
    """
    global _state
    with _state_lock:
        if _state is None:
            _state = _load_state(
                config_path or DEFAULT_HERMES_CONFIG_PATH,
                audit_path,
            )
        return _state


def reset_state_for_tests() -> None:
    """Test helper — clears module-level singletons. Not for production code."""
    global _state, _poison_reason, _degraded_no_origin_skill_emitted
    with _state_lock:
        _state = None
        _poison_reason = None
        _degraded_no_origin_skill_emitted = False


def reload_state() -> None:
    """Public reload entry point — clears the cached PluginState so the
    next hook invocation re-reads ``~/.hermes/config.yaml``.

    Called from ``hermes mordred policy reload``. Does NOT clear the
    poison flag or one-shot ``no_origin_skill`` marker — those are
    process-lifetime invariants and re-asserting them after reload
    requires restarting the session.
    """
    global _state
    with _state_lock:
        _state = None


def get_active_policy_mode(*, config_path: Path | None = None) -> PolicyMode:
    """Read the active policy mode from ``~/.hermes/config.yaml``.

    Public read-only helper for tools (e.g. wizard's ``policy explain``)
    that must evaluate decisions identically to the install hook without
    touching the cached :class:`PluginState`. Reads the same field the
    hook reads (``plugins.mordred_privacy_check.policy``), so explainer
    output cannot drift from install-time enforcement when users edit
    ``config.yaml`` directly.
    """
    cfg = _load_yaml(config_path or DEFAULT_HERMES_CONFIG_PATH)
    plugins_cfg = cfg.get("plugins")
    if not isinstance(plugins_cfg, dict):
        return "lenient"
    section = plugins_cfg.get("mordred_privacy_check")
    if not isinstance(section, dict):
        return "lenient"
    raw = section.get("policy", "lenient")
    if raw in ("strict", "lenient", "off"):
        return cast(PolicyMode, raw)
    _LOG.warning("invalid policy %r in %s; defaulting to lenient", raw, config_path or DEFAULT_HERMES_CONFIG_PATH)
    return "lenient"


def get_active_audit_path(*, config_path: Path | None = None) -> Path:
    """Read the active audit log path from ``~/.hermes/config.yaml``.

    Public read-only helper mirroring :func:`get_active_policy_mode`.
    Returns the same path the install hook's NDJSONWriter is constructed
    with -- :func:`_resolve_audit_path` applies the under-``_HERMES_BASE``
    sandbox so a malicious config edit cannot redirect the wizard CLI
    elsewhere.

    Required so ``hermes mordred audit tail`` / ``grep`` follow the writer
    when users configure a custom ``plugins.mordred_privacy_check.audit_log_path``;
    otherwise the CLI would silently read the default path and miss entries.
    """
    cfg = _load_yaml(config_path or DEFAULT_HERMES_CONFIG_PATH)
    plugins_cfg = cfg.get("plugins")
    if not isinstance(plugins_cfg, dict):
        return DEFAULT_AUDIT_PATH
    section = plugins_cfg.get("mordred_privacy_check")
    if not isinstance(section, dict):
        return DEFAULT_AUDIT_PATH
    return _resolve_audit_path(section.get("audit_log_path"))


def _load_state(config_path: Path, audit_path_override: Path | None) -> PluginState:
    cfg = _load_yaml(config_path)
    plugins_cfg = cfg.get("plugins")
    if not isinstance(plugins_cfg, dict):
        plugins_cfg = {}
    section = plugins_cfg.get("mordred_privacy_check")
    if not isinstance(section, dict):
        section = {}

    raw_policy = section.get("policy", "lenient")
    if raw_policy in ("strict", "lenient", "off"):
        policy_mode: PolicyMode = raw_policy
    else:
        _LOG.warning("invalid policy %r in config; defaulting to lenient", raw_policy)
        policy_mode = "lenient"

    # M2 (security review 2026-06-11): only the bool ``True`` may grant
    # cloud-LLM permission. ``bool(...)`` truthy-coerced YAML strings, so a
    # hand-edited ``allow_cloud_llm: "false"`` silently *enabled* cloud LLMs.
    raw_allow_cloud = section.get("allow_cloud_llm", False)
    if isinstance(raw_allow_cloud, bool):
        allow_cloud_llm = raw_allow_cloud
    else:
        _LOG.warning(
            "non-boolean allow_cloud_llm %r in config; defaulting to False",
            raw_allow_cloud,
        )
        allow_cloud_llm = False

    raw_allowlist = section.get("cloud_provider_allowlist") or []
    allowlist: tuple[str, ...] = (
        tuple(x for x in raw_allowlist if isinstance(x, str)) if isinstance(raw_allowlist, list) else ()
    )

    audit_path = audit_path_override
    if audit_path is None:
        audit_path = _resolve_audit_path(section.get("audit_log_path"))
    # L465: encrypt the audit log once the keyvault is initialized. The
    # factory fails open to plaintext NDJSON. keyvault_home is the Hermes
    # home — the directory holding config.yaml.
    audit = make_audit_writer(audit_path, keyvault_home=config_path.parent)

    return PluginState(
        policy_mode=policy_mode,
        allow_cloud_llm=allow_cloud_llm,
        cloud_provider_allowlist=allowlist,
        audit=audit,
        config_path=config_path,
    )


def _resolve_audit_path(raw: object) -> Path:
    """Resolve and sandbox ``audit_log_path`` from user config.

    Defense-in-depth: even though ``~/.hermes/config.yaml`` is user-owned,
    we constrain the resolved path to live under ``~/.hermes/`` so a
    skill-driven config edit cannot redirect audit entries to e.g.
    ``~/.ssh/authorized_keys``. Out-of-base paths fall back to the default
    audit path with a logged warning.
    """
    if not raw:
        return DEFAULT_AUDIT_PATH
    candidate = Path(str(raw)).expanduser()
    try:
        resolved = candidate.resolve(strict=False)
        base = _HERMES_BASE.resolve(strict=False)
    except (OSError, RuntimeError) as e:
        _LOG.warning("audit_log_path %r could not be resolved (%s); using default", raw, e)
        return DEFAULT_AUDIT_PATH
    if base not in resolved.parents and resolved != base:
        _LOG.warning("audit_log_path %r resolves outside %s; using default", raw, _HERMES_BASE)
        return DEFAULT_AUDIT_PATH
    return resolved


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    from ruamel.yaml import YAML

    yaml = YAML(typ="safe", pure=True)
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.load(f)
    except Exception as e:
        _LOG.warning("failed to read %s: %s", path, e)
        return {}
    return data if isinstance(data, dict) else {}


def _read_disabled_from_yaml(config_path: Path) -> set[str]:
    cfg = _load_yaml(config_path)
    plugins = cfg.get("plugins")
    if not isinstance(plugins, dict):
        return set()
    disabled = plugins.get("disabled")
    if isinstance(disabled, list):
        return {x for x in disabled if isinstance(x, str)}
    return set()


def _read_enabled_from_yaml(config_path: Path) -> set[str] | None:
    cfg = _load_yaml(config_path)
    plugins = cfg.get("plugins")
    if not isinstance(plugins, dict) or "enabled" not in plugins:
        return None
    enabled = plugins.get("enabled")
    if not isinstance(enabled, list):
        return None
    return {x for x in enabled if isinstance(x, str)}


def _is_production_path(config_path: Path | None) -> bool:
    """``None`` and the default-path sentinel both mean "real user config"."""
    return config_path is None or config_path == DEFAULT_HERMES_CONFIG_PATH


def get_disabled_plugins(config_path: Path | None = None) -> set[str]:
    """Return the deny-list.

    Production paths (``None`` or ``DEFAULT_HERMES_CONFIG_PATH``) prefer
    Hermes's private ``_get_disabled_plugins`` API and fall back to reading
    the default YAML (HOOK_PAYLOADS §2). Explicit non-default paths
    (tests, scripted configs) read that path's YAML directly — never the
    user's real config.
    """
    if _is_production_path(config_path):
        try:
            from hermes_cli.plugins import _get_disabled_plugins
        except ImportError:
            pass
        else:
            try:
                return cast(set[str], set(_get_disabled_plugins()))
            except Exception as e:
                _LOG.warning("hermes_cli._get_disabled_plugins failed: %s; falling back to YAML", e)
        return _read_disabled_from_yaml(DEFAULT_HERMES_CONFIG_PATH)
    assert config_path is not None
    return _read_disabled_from_yaml(config_path)


def get_enabled_plugins(config_path: Path | None = None) -> set[str] | None:
    """Return opt-in allow-list (``None`` = key missing = "all loadable").

    Path-resolution rules mirror :func:`get_disabled_plugins`.
    """
    if _is_production_path(config_path):
        try:
            from hermes_cli.plugins import _get_enabled_plugins
        except ImportError:
            pass
        else:
            try:
                result = _get_enabled_plugins()
                return None if result is None else cast(set[str], set(result))
            except Exception as e:
                _LOG.warning("hermes_cli._get_enabled_plugins failed: %s; falling back to YAML", e)
        return _read_enabled_from_yaml(DEFAULT_HERMES_CONFIG_PATH)
    assert config_path is not None
    return _read_enabled_from_yaml(config_path)


def find_disabled_siblings(
    siblings: Iterable[str] = SIBLING_PLUGINS,
    *,
    config_path: Path | None = None,
) -> set[str]:
    """Return Mordred sibling plugins that are not loadable.

    A sibling is considered disabled if it appears in ``plugins.disabled``
    OR if ``plugins.enabled`` is set (not ``None``) and the sibling is not in it.

    ``config_path=None`` uses production resolution (Hermes API + default YAML).
    Explicit paths read only that YAML — never the user's real config.
    """
    deny = get_disabled_plugins(config_path)
    allow = get_enabled_plugins(config_path)
    return {s for s in siblings if s in deny or (allow is not None and s not in allow)}


def poison(reason: str) -> None:
    """Mark this process as poisoned — every subsequent ``pre_tool_call`` blocks.

    In production the poison flag is monotonic (set once, never cleared), so
    racing reads always see a consistent value. The lock here is mainly for
    test cleanliness (``reset_state_for_tests`` runs concurrently with hooks
    in some test workers).
    """
    global _poison_reason
    with _state_lock:
        _poison_reason = reason


def is_poisoned() -> bool:
    with _state_lock:
        return _poison_reason is not None


def get_poison_reason() -> str | None:
    with _state_lock:
        return _poison_reason


def claim_no_origin_skill_emit() -> bool:
    """One-shot guard for the ``mordred.degraded.no_origin_skill`` audit entry.

    Returns ``True`` exactly once per process; subsequent calls return ``False``.
    """
    global _degraded_no_origin_skill_emitted
    with _state_lock:
        if _degraded_no_origin_skill_emitted:
            return False
        _degraded_no_origin_skill_emitted = True
        return True
