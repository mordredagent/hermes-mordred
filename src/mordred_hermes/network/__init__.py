"""mordred_network - Tor / VPN / Clearnet path management.

Phase 3 PR2 wiring:

1. Construct the singleton :class:`Runtime` (PR2-A) reading config from
   ``~/.hermes/config.yaml plugins.mordred_network.*`` and
   ``~/.hermes/mordred/policy.json``.
2. Register it process-wide via :func:`api.set_runtime`.
3. Register :mod:`hooks` callbacks for ``on_session_start`` /
   ``on_session_end`` / ``pre_tool_call``.

Side-effect-free at module import: provider, hook, and runtime
registration all happen inside :func:`register`. Tests verify this via
the ``register(FakeCtx)`` assertions in ``tests/test_network_hooks.py``.
"""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol, cast

from .._home import HERMES_BASE
from . import api, hooks
from .runtime import ActivePath, PolicyMode, Runtime, RuntimeConfig

if TYPE_CHECKING:
    from ..privacy_check.audit import NDJSONWriter

_LOG = logging.getLogger("mordred.network")

DEFAULT_POLICY_JSON_PATH: Path = HERMES_BASE / "mordred" / "policy.json"
DEFAULT_CONFIG_PATH: Path = HERMES_BASE / "config.yaml"
DEFAULT_AUDIT_PATH: Path = HERMES_BASE / "mordred" / "audit.log"


class PluginContext(Protocol):
    """Subset of ``hermes_cli.plugins.PluginContext`` used by mordred_network."""

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> None: ...


_VALID_POLICY_MODES: Final[frozenset[str]] = frozenset({"strict", "lenient", "off"})
_VALID_PATHS: Final[frozenset[str]] = frozenset({"tor", "vpn", "clearnet"})


def register(ctx: PluginContext) -> None:
    """Hermes plugin entry point. Wires the runtime + 3 hooks.

    Codex P1 fix (2026-05-14): build :class:`RuntimeConfig` from
    ``policy.json`` + ``config.yaml`` rather than the always-``off``
    defaults. The runtime's ``policy_mode`` drives the strict-vs-lenient
    branch in :meth:`Runtime._switch` (raise vs fall back to clearnet),
    the ``policy_mode`` argument passed to :func:`paths.vpn.bring_up`
    (Mullvad lockdown), and the audit ``decision`` field for
    ``network.path_dropped``. A stale ``"off"`` silently downgraded
    every one of those.
    """
    audit = _build_audit_writer(DEFAULT_AUDIT_PATH)
    config = _load_runtime_config(
        policy_json_path=DEFAULT_POLICY_JSON_PATH,
        config_path=DEFAULT_CONFIG_PATH,
    )
    runtime = Runtime(config=config, audit=audit)
    api.set_runtime(runtime)

    def _on_session_start(**kwargs: Any) -> None:
        hooks.on_session_start(
            policy_json_path=DEFAULT_POLICY_JSON_PATH,
            config_path=DEFAULT_CONFIG_PATH,
            audit=audit,
            **kwargs,
        )

    def _pre_tool_call(**kwargs: Any) -> dict[str, Any] | None:
        return hooks.pre_tool_call(
            policy_json_path=DEFAULT_POLICY_JSON_PATH,
            audit=audit,
            **kwargs,
        )

    ctx.register_hook("on_session_start", _on_session_start)
    ctx.register_hook("on_session_end", hooks.on_session_end)
    ctx.register_hook("pre_tool_call", _pre_tool_call)


def _load_runtime_config(*, policy_json_path: Path, config_path: Path) -> RuntimeConfig:
    """Build a :class:`RuntimeConfig` from disk state.

    Reads:
    - ``policy.json`` for ``policy_mode`` (strict / lenient / off)
    - ``policy.json`` for ``disable_ipv6`` (advisory IPv6-leak defence;
      strict-mode default ``True``, lenient/off default ``False``, Phase 3
      PR3a Task #2). User pin always wins.
    - ``config.yaml plugins.mordred_network.default_path`` for
      ``default_path``

    Also pins ``tor_data_dir`` to the active Hermes profile via
    :data:`HERMES_BASE` (Codex P2 round 2, 2026-05-14). Falling back to
    :class:`RuntimeConfig`'s built-in default would hard-code
    ``~/.hermes`` and leak Tor cookies across profiles when the user
    has ``HERMES_HOME`` set or an ``active_profile`` configured.

    Falls back to safe defaults (off / clearnet) when the policy /
    config files are absent or malformed - matches the hooks-layer
    fallback so the two readers stay in agreement.
    """
    policy_data = _load_policy_json(policy_json_path)
    policy_mode = _resolve_policy_mode(policy_data)
    disable_ipv6 = _resolve_disable_ipv6(policy_data, policy_mode)
    default_path = _read_default_path(config_path)
    return RuntimeConfig(
        policy_mode=cast(PolicyMode, policy_mode),
        default_path=cast(ActivePath, default_path),
        tor_data_dir=HERMES_BASE / "mordred" / "tor-data",
        disable_ipv6=disable_ipv6,
    )


def _load_policy_json(policy_json_path: Path) -> dict[str, Any]:
    """Open ``policy.json`` once and return its dict (or ``{}`` on miss).

    Phase 3 PR3a Task #2: ``_load_runtime_config`` derives multiple
    fields from the same JSON so a single read amortises the IO. All
    failure modes (absent, unreadable, malformed, non-dict root) collapse
    to ``{}`` so downstream resolvers can apply their own defaults
    without crashing plugin registration.
    """
    if not policy_json_path.exists():
        return {}
    try:
        with policy_json_path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        _LOG.warning("could not read %s: %s; defaulting to empty", policy_json_path, e)
        return {}
    if not isinstance(data, dict):
        return {}
    return cast(dict[str, Any], data)


def _resolve_policy_mode(data: dict[str, Any]) -> str:
    """Derive ``policy_mode`` from a pre-loaded ``policy.json`` dict."""
    mode = data.get("policy", "off")
    # Codex round 3 P2 (2026-05-14): isinstance check first; ``in`` on a
    # frozenset raises TypeError for unhashable values like ``[]`` or
    # ``{}``. A corrupted ``policy.json`` must collapse to ``off``, not
    # crash plugin registration before the hooks are installed.
    if isinstance(mode, str) and mode in _VALID_POLICY_MODES:
        return mode
    return "off"


def _resolve_disable_ipv6(data: dict[str, Any], policy_mode: str) -> bool:
    """Derive ``disable_ipv6`` from a pre-loaded ``policy.json`` dict.

    Phase 3 PR3a Task #2. If the user pinned a bool, honour it. Otherwise
    default by policy mode: ``strict`` → ``True`` (safe-by-default IPv6
    leak defence), ``lenient`` / ``off`` → ``False`` (user-friendly).

    Non-bool values (``"yes"``, ``1``, ``[]``) collapse to the mode default
    -- the contract is documented in POLICY.md §disable_ipv6 schema.
    """
    raw = data.get("disable_ipv6")
    if isinstance(raw, bool):
        return raw
    return policy_mode == "strict"


def _read_policy_mode(policy_json_path: Path) -> str:
    """Backward-compatible wrapper for the single-field reader.

    Kept so the hooks layer can call the single-field reader without
    learning the new ``_load_policy_json`` interface. New code should
    prefer the bulk reader.
    """
    return _resolve_policy_mode(_load_policy_json(policy_json_path))


def _read_default_path(config_path: Path) -> str:
    if not config_path.exists():
        return "clearnet"
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    yaml = YAML(typ="safe", pure=True)
    try:
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
    except (OSError, YAMLError) as e:
        _LOG.warning("could not read %s: %s", config_path, e)
        return "clearnet"
    if not isinstance(data, dict):
        return "clearnet"
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return "clearnet"
    network = plugins.get("mordred_network")
    if not isinstance(network, dict):
        return "clearnet"
    value = network.get("default_path", "clearnet")
    if isinstance(value, str) and value in _VALID_PATHS:
        return value
    return "clearnet"


@functools.lru_cache(maxsize=1)
def _build_audit_writer(path: Path) -> NDJSONWriter:
    """Build the shared NDJSON writer.

    Cached so ``__post_init__`` (``mkdir`` + ``chmod``) only fires once
    per process per path. Mirrors the pattern in
    :func:`mordred_hermes.llm_guard._build_audit_writer`.
    Local import keeps ``register`` cheap by avoiding privacy_check
    load at plugin-discovery time.
    """
    from ..privacy_check.audit import NDJSONWriter

    return NDJSONWriter(path=path)
