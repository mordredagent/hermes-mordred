"""Handlers for ``hermes mordred network {use,status}`` (Phase 3 PR2-C).

Replaces the ``NotImplementedError`` stubs that lived in
``wizard/cli.py`` from Phase 0 through Phase 2. Two responsibilities:

1. **Persist the user's desired default path** to
   ``~/.hermes/config.yaml plugins.mordred_network.default_path`` so
   the next ``hermes`` session brings that path up automatically at
   ``on_session_start`` (see :mod:`mordred_hermes.network.hooks`).
2. **Switch the in-process runtime live** when one is registered -
   that's the path the acceptance gate ("within 2s") exercises. From
   a standalone ``hermes-mordred`` invocation no runtime is registered
   (different process from the long-running ``hermes`` agent), so the
   handler degrades gracefully: write to disk, tell the user the
   change is deferred to the next session.

Audit reasons emitted by the underlying runtime (``network.use`` /
``network.use_failed``) come from PR2-A. The CLI itself does not write
audit entries - it is a thin user-facing wrapper.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from .._home import HERMES_BASE
from ..network import api
from ..network._exceptions import MordredNetworkError

_LOG = logging.getLogger("mordred.wizard.network_cli")

DEFAULT_CONFIG_PATH: Path = HERMES_BASE / "config.yaml"
_VALID_PATHS = ("tor", "vpn", "clearnet")


# --------------------------------------------------------------------------- #
# Public handlers                                                             #
# --------------------------------------------------------------------------- #


def handle_use(args: argparse.Namespace) -> int:
    """Process ``hermes mordred network use <path>``.

    Always writes the choice to ``config.yaml``. If a runtime is
    registered, also drives :func:`api.use` for live effect. Returns 0
    on success, non-zero when the live switch raised.
    """
    target = str(getattr(args, "path", ""))
    if target not in _VALID_PATHS:
        print(f"error: unknown network path {target!r}; choose one of {_VALID_PATHS}")
        return 2

    config_path = _resolve_config_path(args)

    try:
        _write_default_path_to_config(config_path, target)
    except OSError as e:
        print(f"error: failed to write {config_path}: {e}")
        return 3

    live = _runtime_registered()
    if not live:
        print(f"set default_path = {target!r} in {config_path}. Change is deferred to the next `hermes` session.")
        return 0

    try:
        api.use(target)  # type: ignore[arg-type]
    except MordredNetworkError as e:
        print(f"error: api.use({target!r}) failed: {e}")
        return 1
    print(f"switched to {target!r} (also persisted to {config_path}).")
    return 0


def handle_status(args: argparse.Namespace) -> int:
    """Process ``hermes mordred network status``.

    Shows live runtime state when available, else the disk-configured
    default with a "(not active in this process)" marker so the user
    can tell whether the value they see is currently routing traffic.
    """
    config_path = _resolve_config_path(args)
    if _runtime_registered():
        s = api.status()
        ready_label = "ready" if s.ready else "not ready"
        last_health = "ok" if s.last_health else "FAILED"
        print(f"active_path = {s.active_path!r}  state = {ready_label}  last_health = {last_health}")
        if api.is_dropped():
            print(
                "  [warning] path was flagged as DROPPED by the liveness "
                "worker. Strict-mode tool calls will refuse until the path "
                "is re-bring-up'd via `hermes mordred network use <path>`."
            )
        return 0

    configured = _read_default_path_from_config(config_path)
    print(f"configured default_path = {configured!r}  (runtime not active in this process)")
    return 0


# --------------------------------------------------------------------------- #
# Internals                                                                   #
# --------------------------------------------------------------------------- #


def _resolve_config_path(args: argparse.Namespace) -> Path:
    """Honour an injected ``config_path`` (tests) but fall back to default."""
    override = getattr(args, "config_path", None)
    if isinstance(override, Path):
        return override
    return DEFAULT_CONFIG_PATH


def _runtime_registered() -> bool:
    """Has the plugin's ``register(ctx)`` already run in this process?"""
    try:
        api.status()
    except MordredNetworkError:
        return False
    return True


def _write_default_path_to_config(config_path: Path, default_path: str) -> None:
    """Merge ``default_path`` into ``plugins.mordred_network`` via PolicyWriter.

    Routes through :meth:`PolicyWriter.merge_mordred_sections` (Phase 3 PR3a,
    landed alongside the wizard configure prompts that introduced Tor /
    Mullvad sub-fields) so a ``network use clearnet`` invocation does NOT
    clobber ``tor_binary_path`` / ``tor_socks_port`` / ``mullvad_*`` written
    earlier by ``hermes mordred configure`` or by hand.

    The merge path inherits the canonical ``_atomic_write_text`` (tempfile +
    ``os.replace``) guarantee from the writer pipeline, so a crash or
    concurrent ``hermes mordred configure`` invocation cannot truncate the
    file -- readers always see either the pre-write or post-write content.
    """
    from .policy_writer import PolicyWriter

    PolicyWriter(config_path=config_path).merge_mordred_sections({"mordred_network": {"default_path": default_path}})


def _read_default_path_from_config(config_path: Path) -> str:
    """Read ``plugins.mordred_network.default_path`` or fall back to clearnet."""
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


__all__ = ["handle_status", "handle_use"]
