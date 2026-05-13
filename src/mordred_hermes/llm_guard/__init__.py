"""mordred_llm_guard — local LLM enforcement (Phase 2 PR1: provider + harness).

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

PR2 will add the enforce hook on the same ``on_session_start`` slot,
registered AFTER the harness handler so harness refusals take precedence
(HOOK_PAYLOADS.md §1: callbacks fire in registration order).

This module is intentionally side-effect-free at import time: provider
registration only happens via :func:`register`. Tests verify this
invariant (``test_llm_guard_register.py``).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, cast

from .._home import HERMES_BASE
from . import harness_detect, local_adapter
from ._typing import PluginContext

_LOG = logging.getLogger("mordred.llm_guard")

DEFAULT_CONFIG_PATH: Path = HERMES_BASE / "config.yaml"
DEFAULT_POLICY_JSON_PATH: Path = HERMES_BASE / "mordred" / "policy.json"
DEFAULT_AUDIT_PATH: Path = HERMES_BASE / "mordred" / "audit.log"


def register(ctx: PluginContext) -> None:
    """Hermes plugin entry point — wires PR1 surface.

    Steps:

    1. Register the ``mordred-local`` synthetic provider with the upstream
       provider registry.
    2. Register the harness-primary detector on ``on_session_start``.

    The hook handler captures :data:`DEFAULT_CONFIG_PATH` /
    :data:`DEFAULT_POLICY_JSON_PATH` / :data:`DEFAULT_AUDIT_PATH` as
    defaults; tests can patch the module attrs to redirect.
    """
    local_adapter.register_mordred_local(policy_json_path=DEFAULT_POLICY_JSON_PATH)
    ctx.register_hook("on_session_start", _on_session_start)


def _on_session_start(**_kwargs: Any) -> None:
    """Run PR1 session-start checks.

    PR1: harness detection only. PR2 adds enforce.
    Lazily constructs the audit writer so plugin discovery stays cheap.
    """
    policy_mode = _read_policy_mode(DEFAULT_POLICY_JSON_PATH)
    audit = _build_audit_writer(DEFAULT_AUDIT_PATH)
    harness_detect.check_harness_primary(
        policy_mode=policy_mode,
        config_path=DEFAULT_CONFIG_PATH,
        audit=audit,
    )


def _read_policy_mode(policy_json_path: Path) -> str:
    """Read ``policy`` from ``policy.json``; default to ``"lenient"``."""
    if not policy_json_path.exists():
        return "lenient"
    try:
        with policy_json_path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        _LOG.warning("could not read %s: %s; defaulting to lenient", policy_json_path, e)
        return "lenient"
    if not isinstance(data, dict):
        return "lenient"
    mode = data.get("policy", "lenient")
    if mode in ("strict", "lenient", "off"):
        return cast(str, mode)
    _LOG.warning("invalid policy %r in %s; defaulting to lenient", mode, policy_json_path)
    return "lenient"


def _build_audit_writer(path: Path) -> Any:
    """Construct the NDJSON writer privacy_check already uses.

    Local import avoids loading privacy_check at plugin-discovery time
    (keeps :func:`register` cheap and side-effect-free until invoked).
    """
    from ..privacy_check.audit import NDJSONWriter

    return NDJSONWriter(path=path)
