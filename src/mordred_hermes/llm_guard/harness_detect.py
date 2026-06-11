"""Detect agent-harness primaries that bypass Hermes hooks.

SPEC.md L143: harnesses (Codex CLI, Claude CLI, Cursor, ACP clients)
drive Hermes externally and run their own LLM call paths that ``pre_llm_call``
never sees. Mordred cannot enforce strict policy on traffic it cannot
observe, so under strict mode the session is refused at startup; under
lenient mode it warns + audits and continues; under off mode it is a no-op.

The harness identity is declared by the user in ``~/.hermes/config.yaml``:

.. code-block:: yaml

   plugins:
     mordred_llm_guard:
       harness_primary: codex      # or claude-cli / cursor / acp-claude / ...

Prefix-based matching avoids both:

- false negatives from version suffixes (``codex-0.130.0``)
- false positives from substring containment (``my-cursor-helper`` is NOT
  cursor; ``codex-style-prompt`` is NOT codex)

This module is read-only: it never writes to ``config.yaml`` or to
``policy.json``. The wizard is the sole writer of those files
(PATHS.md §writer column).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Protocol

from ._exceptions import MordredHarnessRefused

_LOG = logging.getLogger("mordred.llm_guard.harness_detect")

# Allowlist of harness-primary identifiers as compiled regexes.
# Keep in sync with SPEC.md L143.
#
# Matching rules per harness:
#   - codex / claude-cli / cursor: exact OR ``<harness>-<semver>``
#     (semver = digits + dots only). This admits ``codex-0.130.0`` while
#     rejecting ``codex-style-prompt`` and ``my-cursor-helper``.
#   - acp-: prefix form, the suffix is the ACP flavor (``claude``, ``cline``).
#     Must contain at least one non-empty token after the dash; bare ``acp-``
#     does not match.
_VERSION_SUFFIX = r"(-\d+(?:\.\d+)*)?"  # optional ``-1`` / ``-0.130.0`` / etc.
_HARNESS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(rf"^codex{_VERSION_SUFFIX}$"),
    re.compile(rf"^claude-cli{_VERSION_SUFFIX}$"),
    re.compile(rf"^cursor{_VERSION_SUFFIX}$"),
    re.compile(r"^acp-[a-z][a-z0-9-]*$"),
)

# Audit reason — shared with privacy_check's sibling-disable degradation
# because the operational risk is the same (Mordred cannot observe LLM
# traffic). The 12-code freeze (POLICY.md) does not yet include a
# harness-specific reason; if Phase 2 PR2 adds one, swap here.
_REASON = "mordred.degraded.disable_unprotected"


class _AuditWriter(Protocol):
    """Structural protocol for the audit writer injected by ``register(ctx)``.

    Declared inline to avoid importing privacy_check from llm_guard at
    module-import time (cross-plugin coupling). The shared
    ``privacy_check.audit.Writer`` Protocol is duck-compatible.
    """

    def append(self, entry: dict[str, Any]) -> None: ...


def _safe_audit_append(audit: _AuditWriter, entry: dict[str, Any]) -> None:
    """Best-effort audit write that never fails the caller open.

    Mirrors :func:`mordred_hermes.llm_guard.enforce._safe_audit_append`
    (security review H1): the strict-mode refusal raises
    :class:`MordredHarnessRefused` (``BaseException``-derived) so it
    escapes Hermes' ``except Exception:`` filters at
    ``hermes_cli/plugins.py`` and ``run_agent.py``. If the audit writer
    itself raises a plain :class:`Exception` (disk full, broken NDJSON
    path, permission denied) BEFORE the raise, Hermes would catch it and
    continue the session — a fail-open bypass of harness detection. This
    wrapper swallows audit-side failures so the refusal still fires; the
    underlying error is logged for operators.
    """
    try:
        audit.append(entry)
    except Exception as e:
        _LOG.error("audit append failed for entry %r: %s", entry, e)


def check_harness_primary(
    *,
    policy_mode: str,
    config_path: Path,
    audit: _AuditWriter,
) -> None:
    """Inspect the declared harness primary and act according to ``policy_mode``.

    Raises :class:`MordredHarnessRefused` only under strict mode when a
    known harness prefix matches. Otherwise emits an audit warning (lenient)
    or returns silently (off / unknown harness / missing config).

    The audit entry is written BEFORE the raise so the refusal is
    observable even when the BaseException propagates past
    ``except Exception:`` wrappers.
    """
    harness = _read_harness_primary(config_path)
    if harness is None:
        return  # nothing to check

    if not _is_known_harness(harness):
        return  # user declared a non-harness primary; ignore

    if policy_mode == "off":
        # Off mode: silent no-op. The user has explicitly opted out of
        # Mordred enforcement; we do not even audit (matches the
        # privacy_check ``off`` semantics at install_wrapper).
        return

    decision = "block" if policy_mode == "strict" else "warn"

    # Best-effort: a failing audit write must not stop the strict-mode
    # refusal below from raising (security review H1).
    _safe_audit_append(
        audit,
        {
            "event": "on_session_start",
            "decision": decision,
            "reason": _REASON,
            "harness_primary": harness,
        },
    )

    if decision == "block":
        msg = (
            f"Mordred strict mode: harness primary {harness!r} bypasses Hermes hooks; "
            "refusing the session. Switch to a non-harness primary or set policy to lenient."
        )
        _LOG.error(msg)
        raise MordredHarnessRefused(msg)

    # lenient (or fallback) — warn + continue
    _LOG.warning(
        "Mordred lenient mode: harness primary %r bypasses Hermes hooks; continuing with degraded enforcement",
        harness,
    )


def _is_known_harness(harness_primary: str) -> bool:
    """Match the declared primary against the allowlist of regex patterns.

    Empty string never matches. Substring containment never matches.
    Version-suffix forms (``codex-0.130.0``) match; non-version suffixes
    (``codex-style-prompt``) do not.
    """
    if not harness_primary:
        return False
    return any(pattern.match(harness_primary) for pattern in _HARNESS_PATTERNS)


def _read_harness_primary(config_path: Path) -> str | None:
    """Read ``plugins.mordred_llm_guard.harness_primary`` from config.yaml.

    Returns ``None`` if the file or key is absent — this is the wizard-
    not-yet-run path, which must never trigger a refusal (users would be
    locked out before they could configure).
    """
    if not config_path.exists():
        return None

    from ruamel.yaml import YAML

    yaml = YAML(typ="safe", pure=True)
    try:
        with config_path.open(encoding="utf-8") as f:
            data = yaml.load(f)
    except Exception as e:
        _LOG.warning("failed to read %s: %s", config_path, e)
        return None
    if not isinstance(data, dict):
        return None

    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return None

    section = plugins.get("mordred_llm_guard")
    if not isinstance(section, dict):
        return None

    value = section.get("harness_primary")
    if not isinstance(value, str):
        return None
    return value
