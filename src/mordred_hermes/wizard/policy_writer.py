"""Round-trip writer for ``~/.hermes/config.yaml`` and ``~/.hermes/mordred/policy.json``.

Sole writer for the wizard-owned files (PATHS.md L17-19 writer column).
Preserves user comments, key order, and anchors in ``config.yaml`` via
``ruamel.yaml`` round-trip mode. Writes ``policy.json`` as the
debugger-friendly mirror that other Mordred plugins read directly.

Three core operations:

- :meth:`PolicyWriter.upsert_mordred_sections` — mutate ``plugins.mordred_*``
  blocks in ``~/.hermes/config.yaml``. Also ensures the 5 entry-point
  plugin names appear in ``plugins.enabled`` (HOOK_PAYLOADS.md §1 mandate
  -- Hermes loader will not invoke ``register()`` otherwise).
- :meth:`PolicyWriter.emit_policy_json` -- serialise the resolved policy
  snapshot to ``policy.json`` (file mode ``0o600``, atomic via tmp + replace).
- :meth:`PolicyWriter.write` -- convenience composition that does both.

Idempotency: if the on-disk content already matches, no write happens
(byte-for-byte compare for both files). Writes use ``<dest>.tmp`` +
``os.replace`` for POSIX-atomic substitution; a crash mid-write leaves
the previous file intact.
"""

from __future__ import annotations

import io
import json
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

from ruamel.yaml import YAML

from ._runtime import (
    DEFAULT_HERMES_CONFIG_PATH,
    DEFAULT_MORDRED_DIR,
    DEFAULT_POLICY_JSON_PATH,
)

_LOG = logging.getLogger("mordred.wizard.policy_writer")

MORDRED_PLUGIN_NAMES: Final = (
    "mordred_privacy_check",
    "mordred_wizard",
    "mordred_llm_guard",
    "mordred_network",
    "mordred_keyvault",
)


def _round_trip_yaml() -> YAML:
    """ruamel YAML instance configured for round-trip preservation.

    ``typ="rt"`` retains comments, key order, and anchors. Indent settings
    match the Hermes-shipped config style (2-space mapping, 4-space sequence,
    sequences offset 2 from their parent key) so the diff stays minimal
    when we touch unrelated nested keys.
    """
    yaml = YAML(typ="rt")
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    yaml.width = 4096  # don't wrap long values
    return yaml


def _atomic_write_text(path: Path, text: str, *, mode: int | None = None) -> None:
    """Write ``text`` to ``path`` via tmp + replace.

    Idempotent: if ``path`` already contains ``text`` byte-for-byte, no
    write happens (avoids touching mtime and triggering downstream watchers).
    Sets the optional file mode AFTER replace so it lands atomically.
    """
    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8")
        except OSError as e:
            _LOG.warning("could not read existing %s for compare: %s; will overwrite", path, e)
            existing = None
        if existing == text:
            return  # no-op -- content unchanged

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


def _ensure_plugins_enabled(root: Any) -> None:
    """Ensure all 5 Mordred plugin names appear in ``plugins.enabled``.

    Per HOOK_PAYLOADS.md §1 / TODO.md §0.5 acceptance gate L128, Hermes's
    entry-point plugins are NOT auto-loaded; their names must be listed
    in ``plugins.enabled`` for ``register()`` to be invoked.

    No-op if the section is already complete. If ``plugins.enabled`` is
    absent we add it; if ``plugins`` itself is absent we add it. Existing
    non-Mordred entries are preserved.
    """
    plugins = root.get("plugins") if isinstance(root, Mapping) else None
    if plugins is None:
        # Use a plain dict -- ruamel will still emit it as a mapping; round-trip
        # treatment of NEW keys is best-effort (we own this section).
        root["plugins"] = {"enabled": list(MORDRED_PLUGIN_NAMES)}
        return

    enabled = plugins.get("enabled")
    if enabled is None:
        plugins["enabled"] = list(MORDRED_PLUGIN_NAMES)
        return

    if not isinstance(enabled, list):
        # Pathological config -- leave alone, log, and bail. Wizard upgrade
        # path will surface the conflict to the user via diff + prompt.
        _LOG.warning("plugins.enabled is %s, not list; skipping mordred plugin auto-add", type(enabled).__name__)
        return

    existing = {str(x) for x in enabled if isinstance(x, str)}
    for name in MORDRED_PLUGIN_NAMES:
        if name not in existing:
            enabled.append(name)


def _upsert_mordred_section(root: Any, plugin_name: str, body: Mapping[str, Any]) -> None:
    """Replace ``plugins.<plugin_name>`` with ``body``, leaving siblings alone.

    Whole-section replacement is intentional -- partial merges across
    invocations would leave dangling keys from prior policy modes.
    Non-Mordred plugin sections are preserved.
    """
    plugins = root.get("plugins")
    if plugins is None:
        root["plugins"] = {plugin_name: dict(body)}
        return
    plugins[plugin_name] = dict(body)


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """Resolved policy values destined for ``policy.json``.

    Phase 1 + Phase 2 fields. Order of fields matches the JSON serialisation
    order — keep stable for diffability.

    Phase 2 fields (``local_llm_endpoint`` / ``local_llm_model_id`` /
    ``cloud_attempt_action``) are read by ``mordred_llm_guard`` and persisted
    here so future wizard reruns are not required after upgrading from
    Phase 1. They deliberately do NOT appear in
    :meth:`to_config_yaml_section`; ``plugins.mordred_privacy_check`` is
    privacy-check's namespace and Phase 2 fields belong to llm_guard.
    """

    policy: str  # "strict" | "lenient" | "off"
    allow_cloud_llm: bool = False
    cloud_provider_allowlist: tuple[str, ...] = ()
    audit_log_path: str | None = None
    # Phase 2 (Codex M3 — moved from PR2 so Phase 2 has a stable policy input surface).
    local_llm_endpoint: str = "http://localhost:1234/v1"
    local_llm_model_id: str = ""
    cloud_attempt_action: Literal["always-block", "prompt-once"] = "always-block"

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "allow_cloud_llm": self.allow_cloud_llm,
            "cloud_provider_allowlist": list(self.cloud_provider_allowlist),
            "audit_log_path": self.audit_log_path,
            "local_llm_endpoint": self.local_llm_endpoint,
            "local_llm_model_id": self.local_llm_model_id,
            "cloud_attempt_action": self.cloud_attempt_action,
        }

    def to_config_yaml_section(self) -> dict[str, Any]:
        """The body that lives under ``plugins.mordred_privacy_check`` in config.yaml.

        The same shape is read by ``privacy_check._runtime._load_state``
        (see ``privacy_check/_runtime.py:106``); changing field names here
        requires a coordinated change there. Phase 2 fields are intentionally
        excluded — they belong to ``plugins.mordred_llm_guard`` (PR2) and the
        ``policy.json`` cross-plugin mirror.
        """
        body: dict[str, Any] = {
            "policy": self.policy,
            "allow_cloud_llm": self.allow_cloud_llm,
            "cloud_provider_allowlist": list(self.cloud_provider_allowlist),
        }
        if self.audit_log_path is not None:
            body["audit_log_path"] = self.audit_log_path
        return body


@dataclass
class PolicyWriter:
    """Sole writer for ``~/.hermes/config.yaml plugins.mordred_*`` and ``policy.json``."""

    config_path: Path = DEFAULT_HERMES_CONFIG_PATH
    policy_json_path: Path = DEFAULT_POLICY_JSON_PATH
    mordred_dir: Path = DEFAULT_MORDRED_DIR

    def upsert_mordred_sections(self, sections: Mapping[str, Mapping[str, Any]]) -> None:
        """Round-trip-edit ``config.yaml`` to upsert one or more Mordred plugin sections.

        ``sections`` maps plugin name (e.g. ``"mordred_privacy_check"``) to
        the new section body. Non-listed Mordred plugins and non-Mordred
        plugins in ``config.yaml`` are left untouched.

        Also ensures all 5 Mordred plugin names appear in ``plugins.enabled``
        (Hermes entry-point loader requires this -- HOOK_PAYLOADS §1).
        """
        yaml = _round_trip_yaml()
        if self.config_path.exists():
            with self.config_path.open(encoding="utf-8") as f:
                root = yaml.load(f)
            if root is None:
                root = {}
        else:
            root = {}

        for plugin_name, body in sections.items():
            if plugin_name not in MORDRED_PLUGIN_NAMES:
                raise ValueError(f"PolicyWriter only edits Mordred plugin sections; refusing to touch {plugin_name!r}")
            _upsert_mordred_section(root, plugin_name, body)

        _ensure_plugins_enabled(root)

        buf = io.StringIO()
        yaml.dump(root, buf)
        _atomic_write_text(self.config_path, buf.getvalue())

    def emit_policy_json(self, snapshot: PolicySnapshot) -> None:
        """Serialise ``snapshot`` to ``policy.json`` (mode 0o600, atomic).

        ``json.dumps`` with ``sort_keys=False`` to honour :class:`PolicySnapshot`
        field order; a 2-space indent for human readability. Idempotent --
        rewrite is skipped if content matches.
        """
        text = json.dumps(snapshot.to_json_dict(), indent=2, sort_keys=False) + "\n"
        _atomic_write_text(self.policy_json_path, text, mode=0o600)

    def write(self, snapshot: PolicySnapshot) -> None:
        """Compose: write both ``policy.json`` AND the matching config.yaml section.

        Convenience for ``hermes mordred configure``. Note that only the
        ``mordred_privacy_check`` section is updated here -- wizard / network /
        llm_guard / keyvault sections are written by their own configure
        flows in later phases.
        """
        self.emit_policy_json(snapshot)
        self.upsert_mordred_sections({"mordred_privacy_check": snapshot.to_config_yaml_section()})
