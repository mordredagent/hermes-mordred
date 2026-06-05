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

import contextlib
import io
import json
import logging
import os
import tempfile
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, Protocol, runtime_checkable

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


@runtime_checkable
class _HasConfigYamlSection(Protocol):
    """Structural shape required by :meth:`PolicyWriter.write` for the
    optional ``network_answers`` argument.

    Implemented by :class:`mordred_hermes.wizard.network_cli.NetworkAnswers`.
    Kept as a Protocol (not a concrete import) to avoid the
    ``configure -> policy_writer -> configure`` import cycle while still
    enforcing the contract under ``mypy --strict``. ``runtime_checkable`` so
    callers and tests can ``isinstance``-check at the boundary.
    """

    def to_config_yaml_section(self) -> Mapping[str, Any]: ...


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

    The tmpfile is created via :func:`tempfile.mkstemp` (atomic
    ``O_CREAT|O_EXCL`` at mode 0o600 with a random suffix). This closes:

    - H3 (review 2026-05-14): for ``mode=0o600`` calls (policy.json,
      .env, credentials JSON) the secret content never lands on disk at
      umask-default — the file is 0o600 from the moment of creation.
    - M5: predictable ``<name>.tmp`` paths could collide under
      concurrent writers; the random suffix removes that.
    - M6: stale ``<name>.tmp`` from a prior crash no longer collides
      with subsequent writes.

    The final file mode after ``os.replace`` is the explicit ``mode``
    argument when provided; otherwise the tmpfile's 0o600 (tightest safe
    default — the parent directory is 0o700 so this doesn't restrict
    legitimate access).
    """
    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8")
        except OSError as e:
            _LOG.warning("could not read existing %s for compare: %s; will overwrite", path, e)
            existing = None
        if existing == text:
            return  # no-op -- content unchanged

    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    # mkstemp returns (fd, name). fd is opened O_RDWR|O_CREAT|O_EXCL at
    # mode 0o600 atomically -- no umask-default window. prefix/suffix
    # combine to keep the path adjacent to its target so os.replace stays
    # within the same filesystem (otherwise replace is non-atomic).
    fd, tmp_name = tempfile.mkstemp(dir=parent, prefix=path.name + ".", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        if mode is not None and mode != 0o600:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        # Best-effort cleanup -- if replace already happened the unlink is
        # a no-op (the path no longer points at our tmpfile).
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


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
    if not isinstance(plugins, MutableMapping):
        if plugins is not None:
            _LOG.warning(
                "plugins is %s, not a mapping; replacing with fresh enabled list",
                type(plugins).__name__,
            )
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

    Pathological cases (``plugins`` itself is a scalar / list from a hand-edit
    or interrupted write) fall back to whole-replacement of the ``plugins``
    key with a fresh dict — crashing on ``int[str] = ...`` would leave the
    user with an unrecoverable config. Logged at WARNING so the operator
    sees the corruption.
    """
    plugins = root.get("plugins")
    if not isinstance(plugins, MutableMapping):
        if plugins is not None:
            _LOG.warning(
                "plugins is %s, not a mapping; replacing with upsert body",
                type(plugins).__name__,
            )
        root["plugins"] = {plugin_name: dict(body)}
        return
    plugins[plugin_name] = dict(body)


def _merge_mordred_section(root: Any, plugin_name: str, body: Mapping[str, Any]) -> None:
    """In-place merge ``body`` into ``plugins.<plugin_name>``, preserving siblings.

    Unlike :func:`_upsert_mordred_section`, the existing section's sub-fields
    survive: only keys in ``body`` are touched. ruamel.yaml's CommentedMap
    in-place update preserves comments and key order for retained keys; new
    keys are appended at the end of the section.

    Pathological cases (the section is currently a scalar / list / null) fall
    back to whole-replacement -- the on-disk shape is no longer mergeable and
    crashing with ``AttributeError: 'str' has no 'get'`` would leave the user
    with an unrecoverable config. Logged at WARNING so the operator sees it.

    Used by :meth:`PolicyWriter.merge_mordred_sections` (Phase 3 PR3a) to
    drive ``hermes mordred network use <path>`` without dropping Tor /
    Mullvad sub-fields the wizard configure step wrote earlier.
    """
    plugins = root.get("plugins")
    if not isinstance(plugins, MutableMapping):
        if plugins is not None:
            _LOG.warning(
                "plugins is %s, not a mapping; replacing with merge body",
                type(plugins).__name__,
            )
        root["plugins"] = {plugin_name: dict(body)}
        return
    existing = plugins.get(plugin_name)
    # ``MutableMapping`` (not ``Mapping``) so the index-assignment loop below
    # narrows under mypy --strict. ruamel.yaml ``CommentedMap`` is a
    # ``MutableMapping`` so this is exactly the shape we need.
    if not isinstance(existing, MutableMapping):
        if existing is not None:
            _LOG.warning(
                "plugins.%s is %s, not a mapping; replacing with merge body",
                plugin_name,
                type(existing).__name__,
            )
        plugins[plugin_name] = dict(body)
        return
    for key, value in body.items():
        existing[key] = value


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
    # Phase 2 PR2: config.yaml-only (consumed by harness_detect). Default
    # ``"none"`` is a sentinel that doesn't match any harness regex pattern.
    harness_primary: str = "none"
    # Phase 3 PR3a Task #7: persisted to policy.json so the network reader
    # (mordred_hermes.network._resolve_disable_ipv6) can consume it.
    # Default ``True`` matches the safe-by-default in RuntimeConfig.
    disable_ipv6: bool = True

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "allow_cloud_llm": self.allow_cloud_llm,
            "cloud_provider_allowlist": list(self.cloud_provider_allowlist),
            "audit_log_path": self.audit_log_path,
            "local_llm_endpoint": self.local_llm_endpoint,
            "local_llm_model_id": self.local_llm_model_id,
            "cloud_attempt_action": self.cloud_attempt_action,
            "disable_ipv6": self.disable_ipv6,
        }

    def to_llm_guard_section(self) -> dict[str, Any]:
        """The body under ``plugins.mordred_llm_guard`` in config.yaml.

        Phase 2 PR2: only ``harness_primary`` for now — wizard is the sole
        writer and ``harness_detect`` is the sole reader. Other Phase 2
        fields stay in policy.json so plugins read through one mirror
        rather than two.
        """
        return {"harness_primary": self.harness_primary}

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

        Whole-section replacement: any sub-field not in ``body`` is dropped.
        Use :meth:`merge_mordred_sections` for partial writes (e.g.
        ``hermes mordred network use``) that must preserve sub-fields written
        by other code paths or by hand.

        Also ensures all 5 Mordred plugin names appear in ``plugins.enabled``
        (Hermes entry-point loader requires this -- HOOK_PAYLOADS §1).
        """
        self._edit_config(sections, _upsert_mordred_section)

    def merge_mordred_sections(self, sections: Mapping[str, Mapping[str, Any]]) -> None:
        """In-place merge sub-fields into ``plugins.<plugin_name>`` sections.

        Unlike :meth:`upsert_mordred_sections`, sub-fields not present in
        ``body`` survive on-disk. Use for partial writers like
        ``hermes mordred network use <path>`` that only know one field and
        must not drop Tor / Mullvad fields set by the wizard configure step.

        Pathological cases (the on-disk value is a scalar / list) fall back
        to whole-replacement -- a corrupted section is no longer mergeable.
        """
        self._edit_config(sections, _merge_mordred_section)

    def _edit_config(
        self,
        sections: Mapping[str, Mapping[str, Any]],
        section_mutator: Callable[[Any, str, Mapping[str, Any]], None],
    ) -> None:
        """Shared round-trip pipeline for upsert / merge.

        Loads ``config.yaml`` (or starts empty), applies ``section_mutator`` to
        each requested section, runs :func:`_ensure_plugins_enabled`, and
        writes back atomically via :func:`_atomic_write_text`.
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
            section_mutator(root, plugin_name, body)

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

    def write(
        self,
        snapshot: PolicySnapshot,
        *,
        network_answers: _HasConfigYamlSection | None = None,
    ) -> None:
        """Compose: write ``policy.json`` AND the matching config.yaml sections.

        Convenience for ``hermes mordred configure``. Phase 2 PR2 added
        ``mordred_llm_guard`` to the upserted set so ``harness_primary``
        lands in config.yaml. Phase 3 PR3a Task #7 adds an optional
        ``network_answers`` (concretely
        ``mordred_hermes.wizard.network_cli.NetworkAnswers`` but typed here
        via the :class:`_HasConfigYamlSection` Protocol to avoid the
        ``configure -> policy_writer -> configure`` import cycle) which
        lands in ``plugins.mordred_network`` via the Task #1
        :meth:`merge_mordred_sections` so subsequent ``hermes mordred
        network use <path>`` invocations don't clobber the wizard's
        choices.
        """
        self.emit_policy_json(snapshot)
        self.upsert_mordred_sections(
            {
                "mordred_privacy_check": snapshot.to_config_yaml_section(),
                "mordred_llm_guard": snapshot.to_llm_guard_section(),
            }
        )
        if network_answers is not None:
            self.merge_mordred_sections({"mordred_network": network_answers.to_config_yaml_section()})
