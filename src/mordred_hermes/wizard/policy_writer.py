"""Round-trip writer for ``~/.hermes/config.yaml`` and ``~/.hermes/mordred/policy.json``.

Sole writer for the wizard-owned policy files (PATHS.md §Overview).
Preserves user comments, key order, and anchors in ``config.yaml`` via
``ruamel.yaml`` round-trip mode. Writes ``policy.json`` as the
debugger-friendly mirror that other Mordred plugins read directly.

Three core operations:

- :meth:`PolicyWriter.upsert_mordred_sections` — mutate ``plugins.mordred_*``
  blocks in ``~/.hermes/config.yaml``. Also ensures the Mordred entry-point
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

import copy
import errno
import io
import json
import logging
import os
import stat
import threading
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal, NoReturn, Protocol, runtime_checkable

from .._file_lock import private_flock
from .._policy_io import (
    load_policy_mapping,
    policy_transaction_marker_for_policy,
)
from ._atomic_io import (
    _atomic_write_text,
    _ensure_real_directory,
    _fsync_durable,
    _fsync_parent,
    _read_regular_text,
    _round_trip_yaml,
)
from ._runtime import (
    DEFAULT_HERMES_CONFIG_PATH,
    DEFAULT_MORDRED_DIR,
    DEFAULT_POLICY_JSON_PATH,
)

_LOG = logging.getLogger("mordred.wizard.policy_writer")
_POLICY_LOCK_FILENAME = ".policy-write.lock"
_POLICY_THREAD_LOCK = threading.RLock()
_POLICY_LOCK_STATE = threading.local()
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

MORDRED_PLUGIN_NAMES: Final = (
    "mordred_privacy_check",
    "mordred_wizard",
    "mordred_llm_guard",
    "mordred_network",
    "mordred_keyvault",
    "mordred_e2e",
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


def _reject_unopenable_policy_lock(lock_path: Path, exc: OSError) -> NoReturn:
    """Wrap an ``os.open`` failure on the policy lock as a tagged ``EPERM``."""
    raise OSError(errno.EPERM, "policy writer lock is unsafe or unavailable", str(lock_path)) from exc


def _reject_unsafe_policy_lock(lock_path: Path) -> NoReturn:
    """Fail closed when the policy lock is not a private regular file."""
    raise OSError(errno.EPERM, "policy writer lock must be a mode-0600 regular file", str(lock_path))


@contextmanager
def _policy_write_lock(directory: Path) -> Iterator[None]:
    """Serialize policy/config read-modify-write cycles across threads/processes.

    The descriptor lifecycle is
    :func:`mordred_hermes._file_lock.private_flock`. The reentrancy-depth
    bookkeeping, the ``RLock``, the parent-directory check, and both raises
    stay here: the depth counter is specific to this module's nested
    transactions, and keeping the raises local keeps the tagged ``EPERM``
    :exc:`OSError`\\ s (and the ``from exc`` chaining) byte-identical. ``depth``
    is still set only *after* the flock is held and cleared *before* it is
    released, so a nested caller can never observe the flag without the lock.
    """
    with _POLICY_THREAD_LOCK:
        depth = getattr(_POLICY_LOCK_STATE, "depth", 0)
        if depth:
            _POLICY_LOCK_STATE.depth = depth + 1
            try:
                yield
            finally:
                _POLICY_LOCK_STATE.depth = depth
            return

        _ensure_real_directory(directory)
        with private_flock(
            directory / _POLICY_LOCK_FILENAME,
            on_unsafe=_reject_unsafe_policy_lock,
            on_open_error=_reject_unopenable_policy_lock,
        ):
            _POLICY_LOCK_STATE.depth = 1
            try:
                yield
            finally:
                _POLICY_LOCK_STATE.depth = 0


def _begin_policy_transaction(policy_json_path: Path) -> Path:
    marker = policy_transaction_marker_for_policy(policy_json_path)
    # Record who/when so a marker surviving an interrupted run is diagnosable
    # rather than an unexplained file that silently forces strict mode.
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    _atomic_write_text(marker, f"pending pid={os.getpid()} since={stamp}\n", mode=0o600)
    # Even an idempotent pre-existing marker must be re-synchronized. A prior
    # begin may have made the directory entry visible and then failed its
    # parent fsync; simply returning on identical content could otherwise let
    # the two mirrors update while the marker is still non-durable.
    fd = os.open(marker, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise OSError(errno.EPERM, "policy transaction marker must be a mode-0600 regular file", str(marker))
        _fsync_durable(fd)
    finally:
        os.close(fd)
    _fsync_parent(marker)
    return marker


def _finish_policy_transaction(marker: Path) -> None:
    """Clear the marker, failing loudly enough to be actionable if it survives.

    A surviving marker forces every reader closed to strict mode with empty
    settings. Re-raising a bare ``PermissionError`` here would leave the operator
    with refusals and no named cause, so the message states the consequence and
    the remedy.
    """
    try:
        marker.unlink()
    except FileNotFoundError:
        return  # already cleared (concurrent writer finished the transaction)
    except OSError as exc:
        raise OSError(
            errno.EACCES,
            (
                f"the Mordred policy files were written, but the transaction marker {marker} "
                f"could not be removed ({exc}). Every policy read fails closed to strict mode "
                "with empty settings until it is gone — delete it by hand"
            ),
            str(marker),
        ) from exc
    _fsync_parent(marker)


def _ensure_plugins_enabled(root: Any) -> None:
    """Ensure all Mordred plugin names appear in ``plugins.enabled``.

    Per HOOK_PAYLOADS.md §1, Hermes's
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
        # Hermes treats a malformed allow-list exactly like a missing one:
        # no entry-point plugin loads.  Leaving it untouched after a successful
        # configure therefore strands every runtime guard.  Preserve a scalar
        # plugin name when possible, otherwise replace the unusable value, then
        # extend the repaired list below.
        recovered = [enabled] if isinstance(enabled, str) and enabled.strip() else []
        _LOG.warning(
            "plugins.enabled is %s, not list; replacing with a valid enabled list",
            type(enabled).__name__,
        )
        plugins["enabled"] = recovered
        enabled = recovered

    sanitized = [item for item in enabled if isinstance(item, str) and item.strip()]
    if len(sanitized) != len(enabled):
        _LOG.warning("plugins.enabled contains invalid plugin names; removing non-string or empty entries")
        enabled[:] = sanitized

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
    # (mordred_hermes.network.settings.resolve_disable_ipv6) can consume it.
    # Default ``True`` matches the safe-by-default in RuntimeConfig.
    disable_ipv6: bool = True
    # Phase 3 transport facts are an intentionally opaque JSON value here.
    # A valid value is an object keyed by provider id, but keeping the wider
    # ``object`` type is security-significant: if a hand edit leaves a list,
    # scalar, or malformed entry, configure/upgrade must preserve that value
    # so the network gate continues to reject it rather than silently
    # sanitising it to the permissive empty-object default.
    # Exclude the opaque JSON container from the generated hash so adding the
    # field does not make this previously-hashable frozen snapshot unhashable.
    provider_overrides: object = field(default_factory=dict, hash=False)

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
            # Defensive copy: callers receive a serialisation payload, not a
            # mutable alias to the snapshot's preserved extension value.
            "provider_overrides": copy.deepcopy(self.provider_overrides),
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


def _preserve_provider_overrides(snapshot: PolicySnapshot, policy_json_path: Path) -> PolicySnapshot:
    """Carry the existing opaque ``provider_overrides`` value into ``snapshot``.

    The wizard owns all other policy.json fields, but provider overrides are
    operator-managed transport evidence. A configure/upgrade rewrite therefore
    preserves that one field verbatim. Crucially, this helper does *not*
    validate or coerce it: invalid types and unknown nested fields must survive
    so ``network.hooks._read_provider_overrides`` retains its fail-closed
    behaviour under strict + Tor.

    A non-empty/non-default value already supplied by the caller is explicit
    and wins. Missing/unreadable/non-object policy files have no preservable
    field and leave the snapshot unchanged.
    """
    if snapshot.provider_overrides != {}:
        return snapshot
    # A recovery write intentionally runs while a stale/pending transaction
    # marker is present. The writer holds the exclusive policy lock, so it may
    # inspect the previous mirror to preserve operator-managed overrides even
    # though runtime readers must treat the same state as fail-closed.
    existing = load_policy_mapping(
        policy_json_path,
        log=_LOG,
        allow_pending_transaction=True,
    )
    if "provider_overrides" not in existing:
        return snapshot
    return replace(
        snapshot,
        provider_overrides=copy.deepcopy(existing["provider_overrides"]),
    )


def _section_matches_dict(existing: Mapping[str, Any], want: Mapping[str, Any]) -> bool:
    """True iff ``existing`` super-set-equals ``want`` field-by-field.

    The idempotency / conflict predicate shared by ``upgrade`` and
    ``openclaw_migration`` for comparing an on-disk ``plugins.mordred_*``
    section against a :meth:`PolicySnapshot.to_config_yaml_section` body:
    every target field must be present with an equal value, while extra
    user-added keys are tolerated (a superset still matches, so an annotated
    config is not flagged as a conflict). Lives beside the snapshot it
    compares against so the two migration callers cannot drift.
    """
    return all(existing.get(k) == v for k, v in want.items()) and set(existing.keys()) >= set(want.keys())


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

        Also ensures all Mordred plugin names appear in ``plugins.enabled``
        (Hermes entry-point loader requires this -- HOOK_PAYLOADS §1).
        """
        with _policy_write_lock(self.policy_json_path.parent):
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
        with _policy_write_lock(self.policy_json_path.parent):
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
        existing = _read_regular_text(self.config_path)
        if existing is not None:
            root = yaml.load(existing)
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
        rewrite is skipped if content matches. Existing operator-managed
        ``provider_overrides`` are carried forward verbatim, including invalid
        values that the strict transport gate must continue to reject.
        """
        with _policy_write_lock(self.policy_json_path.parent):
            snapshot = _preserve_provider_overrides(snapshot, self.policy_json_path)
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
        with _policy_write_lock(self.policy_json_path.parent):
            marker = _begin_policy_transaction(self.policy_json_path)
            self.emit_policy_json(snapshot)
            self.upsert_mordred_sections(
                {
                    "mordred_privacy_check": snapshot.to_config_yaml_section(),
                    "mordred_llm_guard": snapshot.to_llm_guard_section(),
                }
            )
            if network_answers is not None:
                self.merge_mordred_sections({"mordred_network": network_answers.to_config_yaml_section()})
            _finish_policy_transaction(marker)
