"""Story 1.5 -- migrate ``~/.openclaw/mordred/`` into ``~/.hermes/mordred/``.

Per PATHS.md §OpenClaw migration L286 the H5 row-level conflict policy is:

| OpenClaw path | Hermes destination | Conflict policy |
|---|---|---|
| ``audit.log`` | ``audit.log`` (append) | ``--audit-merge={skip,append-all,abort}`` |
| ``keyvault/`` | ``keyvault/`` (copytree) | abort if dest exists |
| ``credentials/`` | ``credentials/`` (copytree) | abort if dest exists |
| ``openclaw.json plugins.entries.mordred-*.config`` | ``config.yaml plugins.mordred_*`` | (see below) |

The policy-section conflict policy (``--policy-conflict``) is resolved
upstream by :func:`upgrade.run` before this module's :func:`migrate` is
invoked.

Idempotency contract: a marker file
``~/.hermes/mordred/.audit-migrated-from-openclaw`` (containing an
ISO-8601 UTC timestamp) is written **last** in the audit step. On
re-runs, marker presence skips audit migration. ``--reset`` overrides
the marker.

Atomicity: every destination write goes through ``<dest>.tmp`` +
``os.replace`` so a crash mid-write leaves the previous file intact.
"""

from __future__ import annotations

import filecmp
import json
import logging
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .._policy_types import POLICY_MODES
from .._yaml_io import load_plugin_section
from .policy_writer import PolicySnapshot, PolicyWriter, _atomic_write_text, _section_matches_dict

if TYPE_CHECKING:
    from .upgrade import Story1_5Action, UpgradeOptions

_LOG = logging.getLogger("mordred.wizard.openclaw_migration")

MARKER_FILENAME = ".audit-migrated-from-openclaw"


@dataclass(frozen=True, slots=True)
class OpenClawState:
    """Presence flags for the legacy OpenClaw layout. Empty-flag = nothing to do."""

    has_audit: bool
    has_policy_json: bool
    has_keyvault: bool
    has_credentials: bool
    has_openclaw_json: bool


def detect(openclaw_base: Path) -> OpenClawState:
    """Probe the legacy ``~/.openclaw/mordred/`` tree without mutating anything."""
    return OpenClawState(
        has_audit=(openclaw_base / "audit.log").is_file(),
        has_policy_json=(openclaw_base / "policy.json").is_file(),
        has_keyvault=(openclaw_base / "keyvault").is_dir(),
        has_credentials=(openclaw_base / "credentials").is_dir(),
        has_openclaw_json=(openclaw_base.parent / "openclaw.json").is_file(),
    )


# -----------------------------------------------------------------------------
# Audit-log migration -- append-by-timestamp-window + idempotency marker
# -----------------------------------------------------------------------------


def _utcnow_iso() -> str:
    """ISO-8601 UTC ms-precision -- matches privacy_check.audit format."""
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _read_audit_lines(path: Path) -> list[str]:
    """Read NDJSON lines from ``path``; missing file = empty."""
    if not path.is_file():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _audit_overlap(hermes_lines: list[str], openclaw_lines: list[str]) -> bool:
    """True iff existing Hermes audit and OpenClaw audit timestamp ranges overlap.

    Conservative: any parse failure on either side is treated as overlap
    (caller must then specify ``--audit-merge`` explicitly). The check is
    "does OpenClaw's newest ts come after Hermes's oldest ts?" -- safe append
    requires the OpenClaw range to be entirely older than the Hermes range.
    """
    try:
        hermes_oldest = min(str(json.loads(line)["ts"]) for line in hermes_lines if line)
        openclaw_newest = max(str(json.loads(line)["ts"]) for line in openclaw_lines if line)
    except (KeyError, ValueError, TypeError) as e:
        _LOG.warning("could not parse audit timestamps for overlap check: %s; treating as overlap", e)
        return True
    return openclaw_newest >= hermes_oldest


def _migrate_audit(
    openclaw_base: Path,
    dest_audit: Path,
    marker: Path,
    options: UpgradeOptions,
) -> bool:
    """Migrate audit.log; return True if a real migration happened, False if skipped.

    Skip-vs-migrate decision (in order):
    - marker present + not --reset -> skip (idempotent)
    - openclaw audit absent -> skip (nothing to copy)
    - hermes audit absent -> safe append (no overlap possible)
    - timestamp ranges disjoint (openclaw_newest < hermes_oldest) -> safe append
    - overlap + --audit-merge=skip -> no append, mark migrated
    - overlap + --audit-merge=append-all -> force append duplicates
    - overlap + --audit-merge=abort or unset -> SystemExit
    """
    src_audit = openclaw_base / "audit.log"
    if not src_audit.is_file():
        return False

    if marker.exists() and not options.reset:
        _LOG.info("audit migration skipped: marker %s present (use --reset to force)", marker)
        return False

    src_lines = _read_audit_lines(src_audit)
    dest_lines = _read_audit_lines(dest_audit)

    overlap = bool(dest_lines) and _audit_overlap(dest_lines, src_lines)

    if overlap and options.audit_merge is None:
        raise SystemExit(
            "hermes-mordred upgrade: OpenClaw audit.log overlaps existing "
            "Hermes audit.log timestamps. Re-run with one of "
            "--audit-merge=skip|append-all|abort."
        )
    if overlap and options.audit_merge == "abort":
        raise SystemExit("hermes-mordred upgrade: --audit-merge=abort and overlap detected -- aborting.")
    if overlap and options.audit_merge == "skip":
        _LOG.info("audit migration: overlap detected, skip per --audit-merge=skip")
        # Marker still gets written so re-runs are noops
        _write_marker(marker)
        return True

    # Safe append (or --audit-merge=append-all forced)
    appended = "\n".join(src_lines)
    if appended:
        appended += "\n"
    if dest_lines:
        existing = "\n".join(dest_lines) + "\n"
        merged = existing + appended
    else:
        merged = appended
    _atomic_write_text(dest_audit, merged, mode=0o600)
    _write_marker(marker)
    return True


def _write_marker(marker: Path) -> None:
    """Write the idempotency marker LAST (so a crashed migration retries safely)."""
    _atomic_write_text(marker, _utcnow_iso() + "\n", mode=0o600)


# -----------------------------------------------------------------------------
# Keyvault / credentials -- never overwrite (abort on dest-exists)
# -----------------------------------------------------------------------------


def _dirs_identical(src: Path, dest: Path) -> bool:
    """True iff ``src`` and ``dest`` contain the same file tree byte-for-byte.

    Uses :class:`filecmp.dircmp` recursively. Tolerates symlinks the same
    way ``filecmp`` does (compares targets, not symlink-vs-file shape).
    Returns ``False`` on any structural difference (extra/missing files,
    differing content, common funny files).
    """
    cmp = filecmp.dircmp(src, dest)
    if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
        return False
    return all(_dirs_identical(src / sub, dest / sub) for sub in cmp.common_dirs)


def _migrate_directory(src: Path, dest: Path, kind: str) -> bool:
    """Idempotently copy ``src`` -> ``dest`` (PATHS.md §OpenClaw migration H5).

    Returns True if a copy happened, False if no-op (source absent OR
    dest already contains the same tree byte-for-byte). Raises
    ``SystemExit`` only on a real data conflict (dest exists with
    different content -- "never overwrite" data-loss protection).

    Idempotency rule: if ``dest`` exists AND its contents match ``src``
    exactly, treat as already-migrated (skip silently). Required so that
    a second ``upgrade`` run, or a retry after audit-overlap abort, does
    not crash on the now-existing dest from the first attempt.
    """
    if not src.is_dir():
        return False
    if dest.exists():
        if _dirs_identical(src, dest):
            _LOG.info("%s already migrated (dest matches src byte-for-byte); skipping", kind)
            return False
        raise SystemExit(
            f"hermes-mordred upgrade: refusing to overwrite existing {kind} "
            f"at {dest} -- contents differ from {src}. "
            f"Move or remove the destination manually before re-running upgrade."
        )
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copytree(src, dest, dirs_exist_ok=False)
    return True


# -----------------------------------------------------------------------------
# openclaw.json policy block -- transform + upsert
# -----------------------------------------------------------------------------


def _migrate_policy(
    openclaw_base: Path,
    policy_writer: PolicyWriter,
    options: UpgradeOptions,
) -> bool:
    """Transform ``openclaw.json plugins.entries.mordred-privacy-check.config``
    into a :class:`PolicySnapshot` and write via ``PolicyWriter``.

    Returns True if policy was migrated, False if no recognisable section.

    Codex review fixes:
    - Honors ``options.policy_conflict`` against the OpenClaw-derived
      snapshot (P1-A: previously the conflict was only checked against
      the default snapshot in ``upgrade._resolve_story1``, leaving the
      OpenClaw upsert path unguarded).
    - Calls ``policy_writer.write()`` instead of ``upsert_mordred_sections``
      so the ``policy.json`` mirror is also emitted (P2: explainer reads
      via ``get_active_policy_mode`` from config.yaml, but other plugins
      and ``policy show`` still rely on the mirror existing).
    """
    src = openclaw_base.parent / "openclaw.json"
    if not src.is_file():
        return False
    try:
        body = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        _LOG.warning("could not read %s: %s", src, e)
        return False

    config = _extract_privacy_config(body)
    if config is None:
        return False

    snapshot = _coerce_snapshot(config)
    # Apply --policy-conflict against the OpenClaw snapshot (P1-A).
    if not _should_write_policy(policy_writer, snapshot, options):
        return False

    # Write BOTH config.yaml and policy.json mirror (P2).
    policy_writer.write(snapshot)
    return True


def _extract_privacy_config(body: object) -> dict[str, Any] | None:
    """Pull ``plugins.entries.mordred-privacy-check.config`` out of openclaw.json.

    Returns the config dict, or None if any level of the expected nesting is
    absent or the wrong type (no recognisable section to migrate).
    """
    plugins = body.get("plugins") if isinstance(body, dict) else None
    entries = plugins.get("entries") if isinstance(plugins, dict) else None
    if not isinstance(entries, dict):
        return None
    privacy = entries.get("mordred-privacy-check")
    if not isinstance(privacy, dict):
        return None
    config = privacy.get("config")
    if not isinstance(config, dict):
        return None
    return config


def _should_write_policy(
    policy_writer: PolicyWriter,
    snapshot: PolicySnapshot,
    options: UpgradeOptions,
) -> bool:
    """Decide whether to write ``snapshot``, honoring ``options.policy_conflict``.

    Returns True to proceed with the write, False to keep the existing section.
    Raises ``SystemExit`` on an unresolved conflict (``abort``, or an
    interactive prompt that a non-interactive run cannot satisfy).

    The section read mirrors ``upgrade._read_existing_section`` (read-only
    comparison, broad catch, and — load-bearing — ``round_trip=True`` so a
    custom-tagged section compares unequal and reaches conflict resolution
    instead of being collapsed to "no section" and overwritten) but goes
    through the shared root helper directly — importing ``upgrade`` here
    would be cyclic.
    """
    section = load_plugin_section(
        policy_writer.config_path, "mordred_privacy_check", catch=(Exception,), log=_LOG, round_trip=True
    )
    if section is None:
        return True
    # Plain-dict coercion (shallow) mirrors upgrade._read_existing_section —
    # the two conflict checks must return the same shape for the same file.
    existing = dict(section)
    want = snapshot.to_config_yaml_section()
    if _section_matches_dict(existing, want):
        return True
    # Existing section differs from the OpenClaw-derived snapshot. --reset and
    # --policy-conflict=overwrite both proceed to write (reset takes precedence,
    # matching the original elif order).
    if options.reset or options.policy_conflict == "overwrite":
        return True
    if options.policy_conflict == "keep-existing":
        return False
    if options.policy_conflict == "abort":
        raise SystemExit(
            "hermes-mordred upgrade: --policy-conflict=abort and OpenClaw "
            "policy differs from existing config.yaml -- aborting."
        )
    # options.policy_conflict is None
    if options.non_interactive:
        raise SystemExit(
            "hermes-mordred upgrade: --non-interactive set but --policy-conflict "
            "not specified; refusing to overwrite existing mordred section "
            "with OpenClaw migration."
        )
    raise SystemExit(
        "hermes-mordred upgrade: OpenClaw policy differs from existing "
        "config.yaml plugins.mordred_privacy_check. Re-run with one of "
        "--policy-conflict=keep-existing|overwrite|abort or --reset."
    )


def _coerce_snapshot(config: dict[str, Any]) -> PolicySnapshot:
    """Map an OpenClaw ``config`` dict to :class:`PolicySnapshot`.

    Defensive against missing/typo'd fields -- defaults match the wizard's
    ``configure`` defaults so users never end up worse-off than fresh setup.
    """
    raw_policy = config.get("policy", "lenient")
    # POLICY_MODES is the tuple, not the frozenset: foreign JSON can carry
    # unhashable values, and tuple membership returns False instead of
    # raising TypeError (hooks.py Codex round 3 P2).
    policy = raw_policy if raw_policy in POLICY_MODES else "lenient"
    # M2 (security review 2026-06-11): a foreign config's string "false"
    # must not truthy-coerce into an enabled cloud-LLM grant.
    raw_allow_flag = config.get("allow_cloud_llm", False)
    allow = raw_allow_flag if isinstance(raw_allow_flag, bool) else False
    raw_allow = config.get("cloud_provider_allowlist") or []
    allowlist: tuple[str, ...] = (
        tuple(x for x in raw_allow if isinstance(x, str)) if isinstance(raw_allow, list) else ()
    )
    return PolicySnapshot(
        policy=policy,
        allow_cloud_llm=allow,
        cloud_provider_allowlist=allowlist,
    )


# -----------------------------------------------------------------------------
# Top-level migrate() orchestrator
# -----------------------------------------------------------------------------


def migrate(
    *,
    openclaw_base: Path,
    policy_writer: PolicyWriter,
    options: UpgradeOptions,
) -> Story1_5Action:
    """Migrate ``openclaw_base`` into the wizard-owned Hermes paths.

    Order matters:
    1. Keyvault / credentials (abort fast on collision -- before any audit
       writes so a refused migration leaves audit.log untouched too).
    2. openclaw.json policy section -> config.yaml via PolicyWriter.
    3. audit.log + marker file (marker is the LAST write so a crashed
       migration safely retries).

    Returns one of: ``noop``, ``migrated``, ``skipped-marker``. ``noop`` covers
    both "no ``openclaw_base`` at all" and "``openclaw_base`` exists but holds
    none of the recognized artifacts" (no audit.log, no keyvault/, no
    credentials/, no sibling openclaw.json, or an openclaw.json with no
    recognisable ``mordred-privacy-check`` section) -- in either case nothing
    was actually copied or written, so reporting ``migrated`` would mislead
    the ``hermes-mordred upgrade`` summary.
    """
    if not openclaw_base.exists():
        return "noop"

    # Resolve destinations from PolicyWriter -- single source of truth for paths.
    dest_audit = policy_writer.mordred_dir / "audit.log"
    dest_keyvault = policy_writer.mordred_dir / "keyvault"
    dest_credentials = policy_writer.mordred_dir / "credentials"
    marker = policy_writer.mordred_dir / MARKER_FILENAME

    state = detect(openclaw_base)

    # 1. Never-overwrite copies (fail fast). Track whether each sub-step
    # actually did something -- an openclaw_base directory that exists but is
    # empty (or an openclaw.json with no recognisable section) must not report
    # "migrated" when nothing was copied or written.
    keyvault_migrated = False
    if state.has_keyvault:
        keyvault_migrated = _migrate_directory(openclaw_base / "keyvault", dest_keyvault, kind="keyvault")
    credentials_migrated = False
    if state.has_credentials:
        credentials_migrated = _migrate_directory(openclaw_base / "credentials", dest_credentials, kind="credentials")

    # 2. Policy transform (idempotent via PolicyWriter compare-and-skip;
    # honors options.policy_conflict against the OpenClaw snapshot per Codex P1-A)
    policy_migrated = False
    if state.has_openclaw_json:
        policy_migrated = _migrate_policy(openclaw_base, policy_writer, options)

    # 3. Audit log -- last, with marker
    audit_migrated = _migrate_audit(openclaw_base, dest_audit, marker, options)
    if not audit_migrated and marker.exists() and state.has_audit:
        return "skipped-marker"
    if keyvault_migrated or credentials_migrated or policy_migrated or audit_migrated:
        return "migrated"
    return "noop"
