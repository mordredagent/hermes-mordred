"""``hermes-mordred activity …`` — browser activity history administration.

- ``status [--json]``                         — feature / collection switches, Hermes's use of the
  history (``history_enabled``), protection gate result, store identifiers and row counts, and
  activity peers. Never event content.
- ``use on|off``                              — set ``plugins.mordred_activity.history_enabled`` (the
  master switch for Hermes's use of the history) in the profile's ``config.yaml``; every other
  key, comment and section is preserved. Hermes picks it up from the next turn.
- ``pair-operator [--label L] [--timeout S]`` — mint a single-use activity pair code for the
  operator collector and wait until it is used (exit 0 paired, 1 failed/expired/cancelled,
  2 pairing storage unavailable).
- ``peers list [--json]`` / ``peers revoke <peer_id>`` — activity peer credentials (revoke is
  idempotent).

- ``correct --episode ID --text TEXT [--attempt ID]`` — record an explicit correction as a raw
  ``correction`` event of an existing episode and print its event id. Nothing is derived from it.
- ``backup``, ``restore``, ``retention`` — store maintenance (``activity_store_cli``).

Raw history is never printed here.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
from collections.abc import Callable, Mapping, MutableMapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .. import _term

if TYPE_CHECKING:
    from ..activity.config import ActivityConfig
    from ..activity.store import ActivityStore

_POLL_SECONDS = 1.0
_HEARTBEAT_SECONDS = 30.0


def _home() -> Path:
    from .._home import hermes_home

    return hermes_home()


def _display(value: object, limit: int = 80) -> str:
    """Same-user-writable state is escaped before it reaches the terminal."""
    text = str(value)[:limit]
    return text if text.isprintable() else text.encode("unicode_escape").decode("ascii")


def _timestamp(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


# --------------------------------------------------------------------------- #
# Probes (module-level so tests can replace them)
# --------------------------------------------------------------------------- #


def _switches(home: Path) -> tuple[bool, bool] | None:
    from ..extension.activity_api import read_activity_switches

    return read_activity_switches(home)


def _history_switches(home: Path) -> tuple[bool, bool, tuple[str, ...]] | None:
    """``(feature enabled, history_enabled, config warnings)`` from the activity config, or ``None``.

    Warnings name keys only (``invalid value for excluded_sites``), never values.
    """
    try:
        from ..activity.config import ActivityConfig

        config = ActivityConfig.load(home)
    except Exception:
        return None
    return config.enabled, config.history_enabled, config.warnings


def _gate_refusal(home: Path) -> str | None:
    from ..extension.activity_api import gate_refusal_code

    return gate_refusal_code(home)


def _store_status(home: Path) -> Mapping[str, Any]:
    """``open_store(home).status()``: identifiers, counts and states only."""
    from ..activity._gate import open_store

    return dataclasses.asdict(open_store(home).status())


def _open(home: Path) -> tuple[ActivityStore, ActivityConfig]:
    from ..activity._gate import open_store
    from ..activity.config import ActivityConfig

    return open_store(home), ActivityConfig.load(home)


def _peer_rows() -> list[dict[str, Any]]:
    from ..activity import peers

    return peers.list_peers()


def _refusal_code(exc: BaseException) -> str:
    refusal = getattr(exc, "refusal", None)
    code = getattr(refusal, "code", None)
    return code if isinstance(code, str) else "store_unavailable"


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #


def collect_status(home: Path) -> dict[str, Any]:
    """The content-free status report shared by the text and ``--json`` output."""
    switches = _switches(home)
    feature, collection = switches if switches is not None else (False, False)
    history = _history_switches(home)
    history_switch = history[1] if history is not None else False
    warnings = list(history[2]) if history is not None else []
    exclusions_ok = "invalid value for excluded_sites" not in warnings
    gate = _gate_refusal(home)
    report: dict[str, Any] = {
        "feature_enabled": feature,
        "collection_enabled": collection,
        "history_enabled": history_switch,
        "history_in_use": feature and history_switch and exclusions_ok,
        "config_warnings": warnings,
        "config_available": switches is not None,
        "protection": "ok" if gate is None else gate,
        "store": None,
        "store_refusal": None,
        "peers": None,
        "peers_error": None,
    }
    if gate is None:
        try:
            report["store"] = _json_safe(dict(_store_status(home)))
        except Exception as exc:
            report["store_refusal"] = _refusal_code(exc)
    try:
        report["peers"] = _peer_rows()
    except Exception:
        report["peers_error"] = "storage_refused"
    return report


def _print_store(store: Mapping[str, Any]) -> None:
    for key, value in store.items():
        rendered = json.dumps(value, sort_keys=True) if isinstance(value, dict | list) else value
        print(f"    {_display(key, 40)}: {_display(rendered, 200)}")


def _print_peers(rows: list[dict[str, Any]]) -> None:
    if not rows:
        print("  (no activity peers)")
        return
    for row in rows:
        revoked = _timestamp(row.get("revoked_at"))
        state = f"revoked {revoked}" if revoked else "active"
        print(
            f"  {_display(row.get('peer_id'), 40)}  label={_display(row.get('label'), 64)}  "
            f"created={_timestamp(row.get('created_at')) or '-'}  {state}"
        )


def _history_line(report: Mapping[str, Any]) -> str:
    if report["history_in_use"]:
        return "on (history_enabled; `activity use off` to stop)"
    if not report["history_enabled"]:
        return "off (history_enabled: false; `activity use on` to start)"
    if not report["feature_enabled"]:
        return "off (the feature is disabled)"
    return "off (excluded_sites is invalid; fix it so no excluded site can be shown)"


def _print_status(report: Mapping[str, Any]) -> None:
    color = _term.should_color(sys.stdout)
    print(_term.heading("Mordred activity history", enabled=color))
    if not report["config_available"]:
        _term.emit_warn("activity configuration could not be read; collection is refused")
    print(f"  feature:     {'enabled' if report['feature_enabled'] else 'disabled'}")
    print(f"  collection:  {'enabled' if report['collection_enabled'] else 'disabled'}")
    print(f"  hermes use:  {_history_line(report)}")
    for warning in report["config_warnings"]:
        _term.emit_warn(f"plugins.mordred_activity: {_display(warning, 120)}")
    protection = report["protection"]
    print(f"  protection:  {'ok' if protection == 'ok' else f'refused ({_display(protection)})'}")
    if report["store"] is not None:
        print("  store:")
        _print_store(report["store"])
    elif report["store_refusal"] is not None:
        print(f"  store:       refused ({_display(report['store_refusal'])})")
    else:
        print("  store:       not opened (protection gate refused)")
    print("Activity peers:")
    if report["peers_error"] is not None:
        _term.emit_warn(f"activity peers could not be read ({report['peers_error']})")
    else:
        _print_peers(report["peers"] or [])


def cmd_status(args: argparse.Namespace, *, home: Path | None = None) -> int:
    report = collect_status(home or _home())
    if getattr(args, "json", False):
        print(json.dumps(report, sort_keys=True))
    else:
        _print_status(report)
    return 0


# --------------------------------------------------------------------------- #
# peers
# --------------------------------------------------------------------------- #


def cmd_peers_list(args: argparse.Namespace) -> int:
    try:
        rows = _peer_rows()
    except Exception:
        _term.emit_error("activity peers could not be read (storage_refused)")
        return 1
    if getattr(args, "json", False):
        print(json.dumps({"peers": rows}, sort_keys=True))
    else:
        _print_peers(rows)
    return 0


def cmd_peers_revoke(args: argparse.Namespace) -> int:
    from ..activity import peers

    peer_id = str(args.peer_id)
    try:
        changed = peers.revoke(peer_id)
    except Exception:
        _term.emit_error("activity peers could not be updated (storage_refused)")
        return 1
    if changed:
        print(f"Revoked {_display(peer_id, 40)}; its open sessions are refused from the next frame.")
    else:
        print(f"No change: {_display(peer_id, 40)} is unknown or already revoked.")
    return 0


# --------------------------------------------------------------------------- #
# pair-operator
# --------------------------------------------------------------------------- #


def _await_peer(code: str, deadline: float) -> tuple[str, str | None]:
    """Poll until paired/failed/expired; ``("timeout", None)`` once ``deadline`` passes."""
    from ..activity import peers

    next_heartbeat = time.monotonic() + _HEARTBEAT_SECONDS
    while True:
        state, reason = peers.pair_outcome(code)
        if state in {"paired", "failed", "expired"}:
            return state, reason
        if time.time() >= deadline:
            return "timeout", None
        if time.monotonic() >= next_heartbeat:
            remaining = max(0, int(deadline - time.time()))
            print(f"Still waiting… ({remaining // 60}m {remaining % 60:02d}s left, Ctrl+C to cancel)")
            next_heartbeat = time.monotonic() + _HEARTBEAT_SECONDS
        time.sleep(_POLL_SECONDS)


def _cancel_code(code: str) -> None:
    from ..activity import peers

    try:
        peers.revoke_peer_code(code)
    except Exception:
        _term.emit_warn("the pending code could not be revoked; it expires on its own within 10 minutes")


def _finish_pairing(state: str, reason: str | None, code: str) -> int:
    if state == "paired":
        print("Paired. The operator collector now holds its activity credential.")
        print("Review peers with `hermes-mordred activity peers list`.")
        return 0
    if state == "failed":
        _term.emit_error(f"pairing failed ({_display(reason or 'unknown')}); run `activity pair-operator` again")
        return 1
    _cancel_code(code)
    what = "expired" if state == "expired" else "timed out"
    _term.emit_warn(
        f"the pairing code {what} before the collector connected. Check that the extension server "
        "is running (`hermes-mordred extension serve`) and run `activity pair-operator` again."
    )
    return 1


def cmd_pair_operator(args: argparse.Namespace) -> int:
    from ..activity import peers

    try:
        code, expires_at = peers.generate_peer_code(str(getattr(args, "label", "operator") or "operator"))
    except Exception:
        _term.emit_error("activity pairing storage is unavailable (storage_refused)")
        return 2
    timeout = float(getattr(args, "timeout", 600.0))
    color = _term.should_color(sys.stdout)
    print(_term.heading("Mordred activity peer pairing", enabled=color))
    # The code is shown exactly once, to the operator, by design.
    print(f"Activity pair code:  {_term.bold(code, enabled=color)}")
    print(f"Expires in {max(1, round((expires_at - time.time()) / 60))} minutes; single use.")
    print("Enter it with `mordred-activity pair` on the operator side. Waiting… (Ctrl+C to cancel)")
    try:
        state, reason = _await_peer(code, min(expires_at, time.time() + timeout))
    except KeyboardInterrupt:
        _cancel_code(code)
        print("\nCancelled — the pending code was revoked.", file=sys.stderr)
        return 1
    except Exception:
        _term.emit_error("activity pairing storage is unavailable (storage_refused)")
        return 2
    return _finish_pairing(state, reason, code)


# --------------------------------------------------------------------------- #
# correct
# --------------------------------------------------------------------------- #


def cmd_correct(args: argparse.Namespace) -> int:
    """Append one correction event; the store refusal code is all that is printed on failure."""
    from ..activity import corrections
    from ..activity._gate import ActivityRefused

    try:
        store, config = _open(_home())
        if not config.enabled:
            _term.emit_error("refused (feature_disabled)")
            return 1
        event = corrections.record_correction(
            store,
            episode_id=str(args.episode),
            text=str(args.text),
            attempt_id=args.attempt,
            excluded_sites=config.excluded_sites,
        )
    except ActivityRefused as exc:
        _term.emit_error(f"refused ({_display(exc.code, 64)})")
        return 1
    print(f"Recorded correction {event.event_id} in episode {_display(event.episode_id, 64)}.")
    return 0


# --------------------------------------------------------------------------- #
# use on|off
# --------------------------------------------------------------------------- #


def set_history_enabled(config_path: Path, value: bool) -> None:
    """Set ``plugins.mordred_activity.history_enabled`` only; everything else in the file is kept.

    Round-trip YAML (comments and order preserved), written atomically under the policy write lock in
    ``<home>/mordred`` (the one :class:`PolicyWriter` takes for ``network use`` and ``configure``). A
    ``plugins`` or ``mordred_activity`` value that is not a mapping, or one shared through a YAML
    anchor (writing through it would change the other section too), is refused (:class:`ValueError`)
    rather than replaced.
    """
    from .policy_writer import PolicyWriter, _windows

    def edit(root: Any) -> None:
        plugins = _mapping(root, "plugins")
        section = _mapping(plugins, "mordred_activity")
        section["history_enabled"] = value

    if _windows():
        mordred = config_path.parent / "mordred"
        PolicyWriter(config_path, mordred / "policy.json", mordred).transform_config(edit)
        return
    _edit_posix(config_path, edit)


def _mapping(parent: MutableMapping[str, Any], key: str) -> MutableMapping[str, Any]:
    """``parent[key]`` as a mapping, created when absent or empty; any other value is refused."""
    if parent.get(key) is None:
        parent[key] = {}
    child = parent[key]
    if not isinstance(child, MutableMapping):
        raise ValueError(f"{key} is not a mapping")
    anchor = getattr(getattr(child, "anchor", None), "value", None)
    if anchor:
        raise ValueError(f"{key} is a YAML anchor shared with another section; edit it by hand")
    return child


def _edit_posix(config_path: Path, edit: Callable[[Any], None]) -> None:
    import io

    from .policy_writer import _atomic_write_text, _policy_write_lock, _read_regular_text, _round_trip_yaml

    with _policy_write_lock(config_path.parent / "mordred"):
        yaml = _round_trip_yaml()
        text = _read_regular_text(config_path)
        root = yaml.load(text) if text else None
        if root is None:
            root = {}
        if not isinstance(root, MutableMapping):
            raise ValueError("config.yaml is not a mapping")
        edit(root)
        buffer = io.StringIO()
        yaml.dump(root, buffer)
        _atomic_write_text(config_path, buffer.getvalue())


def cmd_use(args: argparse.Namespace) -> int:
    """``activity use on|off``: the master switch for Hermes's use of the browser history."""
    value = str(args.state) == "on"
    home = _home()
    try:
        set_history_enabled(home / "config.yaml", value)
    except ValueError as exc:  # our own content-free refusals
        _term.emit_error(f"config.yaml was not changed: {_display(exc, 120)}")
        return 1
    except Exception as exc:  # parse errors quote config lines: name the error type only
        _term.emit_error(f"config.yaml was not changed ({_display(type(exc).__name__, 64)})")
        return 1
    switches = _history_switches(home)
    feature = switches[0] if switches is not None else False
    if value:
        print("Hermes's use of the browser history: on (navigation blocks, turn context, lookup tools).")
        if not feature:
            _term.emit_warn(
                "the activity feature is disabled (plugins.mordred_activity.enabled: false); "
                "Hermes uses the history only once it is enabled"
            )
    else:
        print("Hermes's use of the browser history: off. Recording by the collectors is not affected.")
    print(
        "Applies from the next turn without a restart; an open session keeps listing the lookup tools, "
        "but they refuse while the switch is off."
    )
    return 0


# The store-maintenance subcommands (backup, restore, retention) live in ``activity_store_cli``.
_COMMANDS: dict[str, Callable[[argparse.Namespace], int]] = {
    "status": cmd_status,
    "use": cmd_use,
    "pair-operator": cmd_pair_operator,
    "correct": cmd_correct,
}
_PEER_COMMANDS: dict[str, Callable[[argparse.Namespace], int]] = {
    "list": cmd_peers_list,
    "revoke": cmd_peers_revoke,
}


def cli_activity(args: argparse.Namespace) -> int:
    from . import activity_store_cli

    command = getattr(args, "activity_command", None)
    if command == "peers":
        return _PEER_COMMANDS[str(args.activity_peers_command)](args)
    if command in activity_store_cli.COMMANDS:
        return activity_store_cli.dispatch(str(command), args)
    handler = _COMMANDS.get(str(command))
    if handler is None:
        _term.emit_error(f"unknown activity command {_display(command)}")
        return 2
    return handler(args)
