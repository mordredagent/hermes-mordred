"""The activity receiver: one authenticated batch in, one ``activity_ack`` / ``activity_refused`` body out.

Configuration and the protection gate are evaluated on **every** call, so
disabling collection, disarming encryption or losing the key refuses the next
batch without touching the WebSocket session. Refusal order:

1. collection disabled (``enabled`` and ``collection_enabled`` both required),
   or ``excluded_sites_invalid`` (an invalid ``excluded_sites`` refuses every
   batch rather than recording what it meant to exclude);
2. batch envelope (schema, producer, event count, canonical size);
3. per-event normalization — one excluded, oversized or malformed event refuses the batch;
4. sequence order within the batch;
5. store open (the protection gate);
6. append (``conflict`` / ``busy`` / ``store_full``).

Trust and permitted use come from the authenticated principal, never from the
payload. The WS layer adds ``id`` to the returned body; this module never logs
or returns event content.

Corrections are stored like every other event; nothing is derived from a
batch. After a successful append the receiver runs one bounded retention
pass, at most once per ``retention_interval_s`` per store path (design:
Database and encryption lifecycle); its outcome never changes the ack, which
is for the append. A collection or store refusal is audited as
``activity.capture_refused`` once per process and code.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Final, Protocol

from ._capture_audit import audit_capture_refused
from ._gate import ActivityRefused, open_store
from .config import ActivityConfig
from .contracts import (
    ContractError,
    PeerPrincipal,
    check_batch_envelope,
    check_sequence,
    normalize_event,
)
from .store import ActivityStore

__all__ = ["PeerPrincipal", "Receiver", "StoreReceiver", "build_receiver"]

#: Store/gate refusal codes that keep their name on the wire; every other gate code is ``store_unavailable``.
_WIRE_REASONS = {"conflict": "conflict", "busy": "busy", "disk_full": "store_full"}
_RETENTION_LIMIT: Final = 200
_DEFAULT_RETENTION_INTERVAL_S: Final = 3600.0

_LOG = logging.getLogger(__name__)
#: Monotonic time of the last retention pass per store path, shared by every receiver in the process.
_LAST_RETENTION: dict[str, float] = {}
_RETENTION_LOCK = threading.Lock()


class Receiver(Protocol):
    def ingest(self, principal: PeerPrincipal, batch: Mapping[str, Any]) -> dict[str, Any]: ...


def _refused(reason: str) -> dict[str, Any]:
    return {"type": "activity_refused", "reason": reason}


class StoreReceiver:
    def __init__(
        self,
        home: Path,
        *,
        config_loader: Callable[[Path], ActivityConfig],
        store_factory: Callable[[Path], ActivityStore],
        retention_interval_s: float = _DEFAULT_RETENTION_INTERVAL_S,
    ) -> None:
        self._home = home
        self._config_loader = config_loader
        self._store_factory = store_factory
        self._retention_interval_s = retention_interval_s

    def ingest(self, principal: PeerPrincipal, batch: Mapping[str, Any]) -> dict[str, Any]:
        config = self._config_loader(self._home)
        refusal = config.collection_refusal
        if refusal is not None:  # off, or an invalid excluded_sites that must never mean "exclude less"
            audit_capture_refused(refusal, peer_id=principal.peer_id)
            return _refused(refusal)
        try:
            envelope = check_batch_envelope(
                batch, max_events=config.max_batch_events, max_bytes_raw=config.max_batch_bytes
            )
            # A peer's credential fixes what kind of producer it is.
            if envelope.producer_kind != principal.kind:
                return _refused("malformed")
            events = [
                normalize_event(raw, excluded_sites=config.excluded_sites, max_event_bytes=config.max_event_bytes)
                for raw in envelope.events
            ]
            check_sequence(events)
        except ContractError as exc:
            return _refused(exc.code)
        try:
            store = self._store_factory(self._home)
            result = store.append_batch(
                principal.peer_id,
                envelope.producer_id,
                events,
                trust=principal.trust,
                permitted_use=principal.permitted_use,
            )
        except ActivityRefused as exc:
            reason = _WIRE_REASONS.get(exc.code, "store_unavailable")
            audit_capture_refused(reason, peer_id=principal.peer_id)
            return _refused(reason)
        self._maybe_retain(store, config)
        return {
            "type": "activity_ack",
            "status": "ok",
            "accepted": result.accepted,
            "duplicates": result.duplicates,
            "episode_revisions": dict(result.episode_revisions),
        }

    def _maybe_retain(self, store: ActivityStore, config: ActivityConfig) -> None:
        """One bounded retention pass if this store path has had none for an interval; never raises."""
        key = str(store.path)
        started = time.monotonic()
        with _RETENTION_LOCK:
            last = _LAST_RETENTION.get(key)
            if last is not None and started - last < self._retention_interval_s:
                return
            _LAST_RETENTION[key] = started
        try:
            store.apply_retention(time.time(), raw_days=config.retention_raw_days, limit=_RETENTION_LIMIT)
        except ActivityRefused as exc:
            _LOG.warning("activity retention refused (%s)", exc.code)
        except Exception as exc:
            _LOG.warning("activity retention failed (%s)", type(exc).__name__)


def build_receiver(home: Path) -> Receiver:
    """The production receiver for ``home``: real config, gated SQLCipher store."""
    return StoreReceiver(home, config_loader=ActivityConfig.load, store_factory=open_store)
