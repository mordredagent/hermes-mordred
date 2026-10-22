"""Ingestion-triggered retention and the ``activity.capture_refused`` audit (receiver and recall tools)."""

from __future__ import annotations

import json
import sqlite3
import types
import uuid
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity import _capture_audit, _gate, ingest, tools
from mordred_hermes.activity._gate import ActivityRefused, refusal
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.activity.ingest import PeerPrincipal, StoreReceiver
from mordred_hermes.activity.store import ActivityStore, RetentionReport
from mordred_hermes.privacy_check import _runtime

OPERATOR = PeerPrincipal(peer_id="operator:ab12", kind="operator")
ENABLED = {"enabled": True, "collection_enabled": True}


class CountingStore(ActivityStore):
    def __init__(self, path: Path, failure: BaseException | None = None) -> None:
        super().__init__(path, sqlite3.connect)
        self.retention_calls: list[dict[str, Any]] = []
        self._failure = failure

    def apply_retention(self, now: float, *, raw_days: int, candidate_days: int, limit: int = 500) -> RetentionReport:
        self.retention_calls.append({"raw_days": raw_days, "candidate_days": candidate_days, "limit": limit})
        if self._failure is not None:
            raise self._failure
        return super().apply_retention(now, raw_days=raw_days, candidate_days=candidate_days, limit=limit)


@pytest.fixture(autouse=True)
def fresh_process_state(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    monkeypatch.setattr(ingest, "_LAST_RETENTION", {})
    monkeypatch.setattr(_capture_audit, "_EMITTED", set())
    entries: list[dict[str, Any]] = []
    monkeypatch.setattr(_runtime, "ensure_state", lambda: types.SimpleNamespace(audit=object()))
    monkeypatch.setattr(
        _capture_audit, "safe_audit_append", lambda audit, entry, *, logger: entries.append(dict(entry))
    )
    return entries


def write_config(home: Path, section: dict[str, Any]) -> None:
    (home / "config.yaml").write_text(json.dumps({"plugins": {"mordred_activity": section}}), encoding="utf-8")


def batch(*seqs: int) -> dict[str, Any]:
    events = [
        {
            "event_id": str(uuid.uuid4()),
            "seq": seq,
            "episode_id": "ep-1",
            "source": "operator",
            "actor": "agent",
            "observed_at": 1760950000.0 + seq,
            "phase": "dispatched",
            "action": {"op": "click", "target": "Reports", "site": "example.com", "route": "/reports"},
            "result": {"status": "claimed_success"},
            "quality": {"coverage": "selected_tab"},
        }
        for seq in seqs
    ]
    return {"schema_version": 1, "producer_id": "prod-1", "producer_kind": "operator", "events": events}


def receiver(home: Path, store: ActivityStore, interval: float = 3600.0) -> StoreReceiver:
    def factory(_home: Path) -> ActivityStore:
        store.initialize(_home)
        return store

    return StoreReceiver(home, config_loader=ActivityConfig.load, store_factory=factory, retention_interval_s=interval)


def test_retention_runs_once_per_interval_with_the_configured_windows(tmp_path: Path) -> None:
    write_config(tmp_path, {**ENABLED, "retention_raw_days": 7, "retention_candidate_days": 14})
    store = CountingStore(tmp_path / "mordred.db")
    hourly = receiver(tmp_path, store)

    hourly.ingest(OPERATOR, batch(1))
    hourly.ingest(OPERATOR, batch(2))
    # Another receiver in the same process shares the per-store-path clock.
    receiver(tmp_path, store).ingest(OPERATOR, batch(3))

    assert store.retention_calls == [{"raw_days": 7, "candidate_days": 14, "limit": 200}]


def test_retention_runs_again_once_the_interval_has_passed(tmp_path: Path) -> None:
    write_config(tmp_path, ENABLED)
    store = CountingStore(tmp_path / "mordred.db")
    eager = receiver(tmp_path, store, interval=0.0)

    eager.ingest(OPERATOR, batch(1))
    eager.ingest(OPERATOR, batch(2))

    assert len(store.retention_calls) == 2


def test_retention_does_not_run_after_a_refused_batch(tmp_path: Path) -> None:
    write_config(tmp_path, ENABLED)
    store = CountingStore(tmp_path / "mordred.db")
    reply = receiver(tmp_path, store).ingest(OPERATOR, {"schema_version": 1})
    assert reply["type"] == "activity_refused"
    assert store.retention_calls == []


@pytest.mark.parametrize("failure", [ActivityRefused(refusal("busy")), RuntimeError("boom")])
def test_retention_failure_never_changes_the_ack(
    tmp_path: Path, failure: BaseException, caplog: pytest.LogCaptureFixture
) -> None:
    write_config(tmp_path, ENABLED)
    store = CountingStore(tmp_path / "mordred.db", failure=failure)

    reply = receiver(tmp_path, store).ingest(OPERATOR, batch(1, 2))

    assert reply == {
        "type": "activity_ack",
        "status": "ok",
        "accepted": 2,
        "duplicates": 0,
        "episode_revisions": {"ep-1": 1},
    }
    assert len(store.retention_calls) == 1
    assert "Reports" not in caplog.text


def test_collection_disabled_is_audited_once_per_process(
    tmp_path: Path, fresh_process_state: list[dict[str, Any]]
) -> None:
    write_config(tmp_path, {"enabled": True})
    store = CountingStore(tmp_path / "mordred.db")

    for seq in (1, 2):
        assert receiver(tmp_path, store).ingest(OPERATOR, batch(seq))["reason"] == "collection_disabled"

    assert fresh_process_state == [
        {
            "event": "activity_capture",
            "decision": "refuse",
            "reason": "activity.capture_refused",
            "code": "collection_disabled",
            "peer_id": OPERATOR.peer_id,
        }
    ]


def test_store_refusals_are_audited_once_per_wire_code(
    tmp_path: Path, fresh_process_state: list[dict[str, Any]]
) -> None:
    write_config(tmp_path, ENABLED)
    codes = iter(["busy", "not_armed", "busy", "no_key", "disk_full"])

    def refusing(_home: Path) -> ActivityStore:
        raise ActivityRefused(refusal(next(codes)))

    gated = StoreReceiver(tmp_path, config_loader=ActivityConfig.load, store_factory=refusing)
    replies = [gated.ingest(OPERATOR, batch(seq))["reason"] for seq in range(1, 6)]

    assert replies == ["busy", "store_unavailable", "busy", "store_unavailable", "store_full"]
    assert [entry["code"] for entry in fresh_process_state] == ["busy", "store_unavailable", "store_full"]


def test_contract_errors_are_not_audited(tmp_path: Path, fresh_process_state: list[dict[str, Any]]) -> None:
    write_config(tmp_path, ENABLED)
    store = CountingStore(tmp_path / "mordred.db")
    reply = receiver(tmp_path, store).ingest(OPERATOR, {"schema_version": 1})
    assert reply["type"] == "activity_refused"
    assert fresh_process_state == []


def test_an_audit_failure_never_breaks_ingestion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> Any:
        raise RuntimeError("audit down")

    monkeypatch.setattr(_runtime, "ensure_state", broken)
    write_config(tmp_path, {"enabled": True})
    store = CountingStore(tmp_path / "mordred.db")
    assert receiver(tmp_path, store).ingest(OPERATOR, batch(1)) == {
        "type": "activity_refused",
        "reason": "collection_disabled",
    }


def test_recall_gate_refusal_is_audited_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fresh_process_state: list[dict[str, Any]]
) -> None:
    write_config(tmp_path, {"enabled": True, "recall_enabled": True})
    monkeypatch.setattr(tools, "_home", lambda: tmp_path)

    def refuse(home: Path, **_: Any) -> ActivityStore:
        raise ActivityRefused(refusal("not_armed"))

    monkeypatch.setattr(_gate, "open_store", refuse)

    for _ in range(2):
        reply = json.loads(tools.activity_search({"task": "export the report"}))
        assert reply == {"status": "unavailable", "reason": "not_armed"}

    assert fresh_process_state == [
        {"event": "activity_capture", "decision": "refuse", "reason": "activity.capture_refused", "code": "not_armed"}
    ]
