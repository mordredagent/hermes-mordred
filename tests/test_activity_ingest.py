"""Behaviour contract of the activity receiver: the exact ack / refusal frame bodies."""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.activity._gate import ActivityRefused, refusal
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.activity.ingest import PeerPrincipal, StoreReceiver, build_receiver
from mordred_hermes.activity.store import ActivityStore

OPERATOR = PeerPrincipal(peer_id="operator:ab12", kind="operator")
ENABLED = {"enabled": True, "collection_enabled": True}


def write_config(home: Path, section: dict[str, Any] | None) -> None:
    body = {"plugins": {"mordred_activity": section}} if section is not None else {}
    # JSON is valid YAML.
    (home / "config.yaml").write_text(json.dumps(body), encoding="utf-8")


def plain_store(home: Path) -> ActivityStore:
    store = ActivityStore(home / "mordred.db", sqlite3.connect)
    store.initialize(home)
    return store


def receiver(home: Path, store_factory: Any = plain_store) -> StoreReceiver:
    return StoreReceiver(home, config_loader=ActivityConfig.load, store_factory=store_factory)


def raw_event(seq: int, **overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
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
    event.update(overrides)
    return event


def batch(*events: dict[str, Any], producer_id: str = "prod-1", kind: str = "operator") -> dict[str, Any]:
    return {"schema_version": 1, "producer_id": producer_id, "producer_kind": kind, "events": list(events)}


@pytest.mark.parametrize("section", [None, {"enabled": True}, {"collection_enabled": True}])
def test_disabled_collection_refuses(tmp_path: Path, section: dict[str, Any] | None) -> None:
    write_config(tmp_path, section)
    reply = receiver(tmp_path).ingest(OPERATOR, batch(raw_event(1)))
    assert reply == {"type": "activity_refused", "reason": "collection_disabled"}
    assert not (tmp_path / "mordred.db").exists()


def test_good_batch_is_acknowledged_with_counts_and_revisions(tmp_path: Path) -> None:
    write_config(tmp_path, ENABLED)
    reply = receiver(tmp_path).ingest(OPERATOR, batch(raw_event(1), raw_event(2, episode_id="ep-2")))
    assert reply == {
        "type": "activity_ack",
        "status": "ok",
        "accepted": 2,
        "duplicates": 0,
        "episode_revisions": {"ep-1": 1, "ep-2": 1},
    }


def test_replayed_batch_is_counted_as_duplicates(tmp_path: Path) -> None:
    write_config(tmp_path, ENABLED)
    sent = batch(raw_event(1), raw_event(2))
    receiver(tmp_path).ingest(OPERATOR, sent)

    reply = receiver(tmp_path).ingest(OPERATOR, sent)

    assert reply == {
        "type": "activity_ack",
        "status": "ok",
        "accepted": 0,
        "duplicates": 2,
        "episode_revisions": {"ep-1": 1},
    }


def test_conflicting_replay_is_refused_and_nothing_is_written(tmp_path: Path) -> None:
    write_config(tmp_path, ENABLED)
    first = raw_event(1)
    receiver(tmp_path).ingest(OPERATOR, batch(first))
    changed = {**first, "result": {"status": "claimed_failure"}}

    reply = receiver(tmp_path).ingest(OPERATOR, batch(changed, raw_event(2)))

    assert reply == {"type": "activity_refused", "reason": "conflict"}
    assert plain_store(tmp_path).status().counts["activity_events"] == 1


@pytest.mark.parametrize(
    ("sent", "reason"),
    [
        (batch(raw_event(1, phase="finished")), "malformed"),
        (batch(raw_event(2), raw_event(1)), "sequence_regression"),
        ({**batch(raw_event(1)), "schema_version": 2}, "unsupported_schema"),
        (batch(*(raw_event(i) for i in range(1, 102))), "batch_too_large"),
        (batch(raw_event(1), kind="browser"), "malformed"),
    ],
)
def test_contract_refusals_refuse_the_whole_batch(tmp_path: Path, sent: dict[str, Any], reason: str) -> None:
    write_config(tmp_path, ENABLED)
    reply = receiver(tmp_path).ingest(OPERATOR, sent)
    assert reply == {"type": "activity_refused", "reason": reason}
    assert not (tmp_path / "mordred.db").exists()


def test_a_configured_excluded_site_refuses_the_whole_batch(tmp_path: Path) -> None:
    write_config(tmp_path, {**ENABLED, "excluded_sites": ["web.whatsapp.com"]})
    sent = batch(raw_event(1), raw_event(2, action={"op": "navigate", "site": "web.whatsapp.com"}))
    reply = receiver(tmp_path).ingest(OPERATOR, sent)
    assert reply == {"type": "activity_refused", "reason": "source_excluded"}
    assert not (tmp_path / "mordred.db").exists()


@pytest.mark.parametrize("excluded", [["web.whatsapp.com", "not a host"], "web.whatsapp.com", [None]])
def test_an_invalid_exclusion_list_refuses_every_batch_instead_of_recording_it(tmp_path: Path, excluded: Any) -> None:
    write_config(tmp_path, {**ENABLED, "excluded_sites": excluded})
    whatsapp = raw_event(1, action={"op": "navigate", "site": "web.whatsapp.com"})
    for sent in (batch(whatsapp), batch(raw_event(2))):
        reply = receiver(tmp_path).ingest(OPERATOR, sent)
        assert reply == {"type": "activity_refused", "reason": "excluded_sites_invalid"}
    assert not (tmp_path / "mordred.db").exists()
    # Once it is fixed, the valid entry excludes again and everything else is recorded.
    write_config(tmp_path, {**ENABLED, "excluded_sites": ["web.whatsapp.com"]})
    assert receiver(tmp_path).ingest(OPERATOR, batch(whatsapp)) == {
        "type": "activity_refused",
        "reason": "source_excluded",
    }
    assert receiver(tmp_path).ingest(OPERATOR, batch(raw_event(3)))["type"] == "activity_ack"


def test_no_site_is_excluded_by_default(tmp_path: Path) -> None:
    write_config(tmp_path, ENABLED)
    mail = raw_event(1, action={"op": "navigate", "site": "mail.google.com"})
    reply = receiver(tmp_path).ingest(OPERATOR, batch(mail))
    assert reply == {
        "type": "activity_ack",
        "status": "ok",
        "accepted": 1,
        "duplicates": 0,
        "episode_revisions": {"ep-1": 1},
    }
    assert [event.site for event in plain_store(tmp_path).events_for_episode("ep-1")] == ["mail.google.com"]


@pytest.mark.parametrize(
    ("code", "reason"),
    [
        ("busy", "busy"),
        ("disk_full", "store_full"),
        ("not_armed", "store_unavailable"),
        ("no_key", "store_unavailable"),
    ],
)
def test_store_refusals_map_to_wire_reasons(tmp_path: Path, code: str, reason: str) -> None:
    write_config(tmp_path, ENABLED)

    def refusing(_home: Path) -> ActivityStore:
        raise ActivityRefused(refusal(code))

    assert receiver(tmp_path, refusing).ingest(OPERATOR, batch(raw_event(1))) == {
        "type": "activity_refused",
        "reason": reason,
    }


def test_config_is_reevaluated_on_every_batch(tmp_path: Path) -> None:
    write_config(tmp_path, ENABLED)
    live = receiver(tmp_path)
    assert live.ingest(OPERATOR, batch(raw_event(1)))["type"] == "activity_ack"

    write_config(tmp_path, {"enabled": True, "collection_enabled": False})

    assert live.ingest(OPERATOR, batch(raw_event(2))) == {"type": "activity_refused", "reason": "collection_disabled"}


def test_trust_and_permitted_use_come_from_the_principal(tmp_path: Path) -> None:
    write_config(tmp_path, ENABLED)
    forged = raw_event(1, trust="owner", permitted_use="anything")
    receiver(tmp_path).ingest(OPERATOR, batch(forged))
    with plain_store(tmp_path).connection() as conn:
        stored = conn.execute("SELECT peer_id, trust, permitted_use FROM activity_events").fetchall()
    assert stored == [("operator:ab12", "paired_peer", "learning")]


def test_production_receiver_refuses_without_protection(tmp_path: Path) -> None:
    write_config(tmp_path, ENABLED)
    reply = build_receiver(tmp_path).ingest(OPERATOR, batch(raw_event(1)))
    assert reply == {"type": "activity_refused", "reason": "store_unavailable"}
    assert not (tmp_path / "plugin-data").exists()


def test_an_operator_correction_is_stored_as_a_raw_event_and_nothing_else(tmp_path: Path) -> None:
    write_config(tmp_path, ENABLED)
    store = plain_store(tmp_path)
    attempt = [raw_event(1, phase="intended", attempt_id="att-1"), raw_event(2, attempt_id="att-1")]
    correction = raw_event(3, phase="correction", actor="human", attempt_id="att-1", text="Select Finance first")
    sent = batch(*attempt, correction)

    first = receiver(tmp_path, lambda _home: store).ingest(OPERATOR, sent)
    replay = receiver(tmp_path, lambda _home: store).ingest(OPERATOR, sent)

    assert (first["accepted"], replay["duplicates"]) == (3, 3)
    stored = store.events_for_episode("ep-1")
    assert [(event.phase, event.text) for event in stored][-1] == ("correction", "Select Finance first")
    assert store.status().counts == {"activity_events": 3, "activity_episodes": 1}
    episode = store.episode("ep-1")
    assert episode is not None and episode.has_correction is True


def test_activity_register_only_wires_the_history_and_capture_surfaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mordred_hermes.activity as activity

    calls: list[str] = []

    class Ctx:
        def __getattr__(self, name: str) -> Any:
            calls.append(name)
            return lambda *args, **kwargs: None

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    activity.register(Ctx())

    # The history hooks, the two lookup tools, the skill, then the capture hooks; no store is created.
    assert calls == [
        "register_hook",
        "register_hook",
        "register_tool",
        "register_skill",
        "register_hook",
        "register_hook",
    ]
    assert not (tmp_path / "plugin-data").exists()
