"""``hermes-mordred activity …`` wiring and content-free output."""

from __future__ import annotations

import argparse
import json

import pytest

from mordred_hermes.activity import peers
from mordred_hermes.activity._gate import ActivityRefused, refusal
from mordred_hermes.activity.config import ActivityConfig
from mordred_hermes.wizard import activity_cli, cli
from tests._activity_episode_helpers import CORRECTION_TEXT, RAW_SECRET, make_store, rows, seed_episode


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    return tmp_path


def _pair() -> dict[str, str]:
    code, _ = peers.generate_peer_code("laptop")
    return peers.handle_pair_init(code)


def test_parser_wires_every_activity_subcommand():
    parser = argparse.ArgumentParser()
    cli._setup_subparser(parser)
    for argv in (
        ["activity", "status", "--json"],
        ["activity", "pair-operator", "--label", "x", "--timeout", "5"],
        ["activity", "peers", "list"],
        ["activity", "peers", "revoke", "operator:000000000000"],
        ["activity", "correct", "--episode", "e", "--text", "t", "--attempt", "a"],
    ):
        ns = parser.parse_args(argv)
        assert ns.func is cli._handle_activity


@pytest.mark.parametrize("removed", ["candidates", "validate", "adopt", "reject", "lessons", "review", "jobs"])
def test_lesson_pipeline_subcommands_are_gone(removed, capsys):
    parser = argparse.ArgumentParser()
    cli._setup_subparser(parser)
    with pytest.raises(SystemExit):
        parser.parse_args(["activity", removed])
    assert "invalid choice" in capsys.readouterr().err


def test_status_json_with_store(monkeypatch, capsys):
    monkeypatch.setattr(activity_cli, "_switches", lambda home: (True, True))
    monkeypatch.setattr(activity_cli, "_gate_refusal", lambda home: None)
    monkeypatch.setattr(
        activity_cli,
        "_store_status",
        lambda home: {"schema_version": 1, "store_generation": "ab12", "events": 3, "episodes": {"open": 1}},
    )
    paired = _pair()

    assert cli.main(["activity", "status", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["feature_enabled"] is True
    assert report["collection_enabled"] is True
    assert report["protection"] == "ok"
    assert report["store"] == {"schema_version": 1, "store_generation": "ab12", "events": 3, "episodes": {"open": 1}}
    [peer] = report["peers"]
    assert peer["peer_id"] == paired["peer_id"]
    assert peer["label"] == "laptop"
    assert peer["revoked_at"] is None
    assert paired["peer_token"] not in json.dumps(report)


def test_status_json_gate_refusal_never_opens_the_store(monkeypatch, capsys):
    monkeypatch.setattr(activity_cli, "_switches", lambda home: (True, True))
    monkeypatch.setattr(activity_cli, "_gate_refusal", lambda home: "not_armed")

    def must_not_open(home):
        raise AssertionError("store opened despite a gate refusal")

    monkeypatch.setattr(activity_cli, "_store_status", must_not_open)

    assert cli.main(["activity", "status", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["protection"] == "not_armed"
    assert report["store"] is None
    assert report["peers"] == []


def test_status_text_reports_store_refusal_code(monkeypatch, capsys):
    class Refused(Exception):
        refusal = type("R", (), {"code": "profile_mismatch"})()

    def refuse(home):
        raise Refused("detail that is not printed")

    monkeypatch.setattr(activity_cli, "_switches", lambda home: (True, False))
    monkeypatch.setattr(activity_cli, "_gate_refusal", lambda home: None)
    monkeypatch.setattr(activity_cli, "_store_status", refuse)

    assert cli.main(["activity", "status"]) == 0
    out = capsys.readouterr().out
    assert "collection:  disabled" in out
    assert "refused (profile_mismatch)" in out
    assert "detail that is not printed" not in out


def test_peers_revoke_is_idempotent(capsys):
    paired = _pair()
    assert cli.main(["activity", "peers", "revoke", paired["peer_id"]]) == 0
    assert "Revoked" in capsys.readouterr().out
    assert cli.main(["activity", "peers", "revoke", paired["peer_id"]]) == 0
    assert "No change" in capsys.readouterr().out
    assert peers.check_token(paired["peer_token"]) == (None, "peer_revoked")


def test_peers_list_json(capsys):
    paired = _pair()
    assert cli.main(["activity", "peers", "list", "--json"]) == 0
    out = capsys.readouterr().out
    assert [row["peer_id"] for row in json.loads(out)["peers"]] == [paired["peer_id"]]
    assert "token" not in out


def test_pair_operator_waits_for_the_peer(monkeypatch, capsys):
    calls = {"n": 0}
    real_outcome = peers.pair_outcome
    codes: list[str] = []
    real_generate = peers.generate_peer_code

    def generate(label):
        code, expires_at = real_generate(label)
        codes.append(code)
        return code, expires_at

    def outcome(code):
        calls["n"] += 1
        if calls["n"] == 2:
            peers.handle_pair_init(code)
        return real_outcome(code)

    monkeypatch.setattr(peers, "generate_peer_code", generate)
    monkeypatch.setattr(peers, "pair_outcome", outcome)
    monkeypatch.setattr(activity_cli, "_POLL_SECONDS", 0)

    assert cli.main(["activity", "pair-operator", "--label", "ops"]) == 0
    out = capsys.readouterr().out
    assert codes[0] in out
    assert "Paired" in out
    assert [row["label"] for row in peers.list_peers()] == ["ops"]


def test_pair_operator_timeout_revokes_the_code(monkeypatch, capsys):
    codes: list[str] = []
    real_generate = peers.generate_peer_code

    def generate(label):
        code, expires_at = real_generate(label)
        codes.append(code)
        return code, expires_at

    monkeypatch.setattr(peers, "generate_peer_code", generate)
    monkeypatch.setattr(activity_cli, "_POLL_SECONDS", 0)

    assert cli.main(["activity", "pair-operator", "--timeout", "0"]) == 1
    assert peers.pair_outcome(codes[0]) == ("failed", "cancelled")
    with pytest.raises(peers.PeerPairError):
        peers.handle_pair_init(codes[0])


def test_pair_operator_storage_failure_exits_2(monkeypatch, capsys):
    def broken(label):
        raise OSError("unsafe directory")

    monkeypatch.setattr(peers, "generate_peer_code", broken)
    assert cli.main(["activity", "pair-operator"]) == 2
    assert "unsafe directory" not in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# correct
# --------------------------------------------------------------------------- #


@pytest.fixture
def store(monkeypatch, tmp_path):
    activity_store = make_store(tmp_path)
    config = ActivityConfig.from_mapping({"enabled": True})
    monkeypatch.setattr(activity_cli, "_open", lambda home: (activity_store, config))
    return activity_store


def test_correct_records_one_raw_correction_event(store, capsys):
    seeded = seed_episode(store)

    code = cli.main(
        [
            "activity",
            "correct",
            "--episode",
            seeded.episode_id,
            "--text",
            CORRECTION_TEXT,
            "--attempt",
            seeded.attempt_id,
        ]
    )

    out = capsys.readouterr().out
    assert code == 0
    stored = store.events_for_episode(seeded.episode_id)[-1]
    assert (stored.phase, stored.attempt_id, stored.text) == ("correction", seeded.attempt_id, CORRECTION_TEXT)
    assert f"Recorded correction {stored.event_id} in episode {seeded.episode_id}." in out
    assert "andidate" not in out and "esson" not in out
    assert CORRECTION_TEXT not in out and RAW_SECRET not in out
    assert store.status().counts == {"activity_events": 5, "activity_episodes": 1}


def test_correct_unknown_episode_prints_only_the_code(store, capsys):
    assert cli.main(["activity", "correct", "--episode", "missing", "--text", "secret words"]) == 1
    captured = capsys.readouterr()
    assert "refused (episode_unknown)" in captured.err
    assert "secret words" not in captured.out + captured.err
    assert rows(store, "SELECT count(*) FROM activity_events") == [(0,)]


def test_correct_is_refused_while_the_feature_is_disabled(store, monkeypatch, capsys):
    seeded = seed_episode(store)
    monkeypatch.setattr(activity_cli, "_open", lambda home: (store, ActivityConfig()))

    assert cli.main(["activity", "correct", "--episode", seeded.episode_id, "--text", "x"]) == 1
    assert "refused (feature_disabled)" in capsys.readouterr().err
    assert rows(store, "SELECT count(*) FROM activity_events WHERE phase = 'correction'") == [(0,)]


def test_correct_gate_refusal_exits_one_with_the_code(monkeypatch, capsys):
    def refuse(home):
        raise ActivityRefused(refusal("not_armed"))

    monkeypatch.setattr(activity_cli, "_open", refuse)

    assert cli.main(["activity", "correct", "--episode", "e", "--text", "t"]) == 1
    assert "refused (not_armed)" in capsys.readouterr().err
