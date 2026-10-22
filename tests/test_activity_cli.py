"""``hermes-mordred activity …`` wiring and content-free output."""

from __future__ import annotations

import argparse
import json

import pytest

from mordred_hermes.activity import peers
from mordred_hermes.wizard import activity_cli, cli


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
    ):
        ns = parser.parse_args(argv)
        assert ns.func is cli._handle_activity


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
