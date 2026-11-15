"""The headline model's server, started on demand and stopped once idle (no real process is started)."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.recall import model_server
from mordred_hermes.recall.headlines import HeadlineTarget, HeadlineWriter
from mordred_hermes.recall.model_server import OnDemandServer

BASE = "http://127.0.0.1:8081/v1"
ARGV = ["/bin/sh", "-c", "serve the model"]


class _Proc:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.code: int | None = None

    def poll(self) -> int | None:
        return self.code


class _World:
    """A fake clock, endpoint and process table."""

    def __init__(self, *, loads_in: float = 3.0, answering: bool = False) -> None:
        self.now = 0.0
        self.loads_in = loads_in
        self.answering = answering
        self.started_at: float | None = None
        self.procs: list[_Proc] = []
        self.signals: list[tuple[int, int, bool]] = []
        self.live: set[int] = set()

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    def probe(self, _base: str) -> bool:
        if self.answering:
            return True
        proc = self.procs[-1] if self.procs else None
        if proc is None or proc.code is not None or self.started_at is None:
            return False
        return self.now - self.started_at >= self.loads_in

    def popen(self, argv: list[str], **kwargs: Any) -> _Proc:
        assert argv == ARGV and kwargs["start_new_session"] is True
        proc = _Proc(4_000_000 + len(self.procs))
        self.procs.append(proc)
        self.started_at = self.now
        return proc

    def send_signal(self, pid: int, sig: int, group: bool) -> None:
        self.signals.append((pid, sig, group))
        for proc in self.procs:
            if proc.pid == pid:
                proc.code = -sig
        self.live.discard(pid)

    def server(self, home: Path, **kwargs: Any) -> OnDemandServer:
        options: dict[str, Any] = {
            "idle_s": 300.0,
            "probe": self.probe,
            "popen": self.popen,
            "clock": self.clock,
            "sleep": self.sleep,
            "send_signal": self.send_signal,
            "alive": lambda pid: pid in self.live,
            "command_of": lambda _pid: None,
            "stop_at_exit": False,
            **kwargs,
        }
        return OnDemandServer(ARGV, BASE, home=home, **options)


def test_starts_on_first_use_and_stops_once_idle(tmp_path: Path) -> None:
    world = _World()
    server = world.server(tmp_path)
    assert server.ensure() is True
    assert len(world.procs) == 1 and server.owned
    assert (tmp_path / "run" / "recall-model.pid").read_text().strip() == str(world.procs[0].pid)
    # Used again while up: no second process.
    world.now += 100
    assert server.ensure() is True and len(world.procs) == 1
    world.now += 299
    assert server.release_if_idle() is False
    world.now += 1
    assert server.release_if_idle() is True
    assert world.signals[0][1:] == (15, True)  # SIGTERM to the server's process group
    assert not server.owned and not (tmp_path / "run" / "recall-model.pid").exists()
    # The next piece of work starts it again.
    assert server.ensure() is True and len(world.procs) == 2


def test_a_request_in_flight_is_never_cut(tmp_path: Path) -> None:
    world = _World()
    server = world.server(tmp_path)
    with server.using() as up:
        assert up
        world.now += 1000
        assert server.release_if_idle() is False
    assert server.release_if_idle() is False  # just used
    world.now += 300
    assert server.release_if_idle() is True


def test_a_server_hermes_did_not_start_is_used_but_never_stopped(tmp_path: Path) -> None:
    world = _World(answering=True)
    server = world.server(tmp_path)
    assert server.ensure() is True
    world.now += 10_000
    assert server.release_if_idle() is False
    server.stop()
    assert world.procs == [] and world.signals == []


def test_a_server_left_by_a_killed_hermes_is_taken_back(tmp_path: Path) -> None:
    world = _World(answering=True)
    (tmp_path / "run").mkdir()
    (tmp_path / "run" / "recall-model.pid").write_text("4242\n")
    world.live.add(4242)
    server = world.server(tmp_path, command_of=lambda pid: shlex.join(ARGV) if pid == 4242 else None)
    assert server.ensure() is True and server.owned
    world.now += 300
    assert server.release_if_idle() is True
    assert world.signals[0] == (4242, 15, False)


def test_a_pid_file_naming_another_program_is_not_taken(tmp_path: Path) -> None:
    world = _World(answering=True)
    (tmp_path / "run").mkdir()
    (tmp_path / "run" / "recall-model.pid").write_text("4242\n")
    world.live.add(4242)
    server = world.server(tmp_path, command_of=lambda _pid: "/usr/bin/something-else")
    assert server.ensure() is True and not server.owned


def test_a_server_that_exits_or_never_loads_is_reported(tmp_path: Path) -> None:
    world = _World(loads_in=10_000)
    server = world.server(tmp_path, start_timeout_s=60)
    assert server.ensure() is False
    assert world.signals and not server.owned  # stopped after the start timeout

    exits = _World(loads_in=5)
    crashing = exits.server(tmp_path)

    def exit_now(seconds: float) -> None:
        exits.procs[-1].code = 1
        exits.now += seconds

    crashing._sleep = exit_now
    assert crashing.ensure() is False and not crashing.owned


def test_an_unknown_command_starts_nothing(tmp_path: Path) -> None:
    world = _World()
    server = OnDemandServer(
        ["/nonexistent/serve"],
        BASE,
        home=tmp_path,
        probe=world.probe,
        popen=world.popen,
        clock=world.clock,
        sleep=world.sleep,
        stop_at_exit=False,
    )
    assert server.ensure() is False and world.procs == []


def test_settings_from_the_environment() -> None:
    assert model_server.command_from_env({}) is None
    assert model_server.command_from_env({"MORDRED_RECALL_LLM_COMMAND": "  "}) is None
    assert model_server.command_from_env({"MORDRED_RECALL_LLM_COMMAND": "/a/py -m srv --model 'x y'"}) == [
        "/a/py",
        "-m",
        "srv",
        "--model",
        "x y",
    ]
    assert model_server.idle_from_env({}) == 300.0
    assert model_server.idle_from_env({"MORDRED_RECALL_LLM_IDLE_SECONDS": "60"}) == 60.0
    assert model_server.idle_from_env({"MORDRED_RECALL_LLM_IDLE_SECONDS": "soon"}) == 300.0


class _Down:
    def using(self) -> Any:
        import contextlib

        return contextlib.nullcontext(False)


def test_the_writer_asks_nothing_while_the_server_is_down() -> None:
    asked: list[str] = []

    def post(url: str, _body: dict[str, Any], _timeout: float) -> dict[str, Any]:
        asked.append(url)
        return {"choices": [{"message": {"content": "見出し"}}]}

    writer = HeadlineWriter(HeadlineTarget(BASE, "bonsai"), post=post, server=_Down())
    assert writer.lines([("event", {"a": 1})]) == [None]
    assert asked == [] and writer.reachable is False


@pytest.mark.parametrize("answer", ["", "   "])
def test_an_unusable_answer_from_a_reachable_model_is_not_a_reachability_failure(answer: str) -> None:
    writer = HeadlineWriter(
        HeadlineTarget(BASE, "bonsai"), post=lambda *_a: {"choices": [{"message": {"content": answer}}]}
    )
    assert writer.lines([("event", {"a": 1})]) == [None]
    assert writer.reachable is True
