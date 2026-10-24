"""Synthetic boundaries for database acceptance tooling; never live AWS."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def acceptance_tool(name: str) -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "tools" / f"{name}.py"
    assert path.is_file(), f"missing database acceptance tool: {path.name}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AcceptanceClock:
    def __init__(self) -> None:
        self.value = 1_000.0

    def now(self) -> float:
        return self.value

    def sleep(self, duration: float) -> None:
        self.value += duration


class SyntheticCloud:
    """Stateful external AWS boundary; the controller and receipts stay real."""

    def __init__(self, clock: AcceptanceClock) -> None:
        self.clock = clock
        self.state = "stopped"
        self.owner: str | None = None
        self.expiration: float | None = None
        self.starts = 0
        self.stops: list[float] = []
        self.fail_start_response = False

    def identity(self) -> str:
        return "123456789012"

    def credential_expiration(self) -> float | None:
        return self.expiration

    def observe(self, instance: str) -> tuple[str, str | None]:
        assert instance in {"i-00f4db5c3a204906b", "i-095cbe655c196c749"}
        return self.state, self.owner

    def claim(self, instance: str, owner: str) -> None:
        assert self.state == "stopped" and self.owner is None
        self.owner = owner

    def start(self, instance: str) -> None:
        self.starts += 1
        self.state = "running"
        if self.fail_start_response:
            raise TimeoutError("response lost after accepted start")

    def stop(self, instance: str) -> None:
        self.stops.append(self.clock.now())
        self.state = "stopped"

    def release(self, instance: str, owner: str) -> None:
        assert self.state == "stopped" and self.owner == owner
        self.owner = None


def fake_aws_executable(path: Path, state: Path) -> None:
    """A subprocess boundary for the detached guard, with no credential access."""
    script = f"""#!{sys.executable}
import json
from pathlib import Path
import sys
import time
time.sleep(0.1)
path=Path({str(state)!r})
data=json.loads(path.read_text())
args=sys.argv[1:]
if 'get-caller-identity' in args:
    print('{{"Account":"123456789012"}}')
elif 'describe-instances' in args:
    print(json.dumps({{'Reservations':[{{'Instances':[{{
        'InstanceId':'i-00f4db5c3a204906b','State':{{'Name':data['state']}},
        'Tags':([] if data['owner'] is None else [{{'Key':'mordred:dbcrypt-validation','Value':data['owner']}}])
    }}]}}]}}))
elif 'stop-instances' in args:
    data['state']='stopped'
    data['stopped_at']=time.time()
    path.write_text(json.dumps(data))
    print('{{}}')
elif 'delete-tags' in args:
    data['owner']=None
    path.write_text(json.dumps(data))
    print('{{}}')
else:
    raise SystemExit('unexpected AWS operation in isolated supervisor test')
"""
    path.write_text(script)
    path.chmod(0o755)


DATABASE_LEASE_CHILD = """
import sys
from pathlib import Path
from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes._database_lifecycle import acquire_exclusive, acquire_runtime
operation = sys.argv[2]
try:
    context = acquire_exclusive(Path(sys.argv[1])) if operation == 'exclusive' else acquire_runtime(Path(sys.argv[1]), timeout=0)
    with context:
        print('acquired', flush=True)
        if operation == 'hold': sys.stdin.readline()
except DatabaseRefused:
    print('busy', flush=True)
"""


def database_lease_child(root: Path, operation: str) -> str:
    import subprocess

    result = subprocess.run(
        [sys.executable, "-c", DATABASE_LEASE_CHILD, str(root), operation], text=True, capture_output=True, timeout=10
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


database_lease_child.script = DATABASE_LEASE_CHILD
