"""Native Windows ACL, identity and lock changes cannot preserve a network allow."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from mordred_hermes._config_io import POLICY_TRANSACTION_MARKER, CanonicalPaths, canonical_session
from mordred_hermes.network import api, hooks
from mordred_hermes.network._exceptions import MordredPathBringupFailed
from tests._network_hooks_helpers import _FakeRuntime, _reset_api
from tests.test_private_fs_confidential_windows import descriptor
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = [
    pytest.mark.skipif(os.name != "nt", reason="actual Windows policy ACL, identity and lock admission"),
    pytest.mark.usefixtures(_reset_api.__name__),
]

CONFIG = b"plugins: {mordred_network: {default_path: clearnet}}\n"


def decisions(home: Path) -> None:
    policy, config = home / "mordred" / "policy.json", home / "config.yaml"
    hooks.pre_api_request(policy_json_path=policy, config_path=config, provider="bedrock")
    assert hooks.pre_tool_call(policy_json_path=policy, config_path=config, tool_name="web_search") is None


@pytest.fixture
def warmed(shared_home: Path) -> Path:
    paths = CanonicalPaths(shared_home)
    config = shared_home / "config.yaml"
    # Overwrite the upstream-style inherited file in place, then publish the
    # same bytes: the no-op member must keep its inherited descriptor.
    config.write_bytes(CONFIG)
    config_before = descriptor(config)
    with canonical_session(paths, scope="policy", create=True) as session, session.policy_update() as update:
        update.put_config(CONFIG)
        update.put_policy(b'{"policy":"strict"}')
        update.commit()
    assert descriptor(config) == config_before
    runtime = _FakeRuntime()
    runtime.use("clearnet")
    api.set_runtime(runtime)
    decisions(shared_home)
    return shared_home


@pytest.mark.parametrize("damage", ["config-acl", "policy-acl", "hardlink", "pending"])
def test_native_warmed_network_allow_refuses_changed_admission(warmed: Path, damage: str) -> None:
    policy, config = warmed / "mordred" / "policy.json", warmed / "config.yaml"
    parent_before = descriptor(warmed)
    before = policy.read_bytes(), config.read_bytes()
    # The hardlinked member is config; ACL damage names its own member.
    damaged = policy if damage in ("policy-acl", "pending") else config
    if damage.endswith("acl"):
        subprocess.run(["icacls.exe", str(damaged), "/grant", "*S-1-1-0:(R)"], capture_output=True, check=True)
    elif damage == "hardlink":
        os.link(config, warmed / "copy.yaml")
    else:
        policy.with_name(POLICY_TRANSACTION_MARKER).write_bytes(b"interrupted")
    damaged_descriptor = descriptor(damaged)
    for entrypoint in (hooks.pre_api_request, hooks.pre_tool_call):
        with pytest.raises(MordredPathBringupFailed):
            entrypoint(policy_json_path=policy, config_path=config, provider="bedrock", tool_name="web_search")
    assert (policy.read_bytes(), config.read_bytes()) == before
    assert descriptor(damaged) == damaged_descriptor
    assert descriptor(warmed) == parent_before


def test_native_policy_directory_junction_refuses(warmed: Path) -> None:
    held = warmed / "held-policy"
    (warmed / "mordred").rename(held)
    subprocess.run(["cmd", "/c", "mklink", "/J", str(warmed / "mordred"), str(held)], check=True, capture_output=True)
    try:
        with pytest.raises(MordredPathBringupFailed):
            decisions(warmed)
    finally:
        os.rmdir(warmed / "mordred")
        held.rename(warmed / "mordred")
    decisions(warmed)


def test_native_busy_generation_refuses_without_waiting(warmed: Path) -> None:
    script = """
import sys
from pathlib import Path
from mordred_hermes._config_io import CanonicalPaths, canonical_session
with canonical_session(CanonicalPaths(Path(sys.argv[1])), scope="policy"):
    print("locked", flush=True)
    sys.stdin.readline()
"""
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", script, str(warmed)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    )
    try:
        from tests.test_config_io_windows import line

        assert line(process) == "locked"
        with pytest.raises(MordredPathBringupFailed):
            decisions(warmed)
    finally:
        process.communicate("done\n", timeout=20)
    assert process.returncode == 0
    decisions(warmed)
