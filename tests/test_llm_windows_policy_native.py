"""Native Windows ACL and identity changes cannot preserve a warmed LLM allow."""

from __future__ import annotations

import os
import subprocess

import pytest

from mordred_hermes._config_io import CanonicalPaths, canonical_session
from mordred_hermes.llm_guard import auxiliary_guard, enforce
from mordred_hermes.llm_guard._exceptions import MordredSessionRefused
from tests.test_llm_windows_policy import Audit
from tests.test_private_fs_confidential_windows import descriptor
from tests.test_private_fs_confidential_windows import shared_home as shared_home

pytestmark = pytest.mark.skipif(os.name != "nt", reason="actual Windows policy ACL and identity admission")


@pytest.mark.parametrize("damage", ["config-acl", "policy-acl", "hardlink", "pending"])
def test_native_warmed_grants_refuse_changed_admission(shared_home, damage):
    paths = CanonicalPaths(shared_home)
    # Preserve the existing upstream-style inherited descriptor on a no-op write.
    config = shared_home / "config.yaml"
    config.write_bytes(b"{}")
    parent_before = descriptor(shared_home)
    config_before = descriptor(config)
    with canonical_session(paths, scope="policy", create=True) as session, session.policy_update() as update:
        update.put_config(b"{}")
        update.put_policy(b'{"policy":"strict","cloud_attempt_action":"prompt-once"}')
        update.commit()
    assert descriptor(config) == config_before
    policy = shared_home / "mordred" / "policy.json"
    enforce._reset_state()
    auxiliary_guard.reset_caches()

    def request():
        enforce.check_runtime_provider(
            policy_mode="off",
            policy_json_path=policy,
            active_provider="openai",
            audit=Audit(),
            prompt_fn=lambda provider: True,
        )

    request()
    auxiliary_guard._guard_inputs(policy)
    before = policy.read_bytes(), config.read_bytes()
    damaged_path = config if damage == "config-acl" else policy
    if damage.endswith("acl"):
        subprocess.run(["icacls.exe", str(damaged_path), "/grant", "*S-1-1-0:(R)"], capture_output=True, check=True)
    elif damage == "hardlink":
        os.link(config, shared_home / "copy.yaml")
    else:
        policy.with_name(".policy-write.pending").write_bytes(b"interrupted")
    damaged_acl = descriptor(damaged_path)
    with pytest.raises(MordredSessionRefused):
        request()
    with pytest.raises(MordredSessionRefused):
        auxiliary_guard._guard_inputs(policy)
    assert (policy.read_bytes(), config.read_bytes()) == before
    assert descriptor(damaged_path) == damaged_acl
    assert descriptor(shared_home) == parent_before
