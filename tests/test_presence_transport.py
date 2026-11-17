from __future__ import annotations

import os
import sys

import pytest

from mordred_hermes.keyvault._presence_transport import Channel
from mordred_hermes.keyvault._seckey_errors import _OpsError

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX pipe helper transport")


@pytest.fixture
def helper(tmp_path):
    executable = tmp_path / "helper"
    executable.write_text(
        f"#!{sys.executable}\n"
        + """import sys, json, time
for line in sys.stdin:
    mode = json.loads(line)['mode']
    if mode == 'ok': print('{"shared_hex":"ab"}', flush=True)
    elif mode == 'large': print('x' * 65536, flush=True)
    elif mode == 'invalid': print('bad-json', flush=True)
    elif mode == 'denied': print('{"error":{"status":-25293,"domain":"OSStatus","message":"denied"}}', flush=True)
    elif mode == 'bad_error': print('{"error":{"status":true}}', flush=True)
    elif mode == 'eof': sys.exit(0)
    elif mode == 'slow': time.sleep(10)
"""
    )
    executable.chmod(0o700)
    return executable


@pytest.mark.parametrize("mode", ["large", "invalid", "denied", "bad_error", "eof", "slow"])
def test_malformed_denied_and_delayed_responses_fail(helper, mode):
    channel = Channel(str(helper), None, 300)
    try:
        with pytest.raises(_OpsError):
            channel.exchange({"mode": mode}, 0.2)
    finally:
        channel.close()
        channel.detach()


def test_multiple_frames_use_one_private_pipe(helper):
    channel = Channel(str(helper), None, 300)
    try:
        for _ in range(3):
            assert channel.exchange({"mode": "ok"}, 2) == {"shared_hex": "ab"}
        with pytest.raises(_OpsError, match="frame too large"):
            channel.exchange({"mode": "x" * 65536}, 1)
    finally:
        channel.close()
        channel.detach()
