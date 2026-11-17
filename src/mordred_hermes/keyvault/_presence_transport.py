"""Bounded private pipe transport for the macOS presence helper."""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import time
from typing import Any, Protocol

from ._seckey_errors import _OpsError

_FRAME = 64 * 1024


class PresenceChannel(Protocol):
    def exchange(self, payload: dict[str, Any], timeout: float) -> dict[str, Any]: ...
    def close(self) -> None: ...
    def detach(self) -> None: ...
    def alive(self) -> bool: ...


class Channel:
    def __init__(self, binary: str, override: tuple[str, str] | None, seconds: int) -> None:
        env = dict(os.environ)
        if override is not None:
            env[override[0]] = override[1]
        try:
            self._process = subprocess.Popen(  # noqa: S603 - trusted helper, no shell
                [binary, "--presence-session", str(seconds)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=env,
                bufsize=0,
            )
        except OSError as exc:
            raise _OpsError(-1, "helper", "presence helper spawn failed") from exc
        assert self._process.stdin is not None and self._process.stdout is not None
        os.set_blocking(self._process.stdin.fileno(), False)
        os.set_blocking(self._process.stdout.fileno(), False)

    def alive(self) -> bool:
        return self._process.poll() is None

    def close(self) -> None:
        # Do not close a descriptor while another thread's selector uses it;
        # killing the process produces EOF and wakes the exchange immediately.
        if self.alive():
            self._process.kill()
        self._process.wait(timeout=1)

    def detach(self) -> None:
        # Child after fork: close inherited copies without killing parent's helper.
        for stream in (self._process.stdin, self._process.stdout):
            if stream is not None:
                stream.close()

    def _roundtrip(self, request: bytes, end: float) -> bytearray:
        response = bytearray()
        assert self._process.stdin is not None and self._process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(self._process.stdin, selectors.EVENT_WRITE)
            while request:
                if time.monotonic() >= end:
                    raise TimeoutError
                if not selector.select(max(0, end - time.monotonic())):
                    raise TimeoutError
                count = os.write(self._process.stdin.fileno(), request)
                request = request[count:]
            selector.unregister(self._process.stdin)
            selector.register(self._process.stdout, selectors.EVENT_READ)
            while not response.endswith(b"\n"):
                if time.monotonic() >= end:
                    raise TimeoutError
                if not selector.select(max(0, end - time.monotonic())):
                    raise TimeoutError
                chunk = os.read(self._process.stdout.fileno(), _FRAME + 1 - len(response))
                if not chunk:
                    raise ValueError("presence helper disconnected")
                response.extend(chunk)
                if len(response) > _FRAME or b"\n" in response[:-1]:
                    raise ValueError("invalid presence frame")
        return response

    def exchange(self, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        from ._seckey_helper import _normalize_reason

        request = json.dumps(payload).encode() + b"\n"
        if len(request) > _FRAME:
            raise _OpsError(-1, "helper", "presence frame too large")
        end = time.monotonic() + min(120, timeout)
        try:
            response = self._roundtrip(request, end)
            if time.monotonic() >= end:
                response.clear()
                raise TimeoutError
            result = json.loads(response)
            if not isinstance(result, dict):
                raise ValueError("invalid presence response")
        except (OSError, ValueError, TimeoutError) as exc:
            raise _OpsError(-1, "helper", "presence transport failed") from exc
        if "error" in result:
            error = result["error"]
            if not isinstance(error, dict) or type(error.get("status")) is not int:
                raise _OpsError(-1, "helper", "invalid presence error")
            raise _OpsError(
                error["status"],
                str(error.get("domain", "helper")),
                str(error.get("message", "")),
                reason=_normalize_reason(error.get("reason")),
            )
        return result
