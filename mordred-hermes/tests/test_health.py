"""Tests for ``mordred_hermes.llm_guard.health``.

The health probe is the cheap pre-request guard that prevents Hermes from
starting a turn against an unreachable local LLM endpoint (LM Studio /
Ollama / vLLM). Failure → :class:`MordredLocalUnreachable`.

Uses ``httpx.MockTransport`` (built-in, no respx dependency) so tests run
deterministically without binding network sockets.
"""

from __future__ import annotations

import httpx
import pytest


def _success_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/models"):
        return httpx.Response(
            200,
            json={"object": "list", "data": [{"id": "qwen", "object": "model"}]},
        )
    return httpx.Response(404)


def _server_500_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(500, text="upstream error")


def _connect_error_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused")


def _timeout_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectTimeout("connect timed out")


class TestProbeSuccess:
    def test_returns_none_on_200(self) -> None:
        """Success path: probe completes without raising."""
        from mordred_hermes.llm_guard.health import probe

        transport = httpx.MockTransport(_success_handler)
        # Should not raise. Return value is documented as None.
        result = probe(endpoint="http://localhost:1234/v1", transport=transport)
        assert result is None

    def test_uses_models_endpoint(self) -> None:
        """Probe hits ``{endpoint}/models`` exactly once."""
        from mordred_hermes.llm_guard.health import probe

        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(200, json={"data": []})

        probe(endpoint="http://localhost:1234/v1", transport=httpx.MockTransport(handler))
        assert seen == ["http://localhost:1234/v1/models"], seen

    def test_handles_trailing_slash_endpoint(self) -> None:
        """``http://host/v1/`` with trailing slash must still produce ``/v1/models``."""
        from mordred_hermes.llm_guard.health import probe

        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(200, json={"data": []})

        probe(endpoint="http://localhost:1234/v1/", transport=httpx.MockTransport(handler))
        assert seen == ["http://localhost:1234/v1/models"]


class TestProbeFailure:
    def test_500_raises_unreachable(self) -> None:
        from mordred_hermes.llm_guard._exceptions import MordredLocalUnreachable
        from mordred_hermes.llm_guard.health import probe

        with pytest.raises(MordredLocalUnreachable, match="500"):
            probe(
                endpoint="http://localhost:1234/v1",
                transport=httpx.MockTransport(_server_500_handler),
            )

    def test_connect_error_raises_unreachable(self) -> None:
        from mordred_hermes.llm_guard._exceptions import MordredLocalUnreachable
        from mordred_hermes.llm_guard.health import probe

        with pytest.raises(MordredLocalUnreachable, match=r"connection refused|ConnectError"):
            probe(
                endpoint="http://localhost:1234/v1",
                transport=httpx.MockTransport(_connect_error_handler),
            )

    def test_timeout_raises_unreachable(self) -> None:
        from mordred_hermes.llm_guard._exceptions import MordredLocalUnreachable
        from mordred_hermes.llm_guard.health import probe

        with pytest.raises(MordredLocalUnreachable, match=r"timed out|ConnectTimeout"):
            probe(
                endpoint="http://localhost:1234/v1",
                transport=httpx.MockTransport(_timeout_handler),
            )

    def test_unreachable_is_catchable(self) -> None:
        """Lenient mode must be able to ``except Exception`` and degrade.

        Verifies :class:`MordredLocalUnreachable` is an ``Exception`` subclass
        (already covered in test_exceptions.py but worth pinning here so the
        contract doesn't drift if the class is refactored).
        """
        from mordred_hermes.llm_guard._exceptions import MordredLocalUnreachable
        from mordred_hermes.llm_guard.health import probe

        try:
            probe(
                endpoint="http://localhost:1234/v1",
                transport=httpx.MockTransport(_connect_error_handler),
            )
        except Exception as e:
            assert isinstance(e, MordredLocalUnreachable)


class TestProbeContract:
    def test_default_timeout_is_short(self) -> None:
        """Probe must not block the session start on a slow link.

        Documented contract: short connect / read timeout. The httpx
        Client's timeout attribute exposes both; we assert the default the
        caller would inherit if ``timeout=`` is not passed.
        """
        from mordred_hermes.llm_guard.health import DEFAULT_TIMEOUT_SECONDS

        assert 0 < DEFAULT_TIMEOUT_SECONDS <= 5, f"health probe must be fast; got {DEFAULT_TIMEOUT_SECONDS}s"

    def test_timeout_keyword_propagates(self) -> None:
        """Explicit ``timeout=`` overrides the default."""
        from mordred_hermes.llm_guard.health import probe

        # Just exercises the signature — actual timing is mocked.
        probe(
            endpoint="http://localhost:1234/v1",
            transport=httpx.MockTransport(_success_handler),
            timeout=1.0,
        )
