"""Tests for ``mordred_hermes.network.paths.clearnet``.

Clearnet is the no-op path: no subprocess, no env mutation (proxy_env
handles env), no liveness probe needed. The module exists for symmetry
with ``tor`` / ``vpn`` so :mod:`mordred_hermes.network.runtime` (PR2) can
dispatch uniformly.
"""

from __future__ import annotations


def test_start_returns_handle() -> None:
    from mordred_hermes.network.paths import clearnet

    handle = clearnet.start()
    assert handle is not None


def test_stop_is_noop() -> None:
    from mordred_hermes.network.paths import clearnet

    handle = clearnet.start()
    clearnet.stop(handle)  # must not raise


def test_health_always_true() -> None:
    """Clearnet has nothing to probe — always healthy."""
    from mordred_hermes.network.paths import clearnet

    handle = clearnet.start()
    assert clearnet.health(handle) is True


def test_path_name_constant() -> None:
    from mordred_hermes.network.paths import clearnet

    assert clearnet.PATH_NAME == "clearnet"


def test_start_idempotent() -> None:
    """Two start() calls in a row do not raise (no shared state)."""
    from mordred_hermes.network.paths import clearnet

    h1 = clearnet.start()
    h2 = clearnet.start()
    assert h1 is not None
    assert h2 is not None
