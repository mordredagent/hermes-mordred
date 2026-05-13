"""Tests for ``mordred_hermes.network.proxy_env``.

Pure function module — no ``os.environ`` mutation here; PR2 ``runtime`` is
the sole writer. Tests cover:

- Clearnet/VPN: no proxy variables set (HTTPS_PROXY etc. absent from returned dict).
- Tor: HTTPS_PROXY / HTTP_PROXY / ALL_PROXY = ``socks5h://127.0.0.1:<port>``.
- ``NO_PROXY`` always contains the three localhost entries (``localhost``,
  ``127.0.0.1``, ``::1``) regardless of path — Phase 2 ``mordred-local``
  health probes break if proxy_env forces them through Tor.
- User-supplied entries from policy.json are appended and deduplicated
  while preserving insertion order.
- Tor uses the supplied port (shift 9050 → 9150 is honored).
- The ``socks5h://`` (DNS server-side) scheme is used, not ``socks5://``.
- ``managed_var_names()`` enumerates every env var the module touches —
  PR2 ``runtime`` uses it to know which keys to remove on path switches.

See TODO §3.1 L315-317.
"""

from __future__ import annotations

import pytest


def test_clearnet_sets_no_proxy_vars() -> None:
    from mordred_hermes.network import proxy_env

    env = proxy_env.desired_env(path="clearnet")
    assert "HTTPS_PROXY" not in env
    assert "HTTP_PROXY" not in env
    assert "ALL_PROXY" not in env


def test_vpn_sets_no_proxy_vars() -> None:
    from mordred_hermes.network import proxy_env

    env = proxy_env.desired_env(path="vpn")
    assert "HTTPS_PROXY" not in env
    assert "HTTP_PROXY" not in env
    assert "ALL_PROXY" not in env


def test_tor_sets_socks5h() -> None:
    from mordred_hermes.network import proxy_env

    env = proxy_env.desired_env(path="tor", tor_socks_port=9050)
    assert env["HTTPS_PROXY"] == "socks5h://127.0.0.1:9050"
    assert env["HTTP_PROXY"] == "socks5h://127.0.0.1:9050"
    assert env["ALL_PROXY"] == "socks5h://127.0.0.1:9050"


def test_tor_uses_shifted_port() -> None:
    """When ``pick_free_port`` chose 9150, proxy_env must follow."""
    from mordred_hermes.network import proxy_env

    env = proxy_env.desired_env(path="tor", tor_socks_port=9150)
    assert env["HTTPS_PROXY"] == "socks5h://127.0.0.1:9150"


def test_tor_never_uses_plain_http_scheme() -> None:
    """Plain ``http://`` proxy URLs leak DNS via the system resolver — forbidden."""
    from mordred_hermes.network import proxy_env

    env = proxy_env.desired_env(path="tor", tor_socks_port=9050)
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
        assert env[key].startswith("socks5h://"), env[key]


def test_no_proxy_default_localhost_clearnet() -> None:
    from mordred_hermes.network import proxy_env

    env = proxy_env.desired_env(path="clearnet")
    np = env["NO_PROXY"].split(",")
    assert "localhost" in np
    assert "127.0.0.1" in np
    assert "::1" in np


def test_no_proxy_default_localhost_tor() -> None:
    from mordred_hermes.network import proxy_env

    env = proxy_env.desired_env(path="tor", tor_socks_port=9050)
    np = env["NO_PROXY"].split(",")
    assert "localhost" in np
    assert "127.0.0.1" in np
    assert "::1" in np


def test_no_proxy_default_localhost_vpn() -> None:
    from mordred_hermes.network import proxy_env

    env = proxy_env.desired_env(path="vpn")
    np = env["NO_PROXY"].split(",")
    assert "localhost" in np
    assert "127.0.0.1" in np
    assert "::1" in np


def test_no_proxy_user_extras_appended() -> None:
    from mordred_hermes.network import proxy_env

    env = proxy_env.desired_env(
        path="tor",
        tor_socks_port=9050,
        no_proxy_extra=("internal.example.com", "10.0.0.0/8"),
    )
    np = env["NO_PROXY"].split(",")
    assert "internal.example.com" in np
    assert "10.0.0.0/8" in np


def test_no_proxy_deduplicates() -> None:
    """User-supplied ``localhost`` must not produce a duplicate entry."""
    from mordred_hermes.network import proxy_env

    env = proxy_env.desired_env(
        path="tor",
        tor_socks_port=9050,
        no_proxy_extra=("localhost", "10.0.0.0/8", "127.0.0.1"),
    )
    np = env["NO_PROXY"].split(",")
    assert np.count("localhost") == 1
    assert np.count("127.0.0.1") == 1


def test_no_proxy_preserves_order() -> None:
    """Defaults come first, then user extras in input order. Determinism aids
    debugging when env vars surface in CI logs."""
    from mordred_hermes.network import proxy_env

    env = proxy_env.desired_env(
        path="tor",
        tor_socks_port=9050,
        no_proxy_extra=("alpha.example", "beta.example"),
    )
    np = env["NO_PROXY"].split(",")
    assert np.index("localhost") < np.index("alpha.example")
    assert np.index("alpha.example") < np.index("beta.example")


def test_managed_var_names_complete() -> None:
    from mordred_hermes.network import proxy_env

    assert proxy_env.managed_var_names() == {
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    }


def test_unknown_path_raises() -> None:
    """``desired_env`` only knows the three named paths."""
    from mordred_hermes.network import proxy_env
    from mordred_hermes.network._exceptions import UnknownPath

    with pytest.raises(UnknownPath):
        proxy_env.desired_env(path="i2p")  # type: ignore[arg-type]


def test_pure_does_not_mutate_environ() -> None:
    """Document the API contract: ``desired_env`` is read-only."""
    import os

    from mordred_hermes.network import proxy_env

    before = dict(os.environ)
    proxy_env.desired_env(path="tor", tor_socks_port=9050)
    after = dict(os.environ)
    assert before == after
