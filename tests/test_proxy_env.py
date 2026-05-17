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
    """Codex round 5 P1 (2026-05-14): both upper- and lower-case variants
    must be managed. POSIX tools (curl, wget, python ``requests``) honor
    the lowercase forms, so leaving them untouched after a path switch
    would route child traffic through the user's old proxy."""
    from mordred_hermes.network import proxy_env

    assert proxy_env.managed_var_names() == {
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "no_proxy",
    }


def test_tor_sets_lowercase_proxy_vars() -> None:
    """Codex round 5 P1: lowercase keys must also be set, not just uppercase."""
    from mordred_hermes.network import proxy_env

    env = proxy_env.desired_env(path="tor", tor_socks_port=9050)
    assert env["https_proxy"] == "socks5h://127.0.0.1:9050"
    assert env["http_proxy"] == "socks5h://127.0.0.1:9050"
    assert env["all_proxy"] == "socks5h://127.0.0.1:9050"
    assert env["no_proxy"] == env["NO_PROXY"]


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


# --------------------------------------------------------------------------- #
# Phase 3 PR3a Task #4: SOCKS5h library compatibility allowlist               #
# --------------------------------------------------------------------------- #


class TestSocks5hLibraryAllowlist:
    """Static allowlist + ``evaluate_library_compatibility`` helper.

    Maps each HTTP client library known to ship in the Mordred / Hermes
    surface to the minimum version that grew ``socks5h://`` URL-scheme
    support. PR3c playbook flips ``unverified_baseline=True`` entries to
    ``False`` after the operator pins real installed versions.
    """

    def test_known_libraries_present(self) -> None:
        from mordred_hermes.network.proxy_env import SOCKS5H_LIBRARY_REQUIREMENTS

        for lib in ("httpx", "urllib3", "requests", "aiohttp"):
            assert lib in SOCKS5H_LIBRARY_REQUIREMENTS, f"baseline missing {lib}"

    def test_every_entry_is_verified(self) -> None:
        """TODO §0.8 L118-122: every allowlist entry is empirically backed by
        ``tests/integration/test_socks5h_libs.py`` — the live SOCKS5h
        verification clears ``unverified_baseline`` once a library is covered."""
        from mordred_hermes.network.proxy_env import SOCKS5H_LIBRARY_REQUIREMENTS

        for lib, entry in SOCKS5H_LIBRARY_REQUIREMENTS.items():
            assert entry.unverified_baseline is False, f"{lib} not yet verified by the integration suite"

    def test_aiohttp_documented_caveat(self) -> None:
        """aiohttp older releases do not understand ``socks5h://``; min should be high."""
        from mordred_hermes.network.proxy_env import SOCKS5H_LIBRARY_REQUIREMENTS

        entry = SOCKS5H_LIBRARY_REQUIREMENTS["aiohttp"]
        assert entry.min_version, "aiohttp must carry a non-empty min_version"
        assert entry.notes  # caveat documented

    def test_evaluate_library_compatibility_no_libs_no_warnings(self) -> None:
        from mordred_hermes.network import proxy_env

        result = proxy_env.evaluate_library_compatibility(active_path="tor", declared_libs=())
        assert result == []

    def test_evaluate_library_compatibility_clearnet_emits_no_warnings(self) -> None:
        """SOCKS5h only matters under Tor; clearnet bypasses the check."""
        from mordred_hermes.network import proxy_env

        result = proxy_env.evaluate_library_compatibility(
            active_path="clearnet",
            declared_libs=("aiohttp",),
        )
        assert result == []

    def test_evaluate_library_compatibility_tor_unknown_lib_warns(self) -> None:
        """A declared library not in the allowlist is a warning ('we don't know')."""
        from mordred_hermes.network import proxy_env

        result = proxy_env.evaluate_library_compatibility(
            active_path="tor",
            declared_libs=("my-internal-http-lib",),
        )
        assert len(result) == 1
        assert "my-internal-http-lib" in result[0]
        assert "unknown" in result[0].lower()

    def test_evaluate_library_compatibility_tor_known_lib_no_warning(self) -> None:
        """httpx is on the allowlist with a recent min_version; no warning."""
        from mordred_hermes.network import proxy_env

        result = proxy_env.evaluate_library_compatibility(
            active_path="tor",
            declared_libs=("httpx",),
        )
        assert result == []

    def test_evaluate_library_compatibility_tor_multiple_libs(self) -> None:
        """Mixed declared libs return per-library warnings."""
        from mordred_hermes.network import proxy_env

        result = proxy_env.evaluate_library_compatibility(
            active_path="tor",
            declared_libs=("httpx", "my-internal-http-lib", "another-unknown"),
        )
        # httpx → no warning; the two unknowns → one warning each
        assert len(result) == 2
        assert any("my-internal-http-lib" in r for r in result)
        assert any("another-unknown" in r for r in result)
