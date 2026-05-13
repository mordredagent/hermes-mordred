"""Tests for ``mordred_hermes.network.provider_transport_flagger``.

PR1 ships the v1 baseline ``KNOWN_PROVIDERS`` dict with an
``unverified_baseline=True`` flag on every entry. PR3 will run the
real-traffic checks from TODO §0.8 L110-117 (anthropic/openai/gemini
through HTTPS_PROXY, Wireshark / Tor circuit verification) and flip the
flag to ``False`` per entry.

Tests cover:

- Baseline dict has the 6 documented providers (TODO §3.1 L320).
- Every PR1 entry carries ``unverified_baseline=True``.
- Tor + ``respects_socks5h=False`` provider under strict → ``abort`` flag.
- Tor + ``respects_socks5h=True`` provider → no flag.
- Clearnet + ``respects_proxy=False`` provider → ``warning`` flag.
- Localhost-only provider is exempt from Tor flagging.
- Lenient mode downgrades ``abort`` to ``warning``.
- Off mode emits no flags regardless of path.
- Unknown provider produces a ``warning`` (no data ≠ safe).
- Overrides may add new providers but must not replace baseline entries.
"""

from __future__ import annotations

import pytest


def test_known_providers_includes_v1_baseline() -> None:
    from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

    expected = {"anthropic", "openai", "gemini", "mordred-local", "bedrock", "vertex"}
    assert expected.issubset(set(KNOWN_PROVIDERS))


def test_every_baseline_entry_is_unverified_in_pr1() -> None:
    from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

    for name, entry in KNOWN_PROVIDERS.items():
        assert entry.unverified_baseline is True, f"{name} flipped early"


def test_anthropic_respects_socks5h() -> None:
    from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

    entry = KNOWN_PROVIDERS["anthropic"]
    assert entry.respects_proxy is True
    assert entry.respects_socks5h is True


def test_bedrock_socks5h_false() -> None:
    from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

    entry = KNOWN_PROVIDERS["bedrock"]
    assert entry.respects_socks5h is False
    assert entry.dns_quirk is True


def test_vertex_partial_proxy() -> None:
    from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

    entry = KNOWN_PROVIDERS["vertex"]
    assert entry.respects_proxy == "partial"
    assert entry.respects_socks5h is False


def test_mordred_local_is_localhost_only() -> None:
    from mordred_hermes.network.provider_transport_flagger import KNOWN_PROVIDERS

    entry = KNOWN_PROVIDERS["mordred-local"]
    assert entry.localhost_only is True


class TestStrictTor:
    def test_socks5h_compatible_provider_no_flag(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("anthropic",), policy_mode="strict")
        assert flags == []

    def test_bedrock_aborts(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("bedrock",), policy_mode="strict")
        assert len(flags) == 1
        assert flags[0].provider == "bedrock"
        assert flags[0].severity == "abort"

    def test_vertex_aborts(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("vertex",), policy_mode="strict")
        assert len(flags) == 1
        assert flags[0].severity == "abort"

    def test_localhost_only_provider_exempt(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("mordred-local",), policy_mode="strict")
        assert flags == []


class TestStrictClearnet:
    def test_no_flags_for_proxy_compatible(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="clearnet", providers=("anthropic",), policy_mode="strict")
        assert flags == []


class TestLenientMode:
    def test_socks5h_incompatible_downgrades_to_warning(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("bedrock",), policy_mode="lenient")
        assert flags[0].severity == "warning"


class TestOffMode:
    def test_no_flags_regardless_of_path(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(
            active_path="tor",
            providers=("bedrock", "vertex"),
            policy_mode="off",
        )
        assert flags == []


class TestUnknown:
    def test_unknown_provider_warns_under_strict(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        flags = ptf.evaluate(active_path="tor", providers=("custom-llm",), policy_mode="strict")
        assert len(flags) == 1
        assert flags[0].provider == "custom-llm"
        assert flags[0].severity in {"warning", "abort"}


class TestOverrides:
    def test_override_can_add_new_provider(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        entry = ptf.ProviderEntry(
            name="my-internal",
            transport="httpx",
            respects_proxy=True,
            respects_socks5h=True,
            unverified_baseline=False,
        )
        flags = ptf.evaluate(
            active_path="tor",
            providers=("my-internal",),
            policy_mode="strict",
            overrides={"my-internal": entry},
        )
        assert flags == []

    def test_override_cannot_replace_baseline(self) -> None:
        from mordred_hermes.network import provider_transport_flagger as ptf

        entry = ptf.ProviderEntry(
            name="anthropic",
            transport="httpx",
            respects_proxy=False,
            respects_socks5h=False,
            unverified_baseline=False,
        )
        with pytest.raises(ValueError):
            ptf.evaluate(
                active_path="tor",
                providers=("anthropic",),
                policy_mode="strict",
                overrides={"anthropic": entry},
            )


def test_multiple_providers_returns_one_flag_each() -> None:
    from mordred_hermes.network import provider_transport_flagger as ptf

    flags = ptf.evaluate(
        active_path="tor",
        providers=("anthropic", "bedrock", "vertex", "mordred-local"),
        policy_mode="strict",
    )
    names_flagged = {f.provider for f in flags}
    assert "bedrock" in names_flagged
    assert "vertex" in names_flagged
    assert "anthropic" not in names_flagged
    assert "mordred-local" not in names_flagged


def test_provider_entry_is_immutable() -> None:
    """``ProviderEntry`` must be frozen so user code can't smuggle a mutation."""
    import dataclasses

    from mordred_hermes.network import provider_transport_flagger as ptf

    entry = ptf.KNOWN_PROVIDERS["anthropic"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.respects_socks5h = False  # type: ignore[misc]
