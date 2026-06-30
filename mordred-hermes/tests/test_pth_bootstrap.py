"""Tests for the ``.pth`` interpreter-startup hook (config.yaml at-rest, v2-F8 Phase 2).

The ``.pth`` file ships to the venv's site-packages root and runs at *every*
interpreter start in that environment. The module it imports
(:mod:`mordred_hermes._pth_bootstrap`) therefore must:

* engage **only** for an actual Hermes CLI invocation (or an explicit
  ``MORDRED_CONFIG_DECRYPT=1`` override) — never for unrelated python (pytest,
  pip, a REPL) sharing the venv;
* fail **closed** for Hermes (abort startup) when the vault decrypt raises,
  rather than letting Hermes boot on a default/stale config;
* never auto-run on plain ``import`` — the ``.pth`` calls ``run()`` explicitly —
  so importing it here is side-effect free.
"""

from __future__ import annotations

import pytest

from mordred_hermes import _pth_bootstrap


class TestLooksLikeHermes:
    @pytest.mark.parametrize(
        "argv",
        [
            ["/usr/local/bin/hermes"],
            ["/usr/local/bin/hermes", "mordred", "vault", "status"],
            ["/opt/venv/bin/hermes-mordred", "vault", "status"],
            [
                "/opt/venv/lib/python3.11/site-packages/hermes_cli/cli.py"
            ],  # path INSIDE hermes_cli/ (direct-path; NOT `-m`)
            ["/opt/venv/bin/hermes.exe"],  # Windows-style console script (.exe suffix stripped)
        ],
    )
    def test_hermes_invocations(self, argv: list[str]) -> None:
        assert _pth_bootstrap._looks_like_hermes(argv) is True

    @pytest.mark.parametrize(
        "argv",
        [
            [],
            ["/usr/bin/pytest"],
            ["/Users/me/hermes-venv/bin/pytest"],  # venv NAMED hermes, but not a hermes process
            ["/usr/bin/python", "-c", "print(1)"],
            ["/usr/bin/pip", "install", "x"],
            ["-m"],  # `python -m ...` at site-init: argv[0] is '-m' (module name not yet in argv)
            ["-m", "hermes_cli"],  # not matched (and `python -m hermes_cli` is not even runnable: no __main__)
        ],
    )
    def test_non_hermes_invocations(self, argv: list[str]) -> None:
        assert _pth_bootstrap._looks_like_hermes(argv) is False


class TestShouldEngage:
    def test_force_env_engages_non_hermes(self) -> None:
        assert _pth_bootstrap._should_engage(["/usr/bin/python"], {"MORDRED_CONFIG_DECRYPT": "1"}) is True

    def test_optout_env_skips_hermes(self) -> None:
        assert _pth_bootstrap._should_engage(["/usr/local/bin/hermes"], {"MORDRED_CONFIG_DECRYPT": "0"}) is False

    def test_hermes_without_env_engages(self) -> None:
        assert _pth_bootstrap._should_engage(["/usr/local/bin/hermes"], {}) is True

    def test_non_hermes_without_env_skips(self) -> None:
        assert _pth_bootstrap._should_engage(["/usr/bin/pytest"], {}) is False


class TestRun:
    def test_engaged_calls_installer(self) -> None:
        calls: list[str] = []

        def _installer() -> int:
            calls.append("ran")
            return 1

        result = _pth_bootstrap.run(argv=["/usr/local/bin/hermes"], environ={}, installer=_installer)
        assert result is True
        assert calls == ["ran"]

    def test_not_engaged_skips_installer(self) -> None:
        calls: list[str] = []

        def _installer() -> int:
            calls.append("ran")
            return 0

        result = _pth_bootstrap.run(argv=["/usr/bin/pytest"], environ={}, installer=_installer)
        assert result is False
        assert calls == []  # unrelated interpreters never touch the device key

    def test_installer_failure_fails_closed(self) -> None:
        """A vault decrypt error for a Hermes process aborts startup (SystemExit), not a silent boot."""

        def _installer() -> int:
            raise RuntimeError("vault tampered")

        with pytest.raises(SystemExit):
            _pth_bootstrap.run(argv=["/usr/local/bin/hermes"], environ={}, installer=_installer)

    def test_systemexit_from_installer_propagates(self) -> None:
        """A deliberate SystemExit (already fail-closed) passes through unchanged."""

        def _installer() -> int:
            raise SystemExit(3)

        with pytest.raises(SystemExit) as exc_info:
            _pth_bootstrap.run(argv=["/usr/local/bin/hermes"], environ={}, installer=_installer)
        assert exc_info.value.code == 3

    def test_default_installer_is_install_config_decrypt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """With no injected installer, an engaged run lazily calls keyvault.install_config_decrypt."""
        from mordred_hermes.keyvault import _config_bootstrap as cb

        calls: list[str] = []

        def _spy() -> int:
            calls.append("ran")
            return 0

        monkeypatch.setattr(cb, "install_config_decrypt", _spy)
        result = _pth_bootstrap.run(argv=["/usr/local/bin/hermes"], environ={})  # installer=None default
        assert result is True
        assert calls == ["ran"]
