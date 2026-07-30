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

import os as _real_os
from pathlib import Path
from types import SimpleNamespace

import pytest

from mordred_hermes import _pth_bootstrap


class TestLooksLikeHermes:
    @pytest.mark.parametrize(
        "argv",
        [
            ["/usr/local/bin/hermes"],
            ["/usr/local/bin/hermes", "mordred", "vault", "status"],
            ["/opt/venv/bin/hermes-agent", "--query", "hello"],
            ["/opt/venv/bin/hermes-acp"],
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


# --------------------------------------------------------------------------- #
# .pth <-> _looks_like_hermes parity                                          #
# --------------------------------------------------------------------------- #
#
# The shipped ``.pth`` line is the SOLE gate deciding whether
# ``_pth_bootstrap.run()`` is even imported at interpreter start — the engage
# condition is duplicated there as an inline one-liner rather than calling
# into this module (a ``.pth`` file cannot import project code before the
# project's own site-packages entry is on ``sys.path``). That duplication
# means the two copies of the match logic can silently drift: FIX 6 added the
# ``sys.argv[0].endswith('/hermes_cli')`` branch to the ``.pth`` line to catch
# it back up with ``_looks_like_hermes``, which has carried that branch since
# it was written. Nothing enforced they'd ever match before this test.
#
# Evaluation strategy: read the ``.pth`` file as plain text and strip the
# fixed ``import os, sys; `` prefix and `` and __import__(...).run()`` suffix,
# leaving exactly the boolean engage expression. That expression only touches
# ``os.environ.get``, ``os.path.basename``, and ``sys.argv`` — so it can be
# ``eval``'d directly against small stand-in ``os`` / ``sys`` objects (real
# ``os.path`` for the actual basename/splitext logic, a plain dict for
# ``environ`` so the test controls it, and a ``SimpleNamespace`` for ``sys``
# so ``argv`` is whatever the test wants). This is simpler and more honest
# than exec'ing the whole line with a stubbed ``__import__`` — the expression
# IS the part that must match ``_looks_like_hermes``; the ``__import__(...)``
# call after ``and`` is unconditionally the same import, not logic to verify.

_PTH_PATH = Path(__file__).resolve().parent.parent / "packaging" / "pth" / "mordred_hermes_config_decrypt.pth"
_PTH_PREFIX = "import os, sys; "
_PTH_SUFFIX = " and __import__('mordred_hermes._pth_bootstrap', fromlist=['run']).run()"


def _pth_engage_expr() -> str:
    line = _PTH_PATH.read_text(encoding="utf-8").strip()
    assert line.startswith(_PTH_PREFIX), f"unexpected .pth prefix, test needs updating: {line!r}"
    assert line.endswith(_PTH_SUFFIX), f"unexpected .pth suffix, test needs updating: {line!r}"
    return line[len(_PTH_PREFIX) : -len(_PTH_SUFFIX)]


def _eval_pth_engages(argv0: str) -> bool:
    """Evaluate the ``.pth`` boolean expression for a single ``sys.argv[0]``.

    ``environ={}`` mirrors the no-override case so the expression collapses
    to its process-sniffing half — the same half ``_looks_like_hermes``
    implements. ``eval`` needs no explicit ``__builtins__``: Python inserts
    the real builtins automatically when the globals dict omits the key,
    so the expression's bare ``len(...)`` call still resolves.
    """
    fake_sys = SimpleNamespace(argv=[argv0])
    fake_os = SimpleNamespace(environ={}, path=_real_os.path)
    # eval() is safe here: the source is our own tracked packaging/pth/*.pth
    # file (not attacker- or user-controlled input), the prefix/suffix
    # asserts above guarantee it's the expected boolean expression (not
    # arbitrary statements), and the globals dict exposes only the two
    # stand-in os/sys objects constructed above — ast.literal_eval cannot be
    # used since the expression legitimately calls os.environ.get / str
    # methods, not just literals.
    return bool(eval(_pth_engage_expr(), {"os": fake_os, "sys": fake_sys}))


class TestPthGateParity:
    """The ``.pth`` engage expression must decide identically to
    :func:`_pth_bootstrap._looks_like_hermes` for every ``argv[0]`` shape —
    including the ``endswith('/hermes_cli')`` case FIX 6 restored.
    """

    @pytest.mark.parametrize(
        "argv0,expected",
        [
            ("/opt/venv/bin/hermes", True),
            ("/opt/venv/bin/hermes-agent", True),
            ("/opt/venv/bin/hermes-acp", True),
            ("/opt/venv/bin/hermes-mordred", True),
            (r"C:\venv\Scripts\hermes.EXE", True),
            (r"C:\venv\Scripts\HERMES.Exe", True),
            (r"C:\venv\Scripts\HERMES.PY", True),
            ("/x/site-packages/hermes_cli/cli.py", True),
            ("/x/site-packages/hermes_cli", True),  # endswith('/hermes_cli') — the FIX 6 branch
            ("/opt/venv/bin/hermes.backup", False),
            ("/opt/venv/bin/hermes.test.py", False),
            (r"C:\venv\Scripts\hermes.backup.EXE", False),
            ("/x/hermes-venv/bin/pytest", False),  # venv NAMED hermes, but not a hermes process
            ("/usr/bin/python", False),
        ],
    )
    def test_pth_expression_matches_looks_like_hermes(self, argv0: str, expected: bool) -> None:
        engaged = _eval_pth_engages(argv0)
        assert engaged is expected
        # The real parity check: never hard-code only the expected literal —
        # assert equality against the production matcher itself, so the two
        # can never drift again even if one side's behaviour changes later.
        assert engaged == _pth_bootstrap._looks_like_hermes([argv0])
