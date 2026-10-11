"""Unit tests for ``wizard._defaults`` — the lazy production-default seams.

Production defaults are selected lazily, so importing this module never pulls
crypto / Keychain / prompt_toolkit stacks. Injected defaults are exercised by
the vault CLI tests that create and recover a vault using fake dependencies.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

from mordred_hermes.wizard import _defaults


class TestLazyProductionDefaults:
    """``None`` builds the production class — resolved at *call* time, so a
    monkeypatched class in the source module is honoured (proving the import
    happens inside the function, not at module import)."""

    def test_backend_default_is_seckey_backend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.keyvault import _seckey_backend

        class _Fake:
            pass

        monkeypatch.setattr(_seckey_backend, "_SecKeyBackend", _Fake)
        assert isinstance(_defaults.resolve_backend(None), _Fake)

    def test_store_default_is_keychain_store(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.keyvault import _anchor_keychain, _seckey_helper

        class _Fake:
            pass

        monkeypatch.setattr(_seckey_helper, "find_sekey_helper", lambda: None)
        monkeypatch.setattr(_anchor_keychain, "KeychainAnchorStore", _Fake)
        assert isinstance(_defaults.resolve_store(None), _Fake)

    def test_store_default_is_helper_owned_when_the_helper_is_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.keyvault import _anchor_keychain, _seckey_helper

        class _Fake:
            def __init__(self, *_a: object, **_kw: object) -> None:
                pass

        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(_seckey_helper, "find_sekey_helper", lambda: "/x/mordred-hermes-sekey")
        monkeypatch.setattr(_anchor_keychain, "HelperAnchorStore", _Fake)
        assert isinstance(_defaults.resolve_store(None), _Fake)

    def test_prompt_io_default_is_prompt_toolkit_io(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mordred_hermes.wizard import configure

        class _Fake:
            pass

        monkeypatch.setattr(configure, "PromptToolkitIO", _Fake)
        assert isinstance(_defaults.resolve_prompt_io(None), _Fake)


class TestImportLight:
    """Importing ``_defaults`` must not require the ``[keyvault]`` extra.

    Same subprocess-blocker technique as
    ``test_audit_cli.TestMinimalInstallImport`` (blocking in-process would
    race the copies other tests already imported).
    """

    _IMPORT_UNDER_BLOCKER = textwrap.dedent(
        """
        import sys

        class _Blocker:
            BLOCKED = ("cryptography", "blake3", "argon2", "prompt_toolkit")

            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] in self.BLOCKED:
                    raise ModuleNotFoundError(f"No module named {name!r} (blocked by test)")
                return None

        sys.meta_path.insert(0, _Blocker())

        import mordred_hermes.wizard._defaults  # noqa: F401
        """
    )

    def test_defaults_imports_without_heavy_stacks(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-c", self._IMPORT_UNDER_BLOCKER],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert proc.returncode == 0, f"_defaults needs a heavy stack at import time:\n{proc.stderr}"
