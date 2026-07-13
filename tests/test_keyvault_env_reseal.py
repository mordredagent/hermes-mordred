"""Tests for the keyvault-owned ``.env`` reseal core
(:mod:`mordred_hermes.keyvault._env_reseal`).

This core used to live only in ``mordred_hermes.wizard.env_decrypt_cli.reseal``;
:mod:`mordred_hermes.keyvault._env_write_guard` (wired onto the
``on_session_start`` / ``on_session_end`` plugin hooks) reached UP into it at
runtime — a ``keyvault -> wizard`` layering inversion, backwards from every
other call site in the codebase. The merge-and-reseal logic now lives here, in
``keyvault``; ``wizard.env_decrypt_cli.reseal`` is a thin wrapper around it
(covered by ``test_wizard_env_decrypt_cli.py::TestReseal``, unchanged).

These tests prove two independent things:

1. :func:`_env_reseal.reseal_env` itself still does the right thing when
   called directly (a reduced mirror of ``TestReseal`` in
   ``test_wizard_env_decrypt_cli.py`` — full merge-correctness coverage stays
   there so it is not duplicated twice).
2. ``keyvault`` genuinely no longer depends on ``wizard`` to run this logic —
   both statically (source inspection) and dynamically (a real
   session-boundary reseal succeeds even with ``mordred_hermes.wizard``
   blocked from importing).

A revert to the old ``from ..wizard import env_decrypt_cli`` shape in
``_env_write_guard.py`` fails :class:`TestNoWizardImport` immediately, and a
revert that deletes/guts ``_env_reseal.py`` fails every test in this file.
"""

from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path

import pytest

from mordred_hermes.keyvault import _env_reseal, _env_write_guard, _identity, vault
from mordred_hermes.keyvault._env_reseal import reseal_env
from mordred_hermes.keyvault._runtime_env import _env_optout_marker_path

from ._keyvault_fakes import FakeAnchorStore, FakeBackend

_PASSPHRASE = "correct horse battery staple"
_ENV_MULTI = b"A=1\nB=2\n"


def _init_empty_vault(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> None:
    key_id = anchor_label = _identity.vault_identity(root)
    backend.generate_enclave_key(key_id)
    vault.init_vault(
        root, key_id=key_id, passphrase=_PASSPHRASE, backend=backend, store=store, anchor_label=anchor_label
    ).close()


def _vault_env(root: Path, backend: FakeBackend, store: FakeAnchorStore) -> bytes | None:
    key_id = anchor_label = _identity.vault_identity(root)
    with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
        return opened.read_file(".env") if ".env" in opened.list_files() else None


def _seal(root: Path, home: Path, backend: FakeBackend, store: FakeAnchorStore, content: bytes) -> None:
    """Enroll ``content`` directly against the vault (no ``wizard`` involved) and
    reach the sealed state (``.env`` enrolled, no plaintext at rest)."""
    _init_empty_vault(root, backend, store)
    key_id = anchor_label = _identity.vault_identity(root)
    with vault.open_vault(root, key_id=key_id, backend=backend, store=store, anchor_label=anchor_label) as opened:
        opened.enroll_file(".env", content)
    env_path = home / ".env"
    if env_path.exists():
        env_path.unlink()


# -----------------------------------------------------------------------------
# 1. The moved core still merges/reseals correctly when called directly.
# -----------------------------------------------------------------------------
class TestResealEnvCore:
    def test_merges_partial_write_without_losing_secrets(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, _ENV_MULTI)
        (home / ".env").write_bytes(b"C=3\n")  # host writes only the just-set key

        rc = reseal_env(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert not (home / ".env").exists()
        assert _vault_env(root, backend, store) == b"A=1\nB=2\nC=3\n"  # A and B survived

    def test_noop_when_no_plaintext(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, b"A=1\n")

        rc = reseal_env(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert not (home / ".env").exists()

    def test_keeps_plaintext_when_opted_out(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, b"A=1\n")
        marker = _env_optout_marker_path(home)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("opt-out\n", encoding="utf-8")
        (home / ".env").write_bytes(b"B=2\n")  # the intentional live copy

        rc = reseal_env(home=home, root=root, backend=backend, store=store)
        assert rc == 0
        assert (home / ".env").read_bytes() == b"B=2\n"  # untouched
        assert _vault_env(root, backend, store) == b"A=1\n"  # vault unchanged

    def test_noop_when_not_enrolled(self, tmp_path: Path) -> None:
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        (home / ".env").write_bytes(b"A=1\n")  # plaintext but no vault / not enrolled

        rc = reseal_env(home=home, root=root, backend=FakeBackend(), store=FakeAnchorStore())
        assert rc == 0
        assert (home / ".env").read_bytes() == b"A=1\n"  # left alone

    def test_open_failure_reports_and_keeps_plaintext(self, tmp_path: Path) -> None:
        """``_open_hot_or_report`` (the keyvault-local mirror of
        ``wizard._vault_open._open_hot_path_or_report``) must fail closed: a
        store that raises on open must not lose the plaintext."""
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, b"A=1\n")
        (home / ".env").write_bytes(b"B=2\n")

        class _ReadRaisesStore(FakeAnchorStore):
            def read(self, account: str) -> bytes | None:
                raise OSError("keychain unavailable")

        rc = reseal_env(home=home, root=root, backend=backend, store=_ReadRaisesStore())
        assert rc == 1
        assert (home / ".env").read_bytes() == b"B=2\n"  # kept, not lost


# -----------------------------------------------------------------------------
# 2. keyvault no longer depends on wizard to run this logic.
# -----------------------------------------------------------------------------
class TestNoWizardImport:
    def test_env_write_guard_source_has_no_wizard_import(self) -> None:
        """Static check: a revert to ``from ..wizard import env_decrypt_cli``
        (or any other wizard import) in ``_env_write_guard.py`` fails this
        immediately, without needing to exercise any code path."""
        source = inspect.getsource(_env_write_guard)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert "wizard" not in module, f"unexpected wizard import: {ast.dump(node)}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert "wizard" not in alias.name, f"unexpected wizard import: {alias.name}"

    def test_env_reseal_source_has_no_wizard_import(self) -> None:
        """Same static check for the moved core module itself."""
        source = inspect.getsource(_env_reseal)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert "wizard" not in module, f"unexpected wizard import: {ast.dump(node)}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert "wizard" not in alias.name, f"unexpected wizard import: {alias.name}"

    def test_session_boundary_reseal_succeeds_with_wizard_blocked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End-to-end proof: block ``mordred_hermes.wizard`` from importing
        (``sys.modules[name] = None`` makes any ``import``/``from ... import``
        of it raise ``ImportError``), then run the exact session-boundary path
        (:func:`_env_write_guard.reseal_stray_env_if_present`) and confirm it
        still performs a real reseal. If this code path reached back into
        wizard, the blocked import would be swallowed by the broad
        ``except Exception`` in ``reseal_stray_env_if_present`` and the
        function would report failure (``False``, plaintext kept) instead of
        succeeding — so a regression is observable even though the exception
        itself is caught.
        """
        root, home = tmp_path / "v", tmp_path / "home"
        home.mkdir()
        backend, store = FakeBackend(), FakeAnchorStore()
        _seal(root, home, backend, store, _ENV_MULTI)
        (home / ".env").write_bytes(b"C=3\n")

        # `reseal_stray_env_if_present` has no backend/store injection seam of
        # its own (production code always resolves the real Secure Enclave
        # backend + Keychain store) — patch the resolvers `_env_reseal` calls
        # through `_open_hot_or_report` so the *real* reseal_env code path runs
        # against the software fakes instead.
        monkeypatch.setattr(_env_reseal, "resolve_backend", lambda b: backend if b is None else b)
        monkeypatch.setattr(_env_reseal, "resolve_store", lambda s: store if s is None else s)
        monkeypatch.setattr(_env_write_guard, "default_vault_root", lambda: root)
        monkeypatch.setitem(sys.modules, "mordred_hermes.wizard", None)

        result = _env_write_guard.reseal_stray_env_if_present(
            home=home,
            platform="darwin",
        )

        assert result is True
        assert not (home / ".env").exists()
        assert _vault_env(root, backend, store) == b"A=1\nB=2\nC=3\n"
