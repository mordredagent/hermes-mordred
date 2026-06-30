"""Contract: the secret-operations layer lives in ``_secret_ops``.

``api.py`` had grown past 1100 LOC. The "operate on an initialised keyvault"
operations — per-secret envelope ``encrypt`` / ``decrypt`` and whole-keyvault
``export_backup`` / ``import_backup`` (plus their envelope/backup helpers and
wire constants) — are extracted into ``_secret_ops`` so ``api`` stays the
provisioning facade (key generation + seed display). The public surface is
preserved: ``api`` re-exports the four operations, so existing callers
(``from ...api import import_backup``, ``api.encrypt(...)``) are unchanged.

This pins the post-split surface; behavioural coverage stays in the existing
``test_keyvault_api_*`` suites (which call ``api.encrypt`` etc. — re-exported).
"""

from __future__ import annotations

import pytest

from mordred_hermes.keyvault import _secret_ops, api

#: Public operations that must live in the new module and stay re-exported by api.
_PUBLIC = ("encrypt", "decrypt", "export_backup", "import_backup")


@pytest.mark.parametrize("name", _PUBLIC)
def test_secret_ops_exposes_operation(name: str) -> None:
    assert hasattr(_secret_ops, name), f"_secret_ops must expose {name}"


@pytest.mark.parametrize("name", _PUBLIC)
def test_api_reexports_same_object(name: str) -> None:
    # Existing callers do `api.encrypt(...)` / `from ...api import import_backup`;
    # after the split api must surface the SAME object it now imports.
    assert getattr(api, name) is getattr(_secret_ops, name)


def test_public_ops_in_secret_ops_all() -> None:
    for name in _PUBLIC:
        assert name in _secret_ops.__all__
