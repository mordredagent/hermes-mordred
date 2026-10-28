"""Real checked provisioning scopes for native capability unit tests."""

import sys
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from mordred_hermes.keyvault import _native_key_id, _storage, wrap
from mordred_hermes.keyvault._seckey_helper import _HelperSecKeyOps


@contextmanager
def creation_scope(key_id, *, backend, root=None):
    from tests._platform_test_helpers import require_legacy_secret_store

    require_legacy_secret_store()
    with TemporaryDirectory(prefix="mordred-receipt-test-") as temporary:
        root = Path(temporary) / "mordred" / "keyvault" if root is None else root
        _storage.ensure_layout(root)
        for ops in (
            getattr(backend, "_ops", None),
            getattr(backend, "_sw_ops", None),
            getattr(backend, "_legacy_ops", None),
        ):
            if isinstance(ops, _HelperSecKeyOps):
                name, leaf = (
                    ("MORDRED_SEKEY_STORE", "sekey") if sys.platform == "darwin" else ("MORDRED_TPMKEY_STORE", "tpm")
                )
                ops._env_override = (name, str(root / leaf))
        with _storage.keyvault_custody(root, backend=backend) as custody:
            meta = _storage.load_meta(root)
            selector = _native_key_id.add_pending_native_key(root, meta, key_id)
            _storage.save_meta(root, meta)
            with wrap.create_wrapping_key_scope(
                key_id, backend=backend, custody=custody, native_key_id=selector
            ) as receipt:
                yield receipt
