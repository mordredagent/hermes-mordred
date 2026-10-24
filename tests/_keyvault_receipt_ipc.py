"""Subprocess-only software native store; every custody/producer path is real."""

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from mordred_hermes._database_contracts import DatabaseRefused
from mordred_hermes.keyvault import _native_key_id as ids
from mordred_hermes.keyvault import _storage, api, wrap
from mordred_hermes.keyvault._exceptions import WrapError
from mordred_hermes.keyvault._seckey_backend import _SecKeyBackend
from tests.test_keyvault_seckey_backend import _FakeOps


class SharedKeys:
    def __init__(self, root):
        self.root = root
        root.mkdir(mode=0o700, exist_ok=True)

    def path(self, tag):
        return self.root / tag.hex()

    def __contains__(self, tag):
        return self.path(tag).exists()

    def __getitem__(self, tag):
        return serialization.load_der_private_key(self.path(tag).read_bytes(), password=None)

    def __setitem__(self, tag, key):
        with self.path(tag).open("xb") as out:
            out.write(
                key.private_bytes(
                    serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                )
            )

    def pop(self, tag, default=None):
        self.path(tag).unlink(missing_ok=True)


def make_backend(home):
    ops = _FakeOps()
    ops._keys = SharedKeys(home / "native-store")
    return _SecKeyBackend(ops=ops, sw_ops=None, legacy_ops=None), ops


def send(value):
    print(json.dumps(value), flush=True)


def receive():
    value = sys.stdin.readline().strip()
    if not value:
        raise RuntimeError("IPC command missing")
    return value


def main(home, worker, role, stage):
    from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID
    from mordred_hermes.wizard import _keyvault_init as init

    backend, ops = make_backend(home)
    root = _storage.resolve_keyvault_dir(home)
    if worker == "B":
        send({"attempting": True})
    _storage.ensure_layout(root)
    logical = "default" if role == "main" else AUDIT_LOG_KEY_ID
    selector = ids.scoped_native_key_id(root, logical)
    if worker == "linux":
        from mordred_hermes.keyvault._memory_key import ensure_linux_memory_key

        ensure_linux_memory_key(home=home, backend=backend)
        send({"published": True})
        return
    if worker == "B":
        try:
            if role == "main":
                api._commit_key_state(
                    root,
                    key_id=logical,
                    key_id_hash_hex=wrap._key_id_hash(logical).hex(),
                    created_at="test",
                    verification_digest=b"d" * 32,
                    backend=backend,
                    unattended=True,
                )
            else:
                init._provision_audit_log_key_locked(root, backend, logical)
        except (DatabaseRefused, RuntimeError, ValueError, WrapError) as exc:
            send({"result": "refused", "kind": type(exc).__name__})
        else:
            send({"result": "published"})
        return
    if role == "audit":
        api._commit_key_state(
            root,
            key_id="default",
            key_id_hash_hex=wrap._key_id_hash("default").hex(),
            created_at="test",
            verification_digest=b"d" * 32,
            backend=backend,
            unattended=True,
        )
    with _storage.keyvault_custody(root, backend=backend) as custody:
        meta = _storage.load_meta(root)
        if role == "main":
            ids.add_pending_native_key(root, meta, logical)
        else:
            ids.add_pending_audit_key(root, meta, logical)
        _storage.save_meta(root, meta)
        if stage == "create-return":
            create = ops.create_keypair

            def paused_create(*args, **kwargs):
                public = create(*args, **kwargs)
                send({"paused": stage})
                receive()
                return public

            ops.create_keypair = paused_create
        with wrap.create_wrapping_key_scope(
            logical, backend=backend, custody=custody, native_key_id=selector
        ) as receipt:
            send({"ready": True, "public": receipt.public_key.hex()})
            action = receive()
            if action == "rollback":
                if stage == "rollback-lookup":
                    copy = ops.copy_public_key

                    def paused_copy(tag):
                        public = copy(tag)
                        send({"paused": stage})
                        receive()
                        return public

                    ops.copy_public_key = paused_copy
                wrap.rollback_created_key(receipt)
                meta = _storage.load_meta(root)
                meta.pop(ids.PENDING_NATIVE_KEY_FIELD if role == "main" else ids.PENDING_AUDIT_KEY_FIELD)
                _storage.save_meta(root, meta)
            elif action == "commit":
                if role == "main":
                    key_hash = wrap._key_id_hash(logical).hex()
                    _storage.atomic_write(root / "digests" / (key_hash + ".commit"), b"d" * 32)
                    meta["keys"][key_hash] = {"key_id": logical, ids.NATIVE_KEY_ID_FIELD: selector}
                else:
                    ids.add_committed_audit_key(root, meta, logical, selector)
                _storage.save_meta(root, meta)
                wrap.commit_created_key(receipt)
                meta.pop(ids.PENDING_NATIVE_KEY_FIELD if role == "main" else ids.PENDING_AUDIT_KEY_FIELD)
                _storage.save_meta(root, meta)
    before = sum(command == "delete" for command, _ in ops.calls)
    try:
        wrap.rollback_created_key(receipt)
    except DatabaseRefused:
        send(
            {"old_rollback": "refused", "native_deletes": sum(command == "delete" for command, _ in ops.calls) - before}
        )
    else:
        raise AssertionError("old receipt survived unlock")


if __name__ == "__main__":
    main(Path(sys.argv[1]), *sys.argv[2:])
