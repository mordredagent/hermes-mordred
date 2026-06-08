"""RED tests for Phase 4 PR8: ``hermes mordred keyvault {list,verify-digest}``.

SPEC.md §4.2 / TODO.md §4.2 L429-430. These are the **backend-free**
keyvault CLI commands — they only read the on-disk keyvault layout
(``meta.json`` + ``digests/<hash>.commit``) and need no Secure Enclave
``NativeBackend``:

- ``keyvault list`` — list key ids (no key material).
- ``keyvault verify-digest`` — re-display the full verification digest
  of each key for offline cross-checking.

``keyvault init`` / ``keyvault recover`` (and ``audit decrypt``) need the
production ``NativeBackend`` and are deferred to a later PR.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any

import pytest

from mordred_hermes.keyvault import _bip39, _storage, api
from mordred_hermes.keyvault import digest as kvdigest
from mordred_hermes.keyvault import pow as kvpow
from mordred_hermes.keyvault.network_fallback import BlackoutNotAsserted
from mordred_hermes.wizard import keyvault_cli
from tests._keyvault_fakes import FakeBackend


def _key_id_hash(key_id: str) -> str:
    """On-disk key-id hash — ``SHA-256(key_id)[:16].hex()`` (api._hash_id)."""
    return hashlib.sha256(key_id.encode("utf-8")).digest()[:16].hex()


def _build_keyvault(home: Path, keys: dict[str, bytes]) -> Path:
    """Materialize a keyvault under ``home`` with the given ``{key_id: digest}``.

    Returns the keyvault root. Each digest is a 32-byte verification
    digest written to ``digests/<hash>.commit`` exactly as confirm_generate
    would; the ``meta.json`` row carries the cleartext ``key_id``.
    """
    root = _storage.resolve_keyvault_dir(home)
    _storage.ensure_layout(root)
    meta = _storage.load_meta(root)
    for key_id, digest in keys.items():
        h = _key_id_hash(key_id)
        meta["keys"][h] = {"key_id": key_id, "created_at": "2026-05-16T00:00:00Z"}
        _storage.atomic_write(root / "digests" / f"{h}.commit", digest)
    _storage.save_meta(root, meta)
    return root


# ---------------------------------------------------------------------------
# keyvault list
# ---------------------------------------------------------------------------


class TestList:
    def test_empty_keyvault_reports_no_keys(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _storage.ensure_layout(_storage.resolve_keyvault_dir(tmp_path))
        rc = keyvault_cli.list_keys(home=tmp_path)
        assert rc == 0
        assert "no keys" in capsys.readouterr().out.lower()

    def test_absent_keyvault_dir_reports_no_keys(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        # No ensure_layout — the keyvault has never been initialised.
        rc = keyvault_cli.list_keys(home=tmp_path)
        assert rc == 0
        assert "no keys" in capsys.readouterr().out.lower()

    def test_lists_each_key_id_and_hash(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _build_keyvault(tmp_path, {"default": b"\x11" * 32, "payments": b"\x22" * 32})
        rc = keyvault_cli.list_keys(home=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert "default" in out
        assert "payments" in out
        assert _key_id_hash("default") in out
        assert "2026-05-16T00:00:00Z" in out

    def test_list_does_not_leak_key_material(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """``list`` must not print the verification digest (key material)."""
        _build_keyvault(tmp_path, {"default": b"\xab" * 32})
        keyvault_cli.list_keys(home=tmp_path)
        assert (b"\xab" * 32).hex() not in capsys.readouterr().out

    def test_cli_list_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """cli_list(args) delegates to list_keys against the resolved home."""
        _build_keyvault(tmp_path, {"default": b"\x11" * 32})
        monkeypatch.setattr(keyvault_cli, "_hermes_home", lambda: tmp_path)
        assert keyvault_cli.cli_list(argparse.Namespace()) == 0


# ---------------------------------------------------------------------------
# keyvault verify-digest
# ---------------------------------------------------------------------------


class TestVerifyDigest:
    def test_no_keys_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _storage.ensure_layout(_storage.resolve_keyvault_dir(tmp_path))
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 1
        assert "no keys" in capsys.readouterr().err.lower()

    def test_displays_full_digest_hex(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        digest = bytes(range(32))
        _build_keyvault(tmp_path, {"default": digest})
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert digest.hex() in out  # full 64-hex digest, not a prefix
        assert "default" in out

    def test_displays_every_key(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32, "payments": b"\x02" * 32})
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 0
        out = capsys.readouterr().out
        assert (b"\x01" * 32).hex() in out
        assert (b"\x02" * 32).hex() in out

    def test_missing_commit_file_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A meta row whose digests/<hash>.commit is gone is surfaced, not crashed."""
        root = _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        (root / "digests" / f"{_key_id_hash('default')}.commit").unlink()
        rc = keyvault_cli.verify_digest(home=tmp_path)
        assert rc == 1
        combined = capsys.readouterr()
        assert "default" in (combined.out + combined.err)

    def test_cli_verify_digest_adapter_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _build_keyvault(tmp_path, {"default": b"\x09" * 32})
        monkeypatch.setattr(keyvault_cli, "_hermes_home", lambda: tmp_path)
        assert keyvault_cli.cli_verify_digest(argparse.Namespace()) == 0


# ---------------------------------------------------------------------------
# keyvault recover (Phase 4 PR10 step-C)
# ---------------------------------------------------------------------------


class ScriptedPromptIO:
    """Test :class:`~mordred_hermes.wizard.configure.PromptIO` — no TTY.

    ``text`` / ``password`` give a single fixed answer to every
    ``ask_text`` / ``ask_password`` call. ``texts`` / ``passwords`` give
    a queue popped in order (needed for the init flow, which asks for the
    Passphrase twice and then the digest).
    """

    def __init__(
        self,
        *,
        text: str = "",
        password: str = "",
        texts: list[str] | None = None,
        passwords: list[str] | None = None,
    ) -> None:
        self._text = text
        self._password = password
        self._texts = list(texts) if texts is not None else None
        self._passwords = list(passwords) if passwords is not None else None

    def ask_choice(self, label: str, choices: Any, default: str) -> str:
        return default

    def ask_text(self, label: str, default: str = "") -> str:
        if self._texts is not None:
            return self._texts.pop(0)
        return self._text

    def ask_bool(self, label: str, default: bool) -> bool:
        return default

    def ask_password(self, label: str, default: str = "") -> str:
        if self._passwords is not None:
            return self._passwords.pop(0)
        return self._password


class FakeSurface:
    """No-op :class:`~mordred_hermes.keyvault.seed_display.SeedDisplaySurface`."""

    def __init__(self) -> None:
        self.shown: list[str] = []

    def banner(self, message: str) -> None:
        return None

    def show(self, seed: str) -> None:
        self.shown.append(seed)

    def clear(self) -> None:
        return None


def _sink() -> Any:
    """A throwaway audit sink (the CLI tests do not assert on audit entries)."""

    def append(entry: dict[str, Any]) -> None:
        return None

    return append


# A valid 24-word BIP39 phrase + passphrase used across recover tests.
RECOVER_SEED = _bip39.entropy_to_mnemonic(bytes(range(32)))
RECOVER_PASS = "correct horse battery staple"


@pytest.fixture
def _fast_pow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Lower PoW difficulty so recover tests stay sub-second.

    PoW is deterministic in the seed at any difficulty, so a blob built
    and recovered under the same lowered difficulty round-trips cleanly.
    """
    monkeypatch.setattr(kvpow, "POW_DIFFICULTY_BITS", 4)


def _make_backup_blob(home: Path, backend: FakeBackend) -> bytes:
    """Build a real export blob on a 'device A' rooted at ``home``."""
    pow_bytes = kvpow.compute_pow(api._normalize_seed_phrase(RECOVER_SEED), difficulty_bits=kvpow.POW_DIFFICULTY_BITS)
    _handle, digest = api.prepare_generate(RECOVER_SEED, RECOVER_PASS, pow_bytes)
    result = api.generate(RECOVER_SEED, RECOVER_PASS, pow_bytes, digest, backend=backend, audit_sink=_sink(), home=home)
    api.encrypt(result.key_id, b"the-secret", "vault", backend=backend, audit_sink=_sink(), home=home)
    return api.export_backup(result.key_id, RECOVER_PASS, backend=backend, audit_sink=_sink(), home=home)


class TestRecover:
    def test_missing_blob_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = keyvault_cli.recover(
            blob_path=tmp_path / "nope.mrkv",
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(text=RECOVER_SEED, password=RECOVER_PASS),
        )
        assert rc == 1
        assert "nope.mrkv" in capsys.readouterr().err

    def test_bad_seed_checksum_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        blob_file = tmp_path / "b.mrkv"
        blob_file.write_bytes(b"unused")
        bad_seed = " ".join(["abandon"] * 24)  # 24 words but an invalid BIP39 checksum
        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(text=bad_seed, password=RECOVER_PASS),
        )
        assert rc == 1
        assert "seed" in capsys.readouterr().err.lower()

    def test_corrupt_blob_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str], _fast_pow: None) -> None:
        blob_file = tmp_path / "b.mrkv"
        blob_file.write_bytes(b"not-a-real-MRKV-blob" * 8)
        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(text=RECOVER_SEED, password=RECOVER_PASS),
        )
        assert rc == 1
        assert "corrupt" in capsys.readouterr().err.lower()

    def test_recover_roundtrip(self, tmp_path: Path, capsys: pytest.CaptureFixture[str], _fast_pow: None) -> None:
        blob = _make_backup_blob(tmp_path / "a", FakeBackend())
        blob_file = tmp_path / "backup.mrkv"
        blob_file.write_bytes(blob)

        home_b = tmp_path / "b"
        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=home_b,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(text=RECOVER_SEED, password=RECOVER_PASS),
        )
        assert rc == 0
        assert "recovered" in capsys.readouterr().out.lower()
        meta = _storage.load_meta(_storage.resolve_keyvault_dir(home_b))
        assert meta["keys"]  # the imported key landed on device B

    def test_wrong_passphrase_returns_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], _fast_pow: None
    ) -> None:
        blob = _make_backup_blob(tmp_path / "a", FakeBackend())
        blob_file = tmp_path / "backup.mrkv"
        blob_file.write_bytes(blob)

        rc = keyvault_cli.recover(
            blob_path=blob_file,
            home=tmp_path / "b",
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(text=RECOVER_SEED, password="wrong passphrase"),
        )
        assert rc == 1
        assert "mis-transcribed" in capsys.readouterr().err.lower()

    def test_cli_recover_adapter_delegates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, Path] = {}

        def fake(*, blob_path: Path) -> int:
            seen["blob_path"] = blob_path
            return 0

        monkeypatch.setattr(keyvault_cli, "recover", fake)
        assert keyvault_cli.cli_recover(argparse.Namespace(blob="/tmp/x.mrkv")) == 0
        assert str(seen["blob_path"]) == "/tmp/x.mrkv"


# ---------------------------------------------------------------------------
# keyvault init (Phase 4 PR10 step-D)
# ---------------------------------------------------------------------------


class TestInit:
    """``hermes mordred keyvault init`` orchestration.

    ``display_fn`` is injected so the tests never run the full 60s
    Seed-display flow (that flow is covered by test_keyvault_seed_display).
    The PoW difficulty is lowered and the mnemonic pinned so the test can
    precompute the verification digest the operator "transcribes" back.
    """

    FIXED_SEED = _bip39.entropy_to_mnemonic(bytes(range(1, 33)))
    PASSPHRASE = "my secret passphrase"

    @pytest.fixture(autouse=True)
    def _patches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(kvpow, "POW_DIFFICULTY_BITS", 4)
        monkeypatch.setattr(_bip39, "generate_mnemonic", lambda: self.FIXED_SEED)

    def _expected_digest(self) -> bytes:
        norm_seed = api._normalize_seed_phrase(self.FIXED_SEED)
        pow_bytes = kvpow.compute_pow(norm_seed, difficulty_bits=4)
        return kvdigest.compute_digest(norm_seed, api._normalize_passphrase(self.PASSPHRASE), pow_bytes)

    def _noop_display(self, handle: object, surface: object) -> None:
        return None

    def test_already_initialised_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        _build_keyvault(tmp_path, {"default": b"\x01" * 32})
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[self.PASSPHRASE, self.PASSPHRASE]),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert "already" in capsys.readouterr().err.lower()

    def test_passphrase_mismatch_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=["pass-a", "pass-b"]),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert "match" in capsys.readouterr().err.lower()

    def test_empty_passphrase_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=["", ""]),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert "empty" in capsys.readouterr().err.lower()

    def test_blackout_failure_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        def refuse(handle: object, surface: object) -> None:
            raise BlackoutNotAsserted("host is still reachable")

        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[self.PASSPHRASE, self.PASSPHRASE]),
            surface=FakeSurface(),
            display_fn=refuse,
        )
        assert rc == 1
        err = capsys.readouterr().err.lower()
        assert "disconnect" in err or "network" in err
        assert not _storage.load_meta(_storage.resolve_keyvault_dir(tmp_path))["keys"]

    def test_bad_digest_hex_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(texts=["not-hex-zz"], passwords=[self.PASSPHRASE, self.PASSPHRASE]),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert "hex" in capsys.readouterr().err.lower()

    def test_digest_mismatch_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(texts=["00" * 32], passwords=[self.PASSPHRASE, self.PASSPHRASE]),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert "mismatch" in capsys.readouterr().err.lower()
        assert not _storage.load_meta(_storage.resolve_keyvault_dir(tmp_path))["keys"]

    def test_init_success(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 0
        assert "initialised" in capsys.readouterr().out.lower()
        meta = _storage.load_meta(_storage.resolve_keyvault_dir(tmp_path))
        assert meta["keys"]

    def test_cli_init_adapter_delegates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def fake(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_cli, "init_keyvault", fake)
        assert keyvault_cli.cli_init(argparse.Namespace()) == 0
        assert captured["store_seed_for_hd"] is True

    def test_cli_init_forwards_store_seed_for_hd_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def fake(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_cli, "init_keyvault", fake)
        keyvault_cli.cli_init(argparse.Namespace(store_seed_for_hd=True))
        assert captured.get("store_seed_for_hd") is True

    def test_cli_init_forwards_paper_only_opt_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def fake(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        monkeypatch.setattr(keyvault_cli, "init_keyvault", fake)
        keyvault_cli.cli_init(argparse.Namespace(store_seed_for_hd=False))
        assert captured.get("store_seed_for_hd") is False

    def test_init_provisions_audit_log_wrapping_key(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """init must also generate the audit-log wrapping key so the L465
        encrypted-audit factory can engage afterward."""
        from mordred_hermes.keyvault.log_encryption import AUDIT_LOG_KEY_ID

        backend = FakeBackend()
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=backend,
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 0
        assert ("generate", AUDIT_LOG_KEY_ID) in backend.calls

    def test_init_store_seed_for_hd_persists_seed_and_derives(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """init with store_seed_for_hd=True SE-encrypts the seed and lets the
        HD wallet derive deterministic Ethereum accounts from it afterward."""
        # eth_keys (optional `ethereum` extra) is required only by this HD test;
        # skip just this case when it is absent rather than the whole module.
        pytest.importorskip("eth_keys")
        import hashlib

        from eth_keys import keys

        from mordred_hermes.keyvault import _bip32, _bip39
        from mordred_hermes.keyvault.ethereum import _SEED_PURPOSE, derive_ethereum_key

        backend = FakeBackend()
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=backend,
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
            store_seed_for_hd=True,
        )
        assert rc == 0

        # The seed is now stored SE-encrypted under bip39.seed.v1.
        root = _storage.resolve_keyvault_dir(tmp_path)
        purpose_hash_hex = hashlib.sha256(_SEED_PURPOSE.encode()).digest()[:16].hex()
        seed_envs = list((root / "ciphertexts").rglob(f"{purpose_hash_hex}/*.gcm"))
        assert len(seed_envs) == 1
        seed_env_id = seed_envs[0].stem

        # Deriving via the stored seed must match an independent derivation
        # from the same (fixed) mnemonic — proving the round-trip is correct.
        addr, path = derive_ethereum_key("default", seed_env_id, 0, backend=backend, audit_sink=_sink(), home=tmp_path)
        expected_priv = _bip32.derive_path(_bip39.mnemonic_to_seed(self.FIXED_SEED), "m/44'/60'/0'/0/0")
        expected_addr = keys.PrivateKey(expected_priv).public_key.to_checksum_address()
        assert addr == expected_addr
        assert path == "m/44'/60'/0'/0/0"

    def test_init_default_stores_seed(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Default init stores the seed SE-encrypted for later HD use."""
        import hashlib

        from mordred_hermes.keyvault.ethereum import _SEED_PURPOSE

        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 0
        root = _storage.resolve_keyvault_dir(tmp_path)
        purpose_hash_hex = hashlib.sha256(_SEED_PURPOSE.encode()).digest()[:16].hex()
        assert len(list((root / "ciphertexts").rglob(f"{purpose_hash_hex}/*.gcm"))) == 1

    def test_init_paper_only_does_not_store_seed(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Explicit paper-only init must NOT persist the seed at rest."""
        import hashlib

        from mordred_hermes.keyvault.ethereum import _SEED_PURPOSE

        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
            store_seed_for_hd=False,
        )
        assert rc == 0
        root = _storage.resolve_keyvault_dir(tmp_path)
        purpose_hash_hex = hashlib.sha256(_SEED_PURPOSE.encode()).digest()[:16].hex()
        assert not list((root / "ciphertexts").rglob(f"{purpose_hash_hex}/*.gcm"))

    def test_init_store_seed_does_not_unwrap(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """Storing the seed at init time is offline (wrap uses the public key).

        init must NOT perform an Enclave ECDH/unwrap, which on a real device
        would force a Touch ID / passcode prompt at the end of init.
        """
        backend = FakeBackend()
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=backend,
            prompt_io=ScriptedPromptIO(
                texts=[self._expected_digest().hex()],
                passwords=[self.PASSPHRASE, self.PASSPHRASE],
            ),
            surface=FakeSurface(),
            display_fn=self._noop_display,
            store_seed_for_hd=True,
        )
        assert rc == 0
        assert not any(call[0] == "ecdh" for call in backend.calls)

    def test_corrupt_keyvault_meta_returns_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """A corrupt meta.json must surface a clean error, not a traceback."""
        root = _storage.resolve_keyvault_dir(tmp_path)
        _storage.ensure_layout(root)
        (root / "meta.json").write_text("{ not valid json", encoding="utf-8")
        rc = keyvault_cli.init_keyvault(
            home=tmp_path,
            backend=FakeBackend(),
            prompt_io=ScriptedPromptIO(passwords=[self.PASSPHRASE, self.PASSPHRASE]),
            surface=FakeSurface(),
            display_fn=self._noop_display,
        )
        assert rc == 1
        assert "corrupt" in capsys.readouterr().err.lower()
