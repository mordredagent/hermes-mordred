# mordred_keyvault

Secure Enclave-backed key management. macOS Apple Silicon only (`pip install mordred-hermes[macos]`).

## Owned filesystem paths (see `mordred-docs/mordred/PATHS.md`)

- `~/.hermes/mordred/keyvault/` — wrapped DEKs, backup blobs, digest cache (Phase 4 owner; sole writer + reader)

## Phase 0 status

Scaffold only. `register(ctx)` is a no-op. Phase 4.1 wires:
- `native.py` (`Security.framework` lazy import via `pyobjc-framework-Security`; macOS-gated)
- `api.py` (generate / encrypt / decrypt / export_backup / import_backup / verify_digest)
- `crypto.py` AES-GCM (`cryptography`)
- `wrap.py` Secure Enclave wrapping-key
- `backup.py` Argon2id (m=46 MiB, t=1, p=1) + 16-byte salt + verification digest
- `recovery.py` digest mismatch reject
- `digest.py` BLAKE3 `hash(hash(SeedPhrase), hash(Passphrase) ⊕ top4(PoW))`
- `seed_display.py` (blackout assert → 60s monotonic timer → display → auto-clear; M5 capture detection)
- `network_fallback.py` (OS API direct fallback when `mordred_network` absent)
- `log_encryption.py` (Phase 1 audit `Writer` interface slot-in for AES-GCM)

See `mordred-docs/mordred/SPEC.md` §Plugin: `mordred_keyvault` and TODO §4.1.
