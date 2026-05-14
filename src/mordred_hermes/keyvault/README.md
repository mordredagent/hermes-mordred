# mordred_keyvault

Secure Enclave-backed key management. macOS Apple Silicon only (`pip install mordred-hermes[macos]`).

## Owned filesystem paths (see `mordred-docs/mordred/PATHS.md`)

- `~/.hermes/mordred/keyvault/` — wrapped DEKs, backup blobs, digest cache (Phase 4 owner; sole writer + reader)

## Status (per Phase 4 PR)

| File | PR | Status | Notes |
| --- | --- | --- | --- |
| `crypto.py` | PR1 (#21) | **landed** | AES-GCM encrypt/decrypt, AES-128/192/256, `secrets.token_bytes(12)` nonce |
| `digest.py` | PR2 (this) | **landed** | BLAKE3 `H(seed_hash \|\| (pass_hash ⊕_top4 PoW))`; canonical SPEC vector in tests |
| `backup.py` | PR2 (this) | **landed** | Argon2id (m=46 MiB, t=1, p=1) → AES-GCM with `b"MRKV"` self-describing wire format + AAD-bound header; DOS-guarded KDF params |
| `recovery.py` | PR2 (this) | **landed** | Verify-before-decrypt: digest mismatch raises before any KDF / AES work |
| `native.py` | PR3 | placeholder | `Security.framework` lazy import via `pyobjc-framework-Security` |
| `wrap.py` | PR3 | placeholder | Secure Enclave-backed wrapping key |
| `api.py` | PR4 | placeholder | Public Python API (generate / encrypt / decrypt / export_backup / import_backup / verify_digest); BIP39 Unicode normalization gates here |
| `seed_display.py` | PR4 | placeholder | Blackout assert → 60s monotonic timer → display → auto-clear; M5 capture detection |
| `network_fallback.py` | PR4 | placeholder | OS API direct fallback when `mordred_network` absent |
| `log_encryption.py` | PR4 | placeholder | Phase 1 audit `Writer` interface slot-in for AES-GCM |

`register(ctx)` remains a no-op until Phase 4 PR4 wires the public surface to Hermes.

## Wire format (Phase 4 PR2 baseline, frozen 2026-05-14)

`backup.export` produces a self-describing blob whose entire header is bound to the AES-GCM ciphertext via AAD, so any header tampering trips `InvalidTag` at decrypt time:

```
magic(4) = "MRKV"  |  version(1) = 1  |  kdf_id(1) = 1 (Argon2id)
m_cost(4 BE)       |  t_cost(4 BE)    |  p_cost(4 BE)
salt(16)           |  verification_digest(32)
aes_blob_len(4 BE) |  aes_blob = nonce(12) || ciphertext || tag(16)
```

AAD = `magic || version || kdf_id || m_cost || t_cost || p_cost || salt || verification_digest` (66 bytes).

DOS guards in `parse_header` (Phase 4 PR2 integration finding, **not** in the original Codex review): tampered cost-param bytes can otherwise convince `decrypt_body` to request 16 GiB Argon2 allocations. We cap `m_cost ≤ 1 GiB`, `t_cost ≤ 64`, `p_cost ≤ 16` and reject any value ≤ 0; the header-level reject precedes the KDF call.

## Verify-before-decrypt (Codex review #4)

`recovery.import_backup(blob, passphrase, *, recomputed_digest, audit_sink=None)`:

1. Length-confusion guard on `recomputed_digest` (must be 32 bytes) — reject upfront.
2. `backup.parse_header(blob)` — structural validation only; no KDF, no AES.
3. Constant-time compare via `hmac.compare_digest` between `parsed.verification_digest` and `recomputed_digest`. On mismatch: optional audit emit → raise `RecoveryDigestMismatch`.
4. Only on match: `backup.decrypt_body(parsed, passphrase)` runs Argon2id + AES-GCM. `InvalidTag` (wrong passphrase / AAD tamper) propagates.

The secret is **never materialized** on digest mismatch — asserted by explosive-spy tests on both `backup.decrypt_body` and `argon2.low_level.hash_secret_raw`.

## See also

- `mordred-docs/mordred/SPEC.md` §Plugin: `mordred_keyvault` — key hierarchy, digest algorithm canonical form, Seed display security caveats (M4 / M5)
- `mordred-docs/mordred/POLICY.md` §Phase 4 step-0 freeze — `keyvault.recovery_digest_mismatch` and `keyvault.seed_display_aborted_screenshot` reason codes
- `mordred-docs/mordred/TODO.md` §4.1 — implementation checklist
