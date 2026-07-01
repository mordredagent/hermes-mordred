# mordred_keyvault

Secure Enclave-backed key management. macOS Apple Silicon **or T2 Intel** (`pip install mordred-hermes[macos]`). Capability is determined by a runtime probe rather than chip-class checking — `is_secure_enclave_available()` returns False on Linux / Windows without ever loading pyobjc (codex review MEDIUM-1).

## Owned filesystem paths (see `docs/dev/PATHS.md`)

- `~/.hermes/mordred/keyvault/` — wrapped DEKs, backup blobs, digest cache (Phase 4 owner; sole writer + reader)

## Status (per Phase 4 PR)

| File | PR | Status | Notes |
| --- | --- | --- | --- |
| `crypto.py` | PR1 (#21) | **landed** | AES-GCM encrypt/decrypt, AES-128/192/256, `secrets.token_bytes(12)` nonce |
| `digest.py` | PR2 (#23) | **landed** | BLAKE3 `H(seed_hash \|\| (pass_hash ⊕_top4 PoW))`; canonical SPEC vector in tests |
| `backup.py` | PR2 (#23) | **landed** | Argon2id (m=46 MiB, t=1, p=1) → AES-GCM with `b"MRKV"` self-describing wire format + AAD-bound header; DOS-guarded KDF params |
| `recovery.py` | PR2 (#23) | **landed** | Verify-before-decrypt: digest mismatch raises before any KDF / AES work |
| `_exceptions.py` | PR3 (this) | **landed** | `WrapError` base + 5 sibling subclasses (Parse, Integrity, NativeUnavailable, AuthCancelled, KeyNotFound) — codex NIT-1 split of the originally-proposed single `WrapAuthFailed` |
| `native.py` | PR3 (this) | **landed** | Lazy `Security.framework` boundary; `_lazy_import_security()` (cached, non-Darwin short-circuit), `is_secure_enclave_available()` (infallible capability probe) |
| `wrap.py` | PR3 (this) | **landed** | DEK wrap/unwrap via raw P-256 ECDH + HKDF-SHA256 + AES-KW (RFC 3394); `NativeBackend` Protocol for Keychain/SecKey ops only (HKDF/AES-KW/wire parsing in pure Python, tested with real crypto) |
| `api.py` | PR4 | placeholder | Public Python API (generate / encrypt / decrypt / export_backup / import_backup / verify_digest); BIP39 Unicode normalization gates here; production `_SecKeyBackend` (pyobjc) lands with this PR |
| `seed_display.py` | PR7 | **landed** | `display_seed()` orchestrator: blackout assert → M4 banner → screenshot pre-check → `SeedDisplayHandle.consume()` → 60s monotonic timer + capture polling → auto-clear; `_default_capture_probe` wraps macOS `CGScreenIsBeingCaptured` (best-effort, fails open); `SeedDisplaySurface` Protocol abstracts rendering |
| `network_fallback.py` | PR5 | **landed** | OS-API blackout fallback: `resolve_blackout_assert()` delegates to `mordred_network` when importable, else probes macOS `SCNetworkReachability` (pyobjc, lazy import); `blackout_assert` fails closed when the probe cannot run |
| `log_encryption.py` | PR6 | **landed** | `EncryptedWriter` (Phase 1 `Writer` Protocol) + `decrypt_log_file`; `MRAL` v1 line-oriented AES-GCM wire format, keyvault-wrapped DEK in the header, per-entry AAD bound to `SHA-256(header)` |
| `extension_sign.py` | #204 | **landed, unreachable** | `personal_sign` / `sign_typed_data_v4` / `sign_transaction` for the browser extension. Pure Python API — no `gateway` import — but nothing in this repo calls it yet: the caller is the gateway WebSocket server, which lives in the Hermes-fork counterpart to this plugin and isn't published alongside `mordred-hermes` (see `docs/dev/ROADMAP.md` §"Browser-extension gateway counterpart (deferred)"). Requires the `ethereum` extra. |

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

## Wrap wire format & algorithm (Phase 4 PR3, frozen 2026-05-14)

`wrap.wrap_dek(dek, key_id, *, backend)` produces a 127-byte self-describing blob:

```
magic(4) = "MRKW"  |  version(1) = 1  |  alg_suite(1) = 1
key_id_hash(16)    |  ephemeral_pub(65)  |  wrapped_dek(40)
```

- `alg_suite = 1` = `(P256_ECDH_RAW, HKDF_SHA256, AES256_KW_RFC3394)`.
- `key_id_hash` = first 16 bytes of `SHA-256(key_id)` — never the cleartext id.
- `ephemeral_pub` = SEC1 uncompressed P-256 (`0x04 ‖ X ‖ Y`), freshly generated per call (wrap is non-deterministic).
- `wrapped_dek` = 40-byte RFC 3394 AES-KW output for a 32-byte DEK (the 8-byte AIV is internal, **no separate IV field**; codex review BLOCKER-2).

HKDF-SHA256 derives the 32-byte AES-KEK with `salt = b""` and `info = magic ‖ version ‖ alg_suite ‖ key_id_hash ‖ ephemeral_pub` (87 bytes). The `info` parameter binds every non-secret blob field to the KEK, so a tampered byte produces a different KEK → AES-KW AIV check fails → `WrapIntegrityError`. This is the integrity story for AES-KW, which lacks AAD natively (codex review HIGH-2).

**Wrap is offline.** It uses the Enclave **public** key + a software ephemeral private key. No `SecKeyCopyKeyExchangeResult` call, no biometric prompt, no audit emit. Two wraps of the same `(dek, key_id)` produce different blobs.

**Unwrap is authorized.** It calls `backend.enclave_ecdh(key_id, ephemeral_pub)` which on macOS routes to `SecKeyCopyKeyExchangeResult` and may prompt for Touch ID / Optic ID / device passcode (codex review BLOCKER-1 / HIGH-3 corrected the original plan: only unwrap is authorized, not wrap). Each invocation emits exactly one audit entry:

| Outcome | Audit reason | Decision |
| --- | --- | --- |
| ECDH succeeds → DEK recovered | `keyvault.unwrap_authorized` | `allow` |
| Enclave returns `errSec*` | `keyvault.unwrap_denied` | `block` |

`native_error_code` on denial is a translated string (`user_cancelled` / `auth_failed` / `biometry_lockout` / `passcode_not_set` / `key_not_found`) — never the raw `OSStatus` integer.

## Exception taxonomy (Codex review NIT-1)

`mordred_hermes.keyvault._exceptions.WrapError` is the base. Five sibling subclasses (not a chain) let callers handle failures by category:

- `WrapParseError` — malformed blob (length, magic, version, alg_suite, key_id_hash mismatch, invalid EC point). Surface BEFORE any Enclave call — UX + privacy (no biometric prompt for malformed input).
- `WrapIntegrityError` — AES-KW AIV check failed (tampered `ephemeral_pub` or `wrapped_dek`).
- `WrapNativeUnavailable` — `Security.framework` not reachable; chains `ImportError` via `__cause__` on macOS without pyobjc, no chain on non-Darwin.
- `WrapAuthCancelled` — user denied the access-control prompt; chains the `NativeBackendError` via `__cause__` and (if `audit_sink` itself raised during the denial emit) the sink exception via `__context__` (mirrors PR2 `recovery._emit_mismatch` HIGH-1 fix).
- `WrapKeyNotFound` — Keychain has no item for `key_id` (never generated, deleted, wrong device, or biometry-change invalidation — the four cases are deliberately indistinguishable to avoid leaking biometric-state changes).

## Verify-before-decrypt (Codex review #4)

`recovery.import_backup(blob, passphrase, *, recomputed_digest, audit_sink=None)`:

1. Length-confusion guard on `recomputed_digest` (must be 32 bytes) — reject upfront.
2. `backup.parse_header(blob)` — structural validation only; no KDF, no AES.
3. Constant-time compare via `hmac.compare_digest` between `parsed.verification_digest` and `recomputed_digest`. On mismatch: optional audit emit → raise `RecoveryDigestMismatch`.
4. Only on match: `backup.decrypt_body(parsed, passphrase)` runs Argon2id + AES-GCM. `InvalidTag` (wrong passphrase / AAD tamper) propagates.

The secret is **never materialized** on digest mismatch — asserted by explosive-spy tests on both `backup.decrypt_body` and `argon2.low_level.hash_secret_raw`.

## See also

- `docs/dev/SPEC.md` §Plugin: `mordred_keyvault` — key hierarchy, digest algorithm canonical form, Seed display security caveats (M4 / M5); §Backup wire format versioning (PR2); §Wrap wire format & algorithm (PR3) for the full byte layout, algorithm steps, and `kSec*` access-control attributes
- `docs/dev/POLICY.md` §Phase 4 step-0 freeze (PR2) — `keyvault.recovery_digest_mismatch` and `keyvault.seed_display_aborted_screenshot`; §Phase 4 PR3 step-0 freeze — `keyvault.unwrap_authorized` and `keyvault.unwrap_denied`
- `docs/dev/TODO.md` §4.1 — implementation checklist
