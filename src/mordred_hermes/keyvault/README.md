# mordred_keyvault

Hardware-backed key management, encrypted file storage, backup and recovery,
audit-log encryption, and extension wallet signing.

macOS uses Secure Enclave when available and can fall back to a software P-256
key in the login Keychain. Linux uses the packaged TPM 2.0 helper and fails
closed when the helper is unavailable. Platform modules are loaded lazily, so
capability probes do not import macOS-only dependencies on other systems.

Install native helpers with:

```bash
hermes-mordred keyvault enable-se   # macOS
hermes-mordred keyvault enable-tpm  # Linux
```

## Owned filesystem paths (see `docs/dev/PATHS.md`)

- `~/.hermes/mordred/keyvault/` — wrapped keys, envelopes, backup manifests,
  verification digests, and encrypted vault state
- `~/.hermes/mordred/.keyvault.lifecycle.lock` — serialized lifecycle changes
- `~/.hermes/mordred/.keyvault.reset.json` and `.keyvault.generation` — reset
  and generation coordination

See [PATHS.md](../../../docs/dev/PATHS.md) for permissions and ownership.

## Status (per Phase 4 PR)

The historical heading is retained for existing links. All listed surfaces are
current:

| Surface | Purpose |
| --- | --- |
| `api.py` | Generate keys, encrypt/decrypt envelopes, verify digests, and export/import recoverable backups. |
| `wrap.py` and native backends | Hardware-backed DEK wrapping and authorized unwrapping. |
| `vault.py` and `file_container.py` | Versioned encrypted file store used by at-rest protection. |
| `log_encryption.py` | Process-safe `MRAL` encrypted audit writer and decryptor. |
| `seed_display.py` | Time-limited Seed Phrase display under a network blackout. |
| `extension_sign.py` | Ethereum account and transaction signing for the extension; requires the `ethereum` extra. |

At plugin registration, keyvault installs transparent environment decryption,
the host `.env` write guard, sibling-integrity checks, and best-effort
session-boundary resealing. Crypto APIs are called explicitly by the wizard and
extension rather than exposed as Hermes hooks.

## Wire format (Phase 4 PR2 baseline, frozen 2026-05-14)

`MRKV` v1 is the recoverable backup format. Its header carries the Argon2id
profile, salt, verification digest, and AES payload length; the complete header
is authenticated as AES-GCM AAD. Parsers reject duplicate, non-canonical, and
out-of-range KDF parameters before allocating KDF memory.

The frozen v1 Argon2id profile is 46 MiB memory, one iteration, and one lane.
Breaking layout changes require a new version.

## Wrap wire format & algorithm (Phase 4 PR3, frozen 2026-05-14)

`MRKW` v1 is a 127-byte DEK-wrap blob:

```text
magic + version + algorithm + key_id_hash + ephemeral P-256 public key + wrapped DEK
```

Wrapping uses P-256 ECDH, HKDF-SHA256, and RFC 3394 AES-256-KW. It needs only
the hardware key's public half and therefore does not prompt. Unwrapping invokes
the native private-key operation, may require biometric or device
authorization, and emits exactly one allow or deny audit event.

## Exception taxonomy (Codex review NIT-1)

Callers can distinguish:

- `WrapParseError` — malformed or mismatched wire data before native access
- `WrapIntegrityError` — authenticated unwrap failed
- `WrapNativeUnavailable` — the required native backend is unavailable
- `WrapAuthCancelled` — the authorization prompt was denied or cancelled
- `WrapKeyNotFound` — no matching native key exists

All inherit from `WrapError`; sibling subclasses avoid accidentally treating an
authorization refusal as corrupt input.

## Verify-before-decrypt (Codex review #4)

Backup recovery parses structure and compares the recomputed 32-byte
verification digest in constant time before running Argon2id or AES-GCM. A
digest mismatch never materializes the protected secret. Only a matching digest
advances to passphrase-based decryption.

## See also

- [SPEC.md](../../../docs/dev/SPEC.md) — key hierarchy and frozen wire contracts
- [POLICY.md](../../../docs/dev/POLICY.md) — keyvault audit reasons
- [PATHS.md](../../../docs/dev/PATHS.md) — storage ownership and permissions
- [Quickstart](../../../docs/user/QUICKSTART.md) — operator setup
