# mordred-hermes-tpmkey

A small Rust CLI that performs TPM 2.0 P-256 operations on behalf of the Python
`mordred-hermes` keyvault on **Linux** — the cross-platform counterpart to the
macOS Secure-Enclave helper (`mordred-hermes-sekey`).

## Why this exists

The keyvault's wrapping-master-key (WMK) format needs a **non-extractable P-256
key plus on-chip ECDH** (P-256 ECDH → HKDF → RFC 3394 AES-KW). On macOS the
Secure Enclave provides this; on Linux the equivalent is a **TPM 2.0**. This
helper drives the TPM via `tss-esapi`/libtss2 and speaks the **identical
JSON-over-stdio protocol** as the SE helper, so the Python driver
(`mordred_hermes.keyvault._seckey_helper._HelperSecKeyOps`) talks to either one
unchanged.

```
Python (keyvault)
  └─ subprocess ──▶ mordred-hermes-tpmkey
                       └─ TPM 2.0 (tss-esapi / libtss2)
                            • private key: non-extractable inside the TPM
                            • saved blob: <store>/<tag_hex>.bin (opaque key context)
```

## Protection tier

Linux TPM keys are **Tier 2 (machine-bound)**: the private key cannot leave the
TPM, so a copied blob is useless on another machine. This is **not** equivalent
to macOS Touch ID — the MVP does **no per-use user-presence gate** (no PIN/PCR
prompt); `unattended` is accepted for protocol parity but does not change
behaviour. Per-use gating is a deferred follow-up.

## Wire protocol

One process invocation == one operation. A single JSON request object is read
from stdin; a single JSON response object is written to stdout; the process
exits 0 (success) or 1 (error).

| Request (stdin) | Success (stdout, exit 0) |
| --- | --- |
| `{"cmd":"generate","tag_hex":"..","label":"..","unattended":false}` | `{"public_key_hex":"04.."}` |
| `{"cmd":"public_key","tag_hex":".."}` | `{"public_key_hex":"04.."}` |
| `{"cmd":"delete","tag_hex":".."}` | `{"ok":true}` |
| `{"cmd":"ecdh","tag_hex":"..","peer_pub_hex":".."}` | `{"shared_hex":".."}` |
| `{"cmd":"probe"}` | `{"ok":true}` |

- Public keys are **uncompressed SEC1 / X9.63** (`0x04 || X(32) || Y(32)`,
  65 bytes), identical to CryptoKit's `x963Representation`.
- `ecdh` returns the **raw 32-byte X coordinate** of the shared point
  (left-padded to a fixed 32 bytes), identical to the SE helper and the
  software fallback, so the Python HKDF input is unchanged.
- Errors are `{"error":{"domain":"tpm","status":N,"message":"..","reason":".."}}`
  (exit 1). `reason` is the neutral taxonomy
  (`NOT_FOUND`/`EXISTS`/`UNAVAILABLE`/`AUTH_DENIED`) the Python side dispatches
  on; request-shape failures use `domain":"helper"` with no `reason`.

## Key store

Each key persists as an opaque TPM key-context blob at `<store>/<tag_hex>.bin`
(directory `0700`, file `0600`, created `O_CREAT | O_EXCL`). The store directory
resolves as:

1. `MORDRED_TPMKEY_STORE` — explicit absolute directory (authoritative)
2. `$HERMES_HOME/mordred/keyvault/tpm`
3. `~/.hermes/mordred/keyvault/tpm`

## Build & install

```sh
./build.sh   # cargo build --release + install to ~/.local/bin
```

Point Python at it (if not on `PATH`):
`export MORDRED_TPMKEY_HELPER="$HOME/.local/bin/mordred-hermes-tpmkey"`.

## Status

- **Phase 2a (this commit)** — the pure, host-agnostic layer: wire protocol,
  SEC1 codec, the 32-byte ECDH-Z left-pad, the opaque blob store, and the neutral
  error taxonomy, all `cargo test`-covered on any host (incl. macOS). The TPM
  backend is not yet wired, so the binary currently answers every command with
  the neutral `UNAVAILABLE` reason.
- **Phase 2b (next, Linux only)** — `src/tpm.rs` behind
  `#[cfg(target_os = "linux")]` using `tss-esapi`: deterministic ECC P-256
  storage primary (`CreatePrimary`) + non-restricted decrypt child (`Create`,
  `fixedTPM | fixedParent`), `ECDH_ZGen`, `FlushContext` per op, verified against
  a `swtpm` emulator in CI.
