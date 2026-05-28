# mordred-hermes-sekey

A small, signed Swift CLI that performs Secure Enclave (SE) P-256 operations on
behalf of the (unsigned) Python `mordred-hermes` keyvault.

## Why this exists

An unsigned / ad-hoc-signed Python interpreter cannot carry the
`keychain-access-groups` entitlement, so persisting SE keys in the Keychain
fails with `errSecMissingEntitlement (-34018)`.  This helper uses
**CryptoKit** (`SecureEnclave.P256.KeyAgreement.PrivateKey`) and persists key
blobs as ordinary files under `~/.hermes/mordred/keyvault/sekey/<tag_hex>`.
File-backed CryptoKit keys do not require a Keychain entitlement; an ad-hoc
codesign is sufficient.

```
Python (unsigned)
  └─ subprocess ──▶ mordred-hermes-sekey (ad-hoc signed)
                       └─ CryptoKit SecureEnclave key (file-store)
```

## Protocol (one process invocation = one operation)

Send a single JSON object on stdin; read a single JSON object on stdout.

| Request | Success response |
|---|---|
| `{"cmd":"generate","tag_hex":"..","label":".."}` | `{"public_key_hex":"04.."}` |
| `{"cmd":"public_key","tag_hex":".."}` | `{"public_key_hex":"04.."}` |
| `{"cmd":"delete","tag_hex":".."}` | `{"ok":true}` |
| `{"cmd":"ecdh","tag_hex":"..","peer_pub_hex":".."}` | `{"shared_hex":".."}` |
| `{"cmd":"probe"}` | `{"ok":true}` |

Failure (any command), exit code 1:

```json
{"error":{"domain":"OSStatus","status":-25300,"message":".."}}
```

`tag_hex` is derived from `key_id` as a SHA-256 prefix by the Python side.
The cleartext `key_id` is never sent across the subprocess boundary.
`ecdh` triggers the Touch ID / passcode system prompt.

## Build, sign, install

```bash
./build.sh
```

This runs `swift build -c release`, codesigns ad-hoc (no Developer ID
required), and installs to `~/.local/bin/mordred-hermes-sekey`.

Overrides via env: `MORDRED_SEKEY_SIGN_IDENTITY`, `MORDRED_SEKEY_INSTALL_DIR`.

Smoke test:

```bash
echo '{"cmd":"probe"}' | ~/.local/bin/mordred-hermes-sekey
```

## How Python finds it

`mordred_hermes.keyvault._seckey_helper._find_helper()` looks, in order:

1. `MORDRED_SEKEY_HELPER` env var (absolute path)
2. `~/.local/bin/mordred-hermes-sekey`
3. `mordred-hermes-sekey` on `PATH`

When found, it becomes the SE backend; otherwise the keyvault falls back to
pyobjc and then a software P-256 key (see `_seckey_backend.py`).
