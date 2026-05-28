# mordred-hermes-sekey

A small, signed Swift CLI that performs Secure Enclave (SE) operations on
behalf of the (unsigned) Python `mordred-hermes` keyvault.

## Why this exists

An unsigned / ad-hoc-signed Python interpreter cannot carry the
`keychain-access-groups` entitlement, so persisting SE keys fails with
`errSecMissingEntitlement (-34018)`. A separately-signed helper binary
(Developer ID + bundle ID + entitlement) can, so Python shells out to it —
the same pattern the 1Password CLI uses.

```
Python (unsigned)
  └─ subprocess ──▶ mordred-hermes-sekey (signed)
                       └─ SecKeyCreateRandomKey(SE) / ECDH / SecItemDelete
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

`tag_hex` is the Keychain `kSecAttrApplicationTag` as hex. The helper uses it
verbatim — the cleartext `key_id` is never sent (Python derives the tag as a
SHA-256 prefix). `ecdh` triggers the Touch ID / passcode system prompt.

## Build, sign, install

```bash
./build.sh
```

This runs `swift build -c release`, codesigns with the Developer ID identity
and `sekey-helper.entitlements` (hardened runtime), and installs to
`~/.local/bin/mordred-hermes-sekey`.

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
