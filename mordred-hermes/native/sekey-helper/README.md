# mordred-hermes-sekey

A small, signed Swift CLI that performs Secure Enclave (SE) P-256 operations on
behalf of the (unsigned) Python `mordred-hermes` keyvault.

## Why this exists

An unsigned / ad-hoc-signed Python interpreter cannot carry the
`keychain-access-groups` entitlement, so persisting SE keys *in the Keychain*
fails with `errSecMissingEntitlement (-34018)`. The usual fix
(`keychain-access-groups` + a provisioning profile + a `.app` bundle) requires
a **paid Apple Developer Program** membership — and a bare Developer-ID CLI
that requests the entitlement without a profile is SIGKILLed by AMFI.

This helper sidesteps all of that with **CryptoKit**
(`SecureEnclave.P256.KeyAgreement.PrivateKey`): it never touches the Keychain.
The private key lives in the Secure Enclave; its `dataRepresentation` — an
opaque blob that *only this device's Enclave* can decrypt and use — is written
to an ordinary file. A leaked blob is useless on any other machine, so no
entitlement, no provisioning profile, no `.app` bundle, and **no paid Developer
account** are needed. An **ad-hoc codesign** (`codesign --sign -`) is enough.

```
Python (unsigned)
  └─ subprocess ──▶ mordred-hermes-sekey (ad-hoc signed)
                       └─ CryptoKit SecureEnclave key
                            • private key: in the Secure Enclave
                            • dataRepresentation blob: <store>/<tag_hex>.bin
```

### Key blob store

`<store>` is resolved in this order:

1. `MORDRED_SEKEY_STORE` — explicit directory (authoritative).
2. `$HERMES_HOME/mordred/keyvault/sekey`
3. `~/.hermes/mordred/keyvault/sekey`

This mirrors `mordred_hermes._home.hermes_home`. The directory is created
`0700` and each `<tag_hex>.bin` blob is written `0600`.

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

### Authorization policy (per key)

`generate` takes an optional `"unattended"` boolean (default `false`):

- **`false` (interactive, default):** the key is gated by Touch ID / passcode, so every `ecdh` prompts. Use for a human-approved vault.
- **`true` (unattended):** the key carries only `.privateKeyUsage` — still Enclave-bound (cannot be copied to another machine) but `ecdh` runs **without a prompt** while the session is unlocked. Use for autonomous encrypt+decrypt (e.g. hermes / Claude Code).

The choice is baked into the key's `dataRepresentation` at generation time and cannot change afterward. Encryption (`wrap_dek`) never needs the private key, so it is always prompt-free regardless of this flag — only decryption (`unwrap_dek` → `ecdh`) is affected.

On the Python side this is `unattended=` on `api.generate` / `wrap.generate_wrapping_key` / `backend.generate_enclave_key`; when unspecified, the default comes from the `MORDRED_SEKEY_UNATTENDED=1` env var, else interactive.

When **interactive**, `ecdh` triggers a system prompt because the
key is created with the access control
`[.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]` — Touch ID
preferred, with a **device-passcode fallback**. The fallback matters: with
`.biometryCurrentSet` alone, a biometry lockout (e.g. repeated failed Touch ID
reads, which happen with an ad-hoc-signed CLI) would make the wrapping key
unusable until a screen unlock. `.biometryCurrentSet` still invalidates the key
if the enrolled fingerprint set changes.

Error status ints mirror the legacy Keychain path so the Python
`_translate_error` table is unchanged: duplicate → `-25299`
(`errSecDuplicateItem`), missing → `-25300` (`errSecItemNotFound`), any auth /
generic failure → `-25293` (`errSecAuthFailed`), all with `domain:"OSStatus"`.

## Build, sign, install

The easiest way is the Mordred CLI — it locates these sources (in a source
checkout or a `pip install`-ed wheel), builds + ad-hoc-signs + installs the
helper, then verifies the Secure Enclave probe:

```bash
hermes mordred keyvault enable-se          # add --unattended for prompt-free decrypt
```

Or run the build script directly:

```bash
./build.sh
```

Both run `swift build -c release`, codesign ad-hoc (no Developer ID, no
provisioning profile, no paid Apple Developer account required), and install to
`~/.local/bin/mordred-hermes-sekey`.

Overrides via env: `MORDRED_SEKEY_INSTALL_DIR` (install target),
`MORDRED_SEKEY_STORE` (key blob directory).

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
