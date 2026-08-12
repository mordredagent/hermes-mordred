# Mordred — Keyvault Backend Design and Secure Enclave Code-Signing Constraints (Hermes-base)

> **Note**: This document records the design study of `mordred_keyvault`'s **key-protection backends** and the **hands-on verification results for macOS Secure Enclave (SE) code-signing requirements**. (The original Japanese-language version kept technical terms — entitlement, `kSec*`, OSStatus, CLI — in English while the surrounding prose was in Japanese; this translation carries the same terminology into English throughout.)
>
> Related: [`SPEC.md`](./SPEC.md) §Platform Support / §Threat Model, [`ROADMAP.md`](./ROADMAP.md) v2-OS2; the keyvault implementation lives in `src/mordred_hermes/keyvault/`.

---

> **⚠️ Correction (2026-06-01) — This document's conclusion that "SE requires a paid Developer ID" applies only to the _Keychain persistence_ path; the shipped live path has superseded it**:
>
> The verification and conclusions in §2–§4 / §7 all target the path that **persists the SE key in the Keychain** (`SecKeyCreateRandomKey` + `kSecAttrIsPermanent`, the `keychain-access-groups` entitlement); this path has been **abandoned**. The shipped live SE path does not use the Keychain at all — the helper `mordred-hermes-sekey` **stores the CryptoKit `SecureEnclave.P256` `dataRepresentation` blob in a plaintext file**. As a result, **ad-hoc `codesign --sign -` alone is enough to drive real hardware SE — no entitlement, no provisioning profile, and no paid Apple Developer Program membership are required** (the `dataRepresentation` blob is device-bound, so it is meaningless on another machine).
>
> **Installing it is a single command**: `hermes-mordred keyvault enable-se` invokes `native/sekey-helper/build.sh`, which runs build → ad-hoc signing → atomic install to `~/.local/bin` → SE probe. It may also refresh the helper with an existing vault, but installs/probes only; it does **not** create, promote, or migrate a wrapping key. Existing helper-store, legacy PyObjC-Keychain, and software keys stay in their original namespaces and remain reachable through ordered backend fallback. A later fresh `keyvault init` or recovery creates the key through the auto-detected helper. Put `MORDRED_SEKEY_UNATTENDED=1` on that key-creation command when no per-use prompt is required. **Fail-safe**: platform guard, preflight, build, or probe failure exits 1 without claiming activation. See [`SECRETS_ENV_ENCRYPTION.md`](./SECRETS_ENV_ENCRYPTION.md) §7 for details; the implementation is in `keyvault/_seckey_helper.py` / `keyvault/_seckey_backend.py` / `wizard/keyvault_native_cli.py:enable_se`.
>
> §2–§8 below are preserved historically as **an investigation record of the
> Keychain path and design alternatives**. The current disposition of the
> layered-backend and Linux TPM proposals is recorded immediately below.

---

> **Current backend update (2026-06-09)**: Linux TPM 2.0 is no longer a
> roadmap-only proposal. The packaged `mordred-hermes-tpmkey` helper,
> on-chip P-256 ECDH backend, `keyvault enable-tpm` installer, and swtpm CI
> coverage have shipped. Linux deliberately has no software-key fallback:
> keyvault operations fail closed when the helper is absent. The
> `SoftwareBackend on every OS` recommendation preserved below was not adopted
> as the Linux security floor. Windows-native and external-token backends
> remain future work.

---

## 0. TL;DR

- **macOS**: the shipped CryptoKit file-store helper uses hardware Secure
  Enclave with ad-hoc signing; no paid Developer ID or Keychain persistence
  entitlement is required. When SE is unavailable, macOS can use a software
  P-256 key in the login Keychain.
- **Linux**: TPM 2.0 support is MVP-complete through the packaged helper.
  It is machine-bound, uses on-chip ECDH, and fails closed without the helper;
  there is no Linux software fallback.
- **Windows / external tokens**: DPAPI/CNG TPM and PKCS#11/FIDO2 backends remain
  future work.
- **Historical scope**: §2-§4 preserve the investigation that disproved the
  original Keychain-persistence approach. §5-§7 preserve the broader layered
  backend proposal; its all-OS `SoftwareBackend` default was not adopted.

## 1. Summary of the Current State (v1)

- `mordred_keyvault` supports macOS and Linux key custody. macOS selects
  Secure Enclave when available and otherwise uses its login-Keychain
  software fallback. Linux selects the TPM helper and raises
  `WrapNativeUnavailable` when it is missing.
- Key hierarchy: the actual data is encrypted with a **DEK
  (AES-256-GCM)**, and the DEK is wrapped by a **wrapping key (P-256)**.
  Wrapping happens offline with the public key; unwrapping delegates ECDH to
  the selected private-key backend.
- The backend is abstracted behind the **`NativeBackend` Protocol** (`wrap.py`,
  4 methods: `generate_enclave_key` / `get_enclave_public_key` /
  `delete_enclave_key` / `enclave_ecdh`). `_SecKeyBackend` dispatches to the
  macOS helper/Keychain implementation or the Linux TPM helper.
- This Protocol is **the seam that this document's backend-swapping design plugs into**.
- Transparent startup `.env`/config injection and the direct
  `SCNetworkReachability` blackout fallback remain macOS-only integration
  layers; that does not make the underlying Linux TPM keyvault unavailable.

## 2. On-Device Verification: Does SE Work With Self-Signing? (2026-05-25, Apple Silicon)

Using a uv CPython 3.13 copy isolated in `/tmp`, we measured SE key persistence (`SecKeyCreateRandomKey` + `kSecAttrIsPermanent`, biometry=False probe) while varying the signature and entitlement. The shared store was left unmodified.

| # | Signature | Entitlement | Process launch | SE persistence |
| --- | --- | --- | --- | --- |
| 0 | adhoc (baseline) | — | OK | ❌ `-34018` |
| 1 | self-signed (openssl, no team) | none | OK | ❌ `-34018` |
| 2 | self-signed + `keychain-access-groups` | present | ❌ **SIGKILL (137)** | — |
| 3 | Apple Development cert (real team) | none | OK | ❌ `-34018` |
| 4 | Apple Dev + team-prefixed `keychain-access-groups` (no profile) | present | ❌ **SIGKILL (137)** | — |

- `-34018` = `errSecMissingEntitlement`. The SE key itself is generated (`SecKeyRef:('com.apple.setoken')`), but the **add** to the keychain fails.
- `keychain-access-groups` is a **restricted entitlement**. Without a provisioning profile (or Developer ID team approval), AMFI kills the process at launch (137).
- **Conclusion**: merely self-signing the interpreter with `codesign` does not get SE working, whether the certificate is free or paid. Stable operation requires a properly signed, provisioned binary.

### Cleanup (Temporary Artifacts Created During Verification)
All temporary keychains, self-signed-certificate user trust settings, keychain search-list changes, and `/tmp` working files used during verification have been **restored to their original state / deleted**. The shared interpreter remains unmodified, still ad-hoc signed.

## 3. Important Finding: The Premise Behind the Phase 4 Legacy-Keychain Fix Collapses

The code comment in commit `25e048ab6` ("fix(mordred-hermes): switch keyvault keychain from DPK to legacy macOS (Phase 4)") assumes the following:

> The Data Protection Keychain (`kSecUseDataProtectionKeychain=True`) requires the `keychain-access-groups` entitlement, which an unsigned local Python cannot hold → switching to the legacy keychain should allow writes without an entitlement.

However, as #3 in §2 shows, **even a correctly Apple-Dev-signed interpreter hits `-34018` on the legacy keychain path**. In other words, switching to the legacy keychain does not avoid the entitlement requirement, and **the current keyvault cannot persist an SE key from any process other than one holding a provisioned entitlement**. As long as it runs on pip/uv/Homebrew Python, the SE path is expected to fail in anyone's environment.

→ **Proposed fix**: abandon the legacy-keychain approach and rebuild on the Data Protection Keychain + access group + a properly signed helper (§4.2). Recommend filing a detailed issue.

## 4. The Essence of macOS SE's Code-Signing Requirements

### 4.1 It's Not Just About Having a Certificate
The full set of requirements for SE persistence:
1. **The right kind of certificate** — the free "Apple Development" certificate does not work (§2 #3/#4). **A "Developer ID Application" certificate (paid Apple Developer Program, $99/year) is required.**
2. Embedding the **`keychain-access-groups` entitlement** (team-prefixed) in the signature.
3. **A properly signed binary carrying that entitlement** — since it is a restricted entitlement, either a provisioning profile or Developer ID team approval is needed.
4. **Notarization** — to pass Gatekeeper at distribution time.

### 4.2 Distribution Model (the Certificate Is Not Distributed)
- Only the **signed binary** is distributed. The certificate's **private key is kept under strict custody by intmax and never distributed** (a leak would let someone sign as intmax — a single point of failure).
- Each user's **SE key (Mordred's wrapping key) is generated inside the SE on the user's own device and never leaves it**. It is entirely separate from intmax's signing key.
- Apple can **remotely revoke** this certificate and invalidate all distributed copies at once (a censorship/coercion vector, and a weakness for a privacy tool). Notarization involves an initial online check (OCSP).

### 4.3 Mordred Is a CLI Tool — a Poor Fit for SE
- Mordred-Hermes is **the `hermes` command (a Python CLI distributed via pip/uv/Homebrew)**, not a GUI `.app`.
- Using SE requires building a separate small compiled helper (Swift/C/Rust) that does nothing but SE operations, signing and bundling it, and invoking it from Python over IPC (the signed-helper pattern, as seen in e.g. Secretive).
- Bundling a Developer-ID-signed, notarized Mach-O helper inside a pip wheel is **highly unusual and awkward to manage**. The fact that this is a CLI makes the SE route even less suitable.

## 5. Proposed Architecture: Layered Backend ("G")

> **Historical proposal status**: this selector was not implemented as
> written. In particular, Mordred does not silently fall back to an all-OS
> software backend. Current production selection is Secure Enclave plus a
> macOS-only login-Keychain fallback on macOS, and fail-closed TPM 2.0 on
> Linux.

Using the `NativeBackend` Protocol as a common plug-in point, the actual key-protection implementation is swapped based on environment and policy.

```
        api.py  (generate / encrypt / decrypt / export_backup / import_backup)
            |   ← crypto logic unchanged
        wrap.py (ECDH + HKDF + AES-KW, pure-Python, existing)
            |  uses
   +--------+----------  NativeBackend (Protocol: 4 methods)  ← existing seam
   |
   +- SoftwareBackend       … encrypts files with passphrase + Argon2id (all OSes, default)
   +- SecureEnclaveBackend  … existing _SecKeyBackend (signed macOS only)
   +- HardwareTokenBackend  … YubiKey/PIV/FIDO2/PKCS#11 (all OSes, optional)
   +- TpmBackend            … Linux: tpm2-tss / Windows: CNG Platform Crypto Provider
            ^
   resolve_backend(policy, key_id)  ← new: backend selector + keystore index
```

### 5.1 Backend List and Code-Signing Requirements

| backend | private key location | unwrap authorization | operating conditions | code signing |
| --- | --- | --- | --- | --- |
| **SoftwareBackend** (C) | Argon2id+AES-GCM encrypted file | passphrase | all OSes | not required |
| **HardwareTokenBackend** (E) | inside the token | PIN + touch | all OSes (USB) | not required |
| **TpmBackend** | inside the TPM | PIN/policy | Linux/Windows | not required |
| **SecureEnclaveBackend** (A) | Secure Enclave | Touch ID/passcode | signed macOS | **required (§4)** |

→ **Code signing is required only for macOS SE.** The others are gated by permissions and a PIN.

### 5.2 The Selector and the "Key ⇄ Backend Binding" (the Most Important Invariant)
- `policy.keyvault.backend = auto | software | secure_enclave | token | tpm`. `auto` decides based on capability-probe order (token > OS hardware > software), and **the selection result is explicitly surfaced to the user and recorded**.
- **A key is bound to the backend it was generated with.** A DEK wrapped by SE cannot be unwrapped by software (the key material is different). A small **keystore index** (`key_id → {backend, pubkey, created_at}`) is kept under `~/.hermes/mordred/keyvault/`, and unwrap requests are routed to the correct backend. The wire format (MRKW blob) requires no changes.

### Logical IDs and profile-scoped native IDs

`key_id` in MRKW/MREN, backups, and audit events is the portable **logical**
identifier. New `meta.json` rows also carry a deterministic `native_key_id`
derived from the absolute keyvault root and logical id. Only this physical id
is sent to SE/TPM/software native operations, preventing two `HERMES_HOME`
profiles from colliding in a machine-global Keychain namespace. Explicit
`home=` API calls bind file-backed helpers to that root's `sekey/` or `tpm/`
store; an operator-set `MORDRED_*KEY_STORE` remains authoritative.

Rows written before this split have no `native_key_id`. They remain readable
through their legacy logical native id, but automatic reset/rollback never
deletes that global tag because exclusive profile ownership cannot be proven.
For these legacy rows only, helper-backed reads try the explicit profile's
bound store first, then the caller backend's historical ambient
`HERMES_HOME` store on `WrapKeyNotFound`. Current scoped ids never take that
fallback. Operators recovering a non-ambient old profile can point directly at
its helper blobs with the authoritative `MORDRED_SEKEY_STORE` (macOS) or
`MORDRED_TPMKEY_STORE` (Linux) override for the export, then remove the
override before recovery.
The supported migration is: verify/export a backup, reset the old profile, then
recover into the fresh profile. Recovery preserves the backup's logical
`key_id` while generating a new profile-scoped physical key. A durable
`pending_native_key` journal is written before generation so a post-publication
helper failure can be cleaned up safely by `keyvault reset`.
- **No silent fallback.** If an attempt is made to open an SE-generated key in an unsigned environment, it must **fail with an explicit error** rather than silently falling back to software (protection-level degradation must never be hidden).

### 5.3 Migration (Optional)
Migrating between backends = generate a wrapping key with the new backend → for each DEK, {unwrap with the old backend (authorized) → wrap with the new backend's public key (offline)} → update the index → delete the old key. The existing `import_backup` re-wrap flow in `api.py` can be reused.

### 5.4 Proposed phases and actual disposition

| Phase | Content | Disposition |
| --- | --- | --- |
| Proposed P1 | All-OS `SoftwareBackend` + selector + keystore index | **Not adopted** as the Linux security floor |
| macOS helper | CryptoKit Secure Enclave file-store helper + login-Keychain fallback | **Shipped** |
| Linux TPM | Packaged helper + on-chip ECDH + installer/CI | **Shipped 2026-06-09** |
| Windows / external token | CNG/DPAPI or PKCS#11/FIDO2 + migration | Deferred |

See [`SPEC.md`](./SPEC.md) §Platform Support for the current support matrix
and [`ROADMAP.md`](./ROADMAP.md) v2-OS2 for the remaining Windows/external
backend work.

## 6. Security Assessment (by Threat)

| Threat | SoftwareBackend (passphrase) | SE / Token / TPM |
| --- | --- | --- |
| Device loss/theft (powered off) | ✅ High (Argon2id) | ✅ High |
| Key file/backup leak | ✅ High (cannot be decrypted from the file alone) | ✅ High |
| Cryptographic correctness / tamper detection | ✅ High (AEAD, verified) | ✅ High |
| Malware on a running device (in use) | ⚠️ Weak (key/passphrase resides in RAM) | ✅ Strong (key never leaves) |
| Hardware rate-limiting/lockout | ⚠️ None (only the Argon2id cost) | ✅ Present |
| Coercion / phishing / shoulder-surfing | ⚠️ None | ⚠️ Limited (the user can be forced to authorize) |

- **There is no such thing as "absolutely safe"** (SE included).
- SoftwareBackend provides **security on par with `age`, password managers, and FileVault against the "threats most people actually face" — loss, theft, leaks, and at-rest exposure**. Its weak points are two-fold: "malware on a running device" and "a weak passphrase."
- The linchpin of its security is **(1) enforcing a strong passphrase and (2) an uncompromised device**. Hardening measures: strengthen Argon2id (e.g., 256 MiB / t≥3), `mlock` + zeroize the decrypted key, rate-limit and audit unwrap operations, and optionally add the OS keychain as a second layer.

## 7. Historical Recommendation and Current Decisions

1. ~~**Make P1 (SoftwareBackend) the default**~~ — historical proposal, not
   adopted. Software fallback is macOS-only; Linux fails closed on its TPM
   backend.
2. For users who want hardware protection, offer **E (external token)** — no Apple involvement, no profile, no signing needed, works on all OSes, and is best from an anti-surveillance standpoint.
3. ~~**SE (A) remains an unimplemented signed-helper option**~~ — superseded:
   the CryptoKit helper is shipped and works with ad-hoc signing.
4. **Linux TPM is shipped** without a code-signing requirement. Windows TPM /
   DPAPI and external-token support remain to be implemented.

## 8. Open Questions / Next Actions

> As noted in the **Correction (2026-06-01)** at the top, hardware SE has **shipped** as a CryptoKit file-store helper (`keyvault enable-se`). Of the items below, the ones premised on Keychain persistence have been superseded / completed.

- ~~**Unverified**: whether SE persistence + ECDH work with a "Developer ID Application" (paid) certificate + entitlement but no profile~~ — **Superseded (2026-06-01)**: a paid Developer ID turned out to be **unnecessary**. The shipped live path is a file-store helper that does not use the Keychain, and it has been confirmed on real hardware that ad-hoc signing alone is enough to drive real SE generate / ECDH / unwrap. A paid certificate is only needed for "Gatekeeper trust when distributing a prebuilt binary for download," not for using SE itself.
- ~~**Recommended filing an issue**: the Phase 4 SE persistence failure from §3 (with the verification matrix, proposing a rebuild onto "DPK + signed-helper")~~ — **Completed (2026-06-01)**: the rebuild onto a signed-helper has been implemented and shipped. However, what was adopted was not DPK-Keychain but a **CryptoKit `dataRepresentation` file-store** helper (`native/sekey-helper`). Because Keychain persistence itself was avoided, the premise collapse described in §3 is now moot.
- **Doc sync** (ongoing): add cross-references to this document and to the shipped `enable-se` path in [`SPEC.md`](./SPEC.md) §Platform Support / §Threat Model and [`ROADMAP.md`](./ROADMAP.md) v2-OS2.
