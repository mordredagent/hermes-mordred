# Mordred at-rest encryption vault — design note

> **Status**: crypto core + production Keychain `AnchorStore` + operator CLI
> (`vault init` / `add` / `status` / `cat` / `migrate`) implemented (all TDD).
> Runtime transparent decryption: the env and agent-memory sides are done. The
> config.yaml side **landed** via a v2-F8 `.pth` startup hook — reworked from the
> closed PR #85 and **merged in PR #86** (2026-06-03), opt-in and fail-closed.
> Decided 2026-06-03: opt-in stays the design — **not default-enabled**. Real-hardware
> SE e2e done 2026-06-03 — **v2-F8 complete** (§8 item 3).
> **Updated**: 2026-06-03
> **Scope**: **at-rest encryption** of `~/.hermes/.env`, `config.yaml`, and the
> Hermes agent memory on macOS Apple Silicon (`POLICY.md` Phase 4). The original
> MENV (`KEY=value`-only codec) proposal was generalized into a general-purpose
> **vault** that encrypts arbitrary files (the 2026-05-28 redesign).
> **Related**: `POLICY.md:224`, `keyvault/{vault,manifest,anchor,file_container,vault_master,kek}.py`.
> **PR**: #64 (InternetMaximalism/hermes-mordred).

---

## 1. Purpose / goals

Leave no plaintext secrets on disk. Encrypt `~/.hermes/.env` / `config.yaml` /
agent memory with AES-GCM, decrypting via Secure Enclave (hot path) or
passphrase (cold path). There is a **single random master key**, sealed two
ways.

---

## 2. Threat model (settled)

- ✅ **Defends against**: offline disk read + offline disk substitution
  — theft, powered-off device, drive removal, forensic imaging, backup leak.
  Ciphertext-at-rest plus an **unattended Secure Enclave that cannot be
  unwrapped off-device**.
- ❌ **Out of scope**: a **same-uid attacker** on a running, unlocked machine
  (an unattended SE can be unwrapped by any same-uid process), tamper-and-wait,
  live RAM / child-process environment variables.
- **Pair with FileVault** (OS-level full-disk encryption, defense in depth).

---

## 3. Design — one master, double-sealed

```
secret bytes ──AES-GCM (fast software)── master key (32B random)
                                         ├─ SE-wrap        → wmk   (hot path · device-bound · unattended)
                                         └─ Argon2id-wrap  → recovery.mrkv (cold path · passphrase)
```

- **Hot path (wmk)**: unattended Secure-Enclave wrap. Survives reboots
  **without Touch ID** (for telegram / gateway / cron). Unwrap the master once
  at startup, then decrypt all files fast from the in-RAM master.
- **Cold path (recovery.mrkv)**: an Argon2id passphrase recovery sidecar.
  Fallback for SE loss, migration to another machine, or SE failure.
  - The recovery verification digest = **`SHA-256(wmk)`** (*not* derived from
    the passphrase). A substituted wmk is rejected **before paying the Argon2
    cost**, so the passphrase never becomes an oracle.

---

## 4. On-disk layout (under the vault root)

| Path | Contents |
|---|---|
| `manifest.<gen>.mvmf` | One authenticated manifest per generation. `MVMF: {key_id, wmk, files:{name→sha256(ct)}, generation}` + an HMAC under a master-derived subkey |
| `blobs/<sha256>.blob` | Content-addressed MVLT ciphertext (AES-GCM, AAD bound to the name) |
| `recovery.mrkv` | Argon2id passphrase recovery sidecar |
| `.lock` | flock target for write transactions |

- Files are `0600`, directories `0700`, writes are atomic under flock.
- `files` values are **enforced by the codec** to match `^[0-9a-f]{64}$`
  (sha256hex) → this removes digest-shaped path traversal before assembling
  `blobs/<digest>.blob`.
- `_ensure_dir` rejects symlink / non-directory vault paths (offline-substitution
  defense).

---

## 5. Device-bound anchor (`anchor.py`)

The **root of freshness** that the manifest MAC alone cannot provide. `wrap_dek`
is offline (it runs with **only the Secure Enclave's public key**), so an
attacker with disk access can mint a `wmk` that unwraps to a master of their own
choosing and then MAC an entire forged manifest with it (the manifest MAC would
verify). They could also roll back to an earlier valid manifest+files snapshot.

The anchor closes this by pinning **two non-secret values** in a device-bound
store that an offline attacker **can read but cannot write** (the production
backing is a Keychain generic-password, `ThisDeviceOnly` + `AfterFirstUnlock`):

- `wmk_sha256` — the `SHA-256` of the legitimate wmk. A substituted / different-
  vault wmk has a different fingerprint (Codex review **P1-a**).
- `generation` — a monotonically increasing counter the manifest also carries.
  A rolled-back snapshot will not match the pinned generation (**P1-b**).

`verify_anchor` checks both for strict equality before trusting a vault's wmk.
The anchor itself has no MAC (its integrity rests on the store's write control —
exactly what an offline attacker lacks). **Rewriting the anchor is the sole
commit point of enroll.**

---

## 6. Components (all TDD: RED → GREEN)

- `kek.MasterKey.mac` — HKDF domain-separated HMAC-SHA256 for manifest
  authentication.
- `file_container.py` (MVLT) — an AEAD container for arbitrary bytes. AAD =
  `MAGIC ‖ ver ‖ SHA-256(header) ‖ name` defends against blob-swap /
  header-rebind / name-rewrite.
- `vault_master.py` — the double seal (SE `wmk` + Argon2id recovery).
- `manifest.py` (MVMF) — the authenticated registry + the `parse_unverified`
  two-phase bootstrap.
- `anchor.py` — the device-bound freshness pin + the `AnchorStore` Protocol.
- `vault.py` — the `init` / `open` / `enroll` / `read` / `recover`
  orchestration.

### 6.1 `open_vault` two-phase bootstrap

You cannot verify the manifest MAC without the master, and you cannot obtain the
master without the wmk the manifest embeds — a chicken-and-egg problem solved in
two phases:

```
read the device anchor (authenticated generation N)
  → load manifest.<N>
  → parse_unverified extracts wmk + generation (MAC unverified, structure-only)
  → verify_anchor pins SHA-256(wmk)+generation (rules out P1-a substitution / P1-b rollback)
  → SE-unwrap recovers the master
  → manifest.decode authenticates the MAC
```

### 6.2 `enroll_file` (crash-safe, anti-rollback)

```
write blob → write manifest.<N+1> → flip the anchor (sole commit point) → best-effort GC
```

- A crash before the anchor flip leaves generation N intact (**P1-c**: neither
  bricks nor rolls forward).
- **stale-writer rollback refusal**: under the lock, re-read the anchor; if the
  in-RAM generation/wmk lags a concurrent committer, fail closed (prevents
  overwriting a newer manifest, regressing the anchor, or GC-ing the new blob).

### 6.3 `read_file` (fail-closed)

An unregistered name / missing blob / content-address mismatch / AEAD failure
are all `VaultError`. It **never falls back to plaintext**. A vanished blob's
`FileNotFoundError` is also wrapped in `VaultError` and fails closed (the racy
`exists()` pre-check was removed).

### 6.4 `recover_vault` (cold path)

Open without an SE backend or device anchor: pick the latest
`manifest.<gen>` → `parse_unverified` for the wmk → `open_passphrase` via
`recovery.mrkv` → `manifest.decode` to authenticate. Because the recovery digest
`SHA-256(wmk)` binds the sidecar to the real wmk, a substituted manifest yields
`RecoveryDigestMismatch`, a wrong passphrase yields `InvalidTag`, and a tampered
manifest yields `ManifestError`.

- **Explicit weakening**: no anchor → no freshness guarantee (an older snapshot
  under the same wmk cannot be detected).
- The recovered vault is **read-only** (`enroll_file` raises `VaultError` until
  you re-key).

---

## 7. Known constraint — Secure Enclave entitlement (-34018)

Empirical verification (2026-05-25, Apple Silicon): persisting the keyvault's
Secure Enclave key fails with **OSStatus -34018 (errSecMissingEntitlement)** from
a Python interpreter that lacks the provisioning-profile-authorized
`keychain-access-groups` entitlement. A plain `codesign` (self-signed or Apple
Development alike) is insufficient — only a properly provisioned, signed
.app/helper can write it.

Implications:

- **The hot path (unattended SE `wmk`) likely does not work from an ordinary
  `pip` / `uv` / Homebrew Python** — which is exactly the unattended-startup
  (telegram / gateway / cron) scenario the Phase 8 runtime integration targets.
- **The cold path (Argon2id passphrase) works software-only on every OS** and
  needs no signing.
- Practical recommendation: anchor on the software default (passphrase +
  Argon2id) and treat SE as an optimization for "a properly provisioned, signed
  build." The `NativeBackend` Protocol in `wrap.py` is the swap seam.

**Follow-up verification (2026-06-01, Apple Silicon, non-provisioned uv/pip Python)**:

- **Keychain generic-password round-trips succeed** (`SecItemAdd` / `Copy` /
  `Delete` all `errSecSuccess`, no -34018). As expected this is a separate path
  from SE key persistence, so the production `AnchorStore` of §8 (a non-secret
  freshness pin) works in production too.
- **`_SecKeyBackend` auto-falls back to software P-256 when SE is unavailable**
  (`_SoftwareFallbackOps`, switching to a software key in the login Keychain on
  `errSecMissingEntitlement`). So the full `init` → `enroll` → reopen (hot-path
  unwrap) → read path round-trips on non-provisioned Python (verified on
  hardware). Trade-off: the `wmk` degrades from SE to software-key protection
  (weaker against a same-uid / unlocked-Keychain attacker) — consistent with the
  "software default, SE is a signed-build optimization" stance above.

**Correction (2026-06-01, `native/sekey-helper`) — "SE requires a provisioned signed build" is wrong**:
The -34018 at the top of this section and the "only a properly provisioned,
signed .app/helper" constraint applied only to the legacy path that **stores the
SE key in the Keychain**. The current signed helper `mordred-hermes-sekey` uses
CryptoKit `SecureEnclave.P256` + `dataRepresentation` and **stores to a file**,
never touching the Keychain — so **no entitlement / provisioning profile / paid
Apple Developer account is needed; an ad-hoc `codesign --sign -` alone runs real
hardware SE** (the `dataRepresentation` blob is device-bound and meaningless on
other machines). `native/sekey-helper/build.sh` does build + ad-hoc sign +
`~/.local/bin` install, and Python `_seckey_helper._find_helper()` auto-detects
it as the primary backend for fresh key creation; ordered fallback still finds
existing legacy keys in their original namespace. Distribution ships the source
and each user runs `build.sh` (free). A signed/notarized build is needed only
for "Gatekeeper trust when downloading a prebuilt binary," not for SE use
itself.

**Enable command (`keyvault enable-se`)**: building and installing the helper
above is a single command — `hermes-mordred keyvault enable-se
[--install-dir PATH]`. It may install or refresh the helper with an existing
keyvault. Internally it calls `native/sekey-helper/build.sh`, running
`swift build -c release` → `codesign --sign -` (ad-hoc) → install to
`~/.local/bin/mordred-hermes-sekey` → an SE probe, in order. Probe success
confirms the helper is available for a **later** `keyvault init` or recovery;
the installer does not create, promote, or migrate any wrapping key. Existing
helper-store, legacy PyObjC-Keychain, and software keys remain in their current
namespace and are still found through the backend's ordered fallback. Thereafter
Python `_seckey_helper._find_helper()` auto-detects it for fresh key creation.
Prerequisites: macOS (Apple Silicon / T2) + Xcode CLI tools
(`swift` / `codesign`). **fail-safe** — if the platform guard / build / probe
fails, no activation is claimed (rc 1). To create an SE key that can decrypt
without a Touch ID prompt while the session is unlocked, put
`MORDRED_SEKEY_UNATTENDED=1` on the later init/recovery command (access control
is `.privateKeyUsage` only; the default requires Touch ID). If the helper is
off `PATH`, point at it with `MORDRED_SEKEY_HELPER`. Implementation:
`wizard/keyvault_native_cli.py:enable_se` /
`keyvault/_seckey_helper.py`; for the full backend picture see the correction
(2026-06-01) at the top of [`KEYVAULT_BACKENDS.md`](./KEYVAULT_BACKENDS.md).

---

## 8. Remaining work (later phases)

1. ~~**Native macOS Keychain `AnchorStore`**~~ — **done** (2026-06-01).
   `KeychainAnchorStore` in `keyvault/_anchor_keychain.py` (generic-password,
   `AfterFirstUnlock` + `ThisDeviceOnly`). It follows the `_seckey_backend.py`
   two-layer style (a narrow `_KeychainOps` + a software `_FakeOps` injection for
   cross-platform tests; `KeychainAnchorError` is an `AnchorError` subclass and
   fails closed). The -34018 concern in §7 is resolved by the follow-up
   verification. There is a hardware round-trip test under the
   `MORDRED_KEYVAULT_LIVE` gate.
2. **Operator CLI** — `vault init` / `add` / `status` / `cat` / `migrate` are
   **done** (`wizard/vault_cli.py`, the `vault` group in `cli.py`, all TDD +
   fail-closed code-review feedback applied). `status` / `cat` are cold-path
   (passphrase recovery, read-only); `init` / `add` / `migrate` are hot-path
   (device key, working even on non-provisioned setups via the §7 software
   fallback). `vault migrate` (bulk-importing existing plaintext) is also
   **done** (2026-06-01) — it opens the vault once on the hot path and
   `enroll_file`s each source by basename. It uses **read-all-then-enroll-all**
   (read every source before enrolling any), so an invalid path or basename
   collision aborts before the first commit (no half-finished migration). With
   no arguments it auto-imports whichever of the Hermes home `.env` +
   `config.yaml` exist. It does not delete the plaintext sources (like `add`,
   shredding is the operator's responsibility).
3. **Runtime transparent decryption + fail-closed core shim** — inserted with a
   minimal footprint into the `env_loader` / config startup path and the
   `memory_tool` (the real goal).
   - **The env side is done** (PR #68 + follow-up). `inject_vault_env` /
     `install_vault_env_decrypt` in `keyvault/_runtime_env.py`. On macOS, at
     startup it hot-path-decrypts the vault's `.env` and override-injects into
     `os.environ` (equivalent to `load_hermes_dotenv(override=True)`).
     Fail-closed: tampering / bad key / non-UTF-8 raise; **it also raises when
     the anchor is absent but `manifest.*.mvmf` still exists on disk** (blocks
     an anchor-deletion downgrade); values are injected verbatim (no `${VAR}`
     interpolation). Wired via `mordred_keyvault.register()`. The vault root /
     identity are consolidated in `keyvault/_identity.py` (shared by the CLI and
     the shim).
   - **Agent memory: done** (`vault set-memory-key`). An on-ramp now stores the
     memory-encryption key (PR #61 — upstream `tools/memory_tool.py`, AES-256-GCM
     keyed by `HERMES_MEMORY_KEY`) in the vault `.env`. `hermes-mordred vault
     set-memory-key [--rotate]` opens the vault on the hot path and generates /
     merges the key (preserving other `.env` entries, idempotent, never printing
     it; `--rotate` regenerates but warns that memories encrypted under the old
     key become undecryptable); the runtime shim then injects
     `HERMES_MEMORY_KEY` into `os.environ` at startup. Set
     `memory.encryption.enabled: true` in `config.yaml` and `~/.hermes/memories/*.md`
     are encrypted, the key protected at rest by the SE (or its software fallback).
     Implementation `wizard/vault_cli.py:set_memory_key`, integration test
     `tests/test_keyvault_memory_integration.py`.
   - **`config.yaml` transparent-decrypt: landed (mechanism (b), reworked)**
     ([`ROADMAP.md`](./ROADMAP.md) v2-F8). A `.pth` startup hook
     (`keyvault/_config_bootstrap.py` / `_pth_bootstrap.py` /
     `wizard/config_decrypt_cli.py`) runs *before* the eager import-time
     `config.yaml` readers. The first cut (PR #85) was closed unmerged after review;
     the reworked version **merged in PR #86** (2026-06-03, commit `a16e97102`)
     resolves each blocker:
     - **Narrow engage / supply-chain**: the shipped `.pth` (force-included into the
       site-packages root) carries a one-line inline guard and imports
       `_pth_bootstrap` **only** for a `hermes` / `hermes-mordred` console-script
       invocation (or `MORDRED_CONFIG_DECRYPT=1`). pytest, pip, a bare REPL, or a venv
       merely *named* "hermes" are left untouched and the device key store is never
       probed.
     - **`python -m hermes_cli`**: **not covered at site-init** — when the `.pth` runs,
       `sys.argv[0]` is still `'-m'` (runpy resolves the module path, and even places
       the module name into argv, only afterward), so `_looks_like_hermes` returns
       false and the hook does not engage. Start via the `hermes` / `hermes-mordred`
       console script, or set `MORDRED_CONFIG_DECRYPT=1` for an `-m` launch. (The
       `/hermes_cli/` path branch in `_looks_like_hermes` only matches if such an argv
       is supplied explicitly — it is not produced by a real `-m` startup.)
     - **Profile**: the home is resolved through `hermes_home()`, which honors
       `HERMES_HOME` **only**; a sticky non-default `active_profile` merely logs a
       one-shot warning and still resolves `~/.hermes` (the transient `-p/--profile`
       flag is likewise not visible at site-init). The opt-in marker is per-home, so a
       non-managed home is a clean no-op — but to put a *non-default profile's*
       `config.yaml` under the hook you must export `HERMES_HOME` for that process.
     - **Concurrency**: `reseal_config` uses `unlink(missing_ok=True)` (closes the
       slow-open TOCTOU window) and leaves the plaintext in place on any vault-open
       failure; the next `materialize_config` self-heals by re-syncing the leftover
       (disk-wins).
     - **Fail-closed**: an engaged Hermes process aborts (`SystemExit(1)`) on any
       decrypt error rather than booting on a default/stale config; an absent anchor
       with manifests still on disk is treated as anchor deletion and refused.

     **Opt-in lifecycle** (using the canonical `hermes-mordred …` form):
     `hermes-mordred vault enable-config-decrypt` enrolls
     `<home>/config.yaml` + writes the marker (`<home>/mordred/config-vault.marker`)
     only after a clean enroll; `disable-config-decrypt` removes the marker and
     guarantees a readable plaintext (recovering the vault copy if sealed). Recovery
     escape hatch: `MORDRED_CONFIG_DECRYPT=0 hermes-mordred vault disable-config-decrypt`
     bypasses the hook so disable is not blocked by the hook it undoes.

     **Trade-off**: while a managed process runs, the plaintext `config.yaml` exists
     on disk at `0o600` (weaker than `.env`'s memory-only injection) — the cost of
     supporting the eager direct readers without a Hermes-core change. It is **low
     value** anyway: `config.yaml` holds no secrets by design (`api_key` defaults to
     `""`, falling back to an env var), and real secrets live in `.env`, already
     encrypted here — so this is defense-in-depth. **Decision (2026-06-03): not
     default-enabled — opt-in stays the design.** Default-ON would impose a
     `SystemExit(1)` startup abort on decrypt failure, an on-disk plaintext while
     managed, and the auto-exec `.pth` supply-chain surprise (the concern the scanner
     flagged on PR #85) on *every* user — not worth it for a file that holds no
     secrets. Explicit opt-in via `hermes-mordred vault enable-config-decrypt` is
     retained; trace-minimization for high-threat users belongs in ROADMAP v2-F6.
     **Done (2026-06-03) → v2-F8 complete**: the config.yaml lifecycle
     (init→enable→reseal→materialize→disable, plus fail-closed) was verified through a
     real Apple Silicon Secure Enclave — two live gated tests in
     `tests/integration/test_keyvault_macos.py` (`MORDRED_KEYVAULT_LIVE=1`, hands-off
     via `MORDRED_SEKEY_UNATTENDED=1`, 4/4 pass). Still opt-in (not active in the dev
     venv); coverage 98%.
4. ~~Remove the legacy MENV (`secrets_env.py`) and rewrite this note for the
   vault design~~ — **done**.

---

## 9. Tests / quality

- The pure-Python keyvault suite is green cross-platform (**1673 passed / 13
  skipped** as of 2026-06-01). `FakeBackend` performs real P-256 ECDH and
  `FakeAnchorStore` is an in-memory keychain, so the open / enroll / read paths
  run for real even in CI.
- The vault CLI (`tests/test_wizard_vault_cli_*.py`) and the production Keychain
  `AnchorStore` (`tests/test_keyvault_anchor_keychain.py`, software `_FakeOps`
  injection) are likewise green cross-platform.
- `ruff` + `ruff format` + `mypy --strict` clean (linters are version-pinned via
  the dev extra in `pyproject.toml` — `ruff==0.15.13` / `mypy==2.1.0`).
- Native SE / Keychain tests are environment-gated (`MORDRED_KEYVAULT_LIVE`; CI
  has no hardware Enclave). As of this note, the Keychain `AnchorStore`
  round-trip and the `vault init` → `add` → `cat` round-trip on real hardware
  (Apple Silicon) were verified passing by hand.

---

## 10. Codex design review — P1 closed

- **P1-a wmk substitution**: open pins the wmk fingerprint against the
  (write-protected) anchor **before** the SE-unwrap.
- **P1-b whole-manifest rollback**: the anchor pins `generation` and names the
  canonical `manifest.<N>`.
- **P1-c crash safety**: the anchor flip is the commit point; a crash before it
  keeps generation N.

Codex confirmed sound (no change needed): single-writer crash ordering, the
non-redundancy of content-address and AEAD, `_gc` set membership, and the
recovery sidecar's isolation.

---

## 11. Unified `encryption` command (operator toggle)

The earlier per-target on-ramps (`vault enable-config-decrypt`, `vault
set-memory-key`, …) are kept, but a single namespace now toggles every at-rest
target the same way:

```
hermes-mordred encryption status                       # all targets, non-prompting (+ --json)
hermes-mordred encryption enable  {env|config|memory}  # turn on
hermes-mordred encryption disable {env|config|memory}  # turn off — reversible, keeps the vault copy
hermes-mordred encryption purge   {env|config|memory} --yes   # remove the encrypted copy — destructive
```

`disable` and `purge` are **per-target state transitions, not symmetric
operations** — each is documented below. The surface always uses the default
vault root (a custom `--root` would not be seen by the macOS startup shims, which
read `default_vault_root()`).

| verb | `env` | `config` | `memory` |
|---|---|---|---|
| **enable** | enroll `.env`; on macOS remove the plaintext + clear the opt-out marker (runtime injects from the vault) | enroll `config.yaml` + write the opt-in marker (the `.pth` startup hook materializes it) | ensure `HERMES_MEMORY_KEY` in the vault `.env` + set `memory.encryption.enabled: true` |
| **disable** (reversible) | restore a conflict-safe plaintext `.env` + write the opt-out marker so the runtime stops injecting; vault copy kept | remove the marker, guarantee a readable plaintext; vault copy kept | set the flag `false`, **keep the key** (suspend — re-enable restores readability); warns if encrypted memories exist |
| **purge** (`--yes`) | restore the plaintext (backing up a diverging vault copy to `.env.vault-purged`), then `unenroll_file('.env')` | recover the plaintext → unenroll the vault copy → drop the marker last (crash-safe order) | set the flag `false` and strip `HERMES_MEMORY_KEY` from the vault `.env` (orphans memories under the old key) |

- **`status` is side-effect-free**: it reads the plaintext manifest body
  (`parse_unverified` — enrolled names are operational metadata, not secret), the
  config opt-in marker, the `memory.encryption.enabled` flag, and never opens the
  cold path or probes the device key. `active` is the *effective* state on this
  OS — an enrolled target off macOS (or with the env opt-out marker set) reports
  `active=false` rather than implying protection that is not wired.
- The **env opt-out marker** (`<home>/mordred/env-vault.optout`) is the reversible
  off switch honored by `install_vault_env_decrypt`; it mirrors the config opt-IN
  marker but inverted (env is injected by default once enrolled).
- **`OpenVault.unenroll_file()`** is the purge primitive — the mirror of
  `enroll_file` (drop the name, bump the generation, flip the anchor, GC the
  orphan blob) with the same stale-handle / recovery-mode guards.

Implementation: `wizard/{encryption_cli,env_decrypt_cli,memory_cli,config_decrypt_cli}.py`,
`keyvault/vault.py:unenroll_file`, `keyvault/_runtime_env.py` (opt-out marker).

### 11.1 `workspace` target (macOS only)

The fourth target wraps the external Touch ID / Secure Enclave-gated
`claude-private` encrypted APFS volume (`wizard/workspace_cli.py`). It is
**macOS-only** (fail-closed off-darwin) and **never auto-mounts** the volume:

| verb | behaviour |
|---|---|
| **enable** | drive `claude-private-setup` when not set up; guide the operator if the external tool is not installed; no-op when already set up |
| **disable** | `hdiutil detach` the mount — seals it (non-destructive, instantly re-mountable); no-op when already sealed |
| **purge** (`--yes`) | **refuses while mounted**; warns that the contents are destroyed too; removes the sparsebundle + key material. Does **not** auto-mount/export — unlocking the SE-sealed volume needs a live Touch ID, so the operator exports first (`claude-private`, copy out, then purge). This keeps the destructive path free of an un-testable auto-unlock. |

All side effects go through injected `run` / `is_mounted` / `tool_on_path`, so the
orchestration is unit-tested on any platform; the real SE/mount path still needs
real-hardware verification.
