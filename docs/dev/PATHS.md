# Mordred-Owned Filesystem Paths (Hermes-base)

This is the complete inventory of persistent paths Mordred reads, writes, or
deliberately manages. `<home>` means the active, profile-aware Hermes home
returned by `hermes_constants.get_hermes_home()`; it defaults to `~/.hermes`
and honors `HERMES_HOME` when set before plugin discovery.

Most private Mordred state is under `<home>/mordred/`, but that is not an
absolute containment rule. The extension uses Hermes's established
`<home>/extension/` directory, the encryption facade manages selected
Hermes-owned files, native helper executables live outside the profile, and
the optional workspace target has user-home paths of its own.

## Overview

| Path | Owner/writer | Readers or purpose |
|---|---|---|
| `<home>/mordred/audit.log*` | shared audit writer | `audit` CLI and audit consumers |
| `<home>/mordred/.audit.log.lock` | shared audit writer | cross-process audit serialization |
| `<home>/mordred/policy.json` | wizard | privacy-check, LLM guard, network |
| `<home>/mordred/.policy-write.lock` | wizard | policy/config write serialization |
| `<home>/mordred/.policy-write.pending` | wizard | interrupted two-file transaction marker |
| `<home>/mordred/credentials/network.json` | wizard/network setup | non-secret network references |
| `<home>/mordred/tor-data/` | Mordred-launched Tor | Tor runtime state |
| `<home>/mordred/keyvault/` | keyvault | hardware-wrapped key records and envelopes |
| `<home>/mordred/.keyvault.*` | keyvault | lifecycle lock, reset journal, generation epoch |
| `<home>/mordred/vault/` | vault/encryption CLI | at-rest file vault |
| `<home>/mordred/env-vault.optout` | encryption CLI | disables runtime `.env` injection |
| `<home>/mordred/config-vault.marker` | encryption CLI | enables config materialize/reseal lifecycle |
| `<home>/mordred/memory-vault.marker` | encryption CLI | arms the agent-memory at-rest encryption runtime |
| `<home>/mordred/memory-vault.optout` | encryption CLI | pauses the memory hook (paused by operator) |
| `<home>/extension/` | extension and keyvault signer | pairing, E2E, WebAuthn, history, wallet config |
| `<home>/.env` | Hermes + Mordred writers | plaintext runtime secrets when present |
| `<home>/config.yaml` | Hermes + Mordred writers | Hermes config and Mordred plugin sections |
| `<home>/memories/*.md` | Hermes memory tool | sealed by Mordred's memory hook when armed, otherwise plaintext |
| user-home workspace paths | external `claude-private` tools | optional macOS encrypted workspace |

Unless a section says otherwise, private Mordred directories are mode `0700`
and private files are mode `0600`. Implementations additionally reject unsafe
symlink/special-file endpoints at security-sensitive boundaries.

## `~/.hermes/mordred/audit.log`

The displayed path uses the default home; substitute the active `<home>` for a
profile or isolated test.

### File contract

- The active file is either plaintext NDJSON or line-oriented encrypted MRAL.
- Rotation is daily or when the active file reaches 10 MiB. Rotated files use
  `audit.log.YYYY-MM-DD[.N][.gz]` and are retained for 30 days.
- Cooperating processes lock `<home>/mordred/.audit.log.lock` across format
  checks, rotation, append, and rollback.
- Before keyvault audit-key provisioning, NDJSON mode `0600` is the baseline.
  When encrypted logging is expected but cannot be created, Mordred writes a
  plaintext downgrade marker with reason
  `mordred.degraded.audit_encryption_unavailable` when possible.
- Encryption provides confidentiality and per-record AEAD integrity. It does
  not make the history append-only against another process running as the
  same user.

### Entry contract

Every logical entry has `ts`, `event`, `decision`, and `reason`, plus bounded
event-specific fields. Current writers use `allow`, `block`, `override`,
`warn`, `raise`, or `fallback`. The closed reason-code contract is
`privacy_check._audit_reasons.ReasonCode`; [`POLICY.md`](./POLICY.md) explains
live and reserved values.

Never write secret values, seed words, passphrases, raw key IDs, complete
untrusted documents, or arbitrary endpoint paths into an audit field.

### Writer layer

`privacy_check/audit.py` supplies the serialized NDJSON writer and the writer
factory. `keyvault/log_encryption.py` supplies MRAL. Other plugins append
through the shared writer protocol rather than inventing another log format.

### Consumer CLI

- `hermes-mordred audit tail [-n N]`
- `hermes-mordred audit grep <pattern>`
- `hermes-mordred audit decrypt --date YYYY-MM-DD`
- `hermes-mordred audit purge --before YYYY-MM-DD --yes`

### Tamper detection roadmap (v2)

Same-UID history deletion/rewrite is not detected in the current release.
Hash-chain or external-anchor work belongs to [`ROADMAP.md`](./ROADMAP.md)
§v2-F4 and must not be inferred from file permissions or AES-GCM alone.

### Multi-process write serialization (M1 resolved)

The stable sidecar `flock` serializes cooperating processes. Each encrypted
file has its own wrapped DEK; a writer that observes an inode/header ownership
change discards its stale in-memory DEK and creates or adopts a valid successor
under the lock. This can create extra rotations but must not create an
undecryptable mixed-owner file.

### Cross-references

- [`SPEC.md`](./SPEC.md) §Audit log policy
- [`POLICY.md`](./POLICY.md) §Audit log `reason` enum (frozen)

## `~/.hermes/mordred/policy.json`

### Purpose

`policy.json` is a mode-`0600`, debuggable cross-plugin snapshot produced from
the Mordred sections of `<home>/config.yaml`. It is not an independent manual
configuration authority.

### File contract

- UTF-8 JSON, two-space indentation, atomic replacement.
- Wizard writers serialize on `.policy-write.lock`.
- `.policy-write.pending` spans the `config.yaml` + `policy.json` transaction.
  Readers that observe it fail closed rather than combine mismatched files.
- A successful `configure` or `upgrade` reconciles a stale pending marker.
- `provider_overrides` is intentionally preserved verbatim so malformed
  operator evidence remains visible to the strict transport gate instead of
  being silently normalized away.

### Schema sketch (Phase 1)

The current top-level shape is:

```json
{
  "policy": "strict | lenient | off",
  "allow_cloud_llm": false,
  "cloud_provider_allowlist": [],
  "audit_log_path": "<home>/mordred/audit.log",
  "local_llm_endpoint": "http://localhost:1234/v1",
  "local_llm_model_id": "",
  "cloud_attempt_action": "always-block | prompt-once",
  "disable_ipv6": true,
  "provider_overrides": {}
}
```

Network setup also writes its detailed route settings under
`plugins.mordred_network` in `config.yaml`; they are not all duplicated into
the snapshot. [`POLICY.md`](./POLICY.md) owns validation and defaults.

### Defaults

New and migrated installs default to `policy=lenient`. Strict readers use
failure-closed defaults for malformed cloud allowance, endpoint, and transport
evidence.

### Consumer CLI

- `configure` and `upgrade` write the snapshot.
- `policy show`, `policy explain`, and `policy dry-run` inspect/evaluate it.
- `policy reload` clears the in-process policy cache; it is not a filesystem
  watcher.

### Cross-references

- [`POLICY.md`](./POLICY.md) §`plugins.mordred_privacy_check` config schema
- [`PLAN.md`](./PLAN.md) §1.3 Plugin: `mordred_wizard`

## `~/.hermes/mordred/credentials/`

### Purpose

`credentials/network.json` stores references and advisory network settings,
not the Mullvad account value itself. The secret lives in `<home>/.env` as
`MORDRED_MULLVAD_ACCOUNT` until the operator enrolls `.env` in the vault.

### File contract

- Directory `0700`; JSON file `0600`; atomic wizard writes.
- The current network runtime reads resolved settings from `config.yaml` /
  `policy.json`; `credentials/network.json` is a non-secret companion record.
- Writers reject secret-shaped values where an environment-variable reference
  is required.

### Schema sketch (v1, finalized in Phase 3 PR3a / 2026-05-14)

The historical heading remains an anchor. Current shape:

```json
{
  "mullvad": {
    "account_id_env": "MORDRED_MULLVAD_ACCOUNT",
    "relay_country": "auto",
    "killswitch": true
  }
}
```

Tor binary/port and pluggable VPN command settings belong in
`plugins.mordred_network`, not this file.

### Cross-references

- [`POLICY.md`](./POLICY.md) §Mullvad credential indirection
- [`SPEC.md`](./SPEC.md) §Plugin: `mordred_network`

## `~/.hermes/mordred/tor-data/`

### Purpose

DataDirectory for the Tor child process launched by Mordred. Tor owns its
consensus cache, keys, and state inside this directory; Mordred supplies and
owns the location but does not interpret those files.

### File contract

`network.register()` resolves the directory beneath the active home and passes
it to the Tor runtime. Do not copy it between profiles as configuration or
treat it as a backup.

### Cross-references

- [`SPEC.md`](./SPEC.md) §Plugin: `mordred_network`
- [`PLAN.md`](./PLAN.md) §3.1 Plugin: `mordred_network`

## `~/.hermes/mordred/keyvault/`

### Purpose

Hardware-key metadata, verification-digest commitments, and purpose-bound
encrypted envelopes. It is distinct from `<home>/mordred/vault/`, which is the
file-encryption container used by the `encryption` facade.

No seed phrase, recovery passphrase, PoW input, unwrapped DEK, private Ethereum
key, or plaintext backup blob is persistently staged here. In particular, the
keyvault API returns backup bytes to its caller; it does not create a temporary
export file.

### File contract

- Root directory `0700`; subordinate regular files `0600`.
- `<home>/mordred/.keyvault.lifecycle.lock` serializes operations with reset.
- `.keyvault.reset.json` is a durable reset-recovery journal.
- `.keyvault.generation` prevents cached writers from crossing reset/re-init.
- Native-key deletion must succeed before `keyvault reset` removes the root.
- macOS chooses the native helper/key store with documented ordered fallback;
  Linux uses the TPM helper and deliberately has no software-key fallback.

### Expected substructure (Phase 4 PR4 step-0 freeze, 2026-05-15 — codex H3 / H4 corrected)

```text
<home>/mordred/
├── .keyvault.lifecycle.lock
├── .keyvault.reset.json          # only while reset is pending/uncertain
├── .keyvault.generation
└── keyvault/
    ├── .lock
    ├── meta.json
    ├── digests/<key-id-hash>.commit
    └── ciphertexts/<key-id-hash>/<purpose-hash>/<envelope-id>.gcm
```

Clear logical key IDs are metadata, never path components. Mutations use
parent lifecycle lock → root lock ordering, atomic writes, durable parent
flushes, and validated profile-scoped native-key IDs.

### Internal Python API (Phase 4 PR4 step-0 freeze, 2026-05-15)

The stable internal surface includes `prepare_generate`, `confirm_generate`,
`generate`, `encrypt`, `decrypt`, `verify_digest`, `export_backup`, and
`import_backup` in `mordred_hermes.keyvault.api`.

`export_backup()` returns bytes without choosing a path. The wizard's
`keyvault export --output <path>` command owns safe publication of those bytes.

### Consumer CLI

The current keyvault subtree provides `init`, `list`, `verify-digest`,
`export --output`, `recover --blob`, `reset`, `enable-se`, `enable-tpm`, and
`eth`. Export output is caller-owned and may be outside the managed layout.
Its immediate parent must be a real directory and the final path must not
exist. The wizard publishes a complete mode-`0600` file atomically without
replacement and leaves no partial final file on failure.

### Pre-Phase-4 behavior

Historical anchor: profiles created before keyvault initialization simply lack
this directory. Absence is a valid, side-effect-free “not initialized” state.

### Cross-references

- [`SPEC.md`](./SPEC.md) §Plugin: `mordred_keyvault`
- [`TODO.md`](./TODO.md) §4.2 Wizard additions (Phase 4)

## `<home>/mordred/vault/`

This separate file vault contains `manifest.<generation>.mvmf`,
content-addressed `blobs/*.blob`, `recovery.mrkv`, and `.lock`. A device-bound
anchor outside the directory pins the authoritative generation and master-key
fingerprint; the passphrase sidecar is the cold recovery path.

`encryption enable env|config|memory` and the low-level `vault` commands manage
this root. On macOS, `.env` injection and config materialize/reseal can make an
enrolled copy the active runtime source. The production device-anchor store is
the macOS login Keychain, so direct enrollment refuses outside macOS and
`setup` / `encryption enable all` skip these targets. If a copied vault or an
injected test backend already exposes enrollment metadata, `encryption status`
reports it as paused/inactive rather than claiming protection; plaintext
runtime files remain authoritative.

The markers `<home>/mordred/env-vault.optout` and
`<home>/mordred/config-vault.marker` control those macOS lifecycles;
`<home>/mordred/memory-vault.marker` and `<home>/mordred/memory-vault.optout`
control the agent-memory at-rest encryption runtime the same way — marker
present arms the hook, optout present pauses it regardless of the marker. On
macOS, a copied vault can be re-keyed on a new device with `vault recover` and
its recovery passphrase; this is different from `keyvault recover --blob`.
Linux has a TPM wrapping backend for the separate keyvault but no production
device-anchor store for this file vault. Production enrollment and
`vault recover` are therefore unsupported there.

## `<home>/extension/`

The extension owns:

- `.lock`, `pending.json`, `state.json`, and `attest_key.pem` for pairing,
  tokens, channel keys, replay state, and local attestation;
- `webauthn.json` for the credential bound to the active pairing generation;
- `history.enc` for encrypted projected conversation history; and
- `.wallet.lock` / `wallet.json` for account and RPC selection (never a raw
  private key).

These are private mode-`0600` files beneath a real mode-`0700` directory.
Pairing state and the software attestation private key are security-sensitive;
do not publish them as diagnostics.

## Hermes-owned and external targets

- `<home>/.env`: Hermes runtime secrets and the Mullvad account. Mordred's
  writer preserves unrelated keys; the macOS vault lifecycle can remove the
  plaintext after verified enrollment and inject values at startup.
- `<home>/config.yaml`: Hermes's canonical config. The wizard round-trips only
  Mordred sections and plugin enablement; the optional macOS vault lifecycle
  materializes plaintext while Hermes runs and reseals it at exit.
- `<home>/memories/*.md`: written by Hermes's memory tool. Files are
  plaintext unless Mordred's memory hook is armed; when armed, every write is
  sealed in the `HERMES-MEMORY-ENC-v1` format, and drift backups
  (`*.md.bak.<ts>`) are sealed too. Mordred stores `HERMES_MEMORY_KEY` in the
  vault `.env` and owns the sealed container format; Hermes owns the entry
  format inside the plaintext and the memory tool itself. The legacy
  `memory.encryption.enabled` config flag is inert; `encryption status`
  reports a legacy flag without a marker as "legacy flag set — run
  `encryption enable memory`".
- `~/.local/bin/mordred-hermes-sekey` and
  `~/.local/bin/mordred-hermes-tpmkey`: helper executables installed by the
  native-helper commands. Explicit helper environment variables and a final
  `PATH` lookup can select another binary; that trust boundary is in SPEC.
- macOS workspace defaults:
  `~/Private/claude-private.sparsebundle`,
  `~/.config/claude-private/passphrase.wrapped`, and
  `~/.claude-private-mnt`. `CLAUDE_PRIVATE_*` overrides can relocate them.
  External `claude-private` tooling owns the volume format and mount lifecycle.

## Migration from legacy OpenClaw paths

`hermes-mordred upgrade` can detect `~/.openclaw/mordred/` and migrate the
legacy audit log, policy snapshot/config, keyvault tree, and credentials tree.

- Audit input must be plaintext UTF-8 NDJSON with valid object rows. Overlap
  requires `--audit-merge=skip|append-all|abort`; the migration marker prevents
  duplicate append on ordinary reruns.
- Policy conflicts require `--policy-conflict=keep-existing|overwrite|abort`
  in non-interactive use.
- Sensitive trees reject links/special files, stage privately, compare a final
  source rescan, and never overwrite differing destination data implicitly.
- Copying a native-key-backed keyvault is only useful where the corresponding
  native key remains available. For cross-machine migration, create a portable
  MRKV snapshot with `keyvault export` and restore it into a fresh profile with
  `keyvault recover` instead of copying the managed keyvault directory.
- `--reset` selects destructive overwrite behavior for migration conflicts; it
  is unrelated to `keyvault reset`.

## Access boundary discipline

- Resolve production profile paths through the shared home resolver; tests may
  inject explicit temporary roots.
- Prefer owning-module APIs and shared contracts over reaching into another
  component's private layout.
- Never broaden a user-supplied path, follow a final symlink at a secret/key
  boundary, or log contents when reporting a malformed file.
- Hermes core contains no Mordred path knowledge. Optional future vendored
  enforcement remains separately specified under [`UPSTREAM.md`](./UPSTREAM.md).
- This document, not package-local READMEs, is the path ownership authority.
