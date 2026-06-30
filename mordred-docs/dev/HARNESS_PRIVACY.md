# Mordred — Harness-Driven Operation & Workspace Encryption (Threat Note)

Why driving Mordred from an external recording harness (Claude Code, Codex CLI,
Cursor, ACP clients) cannot be made privacy-preserving by encrypting the
harness workspace — and what to do instead.

Companion to:

- `SPEC.md §Threat Model & Accepted Limitations`, `SPEC.md L143` / `L289` (harness primaries bypass Hermes hooks; strict-mode harness refusal at `on_session_start`)
- `mordred-hermes/src/mordred_hermes/llm_guard/harness_detect.py` (the existing harness-refusal mechanism — **config-declared**, see §4)
- `mordred-hermes/src/mordred_hermes/keyvault/log_encryption.py` / `crypto.py` (Mordred's own at-rest encryption)

> **Status**: design / threat note. The conclusion (domain separation) is
> advisory. The hardening items in §8 and the design memos in §9–§10 are
> proposals, not yet implemented.

---

## 1. The question

> "When invoking Mordred from Claude Code, can we encrypt the Claude Code
> workspace — including everything Claude Code stores — so that Mordred usage
> stays private?"

Short answer: **the encryption is technically buildable, but it does not
deliver operational privacy.** Encryption is the wrong layer for this threat.
A recording harness and a trace-minimizing privacy tool are architecturally
opposed; encryption-at-rest does not reconcile them.

---

## 2. "Workspace" is two zones, and the sensitive one is shared

A Claude Code session's data is **not** a single directory. It splits into:

| Zone | Location | Role | Sensitivity |
|---|---|---|---|
| **Zone 1 — project working dir** | the project `cwd` (e.g. the repo) | the *artifact* Claude operates on; git-managed | medium (code + `.envrc`/`.env` if secrets are present) |
| **Zone 2 — Claude Code state dir** | `~/.claude/` (under `$HOME`, **outside** the project) | the tool's own working memory: transcripts, prompt history, command logs, caches, plugins, settings | **high** |

Zone 2 is where "what Claude saw and did" concentrates, and crucially it is
**shared across all projects**, not per-project. Observed contents (paths are
Claude Code's, not Mordred's):

- `~/.claude/projects/<encoded-project-path>/*.jsonl` — full conversation
  transcripts: every user prompt (`type: user` → `message`), tool call, and
  tool result, plus `cwd` / `gitBranch` / timestamps. **Per-project** (the
  project path is encoded into the folder name with `/` → `-`).
- `~/.claude/history.jsonl` — flat prompt-input history (`display` field = the
  prompt text, `pastedContents` = anything pasted). **Cross-project, single
  file** (thousands of entries in practice).
- `~/.claude/bash-commands.log` — executed command lines and output.
  **Cross-project, single file.**
- `~/.claude/file-history/<uuid>/<hash>@vN` — snapshots of edited files.
- `~/.claude/{paste-cache,shell-snapshots,session-data,plugins,settings.json,…}`.

**Implication:** encrypting only Zone 1 is a sieve — anything Claude reads in
Zone 1 is copied verbatim into Zone 2 the moment it is read (transcript,
command log, file-history), in plaintext, outside the encrypted boundary.

There is also **no per-tool boundary** in Zone 2. Mordred-related content is
interleaved at the *content level* inside session transcripts, `bash-commands.log`,
and `history.jsonl`. "Encrypt only Mordred's slice" is therefore not a storage
operation — there is no slice to carve out. The cross-project single-file logs
(`history.jsonl`, `bash-commands.log`) cannot even be partitioned by project.

---

## 3. Why workspace encryption does not deliver operational privacy

Encryption is **at-rest only**. Three independent reasons defeat it for the
*operation* use case:

1. **Mounted = plaintext during the whole session.** An encrypted volume must
   be mounted (decrypted) for Claude Code, git, and the toolchain to read it.
   So during operation everything is plaintext; encryption only protects the
   *gaps between sessions*, not the session itself.

2. **Transmission is out of scope of disk encryption.** Claude Code sends the
   conversation (prompts, tool output, file contents) to the model backend
   (Anthropic API by default; Bedrock/Vertex/proxy in other deployments). Local
   disk encryption has no effect on what is transmitted off-device.

3. **"Encrypted" ≠ "not recorded".** Encrypting the transcript/log at rest is
   "record → then encrypt". The record of *the fact and pattern of execution*
   (which Mordred command, when, with what arguments) is still created and
   transmitted. For a privacy tool, the metadata of use is itself the secret,
   and metadata leaks at creation/transmission time, not at-rest time.

| Encryption protects | Encryption does **not** protect |
|---|---|
| Idle-time disk theft of the at-rest store (≈ already covered by FileVault) | Plaintext state during an active session |
| | Content transmitted to the model backend |
| | The existence of the execution record (metadata) |

You cannot "operate on data while hiding it from the operator." The operator
here is Claude Code + the model backend; operating requires plaintext reaching
them. This is not solvable with encryption (short of compute-on-ciphertext,
which Claude Code does not do).

---

## 4. The fundamental opposition

- **A harness (Claude Code) is, by design, a *recording* tool.** Resumable
  sessions, history, audit, and context all depend on logging what it did.
- **Mordred is, by design, a *trace-minimizing* tool.** Not leaking the fact,
  timing, or pattern of use is the point.

Driving the trace-minimizing tool through the recording tool cannot be private.
This is already acknowledged in Mordred's own design: `harness_detect.py` matches
the **user-declared** `plugins.mordred_llm_guard.harness_primary` in
`~/.hermes/config.yaml` against the known harness identifiers (`codex` /
`claude-cli` / `cursor` / `acp-*`) — these run their own LLM call paths Hermes
hooks never observe — and under **strict mode refuses the session** (lenient
warns+audits; off is a no-op). The encryption question lands on the same
conclusion the harness detector already encodes.

> **Important nuance:** this is **declaration-based**, not runtime detection.
> `harness_detect.py` does not sniff that it is *actually* being driven by
> Claude Code; it only acts on what the user wrote in `config.yaml`. If the
> user never declares `harness_primary: claude-cli`, nothing fires. A genuine
> runtime signal (e.g. `os.isatty()`, see §8) is therefore the more robust
> guard, since it does not depend on the user self-reporting.

---

## 5. Usability collateral (a second reason against encrypting Zone 2)

Because Zone 2 (`~/.claude/`) is **shared by every project**, encrypting/gating
it harms *all* Claude Code usage, not just Mordred work:

- A biometric mount prompt on **every** session start, for **every** project.
- When unmounted, Claude Code loses settings / history / plugins / memory / MCP
  config / agents / commands — it cannot function or loses all personalization.
- **Multiple-window breakage**: concurrent Claude Code instances for different
  projects all require the one `~/.claude/` mounted; unmounting on one session's
  end breaks the others.
- Mount-lifecycle fragility: `SessionEnd` is not guaranteed on SIGKILL / crash /
  abrupt close, so the volume can be left mounted (unlocked) or contend.
- Performance: the at-rest store is large (multi-GB `projects/`, hundreds of MB
  `plugins/`) on a mounted sparsebundle.

So the approach with the most privacy upside (encrypting Zone 2) has the most
usability downside — while delivering only at-rest protection.

---

## 6. Effect × collateral of each option

| Option | Operational-privacy effect | Collateral on other Claude Code usage |
|---|---|---|
| Encrypt Zone 1 only (project dir) | ~none (leaks to Zone 2) | low (that project only) |
| Encrypt Zone 2 (`~/.claude/`) | limited (at-rest only) | **high (all projects)** |
| Mordred harness-refusal guard | high (protects operation) | ~none (only blocks Mordred operation under a harness) |
| Document a dev/operation boundary | high | none |

The safer options are also the lower-friction ones. The more you lean on
encryption, the more you get "ineffective *and* inconvenient".

---

## 7. Cross-platform note

Encrypted volumes are a standard OS feature everywhere:

| OS | Encrypted volume | Hardware key gate |
|---|---|---|
| macOS | FileVault / APFS encrypted volume / encrypted sparsebundle (`hdiutil`) | **Secure Enclave** (Touch ID) |
| Windows | BitLocker / encrypted VHDX / EFS | TPM / Windows Hello |
| Linux | LUKS/dm-crypt / gocryptfs | TPM2 (`systemd-cryptenroll`) / FIDO2 |

But the **Mordred-integrated** form (volume key wrapped by Mordred's keyvault)
is **macOS Apple Silicon only** today — see `crypto.py` ("Linux / WSL2 must not
import this module … Tier 2 / Tier 3 platform fallbacks (TPM / DPAPI) are
scheduled for `v2-OS2`"). On Windows/Linux you would use the OS-native mechanism,
not Mordred. The at-rest-only limitation in §3 is identical on all three OSes —
it is a property of encryption, not of the platform.

---

## 8. Conclusion & recommendations

**Conclusion:** Operational privacy for Mordred cannot be obtained by encrypting
the Claude Code workspace. Separate the domains:

| Activity | Run under Claude Code? |
|---|---|
| **Developing** Mordred (this repo — editing source, running tests) | ✅ Yes — no operational secrets or usage traces are produced |
| **Operating** Mordred (real key custody, real traffic anonymization) | ❌ No — run in a plain terminal **outside** the recording harness |

Operating Mordred through Claude Code leaves a trace by definition; the only
context in which Mordred operation is private is one that neither records nor
transmits — i.e. not Claude Code.

**Hardening proposals (not yet implemented):**

1. **Extend the harness guard to operation commands.** Reuse `harness_detect.py`
   so Mordred *refuses (or loudly warns on) privacy-sensitive operation commands*
   (`keyvault init` / `recover`, seed display, passphrase entry) when a harness
   primary is declared — making "no harness-driven operation" an enforced
   precondition, consistent with the existing strict-mode refusal. **Caveat:**
   this only fires on the *config-declared* `harness_primary` (see §4); it does
   not catch an undeclared Claude Code session. Pair it with the runtime check
   below.

2. **TTY guard on secret output (the more robust, runtime-based guard).**
   `wizard/keyvault_cli.py` `TerminalSeedSurface.show` (≈L226) prints the BIP39
   seed to **stdout** with no `os.isatty()` / harness check, and `clear()`
   (≈L233) uses an ANSI screen-clear that is a no-op on a captured pipe. The
   `seed_display.py` protections (network-blackout assert, screenshot probe, 60s
   timer) are all *human-at-a-terminal* mitigations and do **not** prevent stdout
   capture by a harness. Add an `os.isatty()` precondition that fails **closed**
   (like the network-blackout assert) before any seed reaches stdout. Unlike
   item 1 this needs no user declaration — a captured pipe is not a TTY, so it
   catches harness capture directly. Note: a `! command` typed in Claude Code
   also routes output into the conversation, so it is *not* a safe channel either.

3. **Document the dev/operation boundary** in `AGENTS.md` so any agent/harness
   driving this repo knows operation belongs off-harness.

---

## 9. Appendix — at-rest encryption of `~/.hermes/config.yaml` (design memo)

> **Scope:** this is a *different zone* from §2. Zone 1 (project dir) and Zone 2
> (`~/.claude/`) belong to the harness; `~/.hermes/` is **Hermes's own state
> store** (`.env`, `config.yaml`, memory). This memo records the feasibility of
> a question raised in review — *"put the key in `.env`, encrypt `config.yaml`
> with it, like the memory feature does"* — and is **advisory, not implemented.**

### 9.1 The proposal

Mirror the already-shipped memory at-rest encryption (`tools/memory_tool.py`
`MemoryFileEncryptor`: AES-256-GCM, self-describing `HERMES-MEMORY-ENC-v1`
envelope, key from `HERMES_MEMORY_KEY` in `.env`, `migrate_plaintext` on first
load) for `config.yaml`:

```
.env (plaintext, holds key) ──HERMES_CONFIG_KEY──▶ config.yaml (ciphertext)
        └──────────────────────────────────────▶ MEMORY.md   (ciphertext, already shipped)
```

### 9.2 Verdict: realistic and small — feasibility is *not* the blocker

- **Bootstrap is already solved.** `.env` is loaded at import time
  (`run_agent.py:102`, `load_hermes_dotenv`) **before** any `load_config()`
  (`config.py:3883`). So `HERMES_CONFIG_KEY` is in `os.environ` by the time
  `config.yaml` needs decrypting. Fixing the key-env name by convention avoids
  the circularity flagged earlier (no need to read `config.yaml` to learn where
  its own key is).
- **One clean seam.** Wire decrypt into `load_config()` (`config.py:3883`) and
  encrypt into `save_config()` (`config.py:4010`). Because version migrations
  (`config.py:3076+`) and the mtime cache (`config.py:35`) all go through that
  seam on the decrypted dict / the ciphertext file's mtime, **they keep working
  unchanged.** Reuse `MemoryFileEncryptor` generalized to a `ConfigFileEncryptor`
  (header `HERMES-CONFIG-ENC-v1`, AAD = `config.yaml`). ~100–150 LOC + one CLI
  command. No new dependency (`cryptography` already in use).

### 9.3 The one real cost, and the honest limits

| Item | Assessment |
|---|---|
| **Loss of hand-editability** (the only true cost) | `vim ~/.hermes/config.yaml` / manual edits stop working. Mitigate with `hermes config edit` (decrypt → `$EDITOR` → re-encrypt). Memory needed no such command because it is machine-written; `config.yaml` is human-edited, so this one command is required. |
| **Narrow security gain** | Key (`.env`) and ciphertext (`config.yaml`) sit in the **same `~/.hermes/` with the same permissions** — an attacker who can read `config.yaml` can usually read `.env` too. Protects only the *"config.yaml leaks alone"* cases (stray backup / share / log dump), **not** a local attacker. This is the **same limitation the memory feature already accepts.** |
| **At-rest only** | Same conclusion as §3 — no effect on active-session plaintext, transmission, or the harness recording. Orthogonal to operational privacy. |
| **Wrong granularity** | `config.yaml` is mostly non-secret. The cleaner direction is to keep secrets *out* of it (the codebase is already migrating that way — `config.py:3190-3201` etc.), leaving little to encrypt. |

### 9.4 Invariant to hold if implemented

The `.env`-before-`config.yaml` load order must hold for **every** entrypoint,
not just `run_agent.py`: `mcp_serve.py`, `rl_cli.py`, and the gateway must each
load `.env` before reading config. A single entrypoint that reads `config.yaml`
first would fail to decrypt. Design it to **fail closed** (error, never silently
fall back to treating ciphertext as plaintext).

### 9.5 Recommendation

Buildable and small — so the decision is about **value, not feasibility.** As a
standalone control its upside is narrow (§9.3). Prefer, in order:

1. **Keep secrets out of `config.yaml`** (move them to `.env`, future keyvault) —
   removes the thing you'd want to encrypt, and advances the existing de-dup work.
2. **Disk/volume encryption** of the whole `~/.hermes/` (FileVault / LUKS /
   BitLocker) — covers `.env` + `config.yaml` + memory at once, 0 LOC, all OSes.
3. **Config-file encryption** only as opt-in defense-in-depth for the *"config
   leaks alone"* case, accepting the same co-location limit memory already accepts.

---

## 10. Appendix — encrypting the Hermes home: key custody & unattended operation (design memo)

> **Scope:** generalizes §9 from `config.yaml` to the **whole `~/.hermes/`**
> (`.env`, `config.yaml`, `skills/`, memory). Records the key-custody options and
> the unattended-operation tradeoff. **Advisory, not implemented.** Companion to
> `KEYVAULT_BACKENDS.md` §5 (SoftwareBackend / TpmBackend / SecureEnclaveBackend).

### 10.1 One encrypted volume covers all four files

`.env`, `config.yaml`, `skills/`, and memory all live under `~/.hermes/`. A single
encrypted volume (§7) protects **all of them at rest with 0 app code** — and
dissolves every per-file headache at once:

| File | Per-file encryption pain | With a volume |
|---|---|---|
| `.env` | key-source bootstrap | none (one volume key) |
| `config.yaml` | loses hand-editability (§9.3) | stays editable (plaintext when mounted) |
| `skills/` | name randomization + index leak (§10.2) | hidden wholesale, no index |
| memory | shipped, but key co-located in `.env` | covered with no extra code |

Per-file app-level encryption (the §9 pattern) is worth it only as **narrow
defense-in-depth**; for the whole home, a volume dominates on every axis.

### 10.2 Skills: "what is installed/used" cannot be hidden at rest by file encryption

Goal: hide *which skills a user has installed and uses* from others.

- Encrypting **SKILL.md content alone leaks the inventory** anyway — via the
  directory names (`~/.hermes/skills/<id>/`), the `name → file` index the loader
  needs, filesystem metadata (file count / sizes / timestamps — `atime` can leak
  last-use **where the FS records it**, i.e. not under `noatime`/`relatime`), and
  name references in `config.yaml` / curator / skills-hub cache.
- **Randomizing names + encrypting content + dropping the index** (decrypt-all-at-
  startup, names only in RAM) removes the index leak — but that design **is a
  hand-rolled encrypted container**; an OS volume does the same correctly and also
  hides count/size/timestamps. The mapping is avoidable, but avoiding it converges
  on "use a volume."
- Either way, **runtime usage is unhideable at rest**: the skill name is injected
  into the prompt, transmitted to the model, and (under a harness) written to
  `~/.claude/` in plaintext. Only off-harness operation (§4 / §8) addresses it.

### 10.3 Key custody spectrum (security comes from *where the key lives*, not the cipher)

Two axes decide a scheme: does it **survive an unattended reboot**, and does it
**resist disk/backup theft**.

| Key custody | Unattended reboot | Resists disk theft | Needs |
|---|---|---|---|
| Plaintext key in `.env` | ✅ | ❌ key travels with the data | nothing |
| Startup passphrase (key in head) | ❌ human at every boot | ✅ | strong passphrase + recovery |
| **TPM / Secure Enclave** | ✅ | ✅ non-extractable | compatible hardware |
| Remote KMS / Vault | ✅ | ✅ + revocable, audited | network + machine identity |
| Network-presence (Tang/Clevis) | ✅ on home net | ✅ useless off-net | own network server |
| External USB token (FIDO2/PIV) | ✅ while plugged | ✅ if removed | token left in |

`.env` plaintext is the weakest: stealing the disk steals the key. Every other
row moves the key off the disk so theft yields ciphertext only.

### 10.4 The fundamental law of unattended operation

> Unattended reboot ⇒ the machine must obtain the key **by itself** ⇒ the key (or
> the means to fetch it) must live somewhere the machine reaches **without a
> human**. Therefore *"no human ever"* and *"resists theft of the whole running
> box"* cannot both hold.

A pure startup passphrase (key only in your head) **cannot** survive an
unattended reboot — by definition it must re-prompt. The practical sweet spot is
to **anchor the key in hardware (TPM/SE)**: boots unattended, key non-copyable;
the only thing you give up is the "running machine physically stolen and auto-
boots" edge (closeable with a PIN, which reintroduces a human). Pattern:
**enroll once with a passphrase → seal to the chip → reboots auto-unlock; keep
the passphrase as recovery.** This mirrors BitLocker (TPM + recovery key), LUKS
(TPM2 enrollment + passphrase keyslot), and Mordred keyvault's planned
SoftwareBackend/TpmBackend (`KEYVAULT_BACKENDS.md` §5).

### 10.5 "Exposed after login" — the limit of disk encryption

Disk encryption protects **powered-off / logged-out only**. After login the home
is plaintext to you and to any process running as you, for the whole session — it
does **not** additionally hide `~/.hermes/` from your own logged-in session
(other OS users are blocked by file permissions, not by the volume). To keep the
home locked **even while logged in** (shared machine, away-from-desk), use a
dedicated volume **mounted on demand and unmounted after use** — open only during
the brief active window, at the cost of a manual mount step.

> **Note — the env-vault `[exposed]` mark is a *different*, self-healing case.**
> Mordred's app-level `.env` encryption raises a separate `[exposed]` state in
> `encryption status` when a plaintext `~/.hermes/.env` is left on disk while the
> target is sealed. That drift is reconciled automatically — the write guard
> reseals writes made through the host config writer, and a session-boundary sweep
> (`on_session_start` / `on_session_end`, macOS only, opt-out-aware, fail-open)
> reseals any *other* stray plaintext — so `[exposed]` clears on the next session
> without a manual `encryption enable env`. This is defense-in-depth for the `.env`
> file only; it does not change the disk-encryption limit above.

### 10.6 Recommendation

| Use case | Recommended |
|---|---|
| Always-on bot / daemon | OS disk encryption with **TPM/SE (or KMS / Tang) auto-unlock** + systemd/launchd — unattended after boot, key off-disk, 0 app code |
| Interactive CLI, lock-while-logged-in wanted | **on-demand encrypted volume** (mount → use → unmount) |
| App-level per-file (`.env`-key) encryption | opt-in **defense-in-depth only** for "one file leaks but `.env` doesn't"; does **not** resist disk theft (key co-located) |
| Hiding *who uses what, when* | **not a key-custody problem** — off-harness operation (§3 / §4 / §8) |
