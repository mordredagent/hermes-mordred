# Mordred — usage guide

> **Audience**: operators running Mordred locally. For the design rationale see [`SPEC.md`](../dev/SPEC.md), [`POLICY.md`](../dev/POLICY.md), [`SECRETS_ENV_ENCRYPTION.md`](../dev/SECRETS_ENV_ENCRYPTION.md), [`KEYVAULT_BACKENDS.md`](../dev/KEYVAULT_BACKENDS.md). For developer environment setup see [`setup.md`](../dev/setup.md).
>
> **Scope**: the `mordred_wizard` CLI surface — `hermes-mordred …` (standalone) and `hermes mordred …` (once wired into the host Hermes CLI).

---

## 1. How to invoke

Mordred ships two equivalent entry points to the same subcommand tree:

| Form | When it works | Notes |
|------|---------------|-------|
| `hermes-mordred <cmd>` | Always, once the package is installed in a venv | Standalone console script. **Recommended** for this dev repo. |
| `hermes mordred <cmd>` | Only when the plugin is **enabled** in `~/.hermes/config.yaml` | The `mordred` subcommand is registered by the plugin loader at CLI init. |

In this development checkout the fully-wired venv is `.venv`:

```sh
cd <repo-root>            # /Users/.../Mordred-Hermes
.venv/bin/hermes-mordred status
```

Tip — alias it for the session:

```sh
M=.venv/bin/hermes-mordred
$M status
```

### Wiring `hermes mordred …` into the host CLI (optional)

The plugin is discovered by the loader but the `mordred` subcommand only appears
after you enable it. Edit `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - mordred_privacy_check
    - mordred_wizard
    - mordred_llm_guard
    - mordred_network
    - mordred_keyvault
```

Then `hermes mordred status` works from the same venv. Until then, use
`hermes-mordred` directly. (`hermes plugins list` does not surface entry-point
plugins; use `hermes-mordred plugins list`.)

---

## 2. First-run quickstart

New here? The guided short path lives in **[`QUICKSTART.md`](./QUICKSTART.md)** —
it walks each step as Purpose / Do / Result and tells you what to expect from the
interactive ones. In brief, run these in order (every step is idempotent and safe
to re-run):

```sh
M=.venv/bin/hermes-mordred

$M configure              # interactive setup → writes config.yaml + policy.json
$M network init           # OPTIONAL — Tor / VPN / clearnet privacy path
$M keyvault init          # create the hardware-backed keyvault
$M encryption enable env  # turn on at-rest encryption (first run creates the vault, prompts once for a passphrase)
$M status                 # verify the result at a glance
```

`status` prints a single-screen summary (`policy` / `network` / `keyvault` /
per-target `encryption`); see
[`QUICKSTART.md` §2](./QUICKSTART.md#2-first-run-in-order) for the annotated
output and the `workspace` `sealed` / `open` / `off` axis. Add `--json` for
machine-readable output.

---

## 3. Command reference

### `status` — state at a glance
```sh
$M status            # human-readable
$M status --json     # machine-readable
```

### `configure` — interactive setup
Writes `config.yaml` + `policy.json`. Interactive by default; scriptable with
`--non-interactive` (unspecified flags keep existing values).

Runs in two steps: it first delegates to the upstream `hermes setup` wizard,
then collects the Mordred-specific prompts. `hermes setup` runs on **every**
invocation (Hermes re-shows its wizard even when already configured, pre-filling
each prompt so you can press Enter to keep it). To re-run `configure` and touch
**only** the Mordred policy, pass `--skip-hermes-setup` to suppress that step.
```sh
$M configure
$M configure --skip-hermes-setup                       # Mordred prompts only, no hermes setup
$M configure --non-interactive --policy strict --no-allow-cloud-llm
$M configure --non-interactive --skip-hermes-setup --policy lenient
```
Key flags: `--skip-hermes-setup`, `--policy {strict,lenient,off}`,
`--allow-cloud-llm/--no-allow-cloud-llm`,
`--cloud-allowlist <csv>`, `--local-llm-endpoint <url>`, `--local-llm-model-id <id>`,
`--cloud-attempt-action {always-block,prompt-once}`,
`--harness {none,codex,claude-cli,cursor,acp-claude,acp-cline}`.

### `upgrade` — migrate an existing install
Idempotent migration of an existing Hermes / OpenClaw setup to Mordred
(auto-detects `~/.openclaw`). Safe to re-run.
```sh
$M upgrade
$M upgrade --non-interactive --policy-conflict keep-existing
```
Key flags: `--reset`, `--non-interactive`, `--audit-merge {skip,append-all,abort}`,
`--policy-conflict {keep-existing,overwrite,abort}`.

### `policy` — inspect the active policy
```sh
$M policy show                  # print resolved policy.json
$M policy explain <skill-id>    # explain an install decision (exit 2 = block)
$M policy dry-run <SKILL.md>    # evaluate a SKILL.md without installing
$M policy reload                # re-read policy from config.yaml
```

### `network` — privacy path control
```sh
$M network init                 # set up Tor / VPN / clearnet (Mullvad account)
$M network use {tor,vpn,clearnet}
$M network status               # active path + liveness
```

### `install` — policy-gated skill install
```sh
$M install <skill-name>         # or a path to a dir containing SKILL.md
```

### `audit` — the audit log
```sh
$M audit tail                        # most recent entries
$M audit grep <regex>                # line-wise regex search
$M audit decrypt --date YYYY-MM-DD   # decrypt that day's encrypted entries
$M audit purge  --before YYYY-MM-DD  # purge plaintext entries before a date
```

### `encryption` — the recommended on/off switch
At-rest encryption per target: `env`, `config`, `memory`, `workspace` — or `all`
to apply the verb to every target at once (best-effort; `workspace` is skipped on
non-macOS or when its tooling isn't installed, and never fails the batch).
```sh
$M encryption status                        # all targets (non-prompting)
$M encryption enable  {env,config,memory,workspace,all}
$M encryption disable {env,config,memory,workspace,all}   # reversible; keeps vault copy
$M encryption purge   {env,config,memory,workspace,all} --yes   # destructive
$M encryption change-passphrase             # rotate the recovery passphrase (alias of `vault change-passphrase`)
```

> **Changing the recovery passphrase.** `change-passphrase` rewraps the vault
> under a new passphrase and leaves the master key, the device key, and every
> enrolled file untouched — nothing is re-encrypted, and day-to-day automatic
> opening is unaffected. It tries this device's key first (so you can rotate even
> if you forgot the old passphrase, as long as the machine still works) and falls
> back to asking for the current passphrase when the device key is unavailable
> (non-macOS, or a vault copied to another machine).

### `keyvault` — hardware-backed key management
```sh
$M keyvault init                # initialise the keyvault
$M keyvault list                # list key IDs
$M keyvault verify-digest       # integrity check
$M keyvault recover --blob <path>   # restore from a backup blob
$M keyvault reset               # DESTROY all key material + remove the keyvault (irreversible; --yes to skip the prompt)
$M keyvault enable-se           # macOS: build+install Secure Enclave helper (ad-hoc signed, no Apple Developer account)
$M keyvault enable-tpm          # Linux: build+install TPM 2.0 helper (machine-bound, Tier 2)
```

### `vault` — the underlying encrypted store (advanced)
Normally driven by `encryption`; rarely used directly.
```sh
$M vault init                   # new vault sealed under a recovery passphrase
$M vault add <name> <file>      # encrypt a file under a logical name
$M vault status                 # generation + enrolled file names
$M vault cat <name>             # decrypt one entry to stdout
$M vault migrate                # import plaintext .env + config.yaml
$M vault recover                # re-key a vault copied to this machine onto its device
$M vault change-passphrase      # rotate the recovery passphrase (also exposed as `encryption change-passphrase`)
$M vault set-memory-key         # store/rotate HERMES_MEMORY_KEY
$M vault enable-config-decrypt  # put config.yaml under transparent at-rest decrypt
$M vault disable-config-decrypt # stop managing config.yaml; restore plaintext
```

#### Migrate to a new machine

The vault is sealed two ways: this device's key (the everyday hot path) and a
recovery passphrase (the cold path). When you move to a new machine, copy the
vault directory across and then re-key it onto the new device:

```sh
# on the old machine — the vault lives under <hermes home>/mordred/vault
cp -a ~/.hermes/mordred/vault /path/to/transfer/   # then move it to the new machine

# on the new machine, after restoring the directory to the same location
$M vault recover                # prompts for the recovery passphrase, re-keys onto this device's Secure Enclave
```

`vault recover` cold-opens the copied vault with the recovery passphrase and
re-wraps the **same** master key under a fresh wrapping key on this machine's
Secure Enclave (TPM on Linux), so the everyday automatic (writable) hot path
works locally again — the master key and every enrolled file are unchanged, and
your recovery passphrase stays the same for the next machine. It is the
encryption-vault counterpart to `keyvault recover` (which restores keyvault key
material from a backup blob). Until you run it, a copied vault opens read-only
(`vault status` / `vault cat` work via the passphrase, but enrolling does not).

### `plugins`
```sh
$M plugins list                 # discovered Mordred plugins
```

### `extension` — browser-extension pairing and server (preview)
```sh
$M extension pair               # print a MORT-… pairing code + terminal QR, then wait
$M extension pair --timeout 300 # seconds to wait for the extension to pair (default 600)
$M extension serve              # run the extension WebSocket server in the foreground
$M extension serve --port 7799  # bind a non-default port (default: 127.0.0.1:7788)
```
> `pair` prints a code and waits for a running extension WebSocket server to
> consume it — either this plugin's `extension serve` or a full Hermes
> gateway; both share `~/.hermes/extension/pending.json`. Needs the
> `extension` extra for the built-in pairing backend (full-gateway checkouts
> can fall back to `gateway.extension_pairing` without it) and `messaging`
> for the QR render. On
> builds without the extension package (e.g. the `0.1.0a1` wheel) it fails
> closed with a clear message.
>
> `serve` runs the plugin's own ported server (`mordred_hermes.extension`,
> requires the `extension` extra) standalone — pairing, crypto, history, and
> keyvault signing work, but chat replies are stubbed without a live Hermes
> gateway; see the README's "Browser-extension WebSocket gateway" section.
> Ctrl+C stops it; a bound port (e.g. a full gateway already on 7788) exits
> with a one-line error.

---

## 4. Interactive command walkthroughs

The reference above (§3) is terse on purpose. The three commands that run an
**interactive flow** — `keyvault init`, `network init`, and `configure` — are
walked through in full here. [`QUICKSTART.md`](./QUICKSTART.md) keeps the short
path and points back to these sections for detail.

### 4.1 `keyvault init` — the interactive ceremony

`keyvault init` is not a one-shot key generation: it is an **interactive security
ceremony that needs a real terminal**. In a pipe or non-interactive context it
aborts cleanly with a non-interactive error (and a redirected stdout is refused
separately) instead of raising a raw error — always run it in your own terminal.
Three steps, in order:

1. **Choose a Passphrase** (hidden input). It is never stored anywhere; combined
   with the Seed Phrase it protects the keyvault. Lose it and the keyvault cannot
   be recovered.
2. **A 24-word Seed Phrase is shown** (auto-clears after 60s) — write it down.
3. **Offline verification digest.** In a second tab/device, run the command below,
   then re-enter the 64-char digest it prints at the `Verification digest …`
   prompt on the primary machine:

   ```sh
   python3 scripts/keyvault_offline_digest.py
   ```

   > On this dev checkout, plain `python3` works — the script auto-re-runs under
   > the bundled venv that has `blake3`. On a bare air-gapped device, first run
   > `python3 -m pip install blake3`.

   It asks for three values in order: ① the 24-word Seed Phrase, ② the Passphrase,
   ③ the top4(PoW) hex (shown on the init screen).

> No hardware key? `keyvault init` degrades to a software-protected key by
> design — at-rest encryption still holds, the hardware-binding guarantee is
> lower. The ceremony itself is unchanged.

> The **first** `encryption enable` creates the underlying vault and asks once
> for a recovery passphrase (keep it safe — it is the cold-path recovery if the
> device key is ever lost). Later enables reuse it silently. You *can* pre-create
> the vault with `vault init`, but you don't need to — `encryption` drives it.

> **On ordering**: the recommended order is `keyvault init` → `encryption enable
> env`. But you *can* run `encryption enable env` **directly** — on first run it
> auto-creates the underlying vault and device key and asks once for a recovery
> passphrase. The difference is not "does it work" (both do); it's that running
> `keyvault init` first takes you through the **formal 24-word seed backup
> ceremony** before anything is encrypted. If you just want encryption on, running
> `enable` directly is fine.

### 4.2 The device key and the recovery passphrase are different things

The **device key** that `keyvault init` creates and the **recovery passphrase**
that `encryption enable` asks for are **not the same**. They are **two keyholes**
into the *same single master key* — split on purpose.

| | ① Device key | ② Recovery passphrase |
|---|---|---|
| Created by | `keyvault init` (also auto-made by a direct `encryption enable`) | `encryption enable` (asked once, on first run) |
| What it is | a Secure Enclave / TPM hardware key | a string you remember |
| Where it lives | inside this device's chip (can't be extracted) | in your head / a password manager |
| When it's used | **automatically** on this device (no typing — for unattended runs) | to **recover** when the device is lost (typed by hand) |
| Weakness | useless if the device breaks or is lost | must be typed each time / you must store it |

Both seal the same master key:

```
.env secrets ──encrypt── master key ┬─ sealed by ① device key   (hot path, automatic)
                                     └─ sealed by ② passphrase   (cold path, recovery)
```

**Why not collapse them into one?**
- **Only ①** → lose the device and the vault is **unrecoverable forever**.
- **Only ②** → you must type it on every startup (**no unattended operation**) and you lose hardware protection.

① can't be carried (it never leaves the chip); ② can. They cover each other's
weakness — the classic "**something you have (the device) + something you know
(the passphrase)**" pairing. Since ① literally cannot be typed, they can't be the
same one even in principle.

### 4.3 Touch ID prompts — why several per command, and how to silence them

On macOS the device key (①) lives in the **Secure Enclave**, and by default it is
created in **attended** mode: macOS asks for **Touch ID every time the vault is
unwrapped**. Each component that opens the vault prompts independently, so a
*single* `$M …` run can unlock the vault more than once:

- the `config` decrypt hook at interpreter startup (after `encryption enable config`),
- the `.env` injection when the plugin loads (after `encryption enable env`),
- plus whatever the command itself touches (e.g. `encryption enable memory`
  re-enrolls `.env`).

So with `env` + `config` on you will typically see **2–3 Touch ID prompts per
command** — expected, not a bug.

To make the hot path **silent** (no Touch ID while the Mac is unlocked), build the
SE helper in **unattended** mode **before** the device key is first created:

```sh
$M keyvault enable-se --unattended   # build + install the SE helper as a no-Touch-ID key
$M keyvault init                      # the device key is now created unattended
```

After this the vault decrypts with **zero Touch ID prompts** while your session is
unlocked.

> **Trade-off**: an unattended SE key (access control `.privateKeyUsage` only) can
> be unwrapped by any process running as you while the Mac is unlocked — you trade
> per-use biometric confirmation for convenience. Ciphertext-at-rest and the
> recovery passphrase (②) are unaffected.

> **Already created an attended key?** The attended/unattended choice is fixed when
> the key is created, so switching means re-keying the vault onto a fresh
> unattended key — see [SECRETS_ENV_ENCRYPTION.md](../dev/SECRETS_ENV_ENCRYPTION.md)
> (`keyvault enable-se`).

### 4.4 `network init` — the dialog and prompts

`network init` is interactive. The first thing it shows is the radio dialog —
**Network privacy path**:

```
   ┌─| Network privacy path |──────────┐
   │  ( ) tor                          │
   │  ( ) vpn                          │
   │  (*) clearnet                     │
   │                                   │
   │     < Ok >      < Cancel >        │
   └───────────────────────────────────┘
```

It picks the **default** route written to config — `(*)` marks the current
choice (`clearnet` on a fresh setup). This is just the default; you can still
switch any time later with `network use`.

**How to operate it**: **↑ / ↓** move the highlight, **Space** selects (moves
the `*`), **Tab** jumps to the `< Ok >` / `< Cancel >` buttons, **Enter**
activates the focused button.

**What each route is** — what the setting actually does, and what it needs:

- **`tor` — anonymity, slowest.** Mordred launches the official `tor` daemon as a
  child process and routes traffic through a local SOCKS proxy (port `9050` by
  default); your traffic hops through the Tor network and your source IP is
  hidden. *Needs:* `tor` installed (`brew install tor` / `apt-get install tor`).
  *Note:* bridges / obfs4 / Snowflake (for censored networks) aren't supported in
  v1. Pick this when anonymity matters most and you can accept the speed cost.
- **`vpn` — IP privacy with speed (any VPN; Mullvad recommended).** The `vpn`
  route can drive any VPN — Mullvad is the recommended default, but `wireguard`
  / `custom` providers let you use Proton VPN, IVPN, ExpressVPN, and others (see
  *Using a different VPN* below). With Mullvad, Mordred drives the official
  `mullvad` CLI to connect; your real IP is hidden behind the VPN exit, and it
  judges liveness by handshake age. The *killswitch* prompt blocks all traffic
  if the VPN drops. *Needs (Mullvad):* the Mullvad app/CLI installed,
  `mullvad account login`, and a Mullvad account (a paid service). macOS (Apple
  Silicon) and Ubuntu/Debian only; Windows is out of scope in v1. Pick this for a
  hidden IP without Tor's slowdown.
- **`clearnet` — direct, no privacy (default).** A genuine no-op: no proxy, no
  daemon, no traffic rewriting — your connection goes straight out as usual.
  *Needs:* nothing. Fastest and simplest, but your source IP is fully visible.
  Pick this if you don't need anonymity or just want things working.

After the path, `network init` asks the **Tor prompts**, then a **VPN provider**
question, then the prompts for whichever provider you picked. **Each prompt only
matters for one route** — if you picked `clearnet`, none of them apply, so just
press **Enter** through them.

**Tor route only** (relevant if you picked **tor**) — defaults are usually fine:

| Prompt | Default | What it means |
|---|---|---|
| Tor binary path | `tor` | Where the `tor` program is. Leave as `tor` if it's on your PATH. |
| Tor SOCKS port | `9050` | Local port Tor's SOCKS proxy listens on. Standard is 9050; rarely changed. |

**VPN route only** (relevant if you picked **vpn**) — `network init` asks **which
VPN provider** to use *first*, and only then that provider's prompts:

| Provider | Use it for | What `network init` then asks |
|---|---|---|
| `mullvad` *(default)* | Mullvad — the only provider allowed in **strict** mode. | The 3 Mullvad prompts below. |
| `wireguard` | Any VPN that exports a WireGuard `.conf` (Proton VPN, IVPN, Windscribe, self-hosted). | **WireGuard config path** — the `.conf` file. Mordred runs `wg-quick up/down` on it. |
| `custom` | Any VPN with only its own CLI (ExpressVPN, NordVPN, Surfshark). | **up / down / health** commands, e.g. `expressvpnctl connect` / `expressvpnctl disconnect` / `nordvpn status`. |

The **Mullvad prompts** appear *only if you keep the `mullvad` provider* — pick
`wireguard` or `custom` and you're never asked for a Mullvad account number:

| Prompt | Default | What it means |
|---|---|---|
| Mullvad account number | (keep current) | Your Mullvad account number. Blank keeps the saved one; saved to `~/.hermes/.env`. |
| Mullvad relay country | `auto` | `auto`, or a 2-letter code (e.g. `se`) to pin the VPN exit country. |
| Mullvad killswitch | `no` | Lockdown mode — block all traffic if the VPN drops, so your real IP can't leak. |

> **In short:** the route is the only choice that affects most people.
> Want **clearnet** (the default)? Just Enter through everything. Pick **tor** →
> answer the 2 Tor prompts (defaults usually fine). Pick **vpn** → choose a
> provider, then answer its prompts (3 for Mullvad).
>
> Prefer no dialog? Set everything from flags in one shot:
> `$M network init --non-interactive --path tor` (see `network init --help`).

#### Using a different VPN (not just Mullvad)

Mullvad is the **recommended default**, but the `vpn` route can drive any VPN —
the **VPN provider** question above is where you choose, and the Mullvad prompts
are skipped entirely when you don't pick Mullvad. So **Proton VPN** →
`wireguard` (download its `.conf` from the Proton portal); **ExpressVPN** →
`custom` (`expressvpnctl connect` …). You can also set these directly in
`~/.hermes/config.yaml` under `plugins.mordred_network`: `vpn_provider`,
`wireguard_config_path`, and `custom_up_cmd` / `custom_down_cmd` /
`custom_health_cmd` (each a YAML list, e.g. `[expressvpnctl, connect]`).

> **Strict mode is Mullvad-only.** Mordred can verify a kill-switch / DNS-leak
> protection only for Mullvad (it drives `mullvad lockdown-mode` directly), so
> under **strict** policy a `wireguard` / `custom` provider is **refused**
> (fail-closed). Use them under **lenient** / **off** policy — fine for everyday
> IP privacy. Custom commands run as argv (no shell) and are read only from your
> config. Platform: macOS + Linux.

### 4.5 `configure` — policy mode and the agent harness in detail

`$M configure` walks through a short list of questions — it runs the underlying
Hermes setup first, then Mordred's own prompts. **If in doubt, press Enter
through all of them**: the defaults are the safe, private choice.

| # | Question | Default | What it means | Do |
|---|---|---|---|---|
| 1 | Mordred policy mode | `lenient` | How strictly rules are enforced (detail below). | Enter |
| 2 | Allow cloud LLM providers? | `N` | Permit cloud LLMs at all. | Enter |
| 3 | Cloud provider allowlist | (hidden) | Only shown if you answered `y` above. Pick providers from a checkbox list (Space to toggle, Enter to confirm). | Skipped on `N` |
| 4 | Local LLM endpoint URL | `http://localhost:1234/v1` | Where your local LLM is reached. | Enter |
| 5 | Local LLM model id | empty | Local LLM model name. | Enter |
| 6 | On cloud LLM attempt under strict mode | `always-block` | What to do when a cloud LLM is attempted under strict. | Enter |
| 7 | Agent harness | `none` | Which agent tool drives Hermes (Claude CLI / Codex / Cursor / …). | Enter |

> - Questions 2–7 only change runtime behaviour under **strict** mode; with the
>   default `lenient`, nothing is blocked.
> - `prompt-once` (Q6) asks once per provider whether to allow a one-time call to
>   a non-allowlisted cloud provider under strict mode — but only at an
>   interactive terminal. Headless / harness / CI sessions have no TTY, so it
>   fails closed to `always-block` there. The decision is cached for the session
>   and audited as `policy.strict.cloud_prompted_allow` / `_deny`.
> - Q7 (agent harness): pick the tool you actually drive Hermes with (Codex /
>   Claude CLI / Cursor / …) for accurate auditing, or `none` if unsure. Under
>   strict mode a declared harness refuses the session — by design, because
>   Mordred cannot observe that tool's LLM traffic.
> - `configure` only writes `config.yaml` + `policy.json`. It does **not** create
>   keys or encrypt anything — that is `keyvault init` → `encryption enable`.

#### Policy mode (Q1) in detail

| Mode | What it means | Who it's for |
|---|---|---|
| `strict` | The strictest. Blocks cloud LLMs, disables IPv6, and refuses to run when a known AI harness is detected. | Advanced users who want maximum privacy. |
| `lenient` (**default / recommended**) | Standard. Guards are active but stay out of your way — the built-in default. | Most people, and anyone who just wants it working. |
| `off` | Disables all guards entirely. | Anyone who wants no restrictions at all. |

> Only `strict` can actually stop you (refuse a session or block an install).
> `lenient` just records audit warnings; `off` does nothing.

#### Agent harness (Q7) in detail

This setting declares **which tool you run Hermes through**. It is not a switch that
raises or lowers security — think of it as an honesty field that tells Mordred exactly
what it can and cannot police.

**Premise — how Mordred guards you:**
Mordred hooks into `pre_llm_call`, the moment right before Hermes calls a cloud LLM, and
decides "allow or deny this traffic." This rests on one assumption: **every LLM call must
pass through that hook.**

```
[your code] → [pre_llm_call hook inspects] → [cloud LLM]
                       ↑ Mordred decides allow / deny here
```

**Problem — external tools (harnesses) take a side road:**
Codex / Claude CLI / Cursor / ACP clients carry their own line to the AI. They call the LLM
*without going through Hermes*, so the hook never sees it — the traffic is invisible to
Mordred.

```
[Codex / Claude CLI / …] ──direct──→ [cloud LLM]   ← bypasses the hook = invisible to Mordred
```

**So strict refuses:**
`strict` mode guarantees the policy can be *fully* enforced. If invisible traffic exists it
cannot guarantee that, so it would rather stop than let it half-through (fail-closed).

| Mode | When a known harness is detected |
|---|---|
| `strict` | **Refuses** the session (can't guarantee enforcement → stop) |
| `lenient` | **Warns + audits** and continues |
| `off` | Does nothing (the check is disabled) |

**How to pick:** running `hermes` directly in your terminal → `none`. Running it inside
Codex / Claude CLI / Cursor / Zed (ACP) → pick that tool. `acp-claude` / `acp-cline` apply
only when you reach Claude / Cline **via ACP (Agent Client Protocol)** (e.g. the Zed editor).
If none of this rings a bell, `none` is correct.

#### Inspect or change it later

| Do (command) | Purpose | Result |
|---|---|---|
| `$M policy show` | Print the resolved policy currently in force. | Outputs `policy.json`. |
| `$M configure --non-interactive --policy strict` | Switch to strict mode without prompts. | Policy mode set to `strict`. |
| `$M policy explain <skill-id>` | Explain whether a skill would be allowed to install. | Prints the decision (exit 2 = block). |

---

## 5. The three storage layers

Mordred's at-rest encryption is a stack — pick the highest layer that does the job:

```
encryption   ← recommended on/off switch (env / config / memory / workspace)
   │
keyvault     ← hardware-backed key material (Secure Enclave on macOS, TPM on Linux)
   │
vault        ← the underlying encrypted file store (advanced; rarely touched directly)
```

- **`encryption`** is what you want 95% of the time.
- **`keyvault`** holds the hardware-bound key that seals the vault. On macOS
  Apple Silicon the live path is the Secure Enclave helper (`enable-se`); on
  Linux it is the TPM 2.0 helper (`enable-tpm`).
- **`vault`** is the file container the other two drive. Use it directly only for
  recovery or low-level inspection.

See [`SECRETS_ENV_ENCRYPTION.md`](../dev/SECRETS_ENV_ENCRYPTION.md) and
[`KEYVAULT_BACKENDS.md`](../dev/KEYVAULT_BACKENDS.md) for the full design.

---

## 6. Conversational read-only access (`mordred-status` skill)

Mordred deliberately registers **no agent tools or skills** — an agent must not
be able to loosen its own constraints, and secrets must never flow through a
recorded transcript ([`HARNESS_PRIVACY.md`](../dev/HARNESS_PRIVACY.md), domain
separation). The one sanctioned exception is **observation**: a read-only skill
lets you ask the Hermes agent "what's my mordred status?" in chat.

The skill ships in this repo at `skills/mordred-status/SKILL.md`.
Install = copy it into the Hermes skills directory:

```sh
mkdir -p ~/.hermes/skills/mordred-status
cp skills/mordred-status/SKILL.md ~/.hermes/skills/mordred-status/
```

What it allows the agent to run — metadata-only, no secrets:
`status [--json]`, `policy show`, `policy explain <id>`, `network status`,
`plugins list`. Everything else (any mutation, `audit decrypt`, `vault cat`,
even `audit tail|grep`) is explicitly forbidden inside the skill: the agent must
print the command for you to run yourself in your shell.

The skill declares `metadata.mordred: {network_requirements: local-only,
requires_keyvault: false}` and passes the policy gate cleanly
(`hermes-mordred policy dry-run skills/mordred-status` → allow,
including under strict mode).

> **Residual risk**: the FORBIDDEN list is a prompt-level instruction, not an
> enforcement mechanism. Hard enforcement of what the agent may execute belongs
> to the Hermes exec-tool approval settings, not to this skill.

---

## 7. Platform notes

- **macOS Apple Silicon**: Secure Enclave is the production key backend. The
  helper is ad-hoc codesigned (free — no Apple Developer account). Build/install
  via `keyvault enable-se`. The `workspace` encryption target is "sealed when
  idle" only (not while mounted under the same user).
- **Linux**: TPM 2.0 is the key backend (`keyvault enable-tpm`). MVP binding is
  machine-only (Tier 2 — no per-use PIN/PCR prompt).
- Where there is no hardware backend, the vault degrades to a software-protected
  key by design (still encrypted at rest, lower hardware-binding guarantee).
