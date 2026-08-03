# Mordred — Quickstart

> **Audience**: someone who just wants to get Mordred running and protecting
> secrets at rest, fast. This is the **short path** — it gives you the commands
> and one or two lines of orientation per step. For the full command reference,
> the interactive-command walkthroughs (the keyvault ceremony, the `network init`
> dialog, the `configure` questions), and the three-layer storage model, see
> [`USAGE.md`](./USAGE.md) (the complete guide).
>
> **Scope**: the `hermes-mordred` CLI in this dev checkout. One appendix —
> [Running the base Hermes agent](#running-the-base-hermes-agent-host-cli) —
> covers the host `hermes` command (a different CLI) for convenience.
>
> **How to read each step**: commands are described as **Purpose** / **Do** /
> **Result**. Steps that change your **network path** are marked **🌐 network
> setting**. New to the terms? See the [Glossary](#glossary) at the end.

---

## What is Mordred?

Mordred protects the secrets on your machine — things like API keys, your `.env`
file, and config — by **encrypting them at rest** (kept encrypted on disk,
decrypted only when actually used). It can also route your network traffic
through a **privacy path** (Tor or VPN). This guide takes you from nothing to a
protected install in a handful of commands.

## Before you start

You need:

- **A terminal** you can type commands into.
- **This repository checked out locally** — the guide runs the copy of Mordred
  you build into `.venv`. Don't have the repo yet? Clone it in one
  command — see [Get the repository](#get-the-repository) just below (the full
  dev-environment build is in [`setup.md`](../dev/setup.md)).
- **[uv](https://docs.astral.sh/uv/)** — used to build that venv (`brew install
  uv`, or see the uv install docs). The repo does **not** ship a ready venv; you
  build it once in [Build the venv](#build-the-venv) below.
- **No paid account required.** On macOS the key is guarded by the Secure
  Enclave, with a login-Keychain software fallback. Linux keyvault use requires
  TPM 2.0 plus the helper installed by `keyvault enable-tpm`; it fails closed
  rather than silently storing a software key.

> **Which shell are you in?** The command blocks below are written for
> `sh` / `bash` / `zsh`. If your shell is **fish** (the default on some setups),
> set the alias with `set M …` instead of `M=…` — see §1 for both forms.

### Get the repository

Don't have the repo yet? Clone it and move into it — every command in this guide
runs from this directory (`<repo-root>`):

```sh
git clone git@github.com:InternetMaximalism/Mordred-Hermes.git
cd Mordred-Hermes
```

> **No SSH key set up?** Use the HTTPS URL instead:
> `git clone https://github.com/InternetMaximalism/Mordred-Hermes.git`

### Build the venv

The `hermes-mordred` CLI runs from a virtualenv at `.venv`, which
the repo does **not** ship — build it once with [uv](https://docs.astral.sh/uv/)
from the repo root:

```sh
uv sync --extra macos     # macOS — Secure Enclave keyvault
# Linux:
uv sync --extra keyvault
```

`uv sync` reads `uv.lock` and creates `.venv/` with both the `hermes-mordred`
command and the base `hermes` agent (pulled in as the `hermes-agent` dependency)
on its `bin/`. The `--extra` pulls the crypto stack that `keyvault init` and
`encryption enable` need; plain `uv sync` (no extra) is enough for `status` /
`configure` only. Confirm it landed:

```sh
.venv/bin/hermes-mordred --version  # → hermes-mordred <current version>
```

> **No uv?** `brew install uv` (macOS), or
> `curl -LsSf https://astral.sh/uv/install.sh | sh`. Re-running `uv sync` is safe
> and idempotent.

---

## Setup at a glance

New here? This is the whole setup. Run these from the repo root, top to bottom —
each line says what it does. Detail for every step follows below.

```sh
cd <repo-root>                 # /Users/.../Mordred-Hermes
uv sync --extra macos          # 0. build the venv (Linux: --extra keyvault)
M=.venv/bin/hermes-mordred

$M configure                   # 1. set up policy / LLM / harness
$M network init                # 2. 🌐 network setting — pick a privacy route (optional)
$M keyvault init               # 3. create the key — interactive ceremony, real terminal (see §3)
$M encryption enable env       # 4. encrypt your .env (first run creates the vault — asks for a passphrase once)
$M status                      # 5. confirm: the `env` row reads [on] enrolled
```

> **If a step doesn't do what this guide says**, check
> [README — Troubleshooting][tsg] before retrying — it covers the common ones:
> Touch ID prompts that never arrive, `extension serve` refusing to start on port
> 7788, a network path that silently dropped, and a lost recovery passphrase.

[tsg]: https://github.com/InternetMaximalism/mordred-hermes/blob/main/README.md#troubleshooting

**In one line**: *build the venv → configure → (optional) choose network route →
create the key → encrypt → check.* Want the bare minimum? Just steps 3 → 4 → 5
(see §3).

---

## 1. Invoke it

Once you've [built the venv](#build-the-venv), `.venv` holds the
`hermes-mordred` binary. Run from the repo root and alias it for the session:

```sh
cd <repo-root>            # /Users/.../Mordred-Hermes
M=.venv/bin/hermes-mordred
$M status                 # show current state
```

> **fish shell**: the `M=…` form won't work — set the alias with
> `set M .venv/bin/hermes-mordred` instead. Then `$M status` works
> the same. (In any shell, you can always type the full path instead of `$M`.)

- **Purpose**: confirm Mordred is callable and see where you stand.
- **Result**: prints the one-screen status (see the sample in §2).

> **A shorter form, once you're set up.** `hermes mordred <cmd>` runs the *same*
> subcommand tree off the host Hermes CLI — from any directory, no venv path. It
> needs hermes-agent **0.19.0+** plus the plugins enabled in
> `~/.hermes/config.yaml`, which step 1 (`configure`) writes for you. So follow
> this guide with `hermes-mordred`, then try `hermes mordred status` at the end:
> if it prints Mordred status, you can drop the `$M` alias for good. Details in
> [`USAGE.md` §1](./USAGE.md#1-how-to-invoke).

---

## 2. First run, in order

The same five steps as the glance block above, now with the purpose and result
of each spelled out. Each step is idempotent — re-running is safe.

| # | Do (command) | Purpose | Result |
|---|---|---|---|
| 1 | `$M configure` | Interactive setup of policy / LLM / harness. | Writes `config.yaml` + `policy.json`. |
| 2 | `$M network init` 🌐 **network setting** | Set up the privacy route (Tor / VPN / clearnet). Optional. | A network path is configured (not yet encryption — see §5). |
| 3 | `$M keyvault init` | Create the key store that seals the vault. | Keyvault initialised (macOS = Secure Enclave or Keychain fallback; Linux = TPM). |
| 4 | `$M encryption enable env` | Turn on at-rest encryption for your `.env`. The first enable creates the vault and asks once for a recovery passphrase. | `env` target flips to `[on] enrolled`. |
| 5 | `$M status` | Verify everything above. | Prints the summary below. |

`status` prints a one-screen summary:

```
Mordred status:
  policy mode : lenient
  network     : clearnet (configured; runtime not active in this process)
  keyvault    : not initialised (hardware helper installed)
  encryption  :
    env        [off   ]  not enrolled
    config     [off   ]  not vault-managed
    memory     [off   ]  encryption disabled
    workspace  [sealed]  sealed at rest — protected, not mounted
    workspace: sealed = encrypted & locked at rest | open = mounted, in use | off = not set up here
```

The `workspace` runs on its own axis: its volume is encrypted at rest whenever
it is set up and **sealed** (unmounted), so it reads `sealed` / `open` / `off`
rather than `on` / `paused` / `off`. Sealing it (via `encryption disable
workspace`) is its *protected* state, not its off state.

Add `--json` for machine-readable output.

---

## 3. Fastest path: secrets encrypted at rest

If you only want your `.env` protected, three commands are the whole job:

| # | Do (command) | Purpose | Result |
|---|---|---|---|
| 1 | `$M keyvault init` | Create the key that seals the vault. | Keyvault ready (macOS = Secure Enclave, Linux = TPM). |
| 2 | `$M encryption enable env` | Encrypt `.env` at rest. | `env` flips to `[on] enrolled`. |
| 3 | `$M status` | Confirm. | `env` row shows `[on] enrolled`. |

**What to expect from `keyvault init`.** It is an **interactive security ceremony
that needs a real terminal** (run it non-interactively — e.g. piped — and it
aborts cleanly with a non-interactive error instead of encrypting anything).
You'll choose a passphrase, write down a 24-word seed phrase, and confirm an
offline verification digest. macOS can use its login-Keychain fallback when
Secure Enclave access is unavailable. Linux requires the TPM helper and aborts
if no hardware backend is available; the ceremony itself is otherwise the same.

> You don't strictly need `keyvault init` first: running `encryption enable env`
> **directly** auto-creates the vault and device key and asks once for a recovery
> passphrase. Doing `keyvault init` first just walks you through the formal
> 24-word seed backup before anything is encrypted.

For the full step-by-step ceremony, **why the device key and the recovery
passphrase are two different things**, how to **silence the macOS Touch ID
prompts**, and how to **migrate the vault to a new machine**, see
[`USAGE.md` §4.1–4.3](./USAGE.md#41-keyvault-init--the-interactive-ceremony) and
the `vault recover` notes in
[`USAGE.md` §3 (Migrate to a new machine)](./USAGE.md#migrate-to-a-new-machine).

> **macOS — decide this *before* you create the device key.** By default the key
> is **attended**: macOS asks for Touch ID on every vault unwrap, typically 2–3
> prompts per command. Fine interactively — but a **background** process (a
> launchd-started gateway, `extension serve`) can never answer that prompt and
> starts *without* your sealed secrets. To make the hot path silent instead:
>
> ```sh
> $M keyvault enable-se                        # install + probe the SE helper
> MORDRED_SEKEY_UNATTENDED=1 $M keyvault init  # create the key unattended
> ```
>
> `MORDRED_SEKEY_UNATTENDED=1` sets the policy for **whichever command creates
> the key** — so if you skipped `keyvault init` per the note above, put it on
> your first `encryption enable env` instead:
>
> ```sh
> MORDRED_SEKEY_UNATTENDED=1 $M encryption enable env
> ```
>
> **The attended/unattended choice is fixed when the key is created** — changing
> your mind later means re-keying onto a fresh vault, so it is worth a moment
> now. For the trade-off, the background-process failure in full, and the
> re-keying procedure, see
> [`USAGE.md` §4.3](./USAGE.md#43-touch-id-prompts--why-several-per-command-and-how-to-silence-them).

---

## 4. Encrypt more targets (optional)

The four targets are `env` / `config` / `memory` / `workspace`:

| Do (command) | Purpose | Result |
|---|---|---|
| `$M encryption enable config` | Put `config.yaml` under vault management. | `config` flips to `[on]`. |
| `$M encryption enable memory` | Encrypt Hermes memory. | `memory` flips to `[on]`. |
| `$M encryption enable all` | Encrypt every target at once (env / config / memory, + workspace on macOS). | Core targets flip to `[on]`; `workspace` reads `[sealed]` once set up, or is skipped where unavailable. |
| `$M encryption status` | List the state of all four targets (non-prompting). | Per target: `[on]`/`[paused]`/`[off]`; `workspace` is `[sealed]`/`[open]`/`[off]`. |
| `$M encryption disable <target>` | Turn a target back off (reversible; keeps the vault copy). | Target stops protecting, keeping its encrypted copy (`env` → `[paused]`); `workspace` → `[sealed]` (its protected state). |
| `$M encryption purge <target> --yes` | Destructively remove the encrypted copy. | Encrypted data for that target is deleted. |

> **`all` fan-out is best-effort.** `enable` / `disable` / `purge` all accept
> `all`. Core targets (`env` / `config` / `memory`) are always attempted;
> `workspace` is macOS-only and is *skipped* — never failed — when unavailable.
> Every target runs even if an earlier one fails, then a one-line roll-up prints.
> (`purge all` still requires `--yes`.)

---

## 5. Network settings 🌐

These commands control **how Mordred routes network traffic** — the privacy-path
settings, separate from at-rest encryption (§3–4). Run `network init` once before
`network use` / `network status` will work.

| Do (command) | Purpose | Result |
|---|---|---|
| `$M network init` | One-time setup of the privacy paths (Tor / VPN / clearnet; VPN works with any provider, Mullvad recommended). | Saves the route for the next Hermes start. |
| `$M network use tor` | Select Tor — strongest anonymity. | Saves Tor; restart Hermes to activate it before provider clients are built. |
| `$M network use vpn` | Select your VPN (Mullvad by default) — IP privacy with better speed. | Saves VPN; restart Hermes to activate it before provider clients are built. |
| `$M network use clearnet` | Select direct networking with no privacy route. | Saves clearnet; restart Hermes to rebuild clients without a proxy. |
| `$M network status` | Show which path is active and whether it is live. | Prints active path + liveness check. |

`network init` is interactive: it shows a **Network privacy path** radio dialog
to set your default route, then a few per-route prompts. **If you just want
clearnet (the default), press Enter through everything.**

The route is process-scoped. Changing it while Hermes is running is saved but
not switched live; restart Hermes so the route and provider clients are built
together.

For the full dialog walkthrough, every prompt (Tor / Mullvad), and how to use a
**non-Mullvad VPN** (Proton VPN, ExpressVPN, …), see
[`USAGE.md` §4.4](./USAGE.md#44-network-init--the-dialog-and-prompts).

---

## 6. Tune policy (optional)

`$M configure` walks through a short list of Mordred questions (pass
`--with-hermes-setup` to also run the upstream Hermes setup wizard first).
**If in doubt, press Enter through all of them**: the defaults are the safe,
private choice.

The one setting most people care about is **policy mode**:

| Mode | What it means |
|---|---|
| `strict` | Strictest — blocks cloud LLMs, disables IPv6, refuses to run under a known AI harness. |
| `lenient` (**default**) | Guards are active but stay out of your way. Records audit warnings only. |
| `off` | Disables all guards. |

Only `strict` can actually stop you; `lenient` just audits, `off` does nothing.

For the full question-by-question table, the **policy mode** detail, and the
**agent harness** explainer (why `strict` refuses a known harness), see
[`USAGE.md` §4.5](./USAGE.md#45-configure--policy-mode-and-the-agent-harness-in-detail).

| Do (command) | Purpose |
|---|---|
| `$M policy show` | Print the resolved policy currently in force. |
| `$M configure --non-interactive --policy strict` | Switch to strict mode without prompts. |

---

## Reset or remove the keyvault

Need to start over — wrong hardware tier, a botched setup, or decommissioning a
machine? `keyvault reset` destroys all provably profile-owned key material and
removes the keyvault.

| Do (command) | Purpose | Result |
|---|---|---|
| `$M keyvault reset` | Destroy profile-owned key material and delete the keyvault (irreversible). | Asks you to type `reset` to confirm, deletes profile-owned hardware keys, removes the keyvault. |
| `$M keyvault reset --yes` | Same, but skip the prompt (scripted / non-interactive use). | No confirmation; deletes immediately. |

> **⚠️ This cannot be undone.** Anything sealed by this keyvault — wallets,
> encrypted secrets — is lost unless you can run `$M keyvault recover` with your
> 24-word Seed Phrase, Passphrase and backup blob. Reset prints the exact key IDs
> it will destroy before asking you to confirm; if no keyvault exists it just says
> "nothing to reset". Legacy machine-global keys are retained when exclusive
> profile ownership cannot be proven and are reported explicitly. Afterwards,
> `$M keyvault init` starts a fresh one.

---

## Common checks

| Want to… | Command |
|---|---|
| See state on one screen | `$M status` |
| Machine-readable state | `$M status --json` |
| Tail the audit log | `$M audit tail` |
| List discovered plugins | `$M plugins list` |
| Active network path + liveness | `$M network status` |
| List the keys in the keyvault | `$M keyvault list` |
| Verify the keyvault digest | `$M keyvault verify-digest` |

---

## Ethereum keys (HD wallet)

`keyvault init` stores your 24-word seed encrypted by default
(`--store-seed-for-hd`) so Mordred can derive Ethereum accounts later without
re-entering it. The raw private key never leaves the keyvault — these commands
return only the EIP-55 address and an opaque `envelope_id` handle.

| Want to… | Command |
|---|---|
| Create a fresh random key | `$M keyvault eth new` |
| Derive HD account #0 from the seed | `$M keyvault eth derive --index 0` |
| Show the address for a stored key | `$M keyvault eth address --envelope-id <id>` |

- `new` prints a checksum address + `envelope_id`; add `--json` for scripting.
- `derive` / `address` decrypt key material, so they trigger a Touch ID /
  passcode prompt unless the wrapping key is unattended.
- Needs the optional extra: `pip install "mordred-hermes[ethereum]"`.

Every flag — BIP-44 `--account` / `--change`, `--seed-envelope-id` for
multi-seed vaults, and the BIP-39-passphrase caveat — is in
[`USAGE.md` § `keyvault eth`](./USAGE.md#keyvault-eth--ethereum-keys-hd-wallet).

---

## Running the base Hermes agent (host CLI)

Everything above drives `hermes-mordred` — the privacy layer. The **base Hermes
agent** (the `hermes` command itself) is a different CLI, and it already lives in
the same `.venv` you built above, arriving as the `hermes-agent` dependency:

```sh
.venv/bin/hermes --version   # prints  Project: <repo-root>
```

You need none of it to set Mordred up. If you also want to drive the agent
underneath — running this repo's copy instead of a global one, `hermes setup`,
provider auth, or the background messaging gateway — see
**[`HERMES_BASICS.md`](./HERMES_BASICS.md)**.

---

## Glossary

Short, plain definitions for the terms used above:

- **at-rest encryption** — files are stored encrypted on disk and decrypted only
  when actually used; protects secrets even if someone copies your files.
- **secret** — sensitive data you don't want leaked: API keys, tokens, your
  `.env` file, parts of your config.
- **vault** — Mordred's underlying encrypted file store that holds your secrets.
- **keyvault** — where the key that unlocks the vault lives, guarded by hardware
  (Secure Enclave / TPM) when available.
- **target** — a thing Mordred can encrypt: `env` (your `.env`), `config`
  (`config.yaml`), `memory` (agent memory), `workspace` (your working files).
- **enrolled** — a target whose encryption is currently switched on.
- **master key** — the single key that actually encrypts your secrets. You never
  see or type it; it is sealed behind the two keyholes below.
- **device key / recovery passphrase** — the two keyholes into the same master
  key: the hardware device key (automatic, this machine) and the passphrase you
  remember (recovery). See [`USAGE.md` §4.2](./USAGE.md#42-the-device-key-and-the-recovery-passphrase-are-different-things).
- **wrapping key** — the hardware key that seals (“wraps”) the master key on this
  machine. In everyday terms it *is* the device key; the docs say "wrapping key"
  when talking about the sealing operation itself.
- **attended / unattended** — whether unwrapping asks for Touch ID every time
  (attended, the default) or stays silent while your Mac is unlocked
  (unattended). Fixed when the key is created — see [`USAGE.md` §4.3](./USAGE.md#43-touch-id-prompts--why-several-per-command-and-how-to-silence-them).
- **Secure Enclave / TPM** — the security chip (macOS / Linux) that guards the
  key in hardware. Only macOS has the login-Keychain software fallback; Linux
  fails closed without its TPM helper.
- **network path** — how your traffic is routed: **Tor** (anonymity, slower),
  **VPN** (any VPN, Mullvad recommended; IP privacy with speed), or **clearnet** (direct, no privacy).
- **policy** — the rules Mordred enforces (e.g. whether cloud LLMs are allowed,
  which skills may install). Modes: `strict` / `lenient` / `off`.
- **harness** — the agent tool driving Hermes (Claude CLI, Codex, Cursor, …).
- **idempotent** — safe to run again; re-running a step doesn't break anything.

---

## Next steps

- [`USAGE.md`](./USAGE.md) — full command reference, interactive-command walkthroughs, and the three-layer storage model.
- [`SECRETS_ENV_ENCRYPTION.md`](../dev/SECRETS_ENV_ENCRYPTION.md) / [`KEYVAULT_BACKENDS.md`](../dev/KEYVAULT_BACKENDS.md) — design behind `encryption` / `keyvault`.
- [`setup.md`](../dev/setup.md) — building the dev environment from scratch.
- [README — Troubleshooting](https://github.com/InternetMaximalism/mordred-hermes/blob/main/README.md#troubleshooting) and [README — Upgrading](https://github.com/InternetMaximalism/mordred-hermes/blob/main/README.md#upgrading) — common issues, and how to upgrade the package or migrate config later.
