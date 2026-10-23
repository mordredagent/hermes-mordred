# Mordred — Quickstart

> **Audience**: Hermes users who want to protect local secrets quickly.
> This guide uses the normal Hermes and Mordred installers. Contributors
> working from a checkout should use [`docs/dev/setup.md`](../dev/setup.md).
> For every option and prompt, see [`USAGE.md`](./USAGE.md).

## What is Mordred?

Mordred adds privacy controls to Hermes without modifying Hermes itself. It can
keep keys behind Secure Enclave or TPM 2.0, route traffic through Tor or a VPN,
enforce local-LLM policy, and protect agent memories at rest using macOS
file-vault, Linux TPM, or scoped Windows CNG custody. Transparent `.env` and
configuration lifecycles use macOS integrations.

## Before you start

You need:

- macOS, or Linux with TPM 2.0 development/runtime support;
- a real interactive terminal for `keyvault init`; and
- an installed [Hermes Agent](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/getting-started/installation.md).

Linux supports the hardware-backed keyvault, but the transparent env/config
startup lifecycle is not active there yet. On Linux those encryption targets
report inactive and plaintext remains the runtime source. Dedicated TPM memory
and Private Telegram do work: see [`TELEGRAM.md`](./TELEGRAM.md). General
`setup` and `encryption enable all` enable Linux memory through the dedicated
TPM engine and skip env/config file-vault enrollment. The standalone
`hermes-mordred encryption enable memory` command remains available.

Native Windows has scoped installer, CNG memory, Telegram and Desktop code;
it is not general product or Windows 11 acceptance. Use the native PowerShell
instructions in [`setup.md`](../dev/setup.md#native-windows-installer-and-helper-validation-c4)
and the [Windows TPM workflow](./USAGE.md#native-windows-tpm-workflow).
Capability-specific contracts and remaining gates are in
[`SPEC.md`](../dev/SPEC.md#platform-support-v1), [`TODO.md`](../dev/TODO.md), and
[`CI.md`](../dev/CI.md). The shell installer below is for macOS/Linux.

If `hermes` is not installed yet, use its official installer, then reload your
shell:

```sh
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash
```

Open a new terminal after it finishes so the new `hermes` command is on `PATH`.
Hermes's installer provides its own Python environment and `uv`; you do not
need to create a virtual environment or install Python separately for Mordred.

## Install Mordred

Choose one of the following two install paths. For the standard installation,
run:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | bash
```

It resolves the environment behind the `hermes` on your `PATH`, checks the
Hermes version, selects the macOS or Linux dependencies, installs Mordred from
PyPI, and puts a `hermes-mordred` launcher next to `hermes`. It does **not**
change configuration, create keys, or encrypt data.

For an existing `mordred-hermes==0.1.0a15` installation, the script verifies
that `hermes-mordred>=0.1.0a16` is available before removing the old
distribution and installing the new one. Configuration, keys, and state are
preserved. Do not manually install the two real distributions on top of each
other; use the installer or uninstall the legacy name first.

To include the browser-extension server and Ethereum wallet support from the
start, use the extension bundle instead:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | \
  bash -s -- --with-extension
```

`--with-extension` is the convenience option for the `extension` and
`ethereum` dependency groups. The `messaging` extra is not required to use the
browser extension. Without it, `hermes-mordred extension pair` prints the
`MORT-...` pairing code as text; adding it also renders the code as a terminal
QR.

Add `--version VERSION` after replacing `VERSION` with a release number when
you need an exact PyPI version. For example, the two options can be combined as
`bash -s -- --with-extension --version VERSION`.

To test unreleased changes, install from a local checkout instead of PyPI:
`bash scripts/install.sh --from-source ~/repos/hermes-mordred --with-telegram`.
Add `--editable` to link the checkout so later edits take effect on the next
Hermes restart. The installer finds Hermes Desktop's managed environment and
its bundled `uv` even when neither `hermes` nor `uv` is on PATH.

<details>
<summary>Advanced: choose individual dependency groups</summary>

Most users should use one of the two install paths above. Use `--extras LIST`
only when you want a custom, comma-separated feature set. To add the optional
terminal QR to the extension bundle, append `--extras messaging`, producing
`bash -s -- --with-extension --extras messaging`. `--all-extras` includes all
user-facing extras, including deep Tor liveness checks. Extras can also be
added later by rerunning the installer.

| Extra | Use it for |
|---|---|
| `extension` | Browser-extension WebSocket server and wallet RPC transport |
| `ethereum` | HD-wallet derivation and signing |
| `messaging` | Terminal QR codes for extension pairing |
| `tor-control` | Deep Tor liveness checks |
| `telegram` | Read-only import of your own Telegram account for private questions (Telethon) |

</details>

If you prefer to inspect a downloaded script before running it:

```sh
curl -fsSLo mordred-install.sh \
  https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh
less mordred-install.sh
bash mordred-install.sh                 # default platform dependencies
# Or: bash mordred-install.sh --with-extension --version VERSION
rm mordred-install.sh
```

<details>
<summary>Manual install into the Hermes environment</summary>

The installer automates these commands. Use them directly only when you need
manual package control:

```sh
# macOS
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  --upgrade-package hermes-mordred "hermes-mordred[macos]"

# Linux: run this instead
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  --upgrade-package hermes-mordred "hermes-mordred[keyvault]"
```

</details>

**Updating later.** `hermes-mordred update` installs a newer release and keeps
your extras and Hermes's pins automatically. The manual `uv pip install
--upgrade-package` commands above remain for manual control.

### Get the repository

Normal users can skip this section. Contributors can clone the source with:

```sh
git clone https://github.com/mordredagent/hermes-mordred.git
cd hermes-mordred
```

### Build the venv

Normal users should keep using the installer-managed Hermes environment. From
a development checkout, create the separate editable environment with
`uv sync --all-extras`; follow [`docs/dev/setup.md`](../dev/setup.md) so tests
cannot modify production state under `~/.hermes`.

## Setup at a glance

Run the guided setup command — it is safe to re-run and picks up wherever it
left off:

```sh
hermes-mordred setup
```

Prefer to run each step yourself? `setup` first checks that upstream Hermes
itself is set up, then runs the sequence below, skipping whatever is already
done. Run the interactive configuration, then optionally choose a network
route:

```sh
hermes-mordred configure       # policy / LLM / harness
hermes-mordred network init    # optional: Tor / VPN / clearnet
```

Prepare the platform helper and create the keyvault:

```sh
# macOS — recommended for background gateways
hermes-mordred keyvault enable-se
MORDRED_SEKEY_UNATTENDED=1 hermes-mordred keyvault init

# Linux — run these instead
hermes-mordred keyvault enable-tpm
hermes-mordred keyvault init
```

On macOS, finally encrypt `.env` and verify:

```sh
MORDRED_SEKEY_UNATTENDED=1 hermes-mordred encryption enable env
hermes-mordred encryption enable memory
hermes-mordred status
```

`keyvault init` and the file vault use distinct native keys. The environment
variable applies to one process, so put it on both key-creation commands when
both keys must work unattended.

On Linux, enable dedicated memory with `hermes-mordred encryption enable memory`,
then check `hermes-mordred keyvault list` and `hermes-mordred status`.
Stop gateways before enabling and restart afterward. TPM memory has no portable
recovery and needs no env enrollment; do not expect an `env [on]` row.

## 1. Invoke it

The installer puts `hermes-mordred` in the same directory as `hermes`, so it
works from any directory and in sh, bash, zsh, and fish. If that directory is
not on `PATH`, the installer prints it at the end — add it and reload the
shell.

## 2. First run, in order

`hermes-mordred setup` runs seven steps in order, probing each and skipping
whatever is already complete. Re-running after an interruption picks up the
unfinished work. On macOS, the keyvault Passphrase and 24-word Seed Phrase
backup are at step 5 (have pen and paper ready), and device-key authorization
may occur at steps 6–7. A setup run asks you to choose a passphrase only once
(plus one confirmation): when that run creates the file vault at step 6, the
keyvault Passphrase also becomes its recovery passphrase. If the keyvault
already exists, step 6 asks for the file-vault recovery passphrase instead.
The stores and recovery mechanisms remain separate despite reusing that input.

| # | Command | Result |
|---|---|---|
| 1 | Upstream Hermes check; offers `hermes setup` if needed | Establishes the Hermes configuration prerequisite. |
| 2 | `hermes-mordred configure` | Writes Mordred policy and enables the `mordred` plugin. |
| 3 | `hermes-mordred network init` | Optionally selects Tor, VPN, or clearnet. |
| 4 | `hermes-mordred keyvault enable-se` or `enable-tpm` | Builds and installs the platform key helper. |
| 5 | `hermes-mordred keyvault init` | Creates the main keyvault key and its seed/digest commitment. |
| 6 | `hermes-mordred encryption enable env` (macOS runtime) | Enrolls `.env` and activates transparent injection on macOS. |
| 7 | `hermes-mordred encryption enable memory` | Arms and seals memory through macOS file-vault or Linux TPM custody. |

On macOS, steps 4 to 7, the database encryption of
[Encrypt conversation databases](#encrypt-conversation-databases-macos) and the
mail setup can also be run from the Mordred page in Hermes Desktop, in the same
order, with the reasons shown inline (see
[`desktop`](./USAGE.md#desktop--mordred-setup-page-in-hermes-desktop)).

Final `hermes-mordred status` is outside the numbered steps. Linux skips
step 6 and enables memory without a file vault or recovery-passphrase prompt.
Windows setup uses `enable-winkey`, skips the
unported secret-store keyvault ceremony and excluded env target, and uses its
proof-bound CNG memory flow; the Windows gates remain separate.

On macOS, a successful final status includes an `env [on] enrolled` row. On
Linux the row is inactive even if enrolled; that is an explicit platform
limit, not protected runtime state. The macOS-only `workspace` target has a
separate `sealed` / `open` / `off` state: `sealed` is protected, not disabled.
Add `--json` for machine-readable status.

## 3. Fastest path: secrets encrypted at rest

If policy and network settings can wait, the minimum path is:

```sh
# macOS
hermes-mordred keyvault enable-se
MORDRED_SEKEY_UNATTENDED=1 hermes-mordred encryption enable env
hermes-mordred status
```

This fastest at-rest path is macOS-only. On Linux, use
`hermes-mordred keyvault enable-tpm` followed by `keyvault init` for the
hardware-backed keyvault; transparent `.env` loading still uses plaintext.

Running `keyvault init` first is still recommended when you also use keyvault
envelopes or HD wallet derivation: its ceremony displays the 24-word seed and
verifies the offline digest. It does not back up the separate at-rest file
vault. That vault has its own device key and recovery passphrase; the full
ceremonies are in
[`USAGE.md` §4.1–4.3](./USAGE.md#41-keyvault-init--the-interactive-ceremony).

## 4. Encrypt more targets (optional)

```sh
hermes-mordred encryption enable config
hermes-mordred encryption enable memory
hermes-mordred encryption enable all
hermes-mordred encryption status
```

Immediately after the first `encryption enable config`, the current plaintext
`config.yaml` remains on disk: that command writes the opt-in marker after its
startup hook has already made the decision for that process. Run
`hermes-mordred encryption status` once. When the status command exits cleanly,
the hook reseals the current config and removes the plaintext. Do not re-run
`encryption enable config` to perform this first seal, and do not delete
`config.yaml` manually.

`disable` is reversible and retains the encrypted copy. `purge` deletes it and
requires `--yes`. The macOS-only `workspace` target reports `sealed` when it is
encrypted and unmounted. See [`USAGE.md` §3](./USAGE.md#encryption--the-recommended-onoff-switch).

### Encrypt conversation databases (macOS)

After enabling memory, encrypt `state.db` and Hermes's other SQLite stores:

```sh
hermes-mordred databases encrypt --dry-run
hermes-mordred databases encrypt
hermes-mordred databases status
```

`setup` and `encryption enable all` do not enable this. If conversion is
scheduled, quit all Hermes processes and restart, then check status again.
Linux/Windows databases, session JSONL and text logs are outside this protection.
See [database operations](./USAGE.md#databases--encrypt-hermess-sqlite-databases-macos)
for decryption, backups and migration.

### What the protected states mean

Protection is target-specific. An `on` mark means the target's lifecycle is
active on this OS; it does not mean plaintext never exists while the data is in
use.

| Target and protected mark | What remains protected | Plaintext while in use | Restart requirement |
|---|---|---|---|
| `env [on]` | The vault copy is encrypted and the plaintext `.env` is absent from disk. | Values are injected into the Hermes process environment. | Restart a running gateway after enabling or changing the target. |
| `config [on]` | The vault copy is encrypted between managed Hermes processes. | A mode-`0600` plaintext `config.yaml` exists on disk for the process lifetime and is resealed on clean exit. An unclean exit can leave it until the next managed start and exit. | Restart a running gateway after enabling or disabling the target. |
| `memory [on]` | `~/.hermes/memories/*.md` and drift backups stay sealed on disk; reads and writes pass through the hook. | Plaintext exists in process memory. Approval-pending JSON remains a documented plaintext exception. | Restart a running gateway after enabling or disabling the target. |
| `workspace [sealed]` | The encrypted volume is unmounted and protected at rest. | `workspace [open]` means the volume is mounted and visible to the same user. | No gateway restart; unmount it to return to `sealed`. |

For `env`, `config`, and `memory`, `paused` means the encrypted data is retained
but protection is not active, `off` means the target is not configured, and
`exposed` means plaintext drift was found on disk and must be resealed. The
workspace uses `sealed` / `open` / `off` instead.

On macOS/Linux, the audit log is separate from these four targets. It starts
as plaintext and becomes encrypted after a successful `keyvault init`;
`hermes-mordred status` reports the actual audit-log state and calls out any encrypted-to-plaintext
downgrade.

On macOS, `encryption enable memory` needs the `env` target first (it carries
the memory key) and seals `~/.hermes/memories/*.md` as it goes. Linux TPM and
Windows CNG memory use dedicated custody; see the platform contracts in
[`SPEC.md`](../dev/SPEC.md#platform-support-v1). Restart running gateways after
changing memory protection. A macOS process that lacks the newly created key
refuses sealed reads and writes; Hermes may catch its initial-load error and
show an empty view, while hooked writes preserve the seals. Linux and Windows
normal enable flows require stopped gateways before sealing.

## 5. Network settings 🌐

```sh
hermes-mordred network init
hermes-mordred network use tor              # or: vpn, clearnet
hermes-mordred network status
```

Changing the selected path is saved immediately, but a running Hermes process
must be restarted so its provider clients use the new route. `network init`
asks only the questions the route you pick needs — `clearnet` is a single
question, `tor` adds two more, `vpn` adds the provider question plus that
provider's settings — and supports any VPN provider; Mullvad has the most
guided setup. See
[`USAGE.md` §4.4](./USAGE.md#44-network-init--the-dialog-and-prompts).

## 6. Tune policy (optional)

`hermes-mordred configure` defaults to `lenient`: guards audit problems without
blocking ordinary use. `strict` blocks non-allowlisted cloud LLMs and unsafe
paths; `off` disables policy enforcement.

```sh
hermes-mordred policy show
hermes-mordred configure --non-interactive --policy strict --no-allow-cloud-llm
```

The complete question-by-question explanation is in
[`USAGE.md` §4.5](./USAGE.md#45-configure--policy-mode-and-the-agent-harness-in-detail).

## Reset or remove the keyvault

```sh
hermes-mordred keyvault reset         # asks you to type reset
hermes-mordred keyvault reset --yes   # non-interactive and immediate
```

This destroys profile-owned key material. Before reset, create a fresh snapshot
in an existing private directory:

```sh
hermes-mordred keyvault export --output /secure/path/keyvault-backup.mrkv
```

Keep the blob separate from the Keyvault init passphrase and 24-word Seed
Phrase. Verify recovery against an isolated fresh profile before relying on it.
Do not reset while encrypted secrets or wallets still depend on the source.
The reset command prints the exact key IDs before interactive confirmation.

## Uninstall

**Hermes Desktop:** open **Mordred** in the sidebar and use **Uninstall
Mordred…** at the bottom of the page, choose one of two options, check the
plan it shows, and confirm. Quit and reopen Hermes Desktop afterwards.

- **Decrypt, then uninstall.** Encrypted files (Hermes memory, `.env`,
  `config.yaml`) become normal files again, so Hermes keeps everything.
  Mordred's own data and keys are kept unless you tick "Also delete…".
- **Erase encrypted data without decrypting.** Nothing is decrypted: the
  encrypted Hermes memory, the vault copies of `.env` / `config.yaml` and all
  Mordred data and keys are deleted. Whatever exists only in encrypted form is
  lost for good.

Anything that deletes data asks you to type `delete my data`.

**Terminal:**

```sh
hermes-mordred uninstall --dry-run   # see exactly what will happen
hermes-mordred uninstall             # confirm once; Hermes gets its plaintext files back
hermes-mordred uninstall --erase-encrypted   # delete encrypted data as it is (no decryption)
```

Or through the installer: `curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | bash -s -- --uninstall`.

Quit Hermes Desktop and stop any `hermes gateway` first. On macOS, the command
restores protected databases first, then `.env`, `config.yaml` and memories
to plaintext (it stops before removing anything if it cannot), removes
Mordred's entries from `config.yaml`
(keeping a backup) and `.env`, the Hermes Desktop page and the installer's
launcher, and finally uninstalls the package from Hermes's environment.

On macOS/Linux, your Mordred data — vault, keyvault, Telegram archive, audit log,
device keys — is **kept** and listed with its location. `--purge-data` deletes it too, after
you type `delete my data`; keep your keyvault Seed Phrase / Passphrase and the
vault recovery passphrase if you may want any of it back. Details:
[`USAGE.md` § Uninstall safely](./USAGE.md#uninstall-safely).

Windows restores memory; `--purge-data` removes only its memory custody key
and retains audit/Telegram data and keys. `--erase-encrypted` is unsupported.

## Common checks

| Check | Command |
|---|---|
| Everything at a glance | `hermes-mordred status` |
| Encryption targets | `hermes-mordred encryption status` |
| Active route and liveness | `hermes-mordred network status` |
| Key IDs | `hermes-mordred keyvault list` |
| Recovery digest | `hermes-mordred keyvault verify-digest` |
| Recent audit entries | `hermes-mordred audit tail` |
| Mordred plugin and component status | `hermes-mordred plugins list` |

## Ethereum keys (HD wallet)

Install the `ethereum` optional extra using the manual installation pattern
above, then use:

```sh
hermes-mordred keyvault eth new
hermes-mordred keyvault eth derive --index 0
hermes-mordred keyvault eth address --envelope-id <id>
```

Private keys stay in the keyvault. Options and BIP-39 caveats are in
[`USAGE.md` § `keyvault eth`](./USAGE.md#keyvault-eth--ethereum-keys-hd-wallet).

## Running the base Hermes agent (host CLI)

Mordred's CLI configures the privacy layer; the base `hermes` command runs the
agent itself. Use the upstream
[Hermes installation guide](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/getting-started/installation.md)
and [Hermes documentation](https://github.com/NousResearch/hermes-agent/tree/main/website/docs)
for provider authentication, interactive use, and gateway operation.

## Glossary

- **vault** — encrypted storage for secrets.
- **keyvault** — the hardware-backed key that opens the vault.
- **device key** — the normal machine-local unlock path.
- **recovery passphrase / seed** — the offline recovery path.
- **attended / unattended** — whether macOS asks for Touch ID on every unwrap.
- **network path** — Tor, VPN, or direct clearnet routing.
- **policy mode** — `strict`, `lenient`, or `off` enforcement behavior.

## Next steps

- [`USAGE.md`](./USAGE.md) — complete command reference and ceremonies.
- [`EXTENSION.md`](./EXTENSION.md) — browser extension and E2E messaging.
- [`setup.md`](../dev/setup.md) — development checkout and safe test isolation.
- [`USAGE.md` troubleshooting](./USAGE.md#8-troubleshooting) — common failures and recovery.
