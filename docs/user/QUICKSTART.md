# Mordred — Quickstart

> **Audience**: Hermes users who want to protect local secrets quickly.
> This guide starts with the normal PyPI install. Developers working from a
> checkout can use the short alternative under [Build the venv](#build-the-venv).
> For every option and prompt, see [`USAGE.md`](./USAGE.md).

## What is Mordred?

Mordred adds privacy controls to Hermes without modifying Hermes itself. It can
encrypt `.env`, configuration, and agent memory at rest; keep the unlocking key
behind Secure Enclave or TPM 2.0; route traffic through Tor or a VPN; and enforce
local-LLM policy.

## Before you start

You need:

- An installed Hermes agent, normally under `~/.hermes/hermes-agent/`.
- Python 3.11 or newer and [uv](https://docs.astral.sh/uv/).
- macOS, or Linux with TPM 2.0 development/runtime support.
- A real interactive terminal for `keyvault init`.

Install Mordred into Hermes's own venv:

```sh
# macOS
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  --upgrade "mordred-hermes[macos]"

# Linux: run this instead
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  --upgrade "mordred-hermes[keyvault]"
```

### Get the repository

PyPI users can skip this section. Contributors can clone the source with:

```sh
git clone https://github.com/InternetMaximalism/mordred-hermes.git
cd mordred-hermes
```

### Build the venv

PyPI users should keep using the Hermes-managed venv installed above. From a
development checkout, create the separate editable environment instead:

```sh
uv sync --all-extras
.venv/bin/python -c "import mordred_hermes; print(mordred_hermes.__file__)"
# expected: <repo-root>/src/mordred_hermes/__init__.py
```

The development environment still reads real `~/.hermes` state unless you set
`HERMES_HOME`. See [`setup.md`](../dev/setup.md) before testing destructive
commands.

## Setup at a glance

Choose the command path for your installation:

```sh
# Normal PyPI install
M=~/.hermes/hermes-agent/venv/bin/hermes-mordred

# Development checkout: use this assignment instead
# M=.venv/bin/hermes-mordred
```

Then run the common setup:

```sh
$M configure                 # policy / LLM / harness
$M network init              # optional: Tor / VPN / clearnet
```

Prepare the platform helper and create the keyvault:

```sh
# macOS — recommended for background gateways
$M keyvault enable-se
MORDRED_SEKEY_UNATTENDED=1 $M keyvault init

# Linux — run these instead
$M keyvault enable-tpm
$M keyvault init
```

Finally encrypt `.env` and verify:

```sh
$M encryption enable env
$M status
```

## 1. Invoke it

`hermes-mordred` always works after installation. Hermes 0.19.0+ also exposes
the same tree as `hermes mordred ...` after `configure` enables the plugins.
Use the standalone path for the first run and on older Hermes releases.

For fish, set the command with `set M
~/.hermes/hermes-agent/venv/bin/hermes-mordred`; the `M=...` syntax above is for
sh, bash, and zsh.

## 2. First run, in order

| # | Command | Result |
|---|---|---|
| 1 | `$M configure` | Writes Mordred policy and enables all six plugins. |
| 2 | `$M network init` | Optionally selects Tor, VPN, or clearnet. |
| 3 | `$M keyvault enable-se` or `enable-tpm` | Builds and installs the platform key helper. |
| 4 | `$M keyvault init` | Creates the device key and recovery material. |
| 5 | `$M encryption enable env` | Enrolls `.env` in the encrypted vault. |
| 6 | `$M status` | Shows policy, route, keyvault, and encryption state. |

A successful final status includes an `env [on] enrolled` row. The `workspace`
target has a separate `sealed` / `open` / `off` state: `sealed` is protected,
not disabled. Add `--json` for machine-readable status.

## 3. Fastest path: secrets encrypted at rest

If policy and network settings can wait, the minimum path is:

```sh
# prepare one helper first: enable-se on macOS, enable-tpm on Linux
$M keyvault enable-se
MORDRED_SEKEY_UNATTENDED=1 $M encryption enable env  # creates the vault if needed
$M status
```

On Linux replace the first line with `$M keyvault enable-tpm` and omit
`MORDRED_SEKEY_UNATTENDED=1`.

Running `keyvault init` first is still recommended: its ceremony displays the
24-word recovery seed and verifies the offline digest before data is enrolled.
The device key and recovery passphrase are different recovery paths; the full
ceremony is in
[`USAGE.md` §4.1–4.3](./USAGE.md#41-keyvault-init--the-interactive-ceremony).

## 4. Encrypt more targets (optional)

```sh
$M encryption enable config
$M encryption enable memory
$M encryption enable all
$M encryption status
```

`disable` is reversible and retains the encrypted copy. `purge` deletes it and
requires `--yes`. The macOS-only `workspace` target reports `sealed` when it is
encrypted and unmounted. See [`USAGE.md` §3](./USAGE.md#encryption--the-recommended-onoff-switch).

## 5. Network settings 🌐

```sh
$M network init
$M network use <tor|vpn|clearnet>
$M network status
```

Changing the selected path is saved immediately, but a running Hermes process
must be restarted so its provider clients use the new route. `network init`
supports any VPN provider; Mullvad has the most guided setup. See
[`USAGE.md` §4.4](./USAGE.md#44-network-init--the-dialog-and-prompts).

## 6. Tune policy (optional)

`$M configure` defaults to `lenient`: guards audit problems without blocking
ordinary use. `strict` blocks non-allowlisted cloud LLMs and unsafe paths;
`off` disables policy enforcement.

```sh
$M policy show
$M configure --non-interactive --policy strict --no-allow-cloud-llm
```

The complete question-by-question explanation is in
[`USAGE.md` §4.5](./USAGE.md#45-configure--policy-mode-and-the-agent-harness-in-detail).

## Reset or remove the keyvault

```sh
$M keyvault reset            # asks you to type reset
$M keyvault reset --yes      # non-interactive and immediate
```

This destroys profile-owned key material. Export and verify a backup first;
otherwise encrypted secrets and wallets may be unrecoverable. The command
prints the exact key IDs before interactive confirmation.

## Common checks

| Check | Command |
|---|---|
| Everything at a glance | `$M status` |
| Encryption targets | `$M encryption status` |
| Active route and liveness | `$M network status` |
| Key IDs | `$M keyvault list` |
| Recovery digest | `$M keyvault verify-digest` |
| Recent audit entries | `$M audit tail` |
| Discovered Mordred plugins | `$M plugins list` |

## Ethereum keys (HD wallet)

Install the `ethereum` extra, then use:

```sh
$M keyvault eth new
$M keyvault eth derive --index 0
$M keyvault eth address --envelope-id <id>
```

Private keys stay in the keyvault. Options and BIP-39 caveats are in
[`USAGE.md` § `keyvault eth`](./USAGE.md#keyvault-eth--ethereum-keys-hd-wallet).

## Running the base Hermes agent (host CLI)

Mordred's CLI configures the privacy layer; the base `hermes` command runs the
agent itself. See [`HERMES_BASICS.md`](./HERMES_BASICS.md) for setup, provider
authentication, interactive use, and the messaging gateway.

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
- [`setup.md`](../dev/setup.md) — development environment and safe isolation.
- [README troubleshooting](https://github.com/InternetMaximalism/mordred-hermes/blob/main/README.md#troubleshooting) — common failures and recovery.
