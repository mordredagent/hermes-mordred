# hermes-mordred

[![PyPI](https://img.shields.io/pypi/v/hermes-mordred)](https://pypi.org/project/hermes-mordred/)
[![CI](https://github.com/mordredagent/hermes-mordred/actions/workflows/ci.yml/badge.svg)](https://github.com/mordredagent/hermes-mordred/actions/workflows/ci.yml)

Privacy-preserving plugins for the
[Hermes agent](https://github.com/NousResearch/hermes-agent): hardware-backed
keys, Tor/VPN routing, local-LLM policy enforcement, end-to-end gateway
messages, and macOS-integrated at-rest secret encryption.

**Status: active alpha** — current release `0.1.0a16`.

New here? Follow the
**[Quickstart](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/QUICKSTART.md)**
for the shortest path from an existing Hermes install to encrypted secrets.

## The plugins

The package exposes six `hermes_agent.plugins` entry points:

| Plugin | Purpose |
|---|---|
| `mordred_privacy_check` | Skill-metadata policy enforcement and audit logging |
| `mordred_wizard` | The `hermes-mordred` CLI |
| `mordred_llm_guard` | Strict-mode local-LLM enforcement |
| `mordred_network` | Tor, VPN, and clearnet path management |
| `mordred_keyvault` | Secure Enclave / TPM-backed key management |
| `mordred_e2e` | Encrypted Slack and Discord gateway commands and replies |

## Requirements

- Python 3.11 or newer; CI currently tests 3.11–3.13.
- `hermes-agent>=0.13.0`. Use the canonical `hermes-mordred` command across the
  supported Hermes range.
- macOS or Linux. macOS can fall back from Secure Enclave to a software P-256
  key in the login Keychain. Linux requires TPM 2.0 and fails closed when its
  helper is unavailable.
- The transparent `.env`, configuration, memory-key, and workspace encryption
  lifecycle is currently macOS-only. Linux supports the TPM-backed keyvault,
  but these runtime targets report inactive and continue to use plaintext.

## Install (users, from PyPI)

Start with an installed
[Hermes Agent](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/getting-started/installation.md),
then run the Mordred installer:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | bash
```

To include the browser-extension server and Ethereum wallet support, pass the
installer option through `bash`:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | \
  bash -s -- --with-extension
```

Add `--version VERSION` (replacing `VERSION` with the release to install) to
pin either form to an exact PyPI release. The options can be combined:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | \
  bash -s -- --with-extension --version VERSION
```

The script follows Hermes's own install layout: it resolves the environment
behind the `hermes` on your `PATH`, checks the Hermes version, selects the
macOS or Linux dependencies, installs the PyPI package there, and writes a
`hermes-mordred` launcher next to `hermes` that scrubs `PYTHONPATH` /
`PYTHONHOME` exactly as Hermes's own launcher does. It does not configure
Mordred or create keys.

When upgrading from `mordred-hermes==0.1.0a15` or older, the installer first
confirms that a real `hermes-mordred>=0.1.0a16` release is available. Only then
does it uninstall the legacy distribution and install the canonical one. This
avoids two distributions owning the same `mordred_hermes` files; configuration,
keys, audit data, and other state under `~/.hermes/` are not changed.

To inspect the script first, download it and run `less mordred-install.sh`
before `bash mordred-install.sh`. The equivalent manual commands are:

```sh
# macOS
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  "hermes-mordred[macos]==0.1.0a16"

# Linux
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  "hermes-mordred[keyvault]==0.1.0a16"
```

See the [Quickstart](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/QUICKSTART.md)
for the inspect-before-running sequence and first-time setup.

Optional extras are dependency groups selected at installation time, not Hermes
plugins. The installer automatically selects `macos` on macOS or `keyvault` on
Linux; add the other extras only when you need the corresponding features:

| Extra | Use it for |
|---|---|
| `keyvault` | Cross-platform cryptography used by `encryption` and `keyvault` |
| `macos` | `keyvault` plus Secure Enclave and macOS system bridges |
| `ethereum` | HD-wallet derivation and signing |
| `tor-control` | Deep Tor liveness checks |
| `messaging` | Terminal QR codes for extension pairing |
| `extension` | Browser-extension WebSocket server and wallet RPC transport |

### Enable the plugins

The first `configure` run adds all six `mordred_*` entries to
`plugins.enabled` in `~/.hermes/config.yaml`. No manual edit is normally
required.

### Use it

The fastest path is the guided orchestrator:

```sh
hermes-mordred setup
```

`setup` probes each step in order and only runs what is still incomplete, so
it is safe to re-run after an interruption. It never deletes or recreates an
existing keyvault: a blocked or corrupt keyvault stops setup with repair
guidance instead of auto-repairing it. Add `--non-interactive` to run the
automatable subset and list the interactive commands still needed (exit code
0 only once everything is set up).

Prefer to drive each step yourself, or need to fix just one? `setup` runs the
manual sequence below, in the same order (after first checking upstream
Hermes) — start with the standalone command:

```sh
hermes-mordred configure                 # policy / LLM / harness setup
hermes-mordred network init              # optional: Tor / VPN / clearnet
```

Prepare the platform key helper, then create the keyvault:

```sh
# macOS: unattended keys work in background gateways without Touch ID prompts
hermes-mordred keyvault enable-se
MORDRED_SEKEY_UNATTENDED=1 hermes-mordred keyvault init

# Linux: run these instead
hermes-mordred keyvault enable-tpm
hermes-mordred keyvault init
```

On macOS, turn on transparent `.env` encryption and verify it:

```sh
MORDRED_SEKEY_UNATTENDED=1 hermes-mordred encryption enable env
hermes-mordred status                    # the env row should read [on] enrolled
```

The environment variable applies to each command separately. `keyvault init`
creates the main keyvault key; the first `encryption enable` creates a distinct
device key for the at-rest file vault, so both creation commands need the flag
when both keys must be unattended.

On Linux, the supported operator path stops after keyvault initialization and
status. The transparent env/config startup shims are not active there, and
`vault recover` does not yet have a Linux device-anchor store;
`encryption status` reports enrolled targets as inactive and plaintext remains
the runtime source.

Everyday commands:

```sh
hermes-mordred status
hermes-mordred encryption status
hermes-mordred encryption enable <env|config|memory|workspace|all>
hermes-mordred network use <tor|vpn|clearnet>
hermes-mordred network status
hermes-mordred audit tail
```

Once Hermes 0.19.0+ is configured and the plugins are enabled,
`hermes mordred <command>` exposes the same command tree. On older Hermes
versions, or before the first `configure`, keep using `hermes-mordred`.

See the [Quickstart](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/QUICKSTART.md)
for expected output and the
[usage guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/USAGE.md)
for every command and interactive prompt.

### Verify discovery

```sh
hermes-mordred plugins list
# mordred_e2e / mordred_keyvault / mordred_llm_guard / mordred_network /
# mordred_privacy_check / mordred_wizard
```

`hermes plugins list` scans plugin directories and does not list package entry
points. Use Mordred's command above when checking this package.

## Browser-extension WebSocket gateway (preview)

The optional extension server listens on `ws://127.0.0.1:7788/ext`, validates
the local peer and browser origin, and supports pairing, encrypted chat,
history, wallet accounts, and approval-bound signing.

The installer keeps preview dependencies out of its default install. Re-run it
with `--with-extension` to retain the platform keyvault dependencies and add
both the `extension` and `ethereum` extras:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | \
  bash -s -- --with-extension
```

The equivalent version-pinned manual command on macOS is:

```sh
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  "hermes-mordred[macos,extension,ethereum]==0.1.0a16"
```

Replace `macos` with `keyvault` on Linux, and add `messaging` only when you want
a terminal pairing QR.

The browser client is distributed separately as a
[prebuilt Chromium extension](https://github.com/InternetMaximalism/Mordred-Extension-dist).
Load its `dist/` directory as an unpacked extension.

### How it works

The extension authenticates with a one-time pairing flow and a rotated local
token. Gateway messaging uses the context-bound `ENC:v3` wire and rejects
plaintext Slack/Discord agent commands. Security model and protocol details
are in the
[Extension guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md).

### Run it (standalone)

```sh
hermes-mordred extension serve           # foreground; Ctrl+C to stop
# second terminal
hermes-mordred extension pair
```

The published Chromium bundle is authorized for port 7788 only. Use
`--port 7799` only with the bundled localhost page, tests, or a custom extension
build whose manifest permits that port. If 7788 is occupied, inspect the owner
before starting another server.

### Standalone behavior notes

`extension serve` runs the real Hermes agent when its runtime is installed.
Stock `hermes-agent` does not host this API, and the Mordred plugin does not
start it automatically because Hermes currently exposes no plugin boot hook
for long-running services. Compatible legacy/custom gateways may host the API;
verify the process rather than inferring that from an occupied port. See the
[Extension guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md)
for deployment, protocol, wallet, and troubleshooting details.

## Install (development)

Use the repository's editable `.venv`, separate from the production Hermes
environment:

```sh
git clone https://github.com/mordredagent/hermes-mordred.git
cd hermes-mordred
uv sync --all-extras
.venv/bin/hermes-mordred status
```

Local commands read real `~/.hermes` state unless `HERMES_HOME` is set. See
[development setup](https://github.com/mordredagent/hermes-mordred/blob/main/docs/dev/setup.md)
for safe isolation, loaded-code verification, and the full check suite.

## Troubleshooting

- For keyvault, Touch ID, and recovery issues, see
  [USAGE §4](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/USAGE.md#4-interactive-command-walkthroughs).
  The file-vault recovery command is currently macOS-only; encrypted data
  cannot be recovered if both its device key and recovery passphrase are lost.
  The main keyvault CLI can import but does not yet export a backup blob.
- For extension, gateway, and port 7788 issues, see the
  [extension troubleshooting guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md#troubleshooting).
- For Tor/VPN issues, run `hermes-mordred network status`, then
  `hermes-mordred network use <tor|vpn|clearnet>`; restart Hermes if the route
  changed.
- If the audit log falls back to plaintext with
  `mordred.degraded.audit_encryption_unavailable`, restart from a context that
  can access the device key. Recovery is automatic.

## Upgrading

Re-run the installer, then restart the Hermes gateway or a standalone
`extension serve` process:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | bash
```

This upgrades Mordred only and handles the transition from the old
`mordred-hermes` package name. Run it again if a Hermes update recreates its
virtual environment.

For a version-pinned upgrade, pass the desired PEP 440 release to the installer
(replace `VERSION` before running the command):

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | \
  bash -s -- --version VERSION
```

Add `--with-extension` before `--version` when that installation also runs the
browser-extension gateway or uses its Ethereum wallet bridge.

`hermes-mordred upgrade` migrates an existing Hermes or OpenClaw configuration;
it does not upgrade the package:

```sh
hermes-mordred upgrade
```

It is safe to repeat. Fresh installations should use `configure` instead.

## Uninstall

Decrypt data before removing the package or keys:

```sh
hermes-mordred encryption disable all
hermes-mordred vault disable-config-decrypt
hermes-mordred encryption status          # verify every target is off
```

Optionally destroy profile-owned keys only after verifying the plaintext data:

```sh
hermes-mordred keyvault reset --yes        # irreversible
```

Remove the six `mordred_*` entries from `plugins.enabled`, then uninstall:

```sh
uv pip uninstall --python ~/.hermes/hermes-agent/venv/bin/python3 \
  mordred-hermes hermes-mordred
# the launcher lands next to `hermes`, wherever that is
rm -f "$(dirname "$(command -v hermes)")/hermes-mordred"
```

State under `~/.hermes/mordred/` and installed native helpers are intentionally
left behind. Remove them manually only after confirming no encrypted data or
backup still depends on them.

## Repository layout

```text
src/mordred_hermes/    plugins and shared internals
native/                Secure Enclave and TPM helper sources
skills/                read-only Mordred status skill
scripts/install.sh      user installer for the Hermes-managed environment
tools/                 release and compatibility tooling
tests/                 unit and opt-in integration tests
docs/user/             operator documentation
docs/dev/              specification and developer documentation
```

## Documentation

| Audience | Document | Purpose |
|---|---|---|
| Users | [Quickstart](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/QUICKSTART.md) | PyPI install to protected secrets |
| Users | [Usage guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/USAGE.md) | Complete command reference and ceremonies |
| Users | [Extension guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md) | Browser extension, E2E messaging, and wallet bridge |
| Developers | [Development index](https://github.com/mordredagent/hermes-mordred/blob/main/docs/dev/README.md) | Maintained sources of truth |
| Developers | [Development setup](https://github.com/mordredagent/hermes-mordred/blob/main/docs/dev/setup.md) | Editable environment and validation workflow |

## License

MIT
