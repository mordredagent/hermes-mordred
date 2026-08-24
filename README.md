# hermes-mordred

[![PyPI](https://img.shields.io/pypi/v/hermes-mordred)](https://pypi.org/project/hermes-mordred/)
[![CI](https://github.com/mordredagent/hermes-mordred/actions/workflows/ci.yml/badge.svg)](https://github.com/mordredagent/hermes-mordred/actions/workflows/ci.yml)

Privacy-preserving plugins for the
[Hermes agent](https://github.com/NousResearch/hermes-agent): hardware-backed
keys, Tor/VPN routing, local-LLM policy enforcement, end-to-end gateway
messages, and macOS-integrated at-rest secret encryption.

**Status: active alpha** — current release `0.1.0a19`.

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
- The transparent `.env`, configuration, agent-memory, and workspace encryption
  lifecycle is currently macOS-only. Linux supports the TPM-backed keyvault,
  but production file-vault enables refuse (or are skipped by `setup` / `all`)
  and continue to use plaintext. A copied enrollment reports inactive.

## Install (users, from PyPI)

Start with an installed
[Hermes Agent](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/getting-started/installation.md),
then choose one of these two install paths.

For the standard installation:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | bash
```

For the browser-extension server and Ethereum wallet support, use the extension
bundle:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | \
  bash -s -- --with-extension
```

`--with-extension` is the convenience option for the `extension` and
`ethereum` dependency groups. The `messaging` extra is not required to use the
browser extension. Without it, `hermes-mordred extension pair` prints the
`MORT-...` pairing code as text; adding it also renders the code as a terminal
QR.

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
  "hermes-mordred[macos]==0.1.0a19"

# Linux
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  "hermes-mordred[keyvault]==0.1.0a19"
```

See the [Quickstart](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/QUICKSTART.md)
for the inspect-before-running sequence and first-time setup.

<details>
<summary>Advanced: choose individual dependency groups</summary>

Most users should use one of the two install paths above. Optional extras are
dependency groups, not Hermes plugins. `--extras LIST` accepts any
comma-separated combination from the table below. For example, append
`--extras messaging` to the recommended `--with-extension` command only when
you want a terminal pairing QR. You can add an extra later by rerunning the
installer.

For the extension bundle plus the terminal pairing QR, the equivalent fully
explicit form is:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | \
  bash -s -- --extras extension,ethereum,messaging
```

This selects those three extras only; it does not include `tor-control`.

The installer selects `macos` or `keyvault` automatically. `--all-extras` adds
all four user-facing extras, and `MORDRED_INSTALL_EXTRAS` accepts the same
comma-separated list in automation.

| Extra | Use it for |
|---|---|
| `extension` | Browser-extension WebSocket server and wallet RPC transport |
| `ethereum` | HD-wallet derivation and signing |
| `messaging` | Terminal QR codes for extension pairing |
| `tor-control` | Deep Tor liveness checks |

</details>

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

After initialization, create the first portable Keyvault snapshot in an
existing private directory:

```sh
hermes-mordred keyvault export --output /secure/path/keyvault-backup.mrkv
```

The destination must not already exist. Store the snapshot separately from the
Keyvault init passphrase and 24-word Seed Phrase, and export a new snapshot
after every Keyvault content change, including `keyvault eth new`.

On macOS, turn on transparent `.env` and agent-memory encryption and verify
both targets:

```sh
MORDRED_SEKEY_UNATTENDED=1 hermes-mordred encryption enable env
hermes-mordred encryption enable memory
hermes-mordred status              # the env and memory rows should both read [on]
```

The environment variable applies to each command separately. `keyvault init`
creates the main keyvault key; the first `encryption enable` creates a distinct
device key for the at-rest file vault, so both creation commands need the flag
when both keys must be unattended.

On Linux, the supported operator path stops after keyvault initialization and
status. The transparent env/config startup shims are not active there, and
`vault recover` does not yet have a Linux device-anchor store;
production file-vault enrollment is unavailable. A copied enrollment is
reported inactive, and plaintext remains the runtime source.

Everyday commands:

```sh
hermes-mordred status
hermes-mordred encryption status
hermes-mordred encryption enable env       # or: config, memory, workspace, all
hermes-mordred network use tor              # or: vpn, clearnet
hermes-mordred network status
hermes-mordred audit tail
```

Agent memories (`~/.hermes/memories/`) are encrypted by Mordred itself — no
Hermes release does it. The `memory` target is opt-in (via `setup` or
`encryption enable memory`), macOS-only, and rides on the `env` target, which
carries its key. Enabling seals the files already on disk; `disable` decrypts
them back. Restart a running `hermes gateway` afterwards — until you do, its
memory reads/writes fail closed (they do not write plaintext), and a session
may see an empty memory. Known limitations (raw readers,
out-of-process writers, approval-gated writes) are listed in
[`USAGE.md` §3](docs/user/USAGE.md#encryption--the-recommended-onoff-switch).

An `[on]` mark means that target's protection lifecycle is active; it does not
mean plaintext never exists while the data is in use. In particular, the
`config` target materializes a mode-`0600` plaintext `config.yaml` for the
lifetime of each managed Hermes process and reseals it on clean exit. The
`workspace` target is protected only while its status is `sealed`, not while it
is `open`. The
[Quickstart protection table](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/QUICKSTART.md#what-the-protected-states-mean)
summarizes every target, plaintext window, and restart requirement.

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

The `messaging` extra is not required to use the browser extension. Pairing
works without it because `extension pair` prints the pairing code as text. If
you also want a terminal QR, rerun the same command with `--extras messaging`
after `--with-extension`. For other custom combinations, see the advanced
installer options above.

<details>
<summary>Advanced: version-pinned manual install</summary>

The equivalent version-pinned manual command on macOS is:

```sh
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  "hermes-mordred[macos,extension,ethereum]==0.1.0a19"
```

Replace `macos` with `keyvault` on Linux, and add `messaging` only when you want
a terminal pairing QR.

</details>

The browser client is distributed separately as a
[prebuilt Chromium extension](https://github.com/mordredagent/mordred-extension-dist).
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
  Keyvault snapshots are created with `keyvault export` and restored with
  `keyvault recover`; keep the blob, init passphrase, and Seed Phrase separate.
- For extension, gateway, and port 7788 issues, see the
  [extension troubleshooting guide](https://github.com/mordredagent/hermes-mordred/blob/main/docs/user/EXTENSION.md#troubleshooting).
- For Tor/VPN issues, run `hermes-mordred network status`, then select a route
  with `hermes-mordred network use tor` (or `vpn` / `clearnet`); restart Hermes
  if the route changed.
- If the audit log falls back to plaintext with
  `mordred.degraded.audit_encryption_unavailable`, restart from a context that
  can access the device key. Recovery is automatic.
- The audit log is encrypted only after `keyvault init` (it needs the
  device-wrapped log key); before that, entries are written in plaintext and
  `hermes-mordred status` shows the audit-log row accordingly.

## Upgrading

Re-run the installer with the same `--extras`, `--all-extras`, or
`--with-extension` flags you used originally, then restart the Hermes gateway
or a standalone `extension serve` process:

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | bash
```

This upgrades Mordred only and handles the transition from the old
`mordred-hermes` package name. A Hermes self-update can recreate
`~/.hermes/hermes-agent/venv`; when that happens, a bare re-run installs only
the base package and silently drops any `extension`, `ethereum`, `messaging`,
or `tor-control` extras from before, because a recreated venv only gets what
the re-run itself asks for. Repeat the same extras flags to keep them. A
re-run against an intact venv leaves already-installed extra dependencies in
place, but only a re-run with the same flags re-resolves those extras against
the new release, so pass them every time.

For a version-pinned upgrade, pass the desired PEP 440 release to the installer
(replace `VERSION` before running the command):

```sh
curl -fsSL https://raw.githubusercontent.com/mordredagent/hermes-mordred/main/scripts/install.sh | \
  bash -s -- --version VERSION
```

Add `--with-extension` (or `--extras ...` / `--all-extras`) before `--version`
when that installation also runs the browser-extension gateway or uses its
Ethereum wallet bridge.

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
