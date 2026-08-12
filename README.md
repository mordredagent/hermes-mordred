# mordred-hermes

[![PyPI](https://img.shields.io/pypi/v/mordred-hermes)](https://pypi.org/project/mordred-hermes/)
[![CI](https://github.com/InternetMaximalism/mordred-hermes/actions/workflows/ci.yml/badge.svg)](https://github.com/InternetMaximalism/mordred-hermes/actions/workflows/ci.yml)

Privacy-preserving plugins for the
[Hermes agent](https://github.com/NousResearch/hermes-agent): at-rest secret
encryption, hardware-backed keys, Tor/VPN routing, local-LLM policy enforcement,
and end-to-end encryption for Slack and Discord gateway messages.

**Status: active alpha** — current release `0.1.0a14`.

New here? Follow the
**[Quickstart](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/QUICKSTART.md)**
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
- `hermes-agent>=0.13.0`. The host form `hermes mordred ...` additionally
  requires Hermes 0.19.0 or newer; the standalone `hermes-mordred` command
  works across the supported range.
- macOS or Linux. macOS can fall back from Secure Enclave to a software P-256
  key in the login Keychain. Linux requires TPM 2.0 and fails closed when its
  helper is unavailable.

## Install (users, from PyPI)

Start with an installed
[Hermes Agent](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/getting-started/installation.md),
then run the Mordred installer:

```sh
curl -fsSL https://raw.githubusercontent.com/InternetMaximalism/mordred-hermes/main/scripts/install.sh | bash
```

The script follows Hermes's own install layout: it resolves the environment
behind the `hermes` on your `PATH`, checks the Hermes version, selects the
macOS or Linux dependencies, installs the PyPI package there, and writes a
`hermes-mordred` launcher next to `hermes` that scrubs `PYTHONPATH` /
`PYTHONHOME` exactly as Hermes's own launcher does. It does not configure
Mordred or create keys.

To inspect the script first, download it and run `less mordred-install.sh`
before `bash mordred-install.sh`. The equivalent manual commands are:

```sh
# macOS
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  "mordred-hermes[macos]==0.1.0a14"

# Linux
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  "mordred-hermes[keyvault]==0.1.0a14"
```

See the [Quickstart](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/QUICKSTART.md)
for the inspect-before-running sequence and first-time setup.

Optional extras:

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

Start with the standalone command:

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

Turn on encryption and verify it:

```sh
hermes-mordred encryption enable env
hermes-mordred status                    # the env row should read [on] enrolled
```

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

See the [Quickstart](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/QUICKSTART.md)
for expected output and the
[usage guide](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/USAGE.md)
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

The one-line installer deliberately installs only the platform keyvault extra,
so `extension serve` exits with code 2 and prints how to add the `extension`
extra until it is installed:

```sh
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  "mordred-hermes[macos,extension,ethereum]==0.1.0a14"
```

### How it works

The extension authenticates with a one-time pairing flow and a rotated local
token. Gateway messaging uses the context-bound `ENC:v3` wire and rejects
plaintext Slack/Discord agent commands. Security model and protocol details
are in the
[Extension guide](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/EXTENSION.md).

### Run it (standalone)

```sh
hermes-mordred extension serve           # foreground; Ctrl+C to stop
# second terminal
hermes-mordred extension pair
```

Use `--port 7799` when another Hermes gateway already owns port 7788.

### Standalone behavior notes

`extension serve` runs the real Hermes agent when its runtime is installed.
It does not start automatically because Hermes currently exposes no plugin
boot hook for long-running services. See the
[Extension guide](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/EXTENSION.md)
for deployment, protocol, wallet, and troubleshooting details.

## Install (development)

Use the repository's editable `.venv`; do not replace the production Hermes
environment for normal development:

```sh
git clone https://github.com/InternetMaximalism/mordred-hermes.git
cd mordred-hermes
uv sync --all-extras

.venv/bin/python -c "import mordred_hermes; print(mordred_hermes.__file__)"
.venv/bin/hermes-mordred status
```

The printed module path should be under this checkout's `src/`. Local commands
still use real `~/.hermes` state unless isolated:

```sh
env HERMES_HOME=/tmp/mordred-test-home \
  .venv/bin/hermes-mordred configure
```

Only replace `~/.hermes/hermes-agent/venv` with an editable install when an
end-to-end production-profile test specifically requires it. The full workflow,
including how to restore the PyPI wheel, is in
[development setup](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/setup.md).

Run the standard checks through uv:

```sh
uv run pytest -q
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy --strict src tools
```

## Troubleshooting

| Symptom | What to do |
|---|---|
| A background gateway starts without vault-managed secrets | The vault likely uses an attended Secure Enclave key. Follow the verified backup/recovery procedure in [USAGE §4.3](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/USAGE.md#43-touch-id-prompts--why-several-per-command-and-how-to-silence-them) and create the replacement key with `MORDRED_SEKEY_UNATTENDED=1`. Re-running `enable-se` alone does not change an existing key policy. |
| `extension serve` reports port 7788 in use | Run `lsof -nP -iTCP:7788 -sTCP:LISTEN`. If Hermes already owns it, the API is running; otherwise stop the stale process or use `--port 7799`. |
| Tor/VPN communication stops | Run `hermes-mordred network status`, then re-establish the selected route with `hermes-mordred network use <tor\|vpn\|clearnet>`. Restart Hermes after changing routes. |
| The audit log is plaintext and contains `mordred.degraded.audit_encryption_unavailable` | Restart the process from a context that can access the device key. Recovery is automatic; purge rotated plaintext logs with `hermes-mordred audit purge --before YYYY-MM-DD --yes` if required. |
| The recovery passphrase is lost | If the current device key still works, run `hermes-mordred encryption change-passphrase`. If both the passphrase and device key are gone, the encrypted data cannot be recovered. |

## Upgrading

Package upgrades and config migration are separate operations.

### Upgrade the installed package

Re-run the installer to upgrade Mordred without upgrading Hermes:

```sh
curl -fsSL https://raw.githubusercontent.com/InternetMaximalism/mordred-hermes/main/scripts/install.sh | bash
```

For a version-pinned upgrade, install the desired version manually into the
Hermes environment:

```sh
# macOS; use [keyvault] on Linux
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  "mordred-hermes[macos]==<new-version>"
```

The equivalent manual command for the newest release is:

```sh
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 \
  --upgrade-package mordred-hermes "mordred-hermes[macos]"
```

Restart the Hermes gateway or `extension serve` after upgrading.

### When Hermes itself is updated

An in-place Hermes update normally preserves the Mordred wheel, but does not
upgrade it. If Hermes recreates its venv, reinstall Mordred and verify the
loaded path:

```sh
~/.hermes/hermes-agent/venv/bin/python3 -c \
  "import mordred_hermes; print(mordred_hermes.__file__)"
```

### Migrate config with `hermes-mordred upgrade`

`hermes-mordred upgrade` migrates an existing Hermes or OpenClaw configuration. It is
idempotent and safe to repeat:

```sh
hermes-mordred upgrade
hermes-mordred upgrade --non-interactive --policy-conflict keep-existing
```

Fresh installations should use `configure`, not `upgrade`.

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
uv pip uninstall --python ~/.hermes/hermes-agent/venv/bin/python3 mordred-hermes
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
| Users | [Quickstart](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/QUICKSTART.md) | PyPI install to protected secrets |
| Users | [Usage guide](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/USAGE.md) | Complete command reference and ceremonies |
| Users | [Extension guide](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/EXTENSION.md) | Browser extension, E2E messaging, and wallet bridge |
| Users | [Hermes basics](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/HERMES_BASICS.md) | Running the base Hermes agent |
| Developers | [Development index](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/README.md) | Current sources of truth and historical records |
| Developers | [Development setup](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/setup.md) | Editable environment and validation workflow |

## License

MIT
