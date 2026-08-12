# mordred_wizard

The supported user-facing CLI for Mordred setup, policy inspection, network
selection, key management, at-rest encryption, migration, and extension
pairing.

Use `hermes-mordred` for every operation. It works before any plugin is enabled,
across every supported Hermes version, and during recovery. Run
`hermes-mordred --help` for the authoritative command list.

See [SPEC.md](../../../docs/dev/SPEC.md),
[PATHS.md](../../../docs/dev/PATHS.md), and
[POLICY.md](../../../docs/dev/POLICY.md).

## Subcommand reference

### `status [--json]`

Show policy, configured and live network state, keyvault readiness, and the
four at-rest encryption targets. This command is read-only and does not prompt
or open a hardware authorization flow.

### `configure [--non-interactive] [--policy=...] [--harness=...] [...]`

Configure policy, LLM, and harness settings. It updates
`~/.hermes/config.yaml` and the wizard-owned
`~/.hermes/mordred/policy.json` mirror without replacing unrelated YAML
sections. Network setup is intentionally separate:
`hermes-mordred network init`.

### `upgrade [--reset] [--non-interactive] [--audit-merge=...] [--policy-conflict=...]`

Run the idempotent migration for an existing Hermes installation and, when
detected, legacy `~/.openclaw/mordred/` state. Conflict flags make destructive
choices explicit; `--non-interactive` fails when a required choice is absent.

### `install <skill>`

Install a skill through the same policy decision used by
`mordred_privacy_check`. A strict-mode refusal exits with code 2 after writing
its audit event.

### `network {init,use,status}`

- `network init` configures Tor, VPN, or clearnet and any required credentials.
- `network use <tor|vpn|clearnet>` selects the default route.
- `network status [--json]` shows configured and live route state.

The process route is frozen after activation. Selecting a different route for
an already-running Hermes process requires a restart.

### `policy {show,explain,dry-run,reload}`

Inspect the resolved policy, explain a known skill decision, evaluate a
`SKILL.md` without installing it, or clear the in-process policy cache.
`reload` does not clear an integrity poison flag.

### `audit {tail,grep}`

`tail` and `grep` inspect the audit stream. `decrypt --date YYYY-MM-DD` reads
encrypted `MRAL` logs through the native authorization boundary. The
destructive `purge --before YYYY-MM-DD --yes` command removes only dated,
rotated history and never the active log.

### `plugins list`

List discovered plugins whose key starts with `mordred_`. The command uses the
Hermes plugin manager when available and falls back to configured plugin state.

### `extension {pair,serve}`

Generate a pairing code or run the loopback WebSocket bridge. The server needs
the `extension` extra; QR rendering additionally needs `messaging`. See the
[Extension guide](../../../docs/user/EXTENSION.md).

### `keyvault {list,verify-digest}`

Inspect key IDs and verification digests from disk without loading a native
backend. Secret key material is never printed.

### `keyvault {init,recover,reset}`

Create a hardware-backed keyvault, recover from a backup, or reset profile-owned
state. `reset` is destructive and recovery requires the backup blob, Seed
Phrase, and Passphrase.

Native helpers are installed explicitly:

- macOS: `hermes-mordred keyvault enable-se`
- Linux: `hermes-mordred keyvault enable-tpm`

### `encryption {status,enable,disable,purge,change-passphrase}`

This is the recommended interface for at-rest protection of `env`, `config`,
`memory`, `workspace`, or `all`. `disable` keeps the encrypted vault copy;
`purge` removes it and requires confirmation.

### `vault {init,recover,add,status,cat,migrate,...}`

Low-level encrypted-file storage commands. Most users should use
`encryption`; use `vault` for recovery and advanced maintenance.

## Owned filesystem paths (see `docs/dev/PATHS.md`)

The wizard is the sole writer of:

- `~/.hermes/mordred/policy.json`
- Mordred sections in `~/.hermes/config.yaml`
- `~/.hermes/mordred/.audit-migrated-from-openclaw`

It also coordinates writes to `.env`, network credentials, keyvault, and vault
state through their owning modules. It reads the audit log but never appends
audit entries directly. The complete ownership table is in
[PATHS.md](../../../docs/dev/PATHS.md).

## Internal API

The CLI is the public contract. The implementation is split by command:
`configure.py`, `upgrade.py`, `network_cli.py`, `audit_cli.py`,
`keyvault_cli.py`, `encryption_cli.py`, `vault_cli.py`, and
`extension_pair_cli.py`. Cross-command YAML updates go through
`PolicyWriter` so unrelated settings and comments are preserved.

## Fixture catalog

Shared skill fixtures live under `tests/fixtures/`:

- `clearnet_skill/` declares a clearnet requirement.
- `tor_skill/` declares a Tor requirement.
- `missing_metadata_skill/` has no Mordred metadata.

Wizard tests redirect all owned paths to `tmp_path`; they do not touch the
operator's real `~/.hermes` state.
