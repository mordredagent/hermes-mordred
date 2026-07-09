# mordred-hermes

[![PyPI](https://img.shields.io/pypi/v/mordred-hermes)](https://pypi.org/project/mordred-hermes/)
[![CI](https://github.com/InternetMaximalism/mordred-hermes/actions/workflows/ci.yml/badge.svg)](https://github.com/InternetMaximalism/mordred-hermes/actions/workflows/ci.yml)

Privacy-preserving plugin bundle for the [Hermes agent](https://github.com/NousResearch/hermes-agent):
at-rest encryption for your secrets (`.env`, config, agent memory), hardware-backed
key management (Secure Enclave / TPM 2.0), Tor / VPN network routing, and policy
enforcement for local-only LLM operation.

**Status: active alpha** — current release `0.1.0a1`
([PyPI](https://pypi.org/project/mordred-hermes/), 2026-07-08).

> **⭐ Recommended: set up with an AI coding agent.** The first-run setup
> (`configure`, `network init`, `keyvault init`) is a series of interactive
> ceremonies with several prompts. Running them inside
> [Claude Code](https://www.anthropic.com/claude-code) or
> [Codex](https://openai.com/codex) is the recommended path — the agent walks you
> through each prompt, explains the options, and picks sensible defaults for your
> platform.

## The plugins

Five plugins, exposed via the `hermes_agent.plugins` entry-point group:

| Plugin | What it does |
|---|---|
| `mordred_privacy_check` | Skill-metadata policy enforcement and audit logging |
| `mordred_wizard` | The CLI surface — `configure`, `status`, `encryption`, `keyvault`, `network`, `audit`, … |
| `mordred_llm_guard` | Strict-mode enforcement of local-only LLM usage |
| `mordred_network` | Privacy-path management: Tor / VPN / clearnet |
| `mordred_keyvault` | Hardware-backed key management — Secure Enclave (macOS), TPM 2.0 (Linux), software fallback |

## Requirements

- Python ≥ 3.11
- `hermes-agent` ≥ 0.11.0 (behavior last verified against 0.18.2, 2026-07-08)
- macOS or Linux. No special hardware required — without a Secure Enclave / TPM,
  the keyvault degrades to a software-protected key automatically.

## Install (users, from PyPI)

Install into the **same environment that runs `hermes-agent`** (usually
`~/.hermes/hermes-agent/venv`) so its plugin loader can discover the entry points.
Hermes-managed venvs are often created by uv and ship no `pip`, so the robust
form is `uv pip install --python …`:

```sh
# macOS — includes the Secure Enclave keyvault stack
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 "mordred-hermes[macos]==0.1.0a1"

# Linux — cross-platform crypto stack for `encryption` / `keyvault`
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 "mordred-hermes[keyvault]==0.1.0a1"
```

(If your venv does have pip, `~/.hermes/hermes-agent/venv/bin/pip install …` works
the same.) **Pin the version explicitly** or pass `--pre`: every release is
currently a pre-release, so an unpinned `pip install mordred-hermes` only resolves
via pip's all-prereleases fallback.

Optional extras, all opt-in:

| Extra | Adds | Install when you need |
|---|---|---|
| `keyvault` | `cryptography` / `argon2-cffi` / `blake3` | `encryption` / `keyvault` commands on any platform |
| `macos` | `keyvault` + pyobjc Security / SystemConfiguration / Quartz bridges | Secure Enclave key protection on macOS |
| `ethereum` | `eth-keys` / `eth-hash` / `eth-account` / `rlp` | HD-wallet commands (`keyvault eth new / derive / address`) |
| `tor-control` | `stem` | Deep Tor liveness probing for strict-mode operators |
| `messaging` | `qrcode` | Terminal QR rendering for `extension pair` |

### Enable the plugins

Add them to `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - mordred_privacy_check
    - mordred_wizard
    - mordred_llm_guard
    - mordred_network
    - mordred_keyvault
```

### Use it

The CLI is the standalone `hermes-mordred` console script (installed next to
`hermes` in the same venv):

```sh
M=~/.hermes/hermes-agent/venv/bin/hermes-mordred

# First run — set up, in order:
$M configure                     # interactive setup — policy / LLM / harness
$M configure --skip-hermes-setup # re-run but skip the upstream `hermes setup` step
$M network init                  # optional — pick a privacy route (Tor / VPN / clearnet)
$M keyvault init                 # create the hardware-backed key (interactive ceremony)
$M encryption enable env         # encrypt your .env at rest
$M status                        # verify — the `env` row reads [on] enrolled

# Everyday commands:
$M status                          # protection at a glance
$M encryption status               # what's encrypted (env / config / memory)
$M encryption enable <target>      # turn on at-rest encryption for a target
$M network use <tor|vpn|clearnet>  # switch the active privacy route
$M network status                  # show the active route and liveness
$M encryption change-passphrase    # rotate the vault recovery passphrase
$M configure                       # re-run interactive setup anytime
$M configure --skip-hermes-setup   # re-run but skip the upstream `hermes setup` step
```

> **Network troubleshooting.** If network communication drops out now and then,
> check the active privacy path first — `network status` tells you whether Tor /
> VPN is actually up:
>
> ```sh
> $M network status
> # active_path = tor  state = ready      last_health = ok       ← path is up
> # active_path = tor  state = not ready  last_health = FAILED   ← path is down
> ```
>
> `state` is `ready` / `not ready`, `last_health` is `ok` / `FAILED`. A trailing
> `[warning] path was flagged as DROPPED` line means the liveness worker saw
> consecutive failures; in strict mode tool calls refuse until you re-establish
> the path with `network use <tor|vpn|clearnet>`.

Step-by-step guide with expected output:
**[QUICKSTART](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/QUICKSTART.md)**.
Full command reference and interactive-command walkthroughs:
**[USAGE](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/USAGE.md)**.

> **Why not `hermes mordred …`?** Hermes does not yet wire entry-point CLI
> commands into its argparse (still true on 0.18.2) — `hermes-mordred` is the
> same subcommand tree and works today. Once upstream wires it, both forms will
> coexist without code changes.

### Verify discovery

Use Mordred's own command — it lists the five plugins on any supported Hermes
version:

```sh
~/.hermes/hermes-agent/venv/bin/hermes-mordred plugins list
# → mordred_keyvault / mordred_llm_guard / mordred_network / mordred_privacy_check / mordred_wizard
```

The **host** `hermes plugins list` scans plugin *directories* only (bundled /
user / project), so it does **not** list entry-point plugins like these. To
confirm the loader itself discovers them, query it directly:

```sh
~/.hermes/hermes-agent/venv/bin/python3 -c "
from hermes_cli.plugins import PluginManager
mgr = PluginManager(); mgr.discover_and_load(force=True)
print(sorted(k for k, p in mgr._plugins.items() if p.manifest.source == 'entrypoint'))
"
# → ['mordred_keyvault', 'mordred_llm_guard', 'mordred_network', 'mordred_privacy_check', 'mordred_wizard']
```

## Install (development)

Canonical dev flow: editable install into the Hermes-managed venv
(see [setup.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/setup.md)
for the full environment build):

```sh
# from this repo's root; add ".[macos]" on macOS
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 -e .
```

**Refresh a non-editable live venv.** If the live venv holds a *wheel* instead
of the editable install above — the PyPI wheel, or a prior repo build — repo
edits do **not** reach the `hermes-mordred` binary until you rebuild and
reinstall it from the repo root:

```sh
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 --reinstall --no-deps .
```

`--reinstall` is required whenever the version string is unchanged (two builds
both reporting `0.1.0a1`, say): without it uv treats the requirement as already
satisfied and no-ops, leaving the binary on stale code — the symptom is a newly
added flag such as `configure --skip-hermes-setup` failing with `unrecognized
arguments`. `--no-deps` keeps the live editable `hermes-agent` checkout
untouched. Re-run the same command if Hermes rebuilds its venv and drops the
wheel.

Local checks run from the repo's own uv-managed venv and mirror the CI `test`
job (`HERMES_HOME` keeps the tests away from your real `~/.hermes`):

```sh
uv sync --all-extras                # one-time: builds .venv from uv.lock

uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
HERMES_HOME=/tmp/hermes-mordred-test-home uv run pytest
```

The default suite is hermetic — integration tests (`-m integration`) are
excluded and opt back in per suite:

- **Tor**: hermetic Docker-based `integration-tor` job in CI (`ci.yml`).
- **Keyvault live hardware**: `MORDRED_KEYVAULT_LIVE=1 pytest -m integration tests/integration/test_keyvault_macos.py`
- **Live VPN**: `MORDRED_LIVE_VPN_TEST=1 MORDRED_MULLVAD_ACCOUNT=… pytest -m integration tests/integration/test_vpn.py`
  (also available as the `workflow_dispatch`-only `integration-vpn.yml` job)

Both live suites were last validated on real devices on 2026-05-25.

Releases are cut via the `release.yml` workflow (PyPI Trusted Publishing);
bump versions in lockstep with `tools/bump_version.py`. Runbook:
[CI.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/CI.md).

## Uninstall

Reverse the setup in the order below.

> **⚠️ Decrypt before you remove anything.** If you turned on at-rest encryption,
> uninstalling the package or deleting the key first leaves your `.env`, config,
> and memory **permanently unreadable**. Run step 1 while the CLI and key are still
> present.

```sh
M=~/.hermes/hermes-agent/venv/bin/hermes-mordred
```

**1. Decrypt everything back to plaintext.**

```sh
$M encryption disable all        # env / config / memory / workspace → plaintext
$M vault disable-config-decrypt  # stop transparent config decrypt, restore plaintext config.yaml
$M encryption status             # verify — every row reads [off]
```

**2. Destroy the key material** — optional and **irreversible**. Skip it if you
plan to reinstall and keep the same vault.

```sh
$M keyvault reset --yes          # DESTROY the hardware-backed key + remove the keyvault dir
```

**3. Disable the plugins.** Remove the five `mordred_*` entries from the
`plugins.enabled` list in `~/.hermes/config.yaml` (undo
[Enable the plugins](#enable-the-plugins)).

**4. Uninstall the package** from the Hermes venv. This also removes the
config-decrypt `.pth` bootstrap from site-packages.

```sh
uv pip uninstall --python ~/.hermes/hermes-agent/venv/bin/python3 mordred-hermes
# or, if the venv ships pip:
~/.hermes/hermes-agent/venv/bin/pip uninstall mordred-hermes
```

**5. Remove leftover state** — optional, and only after step 1 (the vault lives
here):

```sh
rm -rf ~/.hermes/mordred/        # audit log, policy, credentials, tor-data, keyvault
```

Also delete any `MORDRED_*` entries you added to `~/.hermes/.env`. If you ran
`keyvault enable-se` / `enable-tpm`, the built helper is **not** removed by the
steps above — delete it by hand (default location, unless you set
`MORDRED_SEKEY_INSTALL_DIR` / `MORDRED_TPMKEY_INSTALL_DIR`):

```sh
rm -f ~/.local/bin/mordred-hermes-sekey    # macOS Secure Enclave helper
rm -f ~/.local/bin/mordred-hermes-tpmkey   # Linux TPM 2.0 helper
```

## Repository layout

```
src/mordred_hermes/    the five plugins + shared internals
native/                hardware-key helper sources, shipped in the wheel and built
                       on demand by `keyvault enable-se` / `enable-tpm`:
                         sekey-helper/  — Swift, Secure Enclave (macOS)
                         tpmkey-helper/ — Rust, TPM 2.0 (Linux)
skills/mordred-status/ read-only conversational status skill for the agent
packaging/             config-decrypt .pth bootstrap; PyPI name-reservation stub
scripts/               offline verification-digest tool for `keyvault init`
tools/                 dev tooling (version bump, hook-payload drift check)
tests/                 hermetic unit suite + opt-in tests/integration/
docs/                  user and developer documentation (see below)
```

## Documentation

| Audience | Doc | Contents |
|---|---|---|
| Users | [QUICKSTART.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/QUICKSTART.md) | Zero → protected install, step by step |
| Users | [USAGE.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/USAGE.md) | Full command reference, interactive walkthroughs, storage model |
| Developers | [setup.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/setup.md) | Development environment from scratch |
| Developers | [SPEC.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/SPEC.md), [POLICY.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/POLICY.md) | Design spec and policy model |
| Developers | [SECRETS_ENV_ENCRYPTION.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/SECRETS_ENV_ENCRYPTION.md), [KEYVAULT_BACKENDS.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/KEYVAULT_BACKENDS.md) | At-rest encryption and key-backend design |
| Developers | [CI.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/CI.md), [UPSTREAM.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/UPSTREAM.md) | CI strategy, release runbook, upstream tracking |

More under [`docs/dev/`](https://github.com/InternetMaximalism/mordred-hermes/tree/main/docs/dev):
PLAN, TODO, ROADMAP, PATHS, MIGRATION, HARNESS_PRIVACY, HOOK_PAYLOADS.

## License

MIT
