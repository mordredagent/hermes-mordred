# mordred-hermes

[![PyPI](https://img.shields.io/pypi/v/mordred-hermes)](https://pypi.org/project/mordred-hermes/)
[![CI](https://github.com/InternetMaximalism/mordred-hermes/actions/workflows/ci.yml/badge.svg)](https://github.com/InternetMaximalism/mordred-hermes/actions/workflows/ci.yml)

Privacy-preserving plugin bundle for the [Hermes agent](https://github.com/NousResearch/hermes-agent):
at-rest encryption for your secrets (`.env`, config, agent memory), hardware-backed
key management (Secure Enclave / TPM 2.0), Tor / VPN network routing, and policy
enforcement for local-only LLM operation.

**Status: active alpha** — current release `0.1.0a13`
([PyPI](https://pypi.org/project/mordred-hermes/) has the release history and dates).

New here? The step-by-step
**[QUICKSTART](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/QUICKSTART.md)**
takes you from zero to a protected install.

> **⭐ Recommended: set up with an AI coding agent.** The first-run setup
> (`configure`, `network init`, `keyvault init`) is a series of interactive
> ceremonies with several prompts. Running them inside
> [Claude Code](https://www.anthropic.com/claude-code) or
> [Codex](https://openai.com/codex) is the recommended path — the agent walks you
> through each prompt, explains the options, and picks sensible defaults for your
> platform.

## The plugins

The Mordred entry-point plugins, exposed via the `hermes_agent.plugins` entry-point group:

| Plugin | What it does |
|---|---|
| `mordred_privacy_check` | Skill-metadata policy enforcement and audit logging |
| `mordred_wizard` | The CLI surface — `configure`, `status`, `encryption`, `keyvault`, `network`, `audit`, … |
| `mordred_llm_guard` | Strict-mode enforcement of local-only LLM usage |
| `mordred_network` | Privacy-path management: Tor / VPN / clearnet |
| `mordred_keyvault` | Hardware-backed key management — Secure Enclave with Keychain fallback (macOS), TPM 2.0 (Linux) |
| `mordred_e2e` | End-to-end encryption for gateway messaging platforms (Slack / Discord) — decrypts inbound, re-encrypts outbound replies |

## Requirements

- Python ≥ 3.11 (CI tests 3.11–3.13)
- `hermes-agent` ≥ 0.13.0 (its first PyPI release — older versions were never
  published and are not installable). The floor is exercised in CI on every PR
  (the `hermes-floor` job pins it exactly); behavior against the latest release
  was last verified on 0.19.0, 2026-07-21
- macOS or Linux. macOS can fall back to a software P-256 key in the login
  Keychain when Secure Enclave access is unavailable. Linux keyvault setup
  requires the TPM 2.0 helper and fails closed when it is absent.

## Install (users, from PyPI)

Install into the **same environment that runs `hermes-agent`** (usually
`~/.hermes/hermes-agent/venv`) so its plugin loader can discover the entry points.
Hermes-managed venvs are often created by uv and ship no `pip`, so the robust
form is `uv pip install --python …` (no `uv` on your machine? Install it first —
`brew install uv` on macOS, or see the
[uv installation guide](https://docs.astral.sh/uv/getting-started/installation/)):

```sh
# macOS — includes the Secure Enclave keyvault stack
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 "mordred-hermes[macos]==0.1.0a13"

# Linux — cross-platform crypto stack for `encryption` / `keyvault`
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 "mordred-hermes[keyvault]==0.1.0a13"
```

(If your venv does have pip, `~/.hermes/hermes-agent/venv/bin/pip install …` works
the same.) **The pinned form above is the recommended default** — it's
deterministic and reproducible. Prefer not to look up the current version? The
unpinned `--upgrade` form resolves to the newest pre-release — every release is
currently a pre-release, so the all-prereleases fallback applies (the same goes
for plain `pip`, which also accepts an explicit `--pre`; see
[Upgrading](#upgrading) for the same command used to update later):

```sh
# macOS — newest release without a version lookup; use [keyvault] on Linux
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 --upgrade "mordred-hermes[macos]"
```

Optional extras, all opt-in:

| Extra | Adds | Install when you need |
|---|---|---|
| `keyvault` | `cryptography` / `argon2-cffi` / `blake3` | `encryption` / `keyvault` commands on any platform |
| `macos` | `keyvault` + pyobjc Security / SystemConfiguration / Quartz bridges | Secure Enclave key protection on macOS |
| `ethereum` | `eth-keys` / `eth-hash` / `eth-account` / `rlp` | HD-wallet commands (`keyvault eth new / derive / address`) |
| `tor-control` | `stem` | Deep Tor liveness probing for strict-mode operators |
| `messaging` | `qrcode` | Terminal QR rendering for `extension pair` |
| `extension` | `aiohttp` / `cryptography` / `requests[socks]` / `urllib3` | The [browser-extension WebSocket gateway](#browser-extension-websocket-gateway-preview), pairing, and Tor-routed RPC transport |

### Enable the plugins

Running `hermes-mordred configure` (next section) does this for you — every
run back-fills all six `mordred_*` entries into `plugins.enabled` in
`~/.hermes/config.yaml` if they're missing, so there's no manual step.
Afterwards `~/.hermes/config.yaml` should contain:

```yaml
plugins:
  enabled:
    - mordred_privacy_check
    - mordred_wizard
    - mordred_llm_guard
    - mordred_network
    - mordred_keyvault
    - mordred_e2e
```

Only edit this by hand if you want the plugins enabled *before* the first
`configure` run — otherwise there's nothing to do here.

### Use it

The CLI is the standalone `hermes-mordred` console script (installed next to
`hermes` in the same venv):

```sh
M=~/.hermes/hermes-agent/venv/bin/hermes-mordred

# First run — set up, in order:
$M configure                       # interactive Mordred setup (policy / LLM / harness)
$M network init                    # optional — pick a privacy route (Tor / VPN / clearnet)
$M keyvault enable-se              # macOS — install/refresh and probe the SE helper
MORDRED_SEKEY_UNATTENDED=1 $M keyvault init
                                    # create a no-Touch-ID hardware key (interactive ceremony)
$M encryption enable env           # encrypt your .env at rest
$M status                          # verify — the `env` row reads [on] enrolled

# Everyday commands:
$M status                          # protection at a glance
$M encryption status               # what's encrypted (env / config / memory)
$M encryption enable <target>      # turn on at-rest encryption for a target
$M network use <tor|vpn|clearnet>  # switch the active privacy route
$M network status                  # show the active route and liveness
$M encryption change-passphrase    # rotate the vault recovery passphrase
$M configure                       # re-run interactive setup anytime
$M configure --with-hermes-setup   # re-run and include the upstream `hermes setup` wizard
```

> **Why unattended key creation is recommended on macOS.** The default
> **attended** device key asks for Touch ID on every vault unwrap — a
> **background** process (a launchd-started gateway, `extension serve`) can
> never answer that prompt and silently starts without the vault-managed
> secrets. `enable-se` only installs/probes the helper; it does not create,
> promote, or migrate a wrapping key. It is safe to refresh with an existing
> vault: existing helper, legacy Keychain, and software keys remain in their
> current namespace and continue through backend fallback. Set
> `MORDRED_SEKEY_UNATTENDED=1` on a later fresh `keyvault init` (or recovery)
> command: the attended/unattended choice is fixed at key creation. Already
> hit this, or want the full trade-off?
> See [Troubleshooting](#troubleshooting) below.

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

> **Two ways to invoke, same subcommand tree.** `hermes-mordred …` is the
> standalone console script and always works. `hermes mordred …` — the same tree
> hanging off the host CLI — additionally needs **hermes-agent 0.19.0+** with the
> plugins enabled in `~/.hermes/config.yaml` (which `configure` does for you).
> Older builds, down to the supported floor of 0.13.0, do not wire entry-point
> CLI commands into their argparse, so there `hermes mordred` falls through to
> the top-level usage — use `hermes-mordred` instead. On a fresh install, before
> `configure` has run, `hermes-mordred` is the only form available.

### Verify discovery

Use Mordred's own command — it lists the Mordred plugins on any supported Hermes
version:

```sh
~/.hermes/hermes-agent/venv/bin/hermes-mordred plugins list
# → mordred_e2e / mordred_keyvault / mordred_llm_guard / mordred_network / mordred_privacy_check / mordred_wizard
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
# → ['mordred_e2e', 'mordred_keyvault', 'mordred_llm_guard', 'mordred_network', 'mordred_privacy_check', 'mordred_wizard']
```

## Browser-extension WebSocket gateway (preview)

`mordred_hermes.extension` ships the WebSocket server the Mordred browser
extension talks to — `ws://127.0.0.1:7788/ext`, localhost-only, no TLS. It was
ported from the full-Hermes gateway layer in #30 and ships on PyPI since
`0.1.0a2` (install the `extension` extra).

Gateway messaging E2E (Slack / Discord) uses the context-bound `ENC:v3`
wire. This is a deliberate breaking change from gateway command/reply v1/v2:
deploy a v3-capable Mordred Extension at the same time. Legacy v1/v2 crypto
remains available to the WebSocket API and stored-history helpers, but is not
accepted as an agent command. See [the gateway E2E wire specification](docs/dev/SLACK_E2E.md).

### How it works

The server refuses non-loopback binds and validates the TCP peer, Host, and
Origin. It admits only `chrome-extension://` / `moz-extension://` clients,
header-less loopback processes, and its own localhost page. On connect
the server sends an `auth_challenge`; the extension authenticates with its
paired `ext_token` (plus a WebAuthn assertion once a Chromium-extension
credential is registered), the localhost page with a per-process page token
delivered only in the private launch URL's fragment. The fragment is not sent
over HTTP and is removed from browser history before the app starts. Extension
WebSocket sessions remain bound to the pairing token generation that
authenticated them; re-pairing or clearing pairing state immediately revokes
their next privileged frame and discards pending approvals. Firefox
transport remains supported, but Firefox WebAuthn registration is refused
until the wire protocol carries its browser-specific stable ceremony origin
and RP ID. After auth:

| Message | What it does |
|---|---|
| `pair_init` | Consume a `MORT-…` pairing code, establish the shared key (pre-auth) |
| `chat` | Stream one conversation turn as `chat_chunk*` + `chat_end`; replies-in-kind E2E with `K_extchat` (encrypted in → encrypted out) |
| `encrypt` / `decrypt` | Slack-message crypto with the paired key |
| `accounts_request` | Wallet address + chain id from the keyvault |
| `sign_request` → `sign_prompt`, then `sign_approve` → `sign_result` | Deterministic risk analysis and keyvault signing. Every prompt freezes the exact requested signer; transactions additionally freeze chain, nonce, gas, fees, and RPC origin after filling. If the selected wallet changes before approval, signing fails |
| `history_get` / `history_clear` | Encrypted-at-rest conversation history. If a read would exceed the bounded WebSocket frame, Hermes returns the newest complete suffix with `truncated: true`; stored history is unchanged |

For `eth_sendTransaction`, the extension cannot introduce an arbitrary RPC
endpoint or chain: both must match the operator-selected values in
`~/.hermes/extension/wallet.json` (or the built-in endpoint for that configured
chain). RPC transport rejects local/private targets and redirects, pins
validated direct DNS answers, and never bypasses the route selected by the
network gateway. Before returning any message signature or broadcasting a raw
transaction, Hermes recovers its actual signer and verifies that it is still
the address shown in the approval prompt.

Wire protocol: the extension repo's `SPEC.ja.md` §6 / `src/lib/protocol.ts`;
server side in [`src/mordred_hermes/extension/api.py`](src/mordred_hermes/extension/api.py).

### Run it (standalone)

Nothing starts the server automatically yet: Hermes exposes no gateway-boot
hook a plugin could use, so `register(ctx)` cannot launch a long-running server
(see `docs/dev/ROADMAP.md` §"Remaining browser-extension gateway integration"). Until that
lands, start it in the foreground with one command — it needs the `extension`
extra (see the [extras table](#install-users-from-pypi) above).

**PyPI install** — include `extension`; add `ethereum` for the wallet signing
flows shown below (swap `macos` for `keyvault` on Linux):

```sh
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 "mordred-hermes[macos,extension,ethereum]==0.1.0a13"
```

Then use the `$M` alias from [Use it](#use-it):

```sh
$M extension serve      # ws://127.0.0.1:7788/ext — Ctrl+C to stop
# equivalent module form, same --host/--port flags:
~/.hermes/hermes-agent/venv/bin/python3 -m mordred_hermes.extension
```

**From a dev checkout** instead:

```sh
uv sync --extra extension --extra ethereum
# or: uv pip install -e ".[extension,ethereum]"

.venv/bin/hermes-mordred extension serve      # ws://127.0.0.1:7788/ext — Ctrl+C to stop
.venv/bin/python -m mordred_hermes.extension
```

Bind failures (port already in use, bad host, privileged port) exit with a
one-line error instead of a traceback — see
[Troubleshooting](#troubleshooting) if you hit a bound-port error. Both
Ctrl+C and SIGTERM (systemd, `docker stop`) shut down cleanly. One divergence
between the two forms: with the `extension` extra missing, only
`hermes-mordred extension serve` prints the install hint — the module form
fails on the package import itself with a plain `ImportError`.

Pairing, auth (incl. Chromium WebAuthn), `encrypt`/`decrypt`, history, and the
keyvault-backed `accounts_request` / `sign_request` flows are fully functional
standalone — they only touch `~/.hermes` and the keyvault.

### Standalone behavior notes

- **Chat runs the real agent.** `serve` probes for the Hermes runtime
  (`gateway` / `run_agent` — shipped by the PyPI `hermes-agent` package, a
  base dependency) and wires `extension/chat.py:make_gateway_chat_handler`
  automatically; E2E-encrypted messages are decrypted, answered by the real
  `AIAgent`, and re-encrypted reply-in-kind. A stub reply appears only when
  that runtime is missing — the startup log names which handler was wired.
- **Pairing works end-to-end**: run `hermes-mordred extension pair` in a
  second terminal while `extension serve` is running — both sides share
  `~/.hermes/extension/pending.json`, so codes are also consumable by a full
  Hermes gateway hosting the WS server.
- **The private `Web page:` URL printed by `extension serve` opens the bundled
  localhost web app** — use the complete URL including its `#token=…` fragment;
  a plain anonymous GET serves only the token-free shell. The extension's WS
  endpoint is `/ext`. A 503 "web app not built" response
  appears only if the bundled page is missing — the PyPI wheel ships it.

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
both reporting the same version, say): without it uv treats the requirement as already
satisfied and no-ops, leaving the binary on stale code — the symptom is a newly
added flag such as `configure --with-hermes-setup` failing with `unrecognized
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

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Slack integration silently off after a Touch ID prompt at login | Attended Secure Enclave device key + a launchd-started background process (gateway, `extension serve`) racing for Touch ID — a background process can never answer the prompt, so it blocks until the helper's 120 s timeout and starts **without** the vault-managed secrets (a sealed Slack bot token silently drops the platform, with only a `Failed to load plugin 'mordred_keyvault': auth_failed` warning in the logs). | `$M keyvault enable-se` may be installed/refreshed at any time, but it never changes an existing key's policy. Already affected vaults need the documented verified-backup/recovery-to-a-fresh-vault workflow, with `MORDRED_SEKEY_UNATTENDED=1` on the recovery key creation. See [`USAGE.md` §4.3](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/USAGE.md#43-touch-id-prompts--why-several-per-command-and-how-to-silence-them). |
| `~/.hermes/mordred/audit.log` is plaintext NDJSON whose entries say `mordred.degraded.audit_encryption_unavailable` | A Mordred process started somewhere the Keychain / Secure Enclave helper is unreachable (a sandboxed shell, a pre-unlock launchd start, a container). The audit-writer factory probes the audit-log wrapping key once per process; on failure it rotates the encrypted log aside and that process writes plaintext for its whole lifetime — fail-open by design, so auditing never stops (each downgrade leaves one `warn` marker in the trail). | A healthy log starts with `{"fmt":"MRAL"` — check with `head -c 20 ~/.hermes/mordred/audit.log`. Recovery is automatic: the next audit write from a healthy context (a normal login shell) rotates the plaintext file aside and starts a fresh encrypted log; long-lived services pick that up on restart. Rotated plaintext siblings remain as dated `audit.log.<date>` files — remove them with `$M audit purge --before YYYY-MM-DD --yes` if they must not persist. |
| `extension serve` fails to start, citing port 7788 in use | Something else already owns `127.0.0.1:7788` — usually a full Hermes gateway already hosting the extension API (nothing to start), occasionally a stale `extension serve` process from an earlier run. | Check what's listening: `lsof -i :7788`. A full Hermes gateway there means there's nothing to do — the API is already up. A stale `extension serve` should be stopped, or bind a different port instead with `$M extension serve --port 7799` (see the [`extension` command reference](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/USAGE.md#extension--browser-extension-pairing-and-server-preview)). |
| `extension serve` logs show the extension reconnecting | A clean reconnect can still be Chrome's Manifest V3 service-worker lifecycle. A close code `1002` / `invalid_server_frame` is different: the running Extension and Mordred server disagree on the strict WebSocket protocol (often a stale bundled page or one side updated alone). | For a clean lifecycle reconnect, nothing is required. For `1002`, update/reload the browser Extension and update Mordred together, then restart the Hermes gateway or standalone `extension serve`. If it persists, capture the close reason and file an issue. |
| Network communication drops out now and then | The active privacy path (Tor / VPN) is down or flagged unhealthy. | See the network-troubleshooting note under [Use it](#use-it) above — run `$M network status` to check `state` / `last_health`, then `$M network use <tor\|vpn\|clearnet>` to re-establish the path. |
| Lost the vault recovery passphrase | The passphrase is the cold-path key and is never stored anywhere by design. | Still on the same device, with its device key intact? Run `$M encryption change-passphrase` — it tries this device's key first, so you can set a new passphrase without knowing the old one (see [`USAGE.md` — `encryption`](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/USAGE.md#encryption--the-recommended-onoff-switch)). If the device key is also gone (new machine, `keyvault reset`, hardware failure), there is no documented recovery path — data sealed only behind that passphrase is permanently lost. |

## Upgrading

Two different things go by "upgrade": the installed **package**, and your
existing **config** (Mordred / OpenClaw settings).

### Upgrade the installed package

Same command as [Install](#install-users-from-pypi), with the version bumped
— a different pinned version is never "already satisfied", so this
reinstalls in place without needing `--upgrade`:

```sh
# macOS
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 "mordred-hermes[macos]==<new-version>"

# Linux
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 "mordred-hermes[keyvault]==<new-version>"
```

Check [PyPI](https://pypi.org/project/mordred-hermes/) (or the badge at the
top of this file) for the latest version. Prefer not to pin?

```sh
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 --upgrade "mordred-hermes[macos]"
```

This resolves to the newest pre-release without extra flags — every release
is currently a pre-release, so the all-prereleases fallback applies (see
[Install](#install-users-from-pypi) above; the same goes for plain `pip`, if
your venv has it — the reference setup's venv ships without one).

### When Hermes itself is updated

A normal in-place Hermes update reuses
`~/.hermes/hermes-agent/venv`, so the installed `mordred-hermes` package is
normally preserved. Hermes does not upgrade Mordred on your behalf; run the
Mordred install command above separately when a new Mordred release is needed.

If a Hermes update recreates the venv, third-party packages are removed with
the old environment. Reinstall `mordred-hermes` into the new venv and verify
its source path with:

```sh
~/.hermes/hermes-agent/venv/bin/python3 -c "import mordred_hermes; print(mordred_hermes.__file__)"
```

Finally, package installation does not replace code already loaded in a
running process. Restart the Hermes gateway after either update. If you run
`hermes-mordred extension serve` manually, stop it with Ctrl+C and start it
again as well.

### Migrate config with `hermes-mordred upgrade`

Different command, different job: `$M upgrade` is an idempotent migration of
an *existing* Hermes / OpenClaw setup onto Mordred's `config.yaml`
conventions — it back-fills the `plugins.mordred_privacy_check` section if
it's missing, no-ops if it already matches Mordred's defaults, and
auto-detects and migrates a legacy `~/.openclaw` install. Safe to re-run.

```sh
$M upgrade
$M upgrade --non-interactive --policy-conflict keep-existing
```

See [`USAGE.md` — `upgrade`](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/USAGE.md#upgrade--migrate-an-existing-install)
for the full flag reference (`--reset`, `--audit-merge`, `--policy-conflict`).
Setting up fresh instead of migrating an existing install? Use `configure`
(above), not `upgrade`.

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
$M keyvault reset --yes          # DESTROY profile-owned wrapping keys + remove the keyvault dir
```

Current profile-scoped keys are deleted. Legacy machine-global keys are
retained when exclusive ownership cannot be proven; export a backup before
reset and follow the migration guidance in `docs/user/USAGE.md`.

**3. Disable the plugins.** Remove the six `mordred_*` entries from the
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
src/mordred_hermes/    the Mordred entry-point plugins + shared internals
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
| Users | [HERMES_BASICS.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/user/HERMES_BASICS.md) | Driving the base `hermes` agent from this checkout (not Mordred) |
| Developers | [setup.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/setup.md) | Development environment from scratch |
| Developers | [SPEC.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/SPEC.md), [POLICY.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/POLICY.md) | Design spec and policy model |
| Developers | [SECRETS_ENV_ENCRYPTION.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/SECRETS_ENV_ENCRYPTION.md), [KEYVAULT_BACKENDS.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/KEYVAULT_BACKENDS.md) | At-rest encryption and key-backend design |
| Developers | [CI.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/CI.md), [UPSTREAM.md](https://github.com/InternetMaximalism/mordred-hermes/blob/main/docs/dev/UPSTREAM.md) | CI strategy, release runbook, upstream tracking |

More under [`docs/dev/`](https://github.com/InternetMaximalism/mordred-hermes/tree/main/docs/dev):
PLAN, TODO, ROADMAP, PATHS, MIGRATION, HARNESS_PRIVACY, HOOK_PAYLOADS, SLACK_E2E,
plus [`docs/dev/hermes/`](https://github.com/InternetMaximalism/mordred-hermes/tree/main/docs/dev/hermes)
(DESIGN, STRUCTURE — upstream Hermes reference).

## License

MIT
