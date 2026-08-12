# mordred_network

Process-scoped Tor, VPN, and clearnet routing with strict transport checks and
liveness enforcement.

The selected route is activated during plugin registration, before provider
clients capture proxy settings. It is then frozen for the life of the process;
changing routes requires a Hermes restart.

## Owned filesystem paths (see `docs/dev/PATHS.md`)

- `~/.hermes/mordred/tor-data/` — owned runtime directory used by the bundled
  Tor process.
- `~/.hermes/mordred/credentials/` — network credential contract; the wizard
  writes references, not raw secrets, to `credentials/network.json`.
- `~/.hermes/mordred/policy.json` and `~/.hermes/config.yaml` — read-only
  policy and route configuration.
- `~/.hermes/mordred/audit.log` — appends through the shared audit writer.

## Phase 3 PR3a status (2026-05-14)

This historical milestone is complete. The current implementation includes
Tor ControlPort liveness, proxy-environment generation, conservative provider
transport metadata, and explicit wizard setup.

## Phase 3 PR3b status (2026-05-14)

Hermetic integration coverage exercises Tor routing, remote DNS through
SOCKS5, supported HTTP libraries, and provider transports. Live Mullvad
validation remains opt-in because it changes machine VPN state and needs an
account.

### PR3a additions

The maintained runtime surface is:

| Module | Responsibility |
| --- | --- |
| `paths/tor.py` | Render and launch Tor, wait for bootstrap, and probe ControlPort circuit/network health. |
| `paths/vpn.py` and `vpn_providers/` | Mullvad, WireGuard, and custom VPN lifecycle adapters. |
| `proxy_env.py` | Build the managed proxy environment; Tor uses `socks5h://` and always bypasses loopback. |
| `provider_transport_flagger.py` | Refuse unknown, unverified, or incompatible transports in strict protected-route mode. |
| `runtime.py` | Own the route state machine, liveness worker, environment snapshot, and final teardown. |
| `hooks.py` | Recheck route health and provider compatibility at session, API-request, and tool boundaries. |
| `api.py` | Expose `use`, `status`, `health`, `stop`, `is_dropped`, `set_isolation_token`, and `blackout_assert`. |

An optional Tor isolation token must be set before activation. Per-session and
per-skill circuit keys remain deferred.

### Phase 3.2 wizard surface (PR3a Task #6)

Use:

```bash
hermes-mordred network init
hermes-mordred network use tor
hermes-mordred network status
```

`network init` configures the default path, Tor binary and SOCKS port, plus VPN
provider settings. Mullvad secrets are written to `~/.hermes/.env`; persisted
JSON contains only environment-variable references. Re-running setup preserves
an existing secret when the account prompt is left blank.

## Network audit reason codes

- `network.use` — initial or unfrozen route activation
- `network.use_failed` — route activation failed
- `network.bringup_failed` — protected route could not become ready
- `network.path_dropped` — repeated liveness failure
- `network.transport_incompatible` — route state or provider transport cannot
  satisfy policy

The closed reason-code contract lives in
[POLICY.md](../../../docs/dev/POLICY.md).

## M3 transitive proxy-env failure mode

The plugin now registers every managed proxy variable with Hermes's supported
`tools.env_passthrough` registry before activating the route, so
`execute_code` children inherit the protected environment. Registration is
verified and strict mode refuses startup if passthrough is incomplete.

Already-running provider clients and subprocesses still retain their original
environment snapshot. This is why a live route change is refused instead of
pretending existing traffic moved safely.

## Phase 3 PR3c status (2026-05-17)

The current test split is:

- `tests/integration/test_tor.py` — Tor route and SOCKS behavior
- `tests/integration/test_socks5h_libs.py` — HTTP-library remote-DNS behavior
- `tests/integration/test_provider_transport.py` — provider transport behavior
- `tests/integration/test_vpn.py` — live, explicitly gated Mullvad validation

Bedrock, Vertex, and providers still marked `unverified_baseline=True` require
real packet-capture evidence before strict Tor use can be enabled. That work is
tracked in [TODO.md](../../../docs/dev/TODO.md).

See [SPEC.md](../../../docs/dev/SPEC.md) and
[PATHS.md](../../../docs/dev/PATHS.md) for the full contract.
