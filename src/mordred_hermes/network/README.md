# mordred_network

Tor / VPN / Clearnet path management.

## Owned filesystem paths (see `mordred-docs/mordred/PATHS.md`)

- `~/.hermes/mordred/credentials/` — Mullvad account, WireGuard config (Phase 3 owner; sole reader)
- `~/.hermes/mordred/tor-data/` — torrc, control_auth_cookie, DataDirectory
- `~/.hermes/mordred/policy.json` — reader (`default_path`, `disable_ipv6`, `provider_overrides`)

## Phase 3 PR1 status (2026-05-13)

Primitives landed. `register(ctx)` is still a no-op; PR2 will wire hooks + runtime + wizard CLI.

| Module | Surface | Tested via |
| --- | --- | --- |
| `_exceptions` | `MordredNetworkError` hierarchy + `BringupFailed` / `AlreadySwitching` / `UnknownPath` / `BlackoutNotAsserted` (Exception-derived); `MordredPathBringupFailed` / `MordredPathDropped` (BaseException-derived for strict-mode hook escape) | `tests/test_network_exceptions.py` |
| `paths/clearnet` | `start()` / `stop()` / `health()` no-op | `tests/test_paths_clearnet.py` |
| `paths/tor` | `render_torrc` / `pick_free_port` (9050→9150 shift) / `wait_for_bootstrap` (30s default) / `start_process` / `stop` (terminate + 5s grace + kill) / `health` (process alive — control-port probe lands in PR2) | `tests/test_paths_tor.py` |
| `paths/vpn` | `detect_cli` (PATH + macOS app bundle fallback) / `bring_up` (lockdown / always-require-vpn / relay / connect) / `wait_connected` (10s polling) / `disconnect(preserve_lockdown=True)` / `health` (wg show handshake age) | `tests/test_paths_vpn.py` |
| `proxy_env` | `desired_env(path, tor_socks_port, no_proxy_extra) -> dict[str, str]` — pure. `NO_PROXY` always includes `localhost,127.0.0.1,::1`. Tor uses `socks5h://`. `managed_var_names()` enumerates the keys PR2 runtime clears on path switch. | `tests/test_proxy_env.py` |
| `provider_transport_flagger` | `KNOWN_PROVIDERS` v1 baseline (6 entries, all `unverified_baseline=True` until PR3). `evaluate(active_path, providers, policy_mode, overrides)` returns `Flag(provider, severity, reason)`. Baseline immutable; overrides may add new providers only. | `tests/test_provider_transport_flagger.py` |
| `api` | Public surface: `use` / `status` / `health` / `blackout_assert`. `Runtime` Protocol; PR2 registers concrete runtime via `set_runtime`. Default blackout probe = UDP connect to 1.1.1.1:53 (connectionless). | `tests/test_network_api.py` |

## Audit reason codes added in PR1

Phase 3 step-0 freeze appended to `mordred_hermes.privacy_check._audit_reasons.ReasonCode` (Literal). Total freeze: **16 codes** (12 Phase 1 + 4 Phase 3):

- `network.use` — successful path switch (decision `override`)
- `network.use_failed` — `api.use(path)` raised `MordredNetworkError` (decision `raise`)
- `network.bringup_failed` — lenient-mode bring-up + clearnet fallback (strict pairs with `MordredPathBringupFailed`)
- `network.path_dropped` — M9 liveness 2× consecutive failure

Naming normalized to dotted form (`network.use` rather than the `network_use` form in TODO L331) for consistency with `policy.*` / `mordred.*`. See `mordred-docs/mordred/POLICY.md`.

## Deferred to PR2

- `runtime.py` — `Runtime` concrete implementation (Popen lifecycle, M9 liveness worker thread, state machine)
- `hooks.py` — `on_session_start` (bring-up + bootstrap order polling fallback) / `on_session_end` (tear-down + worker stop) / `pre_tool_call` (tool-name allowlist)
- Wizard: `hermes mordred configure` Phase 3 prompts; `hermes mordred network use` / `network status` CLI
- `register(ctx)` wires hooks + `api.set_runtime(...)`
- Tor control-port circuit-status liveness probe (`stem` dependency)

## Deferred to PR3

- Real-traffic verification of `KNOWN_PROVIDERS` (TODO §0.8 L110-117): anthropic / openai / gemini / mordred-local / bedrock / vertex through HTTPS_PROXY (Wireshark + Tor circuit log).
- SOCKS5h library compatibility verification (TODO §0.8 L118-122).
- Once verified, per-entry `unverified_baseline` flips to `False`.
- `tests/integration/test_tor.py` (docker-compose with Tor container) and `tests/integration/test_vpn.py` (`MORDRED_LIVE_TOR_TEST=1` gated).

See `mordred-docs/mordred/SPEC.md` §Plugin: `mordred_network` and `mordred-docs/mordred/TODO.md` §3.
