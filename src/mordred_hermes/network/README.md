# mordred_network

Tor / VPN / Clearnet path management.

## Owned filesystem paths (see `docs/dev/PATHS.md`)

- `~/.hermes/mordred/credentials/` — Mullvad account, WireGuard config (Phase 3 owner; sole reader)
- `~/.hermes/mordred/tor-data/` — torrc, control_auth_cookie, DataDirectory
- `~/.hermes/mordred/policy.json` — reader (`default_path`, `disable_ipv6`, `provider_overrides`)

## Phase 3 PR3a status (2026-05-14)

Hermetic code-complete: M8 transport coverage + Tor ControlPort liveness + wizard Mullvad/Tor prompts. PR3b ships docker-compose integration tests, PR3c the operator playbook for the `unverified_baseline=True → False` flips.

## Phase 3 PR3b status (2026-05-14)

Integration test harness landed. `tests/integration/test_tor.py` runs against a hermetic alpine + Tor container (loopback-only port binding, SocksPolicy restricted to RFC1918) — proves SOCKS5 handshake, SOCKS5h DNS routing, and `proxy_env.desired_env` HTTPS_PROXY round-trip end-to-end. `tests/integration/test_vpn.py` is `MORDRED_LIVE_VPN_TEST=1` + `MORDRED_MULLVAD_ACCOUNT` gated — exercises the live Mullvad daemon roundtrip (bring-up / wait_connected / disconnect, lockdown rollback when `lockdown_applied_by_us`, handshake freshness under 180s).

CI surface:

- `.github/workflows/ci.yml` `integration-tor` job — ubuntu-24.04 only, `needs: test`, builds the local Dockerfile and runs `pytest tests/integration/test_tor.py`. No production code paths changed.
- `.github/workflows/integration-vpn.yml` — `workflow_dispatch` only, never auto-runs (paid account + machine state mutation). Consumes `secrets.MORDRED_MULLVAD_ACCOUNT`.

Docker harness: `tests/integration/_docker.py` (compose v2 lifecycle helper with three-tier skip-guard: `MORDRED_SKIP_DOCKER_TESTS=1`, OS, binary + daemon `docker info` probe), `tests/integration/docker/tor/{Dockerfile,torrc,docker-compose.yml}`.

### PR3a additions

- `paths/tor.py::circuit_status_health(handle, *, controller_factory=None)` — Tor ControlPort cookie auth + `GETINFO circuit-status` deep liveness probe. After successful authentication, a reply containing at least one well-formed `BUILT` circuit is healthy on its own. An inconclusive reply — empty, or only in-progress (`LAUNCHED`/`EXTENDED`/`GUARD_WAIT`) or syntactically valid future status keywords — is resolved by a `GETINFO network-liveness` follow-up: `up` is healthy (an idle Tor builds circuits on demand), `down` or a failing liveness query is unhealthy (a running-but-circuit-less Tor whose upstream died; `FAILED`/`CLOSED` circuits are pruned from the reply almost immediately, so the circuit list alone cannot detect this state). A reply whose well-formed circuits are all terminal `FAILED`/`CLOSED`, or a malformed reply without a `BUILT` circuit, is unhealthy. The `[tor-control]` extra (`pip install mordred-hermes[tor-control]`) supplies `stem>=1.8.0,<2`; when available, this is the runtime default. Missing stem / missing cookie falls back to shallow `process.poll()`, while authentication, ControlPort, and GETINFO failures are unhealthy.
- `proxy_env.SOCKS5H_LIBRARY_REQUIREMENTS` + `evaluate_library_compatibility(active_path, declared_libs)` — static allowlist of HTTP client libraries with the minimum version that grew `socks5h://` URL-scheme support. Surfaces one human-readable warning per declared library not on the allowlist. Tor-only; clearnet / vpn skip.
- `provider_transport_flagger.ProviderEntry.transport_class: Literal["http","tcp","udp","quic","grpc","websocket"]` + `respects_ipv6_proxy: bool` — two fields driving `_flag_for_ipv6` (Tor-only; `disable_ipv6=True` does not suppress it because that setting only changes Tor's own client preference) and `_flag_for_non_http` (Tor → abort, clearnet → warning). `evaluate(...)` accepts a `disable_ipv6: bool = False` kw-only diagnostic input.
- Network-related fields in `~/.hermes/mordred/policy.json` — `disable_ipv6` bool (strict default `true`, lenient/off default `false`) plus additive `provider_overrides` for internal providers. The override reader validates every field conservatively; bundled baseline entries cannot be replaced.

### Phase 3.2 wizard surface (PR3a Task #6)

- `hermes mordred configure` now collects six additional answers (after the Phase 1 / Phase 2 prompts):
  - default network path (`tor` / `vpn` / `clearnet`, default `clearnet`)
  - Tor binary path (default `tor`)
  - Tor SOCKS port (default 9050; non-numeric → fallback 9050 + WARN)
  - Mullvad account number (collected via `prompt_toolkit` `is_password=True`; the secret never appears in `ConfigureResult`)
  - Mullvad relay country (`auto` or 2-letter code, default `auto`)
  - Mullvad killswitch (lockdown-mode; strict default `on`)
- `wizard/env_file_writer.py::DotEnvFileWriter` — upserts `MORDRED_MULLVAD_ACCOUNT=<value>` into `~/.hermes/.env` (mode 0600, parent 0700). Empty value removes the line. Refuses non-POSIX keys / newline values.
- `wizard/credentials_writer.py::JSONCredentialsWriter` — writes `~/.hermes/mordred/credentials/network.json` (env-var REFERENCES only; never the secret value; refuses secret-shape values).
- `wizard/policy_writer.py::PolicyWriter.write` gains optional `network_answers` kw-arg routed through `merge_mordred_sections` (Task #1) so subsequent `hermes mordred network use <path>` invocations don't clobber the wizard's choices.

| Module | Surface | Tested via |
| --- | --- | --- |
| `_exceptions` | `MordredNetworkError` hierarchy + `BringupFailed` / `AlreadySwitching` / `UnknownPath` / `BlackoutNotAsserted` (Exception-derived); `MordredPathBringupFailed` / `MordredPathDropped` (BaseException-derived for strict-mode hook escape) | `tests/test_network_exceptions.py` |
| `paths/clearnet` | `start()` / `stop()` / `health()` no-op | `tests/test_paths_clearnet.py` |
| `paths/tor` | `render_torrc` / `pick_free_port` (9050→9150 shift) / `wait_for_bootstrap` (30s default) / `start_process` / `stop` (terminate + 5s grace + kill) / `health` (process alive — control-port probe lands in PR3) | `tests/test_paths_tor.py` |
| `paths/vpn` | `detect_cli` (PATH + macOS app bundle fallback) / `bring_up` (lockdown / relay / connect — Mullvad CLI 2026.2 drift dropped the standalone `always-require-vpn` step; `lockdown-mode` now covers the same kill-switch surface) / `wait_connected` (10s polling) / `disconnect(preserve_lockdown=True)` / `health` (wg show handshake age) | `tests/test_paths_vpn.py` |
| `proxy_env` | `desired_env(path, tor_socks_port, no_proxy_extra, isolation_token=None) -> dict[str, str]` — pure. `NO_PROXY` always includes `localhost,127.0.0.1,::1`. Tor uses `socks5h://`; a non-empty `isolation_token` becomes a percent-encoded SOCKS5 credential (`socks5h://tok:tok@…`) so Tor's `IsolateSOCKSAuth` gives that process context its own circuit pool. The optional token must be chosen before route activation; session hooks never replace it. Per-session/per-skill keying remains deferred. `managed_var_names()` enumerates the proxy keys managed by the runtime. | `tests/test_proxy_env.py` |
| `provider_transport_flagger` | `KNOWN_PROVIDERS` (14 entries: 6 v1 baseline + 8 Hermes-0.14 cloud providers synced in PR-B; the 8 plus bedrock/vertex carry `unverified_baseline=True`). `evaluate(active_path, providers, policy_mode, overrides)` canonicalizes provider aliases then returns `Flag(provider, severity, reason)`. Baseline immutable; overrides may add new providers only. | `tests/test_provider_transport_flagger.py` |
| `api` | Public surface: `use` / `status` / `health` / `stop` / `is_dropped` / `update_policy_mode` / `set_isolation_token` / `blackout_assert`. `Runtime` Protocol; PR2 register populates the singleton via `set_runtime`. Default blackout probe = UDP connect to 1.1.1.1:53 (connectionless). | `tests/test_network_api.py` |
| `runtime` | Concrete `Runtime` class — state machine (`IDLE` / `BRINGING_UP` / `READY` / `TEARING_DOWN` / `DEGRADED`), Tor + Mullvad + clearnet subprocess handles via PR1 path modules, and `os.environ` snapshot/restore via `proxy_env`. An optional process-scoped `isolation_token` may be set before activation. Registration freezes the ready route: reusing the same route is a no-op, while changing the route or token requires a Hermes restart so existing provider clients cannot retain stale proxy transports. Also owns the M9 liveness worker (30s default, 2× failure threshold), `is_dropped()` flag for strict-mode `pre_tool_call` refusal, and M3 `live_subprocess_count` audit field (best-effort `pgrep -P` based). All external touchpoints are injectable for hermetic unit tests. | `tests/test_network_runtime_*.py` |
| `hooks` | `on_session_start` reads policy/config/auth, reuses the already-active process route, then gates the persisted provider; it does not re-key or restart Tor/VPN. `pre_api_request` verifies that a configured protected route (`tor` or `vpn`) still matches the frozen activation config and active, ready, non-dropped route, and repeats the strict-Tor transport gate against Hermes's request-resolved provider. `pre_tool_call` repeats those route checks for strict tool execution, including continuation turns that do not issue provider API requests. Their strict config reader treats only missing/absent configuration as clearnet; malformed YAML, invalid mapping shapes, and invalid explicit paths fail closed. Incompatible/unverified/unknown providers, protected-route mismatch/not-ready state, and internal errors fail closed after audit. Provider refusal preserves the process-global route so another gateway session cannot fall through to clearnet. `on_session_end` retains the route because Hermes emits it after every turn. Lenient downgrades startup flags; off skips them. | `tests/test_network_hooks_{session,requests,registration,config}.py` |
| `__init__.register(ctx)` | Builds the process-global `Runtime`, calls `api.set_runtime(runtime)`, activates and freezes the configured route before `register()` returns (and therefore before provider clients snapshot proxy settings), registers four network callbacks plus the sibling-integrity gate, and installs one `atexit` callback for final teardown. Any unexpected activation/freeze error fails closed before provider construction. Session boundaries and provider refusal never stop a route that another active gateway session may own. | `tests/test_network_hooks_registration.py::TestRegister` |
| wizard `network_cli` | `hermes mordred network init` is the on-demand privacy setup (Tor / VPN / clearnet + Mullvad), moved out of `configure` so first-run setup stays short; re-runnable (seeds prompt defaults from disk, blank Mullvad answer keeps the current secret), merges `plugins.mordred_network` + writes the Mullvad secret to `.env` + relay/killswitch to `credentials/network.json`. `hermes mordred network use <path>` writes `plugins.mordred_network.default_path` to `config.yaml` (round-trip YAML, preserves other plugin sections) and calls in-process `api.use()` when a runtime is registered. Re-selecting the active path is a no-op; a conflicting frozen route is refused and takes effect after restarting Hermes. `hermes mordred network status` prints live runtime state or the disk-configured fallback. | `tests/test_wizard_network_cli.py`, `tests/test_wizard_network_init.py` |

## Network audit reason codes

Phase 3 step-0 appended four `network.*` codes to `mordred_hermes.privacy_check._audit_reasons.ReasonCode` (Literal). The transport-gate follow-up later added `network.transport_incompatible`; a subsequent LLM endpoint-binding reason brings the repository-wide frozen enum to **31 codes**:

- `network.use` — successful initial/unfrozen route activation (decision `override`, fields `prev_path` / `new_path` / `live_subprocess_count`); same frozen route is a no-op and a conflicting route requires restart
- `network.use_failed` — `api.use(path)` raised `MordredNetworkError` (decision `raise`)
- `network.bringup_failed` — lenient: runtime fallback to clearnet (decision `fallback`); strict: hooks layer emits this + raises `MordredPathBringupFailed`
- `network.path_dropped` — M9 liveness 2× consecutive failure (decision `block` in strict, `warn` in lenient)
- `network.transport_incompatible` — configured protected-route mismatch/not-ready state, provider transport incompatibility, or transport-gate failure (decision `block` in strict, `warn` otherwise)

Naming normalized to dotted form (`network.use` rather than the `network_use` form in TODO L331) for consistency with `policy.*` / `mordred.*`. See `docs/dev/POLICY.md`.

## M3 transitive proxy-env failure mode

Registration activates the configured route and mutates `os.environ` via `proxy_env.desired_env()` + `proxy_env.managed_var_names()` before provider clients are constructed. It then freezes that process route; a same-route `Runtime.use(path)` is a no-op, while a different route is rejected with restart-required semantics. Per Phase 0.8 §8.1:

- **Regime A** (`tools/terminal_tool.py` / `tools/environments/*` / `tools/browser_tool.py`): proxy env passed through; new spawns inherit the route activated during registration.
- **Regime B** (`tools/code_execution_tool.py`'s `_SAFE_ENV_PREFIXES` filter): silently drops proxy variables. **Until upstream `tools.env_passthrough` registry registration lands, `execute_code` child traffic can leak the previous path.**

Either way, **already-running subprocesses are not affected** — Hermes spawns with `env=dict(os.environ | env)` snapshot. This snapshot behavior is why live route changes are refused: restart Hermes to rebuild provider clients and child processes on the new route.

## Phase 3 PR3c status (2026-05-17)

Real-traffic verification (TODO §0.8 L110-122) landed via two hermetic integration suites driven by an in-process SOCKS5 inspector (`tests/integration/_socks5_inspector.py`, which records the RFC 1928 ATYP byte of every CONNECT) — no Tor, no Docker, no live network or API credentials needed.

- `tests/integration/test_socks5h_libs.py` — SOCKS5h library compatibility (TODO §0.8 L118-122). Verified httpx / urllib3 / requests / aiohttp; every `proxy_env.SOCKS5H_LIBRARY_REQUIREMENTS` entry now has `unverified_baseline=False`. Finding: `python-socks` (the aiohttp-socks engine) rejects the bare `socks5h://` URL scheme with `ValueError` — remote DNS needs `socks5://` + an explicit `rdns=True`. httpx defers DNS for both `socks5://` and `socks5h://`.
- `tests/integration/test_provider_transport.py` — provider transport (TODO §0.8 L110-117). `anthropic` / `openai` / `gemini` / `mordred-local` verified → `unverified_baseline=False`. Finding: the current `google-genai` SDK is httpx-based, so `KNOWN_PROVIDERS["gemini"].transport` was corrected `"requests"` → `"httpx"`.

CI: the `integration-tor` job installs `mordred-hermes[dev,integration]` and runs all three integration suites (`test_tor.py`, `test_socks5h_libs.py`, `test_provider_transport.py`).

Still deferred:

- `bedrock` keeps `unverified_baseline=True` — `respects_socks5h=False` is verified (botocore's urllib3 transport has no SOCKS support) but the `dns_quirk` / IPv6 facts need a real AWS packet capture.
- `vertex` keeps `unverified_baseline=True` — `google-cloud-aiplatform` deep verify (heavy SDK, GCP-side `partial` proxy behaviour) is out of scope.
- PR-B synced 8 Hermes 0.14 cloud providers (`openrouter`, `nous`, `deepseek`, `xai`, `zai`, `novita`, `minimax`, `alibaba`) — all OpenAI-compatible httpx, seeded `respects_proxy`/`respects_socks5h=True` with `unverified_baseline=True` (IPv6 conservatively `False`) pending packet capture. `test_provider_transport_flagger.TestRegistrySync` asserts every registry slug is a real Hermes provider id with no exceptions (`vertex`/`novita` were carve-outs on older Hermes versions; hermes-agent 0.18.0 recognises both). Provider aliases (`claude`→`anthropic`, `glm`→`zai` …) are canonicalized via `mordred_hermes._provider_identity` before lookup.
- Live Mullvad VPN path verification (Phase 3 acceptance gate L381) — `test_vpn.py` stays `MORDRED_LIVE_VPN_TEST` gated; no `mullvad` CLI on the dev box.
- Stem-against-real-Tor deep liveness probe (requires bind-mounted `data_dir` so the host can read `control_auth_cookie`).

See `docs/dev/SPEC.md` §Plugin: `mordred_network` and `docs/dev/TODO.md` §3.
