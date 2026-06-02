# mordred_network

Tor / VPN / Clearnet path management.

## Owned filesystem paths (see `mordred-docs/mordred/PATHS.md`)

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

- `paths/tor.py::circuit_status_health(handle, *, controller_factory=None)` — Tor ControlPort cookie auth + `GETINFO circuit-status` deep liveness probe. BUILT-circuit-present → True. Optional via the `[tor-control]` extra (`pip install mordred-hermes[tor-control]` pulls in `stem>=1.8.0,<2`). Missing extra / missing cookie file / unreachable port → shallow `process.poll()` fallback. Used by strict-mode operators through the runtime's `tor_health` injection point.
- `proxy_env.SOCKS5H_LIBRARY_REQUIREMENTS` + `evaluate_library_compatibility(active_path, declared_libs)` — static allowlist of HTTP client libraries with the minimum version that grew `socks5h://` URL-scheme support. Surfaces one human-readable warning per declared library not on the allowlist. Tor-only; clearnet / vpn skip.
- `provider_transport_flagger.ProviderEntry.transport_class: Literal["http","tcp","udp","quic","grpc","websocket"]` + `respects_ipv6_proxy: bool` — two new fields driving the new `_flag_for_ipv6` (Tor-only, suppressed when `disable_ipv6=True`) and `_flag_for_non_http` (Tor → abort, clearnet → warning) branches. `evaluate(...)` gains a `disable_ipv6: bool = False` kw-only param.
- Network-related fields in `~/.hermes/mordred/policy.json` — `disable_ipv6` bool (strict default `true`, lenient/off default `false`). Reader `mordred_hermes.network._resolve_disable_ipv6` collapses to mode default on absent / non-bool values.

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
| `proxy_env` | `desired_env(path, tor_socks_port, no_proxy_extra, isolation_token=None) -> dict[str, str]` — pure. `NO_PROXY` always includes `localhost,127.0.0.1,::1`. Tor uses `socks5h://`; a non-empty `isolation_token` becomes a percent-encoded SOCKS5 credential (`socks5h://tok:tok@…`) so Tor's `IsolateSOCKSAuth` gives that context its own circuit (v2-N1 foundation; per-skill keying still needs `origin_skill` → v2-H2). `managed_var_names()` enumerates the keys runtime clears on path switch. | `tests/test_proxy_env.py` |
| `provider_transport_flagger` | `KNOWN_PROVIDERS` v1 baseline (6 entries, all `unverified_baseline=True` until PR3). `evaluate(active_path, providers, policy_mode, overrides)` returns `Flag(provider, severity, reason)`. Baseline immutable; overrides may add new providers only. | `tests/test_provider_transport_flagger.py` |
| `api` | Public surface: `use` / `status` / `health` / `stop` / `is_dropped` / `update_policy_mode` / `set_isolation_token` / `blackout_assert`. `Runtime` Protocol; PR2 register populates the singleton via `set_runtime`. Default blackout probe = UDP connect to 1.1.1.1:53 (connectionless). | `tests/test_network_api.py` |
| `runtime` | Concrete `Runtime` class — state machine (`IDLE` / `BRINGING_UP` / `READY` / `TEARING_DOWN` / `DEGRADED`), Tor + Mullvad + clearnet subprocess handles via PR1 path modules, `os.environ` snapshot/restore via `proxy_env` (incl. per-session `isolation_token` → SOCKS credential, set via `set_isolation_token`), M9 liveness worker (30s default, 2× failure threshold), `is_dropped()` flag for strict-mode pre_tool_call refusal, M3 `live_subprocess_count` audit field (best-effort `pgrep -P` based). All external touchpoints injectable for hermetic unit tests. | `tests/test_network_runtime.py` |
| `hooks` | `on_session_start` (reads policy.json + config.yaml, keys the per-session Tor isolation token on `session_id`, brings up `default_path`; strict bring-up failure raises `MordredPathBringupFailed`) / `on_session_end` (`api.stop`) / `pre_tool_call` (strict + dropped raises `MordredPathDropped`; lenient/off return None). `wait_until_ready(timeout=5s)` polling helper for bootstrap-order races with sibling plugins. | `tests/test_network_hooks.py` |
| `__init__.register(ctx)` | Builds `Runtime` with `RuntimeConfig` defaults, `api.set_runtime(runtime)`, registers 3 hook callbacks wired with audit writer + default config paths. | `tests/test_network_hooks.py::TestRegister` |
| wizard `network_cli` | `hermes mordred network use <path>` writes `plugins.mordred_network.default_path` to `config.yaml` (round-trip YAML, preserves other plugin sections) AND drives in-process `api.use()` when a runtime is registered. `hermes mordred network status` prints live runtime state or the disk-configured fallback. | `tests/test_wizard_network_cli.py` |

## Audit reason codes (16-code freeze)

Phase 3 step-0 freeze appended to `mordred_hermes.privacy_check._audit_reasons.ReasonCode` (Literal). Total freeze: **16 codes** (12 Phase 1 + 4 Phase 3):

- `network.use` — successful path switch (decision `override`, fields `prev_path` / `new_path` / `live_subprocess_count`)
- `network.use_failed` — `api.use(path)` raised `MordredNetworkError` (decision `raise`)
- `network.bringup_failed` — lenient: runtime fallback to clearnet (decision `fallback`); strict: hooks layer emits this + raises `MordredPathBringupFailed`
- `network.path_dropped` — M9 liveness 2× consecutive failure (decision `block` in strict, `warn` in lenient)

Naming normalized to dotted form (`network.use` rather than the `network_use` form in TODO L331) for consistency with `policy.*` / `mordred.*`. See `mordred-docs/mordred/POLICY.md`.

## M3 transitive proxy-env failure mode

`Runtime.use(path)` mutates `os.environ` via `proxy_env.desired_env()` + `proxy_env.managed_var_names()`. Per Phase 0.8 §8.1:

- **Regime A** (`tools/terminal_tool.py` / `tools/environments/*` / `tools/browser_tool.py`): proxy env passed through; new spawns after `use(path)` honour the switch.
- **Regime B** (`tools/code_execution_tool.py`'s `_SAFE_ENV_PREFIXES` filter): silently drops proxy variables. **Until upstream `tools.env_passthrough` registry registration lands, `execute_code` child traffic can leak the previous path.**

Either way, **already-running subprocesses are not affected** — Hermes spawns with `env=dict(os.environ | env)` snapshot. The `live_subprocess_count` audit field is an informational signal of this risk per path switch.

## Phase 3 PR3c status (2026-05-17)

Real-traffic verification (TODO §0.8 L110-122) landed via two hermetic integration suites driven by an in-process SOCKS5 inspector (`tests/integration/_socks5_inspector.py`, which records the RFC 1928 ATYP byte of every CONNECT) — no Tor, no Docker, no live network or API credentials needed.

- `tests/integration/test_socks5h_libs.py` — SOCKS5h library compatibility (TODO §0.8 L118-122). Verified httpx / urllib3 / requests / aiohttp; every `proxy_env.SOCKS5H_LIBRARY_REQUIREMENTS` entry now has `unverified_baseline=False`. Finding: `python-socks` (the aiohttp-socks engine) rejects the bare `socks5h://` URL scheme with `ValueError` — remote DNS needs `socks5://` + an explicit `rdns=True`. httpx defers DNS for both `socks5://` and `socks5h://`.
- `tests/integration/test_provider_transport.py` — provider transport (TODO §0.8 L110-117). `anthropic` / `openai` / `gemini` / `mordred-local` verified → `unverified_baseline=False`. Finding: the current `google-genai` SDK is httpx-based, so `KNOWN_PROVIDERS["gemini"].transport` was corrected `"requests"` → `"httpx"`.

CI: the `integration-tor` job installs `mordred-hermes[dev,integration]` and runs all three integration suites (`test_tor.py`, `test_socks5h_libs.py`, `test_provider_transport.py`).

Still deferred:

- `bedrock` keeps `unverified_baseline=True` — `respects_socks5h=False` is verified (botocore's urllib3 transport has no SOCKS support) but the `dns_quirk` / IPv6 facts need a real AWS packet capture.
- `vertex` keeps `unverified_baseline=True` — `google-cloud-aiplatform` deep verify (heavy SDK, GCP-side `partial` proxy behaviour) is out of scope.
- Live Mullvad VPN path verification (Phase 3 acceptance gate L381) — `test_vpn.py` stays `MORDRED_LIVE_VPN_TEST` gated; no `mullvad` CLI on the dev box.
- Stem-against-real-Tor deep liveness probe (requires bind-mounted `data_dir` so the host can read `control_auth_cookie`).

See `mordred-docs/mordred/SPEC.md` §Plugin: `mordred_network` and `mordred-docs/mordred/TODO.md` §3.
