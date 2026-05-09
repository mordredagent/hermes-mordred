# mordred_network

Tor / VPN / Clearnet path management.

## Owned filesystem paths (see `mordred-docs/mordred/PATHS.md`)

- `~/.hermes/mordred/credentials/` — Mullvad account, WireGuard config (Phase 3 owner; sole reader)
- `~/.hermes/mordred/tor-data/` — torrc, control_auth_cookie, DataDirectory
- `~/.hermes/mordred/policy.json` — reader (`default_path`, `disable_ipv6`, `provider_overrides`)

## Phase 0 status

Scaffold only. `register(ctx)` is a no-op. Phase 3.1 wires:
- `paths/{tor,vpn,clearnet}.py` subprocess managers (Tor daemon v1 default; Mullvad official client v1 default)
- `proxy_env.py` (`HTTPS_PROXY` / `NO_PROXY` injection; SOCKS5h URL scheme for DNS leak prevention)
- `provider_transport_flagger.py` (`KNOWN_PROVIDERS` baseline allowlist + policy overrides)
- `api.py` internal Python API: `use(path)`, `status()`, `health()`, `blackout_assert()`
- `pre_tool_call` hook (origin_skill `network_requirements` mismatch detection)
- M3 / M8 / M9 caveats (transitive proxy env, transport coverage, path failure / liveness)

See `mordred-docs/mordred/SPEC.md` §Plugin: `mordred_network` and TODO §3.1.
