# mordred-hermes

Privacy-preserving plugin bundle for the [Hermes agent](https://github.com/NousResearch/hermes-agent).

Five plugins exposed via the `hermes_agent.plugins` entry-point group:

- `mordred_privacy_check` — skill metadata enforcement, audit logging
- `mordred_wizard` — `hermes mordred …` CLI surface
- `mordred_llm_guard` — strict-mode local LLM enforcement
- `mordred_network` — Tor / VPN / Clearnet path management
- `mordred_keyvault` — Secure Enclave-backed key management (macOS, optional)

## Status

Active alpha (`0.1.0a0`). The five entry-point plugins are implemented beyond
the original Phase 0 scaffold; the default unit suite is intended to stay
hermetic, while hardware- and network-mutating checks remain opt-in.

See `../mordred-docs/dev/` for SPEC, PLAN, TODO, PATHS, MIGRATION, UPSTREAM, CI.

## Validation

Default local checks:

```sh
UV_CACHE_DIR=/tmp/uv-cache uv run ruff check src tests
HERMES_HOME=/private/tmp/hermes-mordred-test-home UV_CACHE_DIR=/tmp/uv-cache uv run pytest -q
```

Manual live-device validation was reported successful on 2026-05-25 for the
hardware/network-gated suites that are excluded from default PR CI:

```sh
MORDRED_KEYVAULT_LIVE=1 pytest -m integration tests/integration/test_keyvault_macos.py -v
MORDRED_LIVE_VPN_TEST=1 MORDRED_MULLVAD_ACCOUNT=... pytest -m integration tests/integration/test_vpn.py -v
```

The Tor path is covered separately by the hermetic Docker-based
`integration-tor` CI job.

## Install (development)

```sh
# From repo root
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 -e ./mordred-hermes
```

Verify discovery (Hermes 0.11.0):

```sh
~/.hermes/hermes-agent/venv/bin/python3 -c "
from hermes_cli.plugins import PluginManager
mgr = PluginManager(); mgr.discover_and_load(force=True)
print(sorted(k for k, p in mgr._plugins.items() if p.manifest.source == 'entrypoint'))
"
# → ['mordred_keyvault', 'mordred_llm_guard', 'mordred_network', 'mordred_privacy_check', 'mordred_wizard']
```

Note: `hermes plugins list` does **not** display entry-point plugins in Hermes 0.11.0 — it only scans `<repo>/plugins/` and `~/.hermes/plugins/` directories. The loader (`PluginManager.discover_and_load`) does discover them and call `register()`. Phase 1.3 will ship `hermes mordred plugins list` as a wrapper that surfaces entry-point plugins in the CLI.

To enable, edit `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - mordred_privacy_check
    - mordred_wizard
    - mordred_llm_guard
    - mordred_network
    - mordred_keyvault
```

For Phase 4 (`mordred_keyvault`) on macOS Apple Silicon:

```sh
uv pip install --python ~/.hermes/hermes-agent/venv/bin/python3 -e "./mordred-hermes[macos]"
```
