# Mordred — OpenClaw → Hermes Migration Guide (Draft)

> **Status: decided historical record.** The migration is complete and this is
> not an active draft. The original title and numbered headings are retained
> because other documents cite them. Current implementation instructions live
> in [`PLAN.md`](./PLAN.md); the lasting decision here is a standalone Hermes
> plugin package with no upstream PRs.

## 0. Background and Motivation

Mordred began as an OpenClaw-oriented design. Hermes provided a Python plugin
SDK, broader provider/platform support, and an existing OpenClaw migration
surface, so Mordred moved to Hermes without inheriting or forking Hermes core.

The migration goal was to preserve privacy controls while making ownership
clear: Mordred code ships from this repository; Hermes remains an ordinary PyPI
dependency.

## 1. Architecture Difference Matrix (Verified)

| Area | OpenClaw-era design | Current Hermes implementation |
|---|---|---|
| Runtime | TypeScript / Node.js | Python 3.11+ |
| Extension model | Core seams plus extensions | `hermes_agent.plugins` entry points |
| Distribution | Fork-oriented tree | `pip install mordred-hermes` |
| State root | `~/.openclaw/mordred/` | `<HERMES_HOME>/mordred/` |
| Configuration | OpenClaw config | `config.yaml` plus Mordred policy mirror |
| Compatibility | Core patches | Plugin hooks plus tested adapters |

## 2. Precise Mapping of Hooks and Signals

Mordred consumes only the hook fields recorded in
[`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md) and
`tools/hook_payload_contract.json`. The primary runtime boundaries are:

| Need | Hermes boundary |
|---|---|
| Startup integrity and route activation | `on_session_start` |
| Generic tool policy | `pre_tool_call` |
| Resolved provider/endpoint policy | `pre_api_request` |
| Gateway command E2E | `pre_gateway_dispatch` |
| Resealing and cleanup | `on_session_end` / `on_session_finalize` |

### Mapping the Old S1–S3 to Hermes

| Old seam | Current decision |
|---|---|
| Prevent disabling privacy plugins | Strict plugin-side startup refusal; no core patch |
| Identify the originating skill at runtime | Not available; enforce skill metadata at install time and use a generic runtime tool guard |
| Rewrite a resolved LLM provider | Not available; validate and refuse at the resolved request boundary |

## 3. Hermes Mapping for the 5 Plugins

The heading is retained for link stability. The initial five manifest-backed
plugins now ship alongside a sixth manifest-less entry point,
`mordred_e2e`:

| Component | Current responsibility |
|---|---|
| `mordred_privacy_check` | Metadata policy and audit |
| `mordred_wizard` | CLI and operator workflows |
| `mordred_llm_guard` | LLM/provider enforcement |
| `mordred_network` | Network route enforcement |
| `mordred_keyvault` | Key custody and encrypted storage |
| `mordred_e2e` | Mandatory Slack/Discord gateway encryption |

## 4. Mapping of Mordred-Owned Paths

Legacy `~/.openclaw/mordred/` data can be migrated by
`hermes-mordred upgrade`. New state is resolved from `HERMES_HOME`; exact path
ownership and migration behavior are canonical in [`PATHS.md`](./PATHS.md).

## 5. Candidate Strategies (3 options → Decision)

### Option A: Hard fork

Rejected. It would make Mordred responsible for merging, releasing, and
securing the whole Hermes codebase.

### Option B: Soft fork + Hermes Core Seams (same philosophy as the old SPEC)

Rejected for the current product. Even small upstream seams create review and
release coupling that is unnecessary for the implemented controls.

### Option C: Pure plugin bundle + patch only when necessary

Selected, with the final clause narrowed further: the normal distribution is a
pure plugin bundle. If a future requirement cannot be implemented safely with
plugins, evaluate a version-pinned vendored module in an optional `hard-lock`
extra rather than modifying or sending PRs to Hermes upstream.

### Decision: Option C + Vendored-fork escape hatch [DECIDED, revised 2026-05-07]

This is the binding decision:

1. Mordred remains a standalone repository and PyPI package. The public
   distribution moves from `mordred-hermes` to `hermes-mordred` through the
   staged compatibility migration in §6; the Python package remains
   `mordred_hermes`.
2. Hermes is an external dependency, not a git parent or subtree.
3. No PRs are submitted to Hermes upstream.
4. Plugin-side degraded/refusal behavior remains explicit and audited.
5. Any future vendored escape hatch is optional, version-pinned, and does not
   alter the default package.

## 6. Naming Conventions

- Distribution: `hermes-mordred` from `0.1.0a16`; the old
  `mordred-hermes` project remains as a metadata-only compatibility shim.
- Import package: `mordred_hermes`.
- Entry points and config IDs: `mordred_*`.
- Canonical operator CLI: `hermes-mordred`.
- Optional host compatibility alias: the registered `mordred` subcommand on
  supported Hermes versions; it is not used in operator guidance.
- Persistent state: `<HERMES_HOME>/mordred/` and the established extension
  state under `<HERMES_HOME>/extension/`.

### Distribution rename contract (decided 2026-08-12)

`mordred-hermes` and `hermes-mordred` are distinct PyPI projects. The rename
therefore uses a staged release rather than treating the metadata edit as an
in-place rename:

1. Publish `hermes-mordred==0.0.0.dev0` from
   `packaging/hermes-mordred-reservation/` to TestPyPI and PyPI with
   `release.yml` mode `reserve-rename`.
2. Only after both reservations exist, change the real root distribution to
   `hermes-mordred` and bump it to `0.1.0a16`.
3. Publish a metadata-only `mordred-hermes==0.1.0a16` compatibility shim that
   depends on the matching `hermes-mordred` release and forwards every extra.
   The shim must not ship `mordred_hermes` files or console scripts, because
   two distributions owning the same installed paths make uninstall unsafe.
4. Publish and verify the new real distribution before publishing the old-name
   shim, first on TestPyPI and then in the same order on PyPI.
5. Change the GitHub repository name only after both PyPI projects work, then
   update every PyPI/TestPyPI Trusted Publisher to the new repository claim.

Until step 1 is recorded as complete, the root package metadata and public
installer continue to use `mordred-hermes`. Native helper names, persistent
key identifiers, state paths, plugin IDs, and `mordred_hermes` imports are
compatibility identifiers and are not renamed.

## 7. Platform Support [DECIDED]

- Python 3.11–3.13.
- macOS: Secure Enclave with login-Keychain software fallback.
- Linux: TPM 2.0 helper, with no software fallback.
- Windows-native key custody: deferred.
- Network paths: macOS and Linux; platform-specific tools remain operator
  prerequisites.

## 8. Documentation Rewrite Phase Plan

Completed. User documentation lives under `docs/user/`; current developer
contracts and operational policy live under `docs/dev/`; point-in-time Hermes
snapshots live under `docs/dev/hermes/`.

## 9. Risks and Open Items

### High

- Plugin hooks cannot contain co-resident malware or an untrusted OS process.
- Missing Hermes hook fields limit per-skill runtime attribution and automatic
  provider replacement.

### Medium

- Hermes releases can change hook names, payload fields, CLI wiring, provider
  aliases, or auxiliary-client construction. CI checks the consumed contract,
  but behavioral review is still required after drift.
- Native hardware and live provider paths cannot be fully exercised in hosted
  CI.

### Low

- A future vendored escape hatch could increase maintenance cost. It remains
  deferred until a concrete requirement justifies it.

## 10. Decision Checklist [All items DECIDED]

- [x] Standalone plugin repository and PyPI distribution.
- [x] Six entry-point plugins, with five manifest-backed modules.
- [x] Zero upstream PRs.
- [x] Plugin-side strict refusal instead of a disable-command patch.
- [x] Install-time per-skill policy where runtime attribution is absent.
- [x] macOS and Linux platform guarantees documented explicitly.
- [x] OpenClaw migration available through `hermes-mordred upgrade`.

## 11. Reference: Minimal Example of a Hermes Plugin Implementation

```python
def register(ctx: object) -> None:
    ctx.register_hook("on_session_start", on_session_start)
```

Real plugins use narrow local Protocols for `ctx`, keep optional dependencies
lazy, and register from the module named by the package entry point. The source
under `src/mordred_hermes/` is the authoritative example.

## Appendix: Verified Hermes API Reference

- Hook contract: [`HOOK_PAYLOADS.md`](./HOOK_PAYLOADS.md).
- Entry points and dependency floors: `pyproject.toml`.
- Upstream relationship: [`UPSTREAM.md`](./UPSTREAM.md).
- Current implementation map: [`PLAN.md`](./PLAN.md).
