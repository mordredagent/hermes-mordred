# mordred_llm_guard

Strict-mode LLM policy enforcement. The plugin registers a `mordred-local`
OpenAI-compatible provider, rejects disallowed runtime providers before their
API request, validates declared auxiliary LLM routes, and blocks agent
harnesses whose traffic would bypass Hermes hooks.

## Phase 2 scope (PR1 + PR2)

The heading is retained for existing links; this section describes the current
runtime.

| Boundary | Current behavior |
| --- | --- |
| Plugin registration | Adds `mordred-local`, establishes loopback proxy bypass, and installs auxiliary-client guards. |
| `on_session_start` | Runs sibling-integrity, harness, auxiliary-route, and disk-state checks in registration order. |
| `pre_api_request` | Makes the authoritative decision from Hermes's resolved `provider` and `base_url`; strict refusals abort the outbound call. |
| Local health check | Probes the configured local endpoint with a short timeout before allowing strict local inference. |

Strict cloud use requires both `allow_cloud_llm: true` and a matching canonical
provider in `cloud_provider_allowlist`. Provider aliases are normalized before
evaluation. Malformed or missing strict-policy values fail closed.

## Deferred to v2

- Automatic provider replacement still needs a provider pre-resolution hook or
  the optional hard-lock strategy. Current behavior refuses; it does not swap.
- A reliable stream-interruption audit needs an upstream streaming hook.
- Auxiliary LLM calls do not all emit `pre_api_request` in Hermes 0.19, so the
  plugin guards the known client-resolver seams and verifies them at session
  start.

Open work is tracked in [TODO.md](../../../docs/dev/TODO.md), not in this
README.

## Owned filesystem paths (see `docs/dev/PATHS.md`)

- `~/.hermes/mordred/policy.json` — reads local endpoint, cloud policy, and
  allowlist fields; the wizard is the sole writer.
- `~/.hermes/config.yaml` — reads
  `plugins.mordred_llm_guard.harness_primary` and provider configuration.
- `~/.hermes/auth.json` — reads the persisted active provider as a fallback.
- `~/.hermes/mordred/audit.log` — appends through the shared audit-writer
  factory, including encrypted logging when the keyvault is active.

## Cross-references

- [SPEC.md](../../../docs/dev/SPEC.md) — plugin contract and strict-provider policy
- [HOOK_PAYLOADS.md](../../../docs/dev/HOOK_PAYLOADS.md) — current hook fields
- [POLICY.md](../../../docs/dev/POLICY.md) — audit reason codes
- [TODO.md](../../../docs/dev/TODO.md) — remaining enforcement work
