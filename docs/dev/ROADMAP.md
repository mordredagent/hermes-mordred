# Mordred Roadmap (post-v1, Hermes-base)

> **Status**: deferred work only. Current behavior belongs in
> [`SPEC.md`](./SPEC.md), implementation shape in [`PLAN.md`](./PLAN.md), and
> actionable current work in [`TODO.md`](./TODO.md). Inclusion here is not a
> commitment or authorization to modify Hermes upstream.

## Legend

- **H** — address early when its dependency exists.
- **M** — decide from user feedback and threat-model need.
- **L** — long-term exploration.
- **Blocked** — requires an interface or platform capability not currently
  available to the plugin package.

## Remaining browser-extension gateway integration

Pairing, localhost serving, encrypted chat, history, wallet/RPC, and the real
Hermes chat bridge ship in `mordred_hermes.extension`. The remaining question is
service lifecycle: keep explicit `extension serve`, document launchd/systemd,
or integrate only if Hermes exposes a safe plugin service-boot hook.

- Preserve coexistence with a full gateway already listening on port 7788.
- Keep explicit startup as the default until ownership and shutdown semantics
  are unambiguous.
- **Priority**: M.

## v2 candidates: Hermes hook extensions (PR candidates)

The historical heading is retained, but the zero-PR commitment remains in
force. These describe capabilities a future optional vendored layer could
provide; Mordred does not submit them to Hermes upstream.

### v2-H1: Skill install hook

Provide one policy gate for both `hermes skills install` and
`hermes-mordred install`. Until then, only Mordred's wrapper can enforce
`metadata.mordred.*` before installation.

- **Priority**: H.
- **Blocked by**: a pre-install boundary before Hermes writes skill files.

### v2-H2: Add `origin_skill` to the `pre_tool_call` payload

Associate tool calls with the originating skill so runtime policy can apply the
skill's declared network and keyvault requirements. Calls without a skill must
remain explicitly unattributed.

- **Priority**: M.
- **Blocked by**: end-to-end provenance through Hermes tool dispatch.

### v2-H3: Add `provider_id` / `model_id` to the `pre_llm_call` payload

No longer required for primary-request refusal: Mordred enforces resolved
provider and endpoint at `pre_api_request`. Revisit only if a pre-construction
provider replacement capability is designed.

- **Priority**: L.

### v2-H4: Plugin loader hook priority control

Could replace local readiness/polling coordination with declared callback
priority. Current behavior must remain correct without it.

- **Priority**: M.

## v2 candidates: OS integration (largest defense expansion)

### v2-OS1: Local malware / co-resident process mitigations

Run skill child processes inside OS sandboxes and restrict direct network,
filesystem, and process-spawn access.

- macOS candidates: sandbox profiles or Endpoint Security.
- Linux candidates: Landlock/seccomp.
- **Risk**: entitlement requirements and breaking legitimate skills.
- **Priority**: H when the threat model expands beyond a trusted host.

### v2-OS2: Remaining keyvault platforms and authorization tiers

Current custody is Secure Enclave/Keychain on macOS and TPM 2.0 on Linux.
Candidates are Windows DPAPI/CNG TPM, external PKCS#11/FIDO2 hardware, and a
stronger Linux PIN/PCR presence policy.

- **Priority**: M.
- **Constraint**: no new backend may weaken the existing platform floors or
  introduce a silent software fallback on Linux.

## v2 candidates: feature expansion

### v2-F1: Per-skill independent network paths

Construct independent transports instead of changing process-global proxy
state. Requires `origin_skill`, per-request/provider-client routing, and
explicit child-process environment injection.

- **Priority**: M.

### v2-F2: Skill metadata signing / integrity verification

Verify publisher signatures over canonical skill metadata and content at
install time. Proceed only with an ecosystem signing chain and a plugin-owned
verification boundary.

- **Priority**: M.

### v2-F3: GUI controls

Offer status, policy, network, and audit controls through a thin client over
stable internal APIs. Do not duplicate security decisions in the UI.

- **Priority**: L.

### v2-F4: Tamper-resistant audit logs

Encrypted logs protect content at rest but do not provide append-only integrity.
Evaluate a hash chain or externally anchored checkpoints while retaining the
current degraded audit trail.

- **Priority**: M.

### v2-F5: Multi-user / multi-tenant

Add user-isolated configuration, credentials, key custody, and audit ownership.

- **Priority**: L; the current target remains one local operator.

### v2-F6: Trace-minimization layer (binary / folder / file-name encryption)

Explore a plugin-owned encrypted overlay for skill artifacts and filenames.
Avoid loader patches unless the optional vendored strategy is separately
approved.

- **Priority**: M only for a concrete forensic-resistance use case.
- **Risk**: decrypted mount lifecycle and OS-specific filesystem facilities.

### v2-F7: Seed-display PC↔phone pairing UI

Move recovery-passphrase input or digest confirmation to a single-use phone
session, bound by QR and a short expiry.

- **Priority**: M.
- **Risk**: local-network MITM and self-signed TLS usability.

### v2-F8: `config.yaml` at-rest transparent decryption

Complete. Transparent config decryption ships as an explicit opt-in and will
not become the default. Future work belongs in bug fixes, not this roadmap item.

## v3+ candidates: Payment layer

### v3-P1: Payment skills

Add policy-aware payment skills only after wallet signing and approval UX have
real operator adoption.

- **Priority**: H within a future payment milestone, not the current product.

### v3-P2: x402 / agent payment protocol integration

Evaluate protocol support with explicit spend limits, destination policy, and
human approval. Never infer payment authorization from a general tool approval.

- **Priority**: M.

## v2+ candidates: miscellaneous

### v2-X1: Mordred-branded mobile apps

Consider only when a concrete workflow, such as seed confirmation, requires a
native companion.

- **Priority**: L.

### v2-X2: Mordred-specific telemetry / crash reporting

Default remains no telemetry. Any future diagnostics must be opt-in, locally
inspectable, aggressively redacted, and documented in the threat model first.

- **Priority**: L; discussion before implementation.

### v2-X3: Documentation reorganization — DONE (2026-06-25, ahead of GA)

Complete. User, developer, and upstream-snapshot documents are separated by
directory and indexed. Keep the structure rather than scheduling another
migration.

## Forever out of scope

- Submitting Mordred changes to Hermes upstream.
- Silent clearnet fallback from a selected privacy route.
- Linux software-key fallback presented as hardware protection.
- Recovery that bypasses the documented seed/passphrase/backup guarantees.
- Plaintext fallback for mandatory Slack/Discord E2E commands or replies.
- Telemetry enabled by default.

## Update rules for this document

1. Add only work that is outside the current release.
2. Move actionable work to `TODO.md` when dependencies and acceptance criteria
   are decided.
3. Move shipped behavior to SPEC/PLAN and reduce the roadmap item to one
   completion sentence.
4. Do not preserve PR-by-PR history here; Git and release notes already do so.
