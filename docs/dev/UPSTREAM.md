# Mordred — Upstream Tracking (Hermes-base)

> **Note**: This document describes the upstream tracking strategy on the `Hermes (NousResearch/hermes-agent)` foundation. The old OpenClaw-based version remains at `../../mordred/mordred-mvp-docs/UPSTREAM.md` (deprecated).

The finalized strategy decisions are in `MIGRATION.md` §5 (`Option C + Vendored-fork escape hatch`, zero-PR commitment, revised 2026-05-07). This file records the concrete operational procedures.

## Repository position

`hermes-mordred/` is a **Hermes plugin development repository** (a pure plugin bundle), not a fork of the Hermes upstream.
The distribution form is a single package via `pip install hermes-mordred` (entry-point `hermes_agent.plugins`).

Therefore:

- **Mordred's own code** lands in `src/mordred_hermes/<plugin>/`
- **Hermes upstream** is inspected read-only through PyPI source, CI's temporary
  clone, or an optional remote
- In normal Mordred development, there is **no need to rebase** Hermes upstream (because only plugins are managed)
- Only if the **vendored fork extra** (Tier B, described below) is introduced in v2, some modules of the relevant Hermes version are copied and kept under `vendor/hermes/<version>/`. This does not affect the plugin distribution layout

As long as this premise holds, the "weekly rebase" and "manual handoff" from the old OpenClaw era are unnecessary.

## Zero-PR commitment

**Mordred does not submit PRs upstream to `NousResearch/hermes-agent`**. See `MIGRATION.md` §5 for the rationale.

- The spots that the old SPEC treated as "core seams" (old S1–S3) are **absorbed on the plugin side** (Tier A)
- Only the spots where hard-enforce is truly necessary are handled via the **vendored fork extra** (Tier B, v2)
- Drafting, submitting, and tracking review of upstream PRs is completely removed from the v1 roadmap

Tracking items like `PR status: pending submission / submitted / accepted` are unnecessary. Only a read-only relationship referencing upstream's readme wording and release notes is maintained.

## Optional remote

Only if you want to inspect the latest Hermes upstream during Mordred
development:

```sh
git remote add hermes-upstream https://github.com/NousResearch/hermes-agent.git
git fetch hermes-upstream
git log --oneline hermes-upstream/main -5
```

Never merge, rebase, or check out `hermes-upstream/main` onto a Mordred branch;
the repositories have different histories and ownership. Use `git show
hermes-upstream/main:<path>` or a separate temporary clone for source review.

## Hook signature drift detection (informational only)

To keep up with Hermes upstream's rapid evolution, CI detects drift in the hook
names and payload fields Mordred consumes.

See the `upstream-check.yml` workflow in [`CI.md`](./CI.md) for details. It
checks both the latest PyPI package and upstream `main` against
`tools/hook_payload_contract.json`. A discrepancy opens or updates a GitHub
issue.

- The scheduled issue is informational and never submits an upstream PR.
- The equivalent local compatibility test is part of normal CI, so a released
  Hermes incompatibility must be resolved or explicitly bounded before release.

## Privacy-lock guard (replacement for the old HSeam-1)

The old SPEC planned to add a `privacy_lock: bool` field to `plugin.yaml` and submit a small PR upstream to Hermes requiring a `--unlock` flag on the `hermes plugins disable` side (old HSeam-1).

In the revised strategy, we do not submit a PR upstream to Hermes, and instead realize privacy-lock via the following two-tier approach:

### Tier A: Plugin-side guard (v1 default, zero core change)

> **Decided 2026-05-07 (H3 Path B)**: For Tier A, **fail-closed under strict mode (dedicated refusal + session abort)** is the default. It is not an audit-only spec. Same definition as SPEC.md §Plugin-disable protection §Tier A / TODO §1.1 H3 Path B.

- The five manifest-backed plugins declare `privacy_lock: true` as a
  declarative marker. Hermes ignores the field, and no runtime code discovers
  siblings from it; enforcement uses the fixed six-entry
  `privacy_check._runtime.SIBLING_PLUGINS` canonical list.
- `mordred_wizard` provides the `hermes-mordred plugins disable <plugin>` wrapper CLI, and plugins under `mordred_*` refuse when an attempt is made to disable them without the `--unlock` flag (defense-in-depth at the UX layer)
- **At the start of each runtime Mordred plugin's `on_session_start`, scan the canonical list (`mordred_privacy_check` / `mordred_network` / `mordred_llm_guard` / `mordred_keyvault` / `mordred_e2e` / `mordred_wizard`)**:
  - **If `policy=strict` and even one sibling is disabled**: raise `MordredIntegrityRefused(BaseException)` with the disabled sibling list and abort the session. At the same time, record an audit log entry `mordred.degraded.disable_unprotected` (decision=`block`). Direct `BaseException` inheritance lets the refusal escape Hermes's `except Exception:` wrapper without being mistaken for an ordinary `SystemExit`.
  - **If `policy=lenient` / `off`**: warning only (the audit `mordred.degraded.disable_unprotected` (decision=`warn`) is likewise recorded, to ensure compatibility)
- If a user uses Hermes's standard `hermes plugins disable mordred_*`, the disable itself goes through on the Hermes side, but **the design is such that the fail-closed behavior above fires and blocks at the next strict session start**
- **Important caveat**: Tier A blocks **at the next session start**. "Immediate stop when disabled during execution" is out of scope for v1 (on the assumption that Hermes does not reflect dynamic plugin disabling while a session is running; to be verified in Phase 0.8)

### Tier B: Vendored fork extra (v2, deferred)

Only when hard-enforce truly becomes necessary (e.g., when it's judged that Tier A's defense-in-depth is insufficient):

- Copy the relevant Hermes version's `plugins_cmd.py` into `vendor/hermes/<version>/hermes_cli/plugins_cmd.py`, and apply a patch that checks `privacy_lock` inside the `disable` internal function
- Add an extra such as `hard-lock = ["hermes-mordred-core==<pinned>"]` to `[project.optional-dependencies]` in `pyproject.toml` (the concrete distribution form will be finalized during v2 design)
- Users obtain the hard-enforce version via `pip install hermes-mordred[hard-lock]`
- Pinned to a specific Hermes version (e.g., `hermes-agent==0.5.0`); the patch is reapplied with each upstream release
- Not included in the v1 release

## Conflict resolution (if a conflict occurs in the vendored fork)

Normally, conflicts don't occur for a plugin-only Mordred (Mordred only touches `src/mordred_hermes/*`, and doesn't touch Hermes upstream).

The policy in the unlikely event of a conflict after the vendored fork extra is introduced in v2 or later:

- Changes to `src/mordred_hermes/*` **always keep the Mordred side**
- Mordred patches under `vendor/hermes/<version>/*` are pinned to the relevant Hermes version. Rather than merging with a new Hermes upstream version, create a new separate vendored directory (`vendor/hermes/<new-version>/`) and migrate into it
- We **do not** submit a PR to Hermes upstream (zero-PR commitment)

## Future migration

Reevaluate the strategy if any of the following situations arise:

- A determination that the Mordred plugin's Tier A guard (CLI wrapper + audit log) is insufficient as defense-in-depth → proceed to **Tier B (vendored fork extra)**
- The vendored fork spreads across multiple Hermes modules and the patch-carry cost becomes excessive → reconsider Option B (soft fork) or Option A (hard fork)
- A need arises for Mordred to strengthen its independent branding → reconsider **Option A (hard fork)**

At that point, update `MIGRATION.md` §5.

## Quick reference

- Hermes upstream URL: `https://github.com/NousResearch/hermes-agent`
- Mordred plugin repository: `hermes-mordred/` (this repository)
- Mordred distribution package: `hermes-mordred` (PyPI; v1 is plugin-only)
- Legacy distribution alias: `mordred-hermes` (metadata-only compatibility shim)
- v2 candidate extra: `hermes-mordred[hard-lock]` (vendored fork, Tier B)
- Hermes upstream PR status: **Not submitted (zero-PR commitment, §Zero-PR commitment)**
