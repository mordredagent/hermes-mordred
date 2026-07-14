# Mordred — Upstream Tracking (Hermes-base)

> **Note**: This document describes the upstream tracking strategy on the `Hermes (NousResearch/hermes-agent)` foundation. The old OpenClaw-based version remains at `../../mordred/mordred-mvp-docs/UPSTREAM.md` (deprecated).

The finalized strategy decisions are in `MIGRATION.md` §5 (`Option C + Vendored-fork escape hatch`, zero-PR commitment, revised 2026-05-07). This file records the concrete operational procedures.

## Repository position

`Mordred-Hermes/` is a **Hermes plugin development repository** (a pure plugin bundle), not a fork of the Hermes upstream.
The distribution form is a single package via `pip install mordred-hermes` (entry-point `hermes_agent.plugins`).

Therefore:

- **Mordred's own code** lands in `src/mordred_hermes/<plugin>/`
- **Hermes upstream** is only used as a clone directly under `Mordred-Hermes/` for testing during development; it's optional as a git remote for Mordred
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

Only if you want to track the latest Hermes upstream during Mordred development:

```sh
git remote add hermes-upstream https://github.com/NousResearch/hermes-agent.git
git fetch hermes-upstream
git log --oneline hermes-upstream/main -5
```

If you want to fast-forward the clone:

```sh
git fetch hermes-upstream
git checkout main
git merge --ff-only hermes-upstream/main   # assumes there are no local changes
```

If you have local Mordred plugin development files, `git stash` them, then `merge --ff-only`, then `git stash pop`.

## Hook signature drift detection (informational only)

To keep up with Hermes upstream's rapid evolution, CI detects signature drift in the hook payloads (e.g., `pre_tool_call`, `pre_llm_call`) that plugins depend on.

See the `upstream-check.yml` workflow in [`CI.md`](./CI.md) for details. This workflow fetches the latest `hermes_cli/plugins.py:VALID_HOOKS` enumeration from Hermes weekly, and cross-checks it against the hook names registered by Mordred plugins. When a discrepancy occurs, a GitHub issue is automatically filed.

- This signal detection is **informational**: it's not for submitting a PR upstream, but is used as material for judging whether the vendored fork extra (Tier B) is needed, and as a trigger for updating the `mordred-min-hermes-version` / `mordred-max-hermes-version` range on the Mordred plugin side
- Detected drift never blocks a release

## Privacy-lock guard (replacement for the old HSeam-1)

The old SPEC planned to add a `privacy_lock: bool` field to `plugin.yaml` and submit a small PR upstream to Hermes requiring a `--unlock` flag on the `hermes plugins disable` side (old HSeam-1).

In the revised strategy, we do not submit a PR upstream to Hermes, and instead realize privacy-lock via the following two-tier approach:

### Tier A: Plugin-side guard (v1 default, zero core change)

> **Decided 2026-05-07 (H3 Path B)**: For Tier A, **fail-closed under strict mode (RuntimeError raise + session abort)** is the default. It is not an audit-only spec. Same definition as SPEC.md §Plugin-disable protection §Tier A / TODO §1.1 H3 Path B.

- Each Mordred plugin declares `privacy_lock: true` in its `plugin.yaml` (the Hermes core ignores this field, but Mordred plugins reference it among themselves)
- `mordred_wizard` provides the `hermes mordred plugins disable <plugin>` wrapper CLI, and plugins under `mordred_*` refuse when an attempt is made to disable them without the `--unlock` flag (defense-in-depth at the UX layer)
- **At the start of each Mordred plugin's `on_session_start`, scan the sibling list (`mordred_network` / `mordred_privacy_check` / `mordred_llm_guard` / `mordred_keyvault` / `mordred_wizard`)**:
  - **If `policy=strict` and even one sibling is disabled**: raise a refusal exception equivalent to `RuntimeError("Mordred strict mode requires all sibling plugins enabled; disabled: [...]. Re-enable via 'hermes plugins enable <name>' or downgrade policy to lenient.")` and abort the session. At the same time, record an audit log entry `mordred.degraded.disable_unprotected` (decision=`block`). **The choice of derived class follows the Exception propagation contract in SPEC.md §Plugin-disable protection §Tier A** (`privacy_check` legacy = derives from `SystemExit`, `llm_guard` onward = derives directly from `BaseException`)
  - **If `policy=lenient` / `off`**: warning only (the audit `mordred.degraded.disable_unprotected` (decision=`warn`) is likewise recorded, to ensure compatibility)
- If a user uses Hermes's standard `hermes plugins disable mordred_*`, the disable itself goes through on the Hermes side, but **the design is such that the fail-closed behavior above fires and blocks at the next strict session start**
- **Important caveat**: Tier A blocks **at the next session start**. "Immediate stop when disabled during execution" is out of scope for v1 (on the assumption that Hermes does not reflect dynamic plugin disabling while a session is running; to be verified in Phase 0.8)

### Tier B: Vendored fork extra (v2, deferred)

Only when hard-enforce truly becomes necessary (e.g., when it's judged that Tier A's defense-in-depth is insufficient):

- Copy the relevant Hermes version's `plugins_cmd.py` into `vendor/hermes/<version>/hermes_cli/plugins_cmd.py`, and apply a patch that checks `privacy_lock` inside the `disable` internal function
- Add an extra such as `hard-lock = ["mordred-hermes-core==<pinned>"]` to `[project.optional-dependencies]` in `pyproject.toml` (the concrete distribution form will be finalized during v2 design)
- Users obtain the hard-enforce version via `pip install mordred-hermes[hard-lock]`
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
- Mordred plugin repository: `Mordred-Hermes/` (this repository)
- Mordred distribution package: `mordred-hermes` (planned for PyPI; v1 is plugin-only)
- v2 candidate extra: `mordred-hermes[hard-lock]` (vendored fork, Tier B)
- Hermes upstream PR status: **Not submitted (zero-PR commitment, §Zero-PR commitment)**
