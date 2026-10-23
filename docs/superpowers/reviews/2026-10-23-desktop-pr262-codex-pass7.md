# Codex seventh-pass review: Desktop mail and ceremony pages (PR #262, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run against commit 96b6d2b13. Verdict SHIP: the last sixth-pass item is resolved and no new findings. Absolute links were flattened to `path:line` text.


Reviewed `96b6d2b13` offline, read-only.

## Sixth-pass item

**RESOLVED.** Both guards reject older answers before changing completion or display state: ImportStep, SetupPage.

- **Busy → stale idle → completed idle:** status reads remain **1 → 1 → 2**; completion displays **9 messages / Done**. The reproduction fails against the parent commit.
- **Stale idle first:** preserves the pending mark; actual completion refreshes exactly once.
- **ImportStep remount:** poll numbers continue **101 → 102 → 103 → 104**. Late answers from either instance cannot overwrite newer busy state.
- **SetupPage remount:** highest-seen resets **201 → 0**, then accepts legitimate poll **204**. Old promises retain the old page’s callbacks and refs; answers arriving before or after the new busy answer cannot contaminate the new page. Completion refreshes correctly.
- An identical newer answer advances the watermark before deduplication, so intervening stale answers remain rejected.

## New findings

None from this commit. Nine existing Node-backed cases and three additional in-memory probes passed; no pytest run or files changed.

## Verdict

**SHIP** — the sixth-pass blocker is resolved; merge PR #262 into its stacked base.