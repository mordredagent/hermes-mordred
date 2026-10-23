# Codex ninth-pass review: Desktop mail and ceremony pages (PR #262, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run against commit 4ab15693e. Verdict REVISE (late-socket ownership race, unbounded abandoned handshake workers, CLI sink not restored); fixed afterwards in 497465edc. Absolute links were flattened to `path:line` text.


## Eighth-pass items

| P2 item | Status | Evidence |
|---|---|---|
| Wrapper verification exceeds deadline | **PARTIAL** | Three 50 ms probes failed with `imap_unreachable` in 53–55 ms. Verification rejection propagated without fallback; certificate/hostname checks remain enabled. Late-socket cleanup fails below. |
| Same-second failure suppression | **RESOLVED** | Same-second failures with both identical and different errors reappear after status refresh. Own-result precedence and suppression while running pass; suppression does not persist across fresh status objects. |

## New findings

- **P2 — Late-socket cleanup races publication.** At imap.py:1028, timeout pops `late` before the blocked wrapper returns. The worker subsequently publishes its socket without checking abandonment or closing it. A detaching-wrapper probe left all three retained late sockets open after worker exit. The added test misses this because it returns the original raw socket, already closed by failure cleanup. Use synchronized ownership transfer and close late results explicitly.

- **Worker accumulation remains unbounded.** Three timed-out attempts left three handshake workers alive until released; all exited afterward. A verifier that never returns retains a worker and its detached socket per retry. Abandonment needs a concurrency bound to prevent accumulation.

- **P3 — CLI sink escapes its invocation.** mail_sync_cli.py:426 installs the global sink without restoring it. Reproduced: text fetch followed by `--json` **in the same process** emits diagnostics to stderr. Fresh-process JSON stays silent and JSON stdout remains valid.

Other checks passed: diagnostic probes emitted no injected content; no sink was silent; a raising sink preserved the failure outcome. Desktop lifespan installed and removed its sink on normal and exceptional body exits. **11 focused tests passed**, including the Windows snapshot.

## Verdict

**REVISE** before merging into the stacked base: finish TLS resource ownership and bound abandoned-worker accumulation.

Reviewed `4ab15693e`; no files changed, network used, or excluded paths/database files read.