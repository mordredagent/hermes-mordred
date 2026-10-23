# Codex eleventh-pass review: Desktop mail and ceremony pages (PR #262, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run against commit 5c62e723e. Verdict SHIP: the tenth-pass item is resolved, no new findings. PR #262 was merged into feat/imported-message-provenance as 69c1ef0d5 after the full CI matrix passed.


Reviewed HEAD `5c62e723efe83ecb3e1098b2dec79dcb50f15966`. Read-only, offline; no prohibited reads.

## Tenth-pass item

**RESOLVED.** Admission precedes `_raw_socket(link)`, with outer `finally` forfeiture (imap.py:1012).

Fresh in-memory probes confirmed:

- Four abandoned workers saturate the cap; refusal makes **zero raw-factory calls and zero DNS calls**.
- `_raw_socket` failure, `os.dup` failure, and an already-interrupted link each release the slot.
- Workers release on success and exception; abandoned workers release when finished.
- All counters return to **zero**, without duplicate releases.

## New findings

None. **12 probe groups passed.** Stdlib success and wrap/handshake/timeout-failure traces match the pre-split implementation. `link.hold`/`drop` ownership remains correct: failure paths close raw and mirror sockets; detached TLS sockets are retained or closed appropriately.

Worktree remains clean. Socket-based tests were not run under the no-network constraint.

## Verdict

**SHIP** — merge PR #262 into its stacked base. No remaining blocker in this narrow confirmation review.