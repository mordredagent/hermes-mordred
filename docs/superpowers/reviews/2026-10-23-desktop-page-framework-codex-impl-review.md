# Codex implementation review: Desktop page framework (D3, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against branch feat/desktop-page-framework at b03a4bc2c (PR #263). Verdict REVISE (2 HIGH, 2 MEDIUM, 1 LOW, test gaps). Absolute links were flattened to `path:line` text. The fixes land on the same PR.


## Findings

1. **HIGH — Error handling can expose response text and typed secrets.**  
   plugin.js:336 treats arbitrary `err.message` as an error code; `explain()` interpolates unknown codes. FailureNote:366 also renders raw `detail`, `remedy`, and other response fields. Controlled probes reproduced a canary in an inline alert and `Failed (HTTP 422 echoed review-canary)` in a Windows notification. The parser is inherited, but D3 newly uses this renderer for secret-submit failures.  
   **Fix:** accept only known codes, use a fixed generic message otherwise, and project safe fields before rendering or notifying. Preserve only the explicitly permitted, validated stale-anchor remedy.

2. **HIGH — Collapsing a completed card does not clear its secret inputs.**  
   The disclosure toggle changes only `Step.open` at plugin.js:447. Secret clearing depends on the parent’s step state, not disclosure visibility (plugin.js:1198). For a completed question model: **Change → type key → Hide → Change** restores the typed key. A dependency-aware harness reproduced this; the Telegram component has the same defect.  
   **Fix:** notify the secret-owning component when the disclosure closes, or move secret state into a form component that unmounts on collapse. Cover collapse followed by blocking as well.

3. **MEDIUM — A stale import poll overrides status-derived `attention`.**  
   plugin.js:1338 preserves only `done` and `blocked` before applying local `starting || syncing`. Supplying `state: "attention", code: "no_key"` while the previous `/sync` answer says `syncing: true` renders **Running** and removes the alert. This violates the required precedence.  
   **Fix:** preserve status-derived `attention` before applying transient running state; test the component transition, not just `stepStates()`.

4. **MEDIUM — Failed edits to a completed step produce no visible error.**  
   plugin.js:1197 keeps a configured model’s state `done`, while the done branch at plugin.js:437 never renders `failure`. Opening **Change** and submitting an invalid key records the error and clears the input, but produces neither an alert nor a notification. Focus has no failure element to target. Telegram has the same pattern.  
   **Fix:** retain the status-derived `done` badge while rendering and focusing the operation failure independently of the state-specific body.

5. **LOW — Windows rendering is not byte-identical.**  
   `WindowsSetup` and the legacy `Step` structure are unchanged, but shared fields add `aria-label` attributes in legacy mode—for example plugin.js:1148, plugin.js:1236, and plugin.js:1308. Comparing 128 initial Windows combinations found four differing rendered trees. These are accessibility improvements, but they violate the stated preservation requirement.  
   **Fix:** restrict new markup to framework mode and compare the complete legacy output against the base, including interactive states.

## Test gaps

**All 119 scoped tests passed.** All 19 state fixtures agree with `stepStates()`, and their rendered heading states also matched when checked individually. The SDK import is exactly unchanged. Linux retains its controls; no conditional-hook violation was found.

- **The tests execute components and handlers, but do not mount React or a DOM.** The harness:34 ignores effect dependencies, component identity and reconciliation. Selected accessibility assertions are meaningful, but focus preservation, lifecycle cleanup and keyboard behavior are not established.

- **The refresh test passes despite deliberately broken identity.** An in-memory mutation that changes step keys when `jobs.length` changes still passed test_desktop_page.py:1199. Use a real React mount and assert DOM identity and `activeElement`.

- **The login-code leakage assertion is ineffective.** test_desktop_page.py:1151 checks the code only against the already-asserted empty input value. An in-memory mutation that explicitly notified the typed login code still passed. Check every canary against notifications, rendered errors and other output sinks.

- **Secret coverage omits 2FA passwords, collapse/reopen, blocking transitions and late responses after cancellation.** The simulated unmount also executes effects at “unmount” rather than modeling React’s actual lifecycle (test_desktop_page.py:1030).

- **D4 needs explicit polling acceptance tests.** Current refreshes overlap and allow an older response to overwrite newer status (plugin.js:2361); this was reproduced. With v4 zero-count status, a completed import also remains **Next / nothing imported yet**, because `/sync` updates do not refresh store counts. Coalescing and store-backed counts are explicitly assigned to D4, so these are handoff requirements rather than additional D3 blockers.

The referenced “Second revision”/NF10 item is absent from the checked-in design document; that item could not be verified.

## Verdict

**REVISE.** Fix error sanitization, disclosure-driven secret clearing, import-state precedence, and invisible failures on completed steps. Restore the required Windows output compatibility and add regression tests that detect the demonstrated failures.

No files were changed; protected paths and database files were not read.