# Codex implementation review: Desktop API for vault, databases, imports and mail (D4 backend, 2026-10-23)

Reviewer: Codex CLI 0.163.0, model `gpt-6-astra`, read-only sandbox, run by the Fable session against commit 845c99a5b (integration branch feat/desktop-mail-ceremonies, PR #262). Verdict REVISE (2 HIGH, 4 MEDIUM, test gaps). Finding 1 was already addressed by the D2 fix bb6c9c515 (raw SQLCipher open) merged after this review started; the other findings are fixed on PR #262. Absolute links were flattened to `path:line` text.


## Findings

1. **HIGH — The real imports status path still invokes a potentially unlocking key provider.**

   Evidence: api.py:335 reaches store.py:1590, whose process-SQLite connection calls the shim’s captured provider at _shim.py:214. That provider can inject the vault environment at _key.py:84.

   A guarded probe confirmed the provider call. A stable valid environment key prevented injection; an unconditional unlock was **not** demonstrated. Nevertheless, NF4/NF5’s provider prohibition is violated, and validation does not bind subsequent connections to the validated key.

   **Fix:** use a connection path bound to captured, validated environment key material, with no injecting provider.

2. **HIGH — A stale legacy anchor can migrate into the helper before the non-migrating diagnosis runs.**

   Evidence: _vault.py:295 invokes the wizard before diagnosis. `ensure_initialised()` resolves and reads the default store at _vault_lifecycle.py:218. The helper store then copies the legacy anchor and deletes its original at _anchor_keychain.py:395.

   A probe with real store logic and fake native operations observed `helper.add` followed by `legacy.discard`; subsequent diagnosis reported `helper`, without the legacy remedy. The ceremony has converted an actionable legacy case into the deferred helper-reset case.

   **Fix:** diagnose missing-vault/stale-anchor state before entering the migratory wizard path, and preserve the vault initialization lock’s concurrent-state checks.

3. **MEDIUM — A cold `/status?client_version=4` poll still creates Telegram filesystem state.**

   Evidence: api.py:236 calls `run_checks()`, which calls `TeeSecretStore.flags()`. Its metadata path invokes `_ensure_private_dir()`, performing `mkdir`, `chmod`, and `.gitignore` creation at telegram/store.py:154. The separate flags call at `api.py:243` repeats this path.

   **Fix:** make both Telegram status reads non-creating. Correcting only the new imports sections cannot satisfy the whole-endpoint contract.

4. **MEDIUM — An unreadable helper anchor is incorrectly classified as legacy when a legacy item also exists.**

   Evidence: _vault.py:194 obtains `unknown`, but a successful legacy read replaces that uncertainty with `legacy`; an empty-directory check then enables the deletion command. A guarded probe reproduced this combination.

   NF6 requires an unreadable/unsupported helper to report `unknown`. The code cannot establish whether that helper also holds an anchor.

   **Fix:** preserve helper uncertainty and suppress the remedy. Test unknown-helper-plus-present-legacy explicitly.

5. **MEDIUM — `/memory/enable` bypasses its vault/env prerequisites when memory already appears active.**

   Evidence: api.py:532 returns `already` before the checks in `_vault.enable_memory()`. The real macOS activity determination checks memory markers/runtime/drift, not vault existence or env enrollment/injection: encryption_cli.py:268.

   Thus existing sealed memory with an opted-out `.env`, or a missing vault, can receive success instead of `env_required`/`vault_required`.

   **Fix:** enforce the macOS prerequisites before the idempotent success response.

6. **MEDIUM — Effective vault policy remains unimplemented despite the normative requirement.**

   Evidence: _vault.py:117 deliberately always returns `unattended: null`. The integration test enshrines that result even after creating an explicitly attended key: test_desktop_vault.py:540.

   Returning unknown is honest, but it does not implement the promised effective-policy field.

   **Fix:** provide a non-unlocking effective-policy interface, or explicitly revise the normative contract to permit unknown policy. Never substitute the requested policy for an existing key’s effective policy.

## Test gaps

- **The status tripwires are over-mocked.** test_desktop_status_v4.py:229 uses a fixture replacing `_open_store_readonly`, `_store`, and `run_checks` at _desktop_support.py:209. These replacements hide findings 1 and 3. Patching `dbcrypt._PROVIDER` after installation also misses the provider captured by the shim. Preserve the real call chain and intercept only native/filesystem/SQLCipher boundaries.
- **The stale-anchor tests bypass the relevant ceremony.** test_desktop_vault.py:218 replaces `env_decrypt_cli.enable()` with an immediate failure. Add real wizard-path coverage with fake helper/legacy operations and assertions against migration.
- **Mail expiry is only partially integrated.** The reaper test substitutes a counter for `MailSetupFlows` at test_desktop_vault.py:443. Exercise a real pending flow through router lifespan, idle expiry, forget, and shutdown. The fetch test also expressly permits a fake address on stdout at test_desktop_mail.py:223; it does not prove the output boundary.
- **No-file-creation evidence needs WAL cases.** Both readonly imports and database discovery use `mode=ro`; that alone does not establish that SQLite sidecars cannot be created. Verify missing-sidecar behavior without using an immutable snapshot that ignores concurrent fetch writes.
- **The deployment version remains unverified.** The repository lock contains Hermes **0.19.0** and FastAPI **0.139.0**, not Hermes 0.21.5. With the installed FastAPI, a guarded probe confirmed router lifespan starts and stops the reaper. There is no demonstrated lifespan bug here, but the exact deployed dependency combination needs evidence.

Several important claims **are supported**:

- Eleven secret routes have no FastAPI body/query parameters or OpenAPI `requestBody`. All 33 guarded malformed-body checks—including non-UTF-8—returned `invalid_body` without echoing the canary.
- The real recovery test at test_desktop_vault.py:510 exercises wizard initialization and `recover_vault()` with the displayed phrase. `FlowSession` supplies it without printing it and clears its reference afterward. Failed commits without vault artifacts retain the prepared flow under its **original** TTL; that bounded retry behavior is acceptable.
- A guarded cancellation probe confirmed the worker retains and releases the ceremony lock after request cancellation.
- All 64 database decision combinations matched the required precedence. The route schedules without calling `migrate()` or `arm()`.
- Mail gates, strict `rows`, confirmation ordering, fetch options/results, failure codes, and encryption-aware audit wiring match the inspected contract.

The reported 91% coverage does not resolve the bypassed integration paths above. I did not rerun filesystem/database-writing pytest suites.

## Verdict

**REVISE.** Fix findings 1–5 and resolve the effective-policy contract in finding 6 before shipping.

The planned sub-router split is safe if shared locks, flow registries, lifespan ownership, and `_library` seams remain centralized. Route modules must resolve replaceable seams dynamically; importing function aliases would break existing monkeypatch seams. Preserve the Windows routes and acknowledgements during extraction.

The anchor “empty” check matches the specified file predicates, but remains a snapshot, not a concurrency-safe reset authorization; K1 still needs locked revalidation.

Review completed read-only and offline. No files changed, prohibited production files accessed, or databases opened.